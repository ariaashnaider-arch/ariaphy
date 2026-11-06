"""VLESS v0 web traffic and DNS transported as WebSocket binary data."""

from dataclasses import dataclass
from ipaddress import AddressValueError, IPv4Address
import socket
import sys
from threading import Event, Lock, Thread
import time

from wsproto.connection import ConnectionState
from wsproto.events import BytesMessage, CloseConnection, Ping, TextMessage
from wsproto.utilities import LocalProtocolError, RemoteProtocolError

from edge_config import valid_domain

CHUNK = 64 * 1024
HEADER_TIMEOUT = 10
IO_TIMEOUT = 4
IDLE_SECONDS = 120
MAX_SESSION_SECONDS = 900
WEB_PORTS = (80, 443)
DNS_PORT = 53
DNS_RESOLVERS = frozenset(IPv4Address(ip) for ip in (
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
))


class TunnelPolicyError(ValueError):
    pass


class OutboundError(OSError):
    def __init__(self, reason, cause):
        super().__init__(getattr(cause, "errno", None), reason)
        self.reason = reason


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    payload_offset: int


def read_target(data):
    if len(data) < 18:
        return None
    if data[0] != 0 or data[17] != 0:
        raise TunnelPolicyError("VLESS v0 without Flow or addons is required")
    if len(data) < 22:
        return None
    command = data[18]
    if command not in (1, 2):
        raise TunnelPolicyError("only TCP and DNS are supported")
    port = int.from_bytes(data[19:21], "big")
    if port != DNS_PORT and (command != 1 or port not in WEB_PORTS):
        raise TunnelPolicyError("destination port is not allowed")
    # VLESS UDP and DNS over TCP both prefix each DNS message with its
    # two-byte length. The same stream relay serves both VLESS DNS commands.
    kind = data[21]
    if kind == 1:
        if len(data) < 26:
            return None
        return Target(str(IPv4Address(bytes(data[22:26]))), port, 26)
    if kind != 2:
        raise TunnelPolicyError("an IPv4 address or domain is required")
    if len(data) < 23:
        return None
    end = 23 + data[22]
    if len(data) < end:
        return None
    try:
        host = data[23:end].decode("ascii").lower().removesuffix(".")
    except UnicodeError as error:
        raise TunnelPolicyError("invalid destination") from error
    if not valid_domain(host):
        raise TunnelPolicyError("invalid destination")
    return Target(host, port, end)


def disable_nagle(stream):
    try:
        stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except (AttributeError, OSError, NotImplementedError):
        pass  # Some runtimes do not expose this socket option.


def connect_public(host, port):
    # Resolve once, then dial the exact validated IP to avoid a second lookup.
    try:
        address = IPv4Address(host)
    except AddressValueError:
        try:
            addresses = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        except (OSError, NotImplementedError) as error:
            raise OutboundError("outbound-dns", error) from error
        targets = dict.fromkeys(endpoint for _, _, _, _, endpoint in addresses)
    else:
        targets = ((str(address), port),)
    public = []
    for endpoint in targets:
        ip = IPv4Address(endpoint[0])
        if port == DNS_PORT and ip not in DNS_RESOLVERS:
            continue
        if ip.is_global and not ip.is_multicast and not ip.is_reserved:
            public.append(endpoint)
    if not public:
        raise TunnelPolicyError("destination is not an allowed public IPv4 address")

    last_error = None
    for endpoint in public[:3]:
        try:
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except (OSError, NotImplementedError) as error:
            raise OutboundError("outbound-socket", error) from error
        try:
            upstream.settimeout(IO_TIMEOUT)
            upstream.connect(endpoint)
            disable_nagle(upstream)
            return upstream
        except (OSError, NotImplementedError) as error:
            last_error = error
            upstream.close()
    raise OutboundError("outbound-connect", last_error) from last_error


def close_frame(client, protocol, code, reason=""):
    if protocol.state in (ConnectionState.OPEN, ConnectionState.REMOTE_CLOSING):
        try:
            client.sendall(protocol.send(CloseConnection(code, reason)))
        except (OSError, LocalProtocolError, NotImplementedError):
            pass


class Tunnel:
    def __init__(self, client, protocol, config):
        self.client = client
        self.protocol = protocol
        self.config = config
        self.upstream = None
        self.downstream = None
        self.header = bytearray()
        self.expires = None
        self.stopped = Event()
        self.ws_lock = Lock()
        self.started = self.last_activity = time.monotonic()
        self.phase = "vless-header"

    def send(self, event):
        with self.ws_lock:
            if self.stopped.is_set() or self.protocol.state != ConnectionState.OPEN:
                return False
            self.client.sendall(self.protocol.send(event))
        return True

    def finish(self, code, reason, error=None):
        with self.ws_lock:
            if self.stopped.is_set():
                return
            self.stopped.set()
            if code != 1000 or self.phase != "relay" or reason == "upstream-empty":
                # Log the phase only. Client credentials and traffic stay out of logs.
                detail = f" error={type(error).__name__}" if error is not None else ""
                errno = getattr(error, "errno", None)
                if isinstance(errno, int):
                    detail += f" errno={errno}"
                print(f"aria tunnel phase={self.phase} close={code} reason={reason}{detail}",
                      file=sys.stderr, flush=True)
            close_frame(self.client, self.protocol, code, reason)

    def binary(self, data):
        if self.upstream is not None:
            self.upstream.sendall(data)
            return
        self.header.extend(data)
        if len(self.header) < 18:
            return
        if self.expires is None:
            self.expires = self.config.client_expiry(bytes(self.header[1:17]))
            if self.expires is None:
                self.finish(1008, "invalid-profile")
                return
        target = read_target(self.header)
        if target is None:
            return
        self.phase = "dns-outbound" if target.port == DNS_PORT else "outbound"
        self.upstream = connect_public(target.host, target.port)
        self.last_activity = time.monotonic()
        self.phase = "relay"
        if not self.send(BytesMessage(data=b"\x00\x00")):
            self.finish(1000, "client-closed")
            return
        # One reader per socket avoids polling both WASIX sockets in one selector.
        worker = Thread(target=self.receive_outbound, daemon=True)
        worker.start()
        self.downstream = worker
        if len(self.header) > target.payload_offset:
            self.upstream.sendall(self.header[target.payload_offset:])
        self.header.clear()

    def receive_client(self, data):
        with self.ws_lock:
            self.protocol.receive_data(data)
            events = self.protocol.events()
        while not self.stopped.is_set():
            with self.ws_lock:
                event = next(events, None)
                state = self.protocol.state
            if event is None:
                break
            if isinstance(event, BytesMessage):
                self.binary(event.data)
            elif isinstance(event, Ping):
                self.send(event.response())
            elif isinstance(event, TextMessage):
                self.finish(1003, "binary-required")
            elif isinstance(event, CloseConnection):
                code = event.code if event.code not in (1005, 1006, 1015) else 1000
                reason = "websocket-protocol" if state == ConnectionState.OPEN else "client-closed"
                self.finish(code, reason)

    def receive_outbound(self):
        received = False
        try:
            while not self.stopped.is_set():
                try:
                    chunk = self.upstream.recv(CHUNK)
                except TimeoutError:
                    continue
                if not chunk:
                    self.finish(1000, "upstream-eof" if received else "upstream-empty")
                    return
                received = True
                self.last_activity = time.monotonic()
                if not self.send(BytesMessage(data=chunk)):
                    return
        except (OSError, LocalProtocolError) as error:
            self.finish(1011, "relay-io", error)
        except Exception as error:
            self.finish(1011, "tunnel-runtime", error)

    def run(self, reader=None):
        self.client.settimeout(IO_TIMEOUT)
        disable_nagle(self.client)
        # The HTTP reader may already contain bytes of the first WS frame.
        read = self.client.recv if reader is None else reader.read1
        while not self.stopped.is_set():
            now = time.monotonic()
            if self.upstream is None and now - self.started >= HEADER_TIMEOUT:
                self.finish(1008, "header-timeout" if self.header else "first-frame-timeout")
                return
            if self.expires is not None and time.time() >= self.expires:
                self.finish(1008, "expired-profile")
                return
            if now - self.last_activity >= IDLE_SECONDS or now - self.started >= MAX_SESSION_SECONDS:
                self.finish(1000, "session-ended")
                return
            try:
                data = read(CHUNK)
            except TimeoutError:
                # read1 only reaches the socket when its buffer is empty. A
                # timed-out SocketIO can't be read again, so resume at the socket.
                read = self.client.recv
                continue
            if not data:
                self.finish(1000, "client-eof")
                return
            self.last_activity = time.monotonic()
            self.receive_client(data)

    def cleanup(self):
        self.stopped.set()
        if self.upstream is None:
            return
        try:
            self.upstream.shutdown(socket.SHUT_RDWR)
        except (OSError, NotImplementedError):
            pass
        if self.downstream is not None:
            self.downstream.join(IO_TIMEOUT + 1)
        self.upstream.close()


def relay(client, protocol, config, *, reader=None):
    tunnel = Tunnel(client, protocol, config)
    try:
        tunnel.run(reader)
    except TunnelPolicyError:
        tunnel.finish(1008, "connection-rejected")
    except OutboundError as error:
        tunnel.finish(1011, error.reason, error)
    except (LocalProtocolError, RemoteProtocolError) as error:
        tunnel.finish(1002, "websocket-protocol", error)
    except OSError as error:
        tunnel.finish(1011, "relay-io", error)
    except Exception as error:
        tunnel.finish(1011, "tunnel-runtime", error)
    finally:
        tunnel.cleanup()
