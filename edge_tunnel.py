"""VLESS v0 TCP sessions transported as WebSocket binary data."""

from dataclasses import dataclass
from ipaddress import IPv4Address
import selectors
import socket
import time

from wsproto.connection import ConnectionState
from wsproto.events import BytesMessage, CloseConnection, Ping, TextMessage
from wsproto.utilities import LocalProtocolError, RemoteProtocolError

from edge_config import valid_domain

CHUNK = 32768
HEADER_TIMEOUT = 10
IDLE_SECONDS = 120
MAX_SESSION_SECONDS = 900
ALLOWED_PORTS = (80, 443)


class TunnelPolicyError(ValueError):
    pass


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
    if data[18] != 1:
        raise TunnelPolicyError("only TCP is supported")
    port = int.from_bytes(data[19:21], "big")
    if port not in ALLOWED_PORTS:
        raise TunnelPolicyError("destination port is not allowed")
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


def connect_public(host, port):
    # Resolve once, then dial the exact validated IP to avoid a second lookup.
    addresses = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    targets = dict.fromkeys(address for _, _, _, _, address in addresses)
    public = []
    for address in targets:
        ip = IPv4Address(address[0])
        if ip.is_global and not ip.is_multicast and not ip.is_reserved:
            public.append(address)
    if not public:
        raise TunnelPolicyError("destination is not a public IPv4 address")
    for address in public[:3]:
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            upstream.settimeout(4)
            upstream.connect(address)
            upstream.settimeout(8)
            return upstream
        except OSError:
            upstream.close()
    raise OSError("outbound connection failed")


def close_frame(client, protocol, code, reason=""):
    if protocol.state in (ConnectionState.OPEN, ConnectionState.REMOTE_CLOSING):
        try:
            client.sendall(protocol.send(CloseConnection(code, reason)))
        except (OSError, LocalProtocolError):
            pass


class Tunnel:
    def __init__(self, client, protocol, config, selector):
        self.client = client
        self.protocol = protocol
        self.config = config
        self.selector = selector
        self.upstream = None
        self.header = bytearray()
        self.expires = None

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
                raise TunnelPolicyError("invalid or expired connection")
        target = read_target(self.header)
        if target is None:
            return
        self.upstream = connect_public(target.host, target.port)
        self.selector.register(self.upstream, selectors.EVENT_READ, "outbound")
        self.client.sendall(self.protocol.send(BytesMessage(data=b"\x00\x00")))
        if len(self.header) > target.payload_offset:
            self.upstream.sendall(self.header[target.payload_offset:])
        self.header.clear()

    def receive_client(self):
        data = self.client.recv(CHUNK)
        if not data:
            return False
        self.protocol.receive_data(data)
        for event in self.protocol.events():
            if isinstance(event, BytesMessage):
                self.binary(event.data)
            elif isinstance(event, Ping):
                self.client.sendall(self.protocol.send(event.response()))
            elif isinstance(event, TextMessage):
                close_frame(self.client, self.protocol, 1003, "binary data required")
                return False
            elif isinstance(event, CloseConnection):
                code = event.code if event.code not in (1005, 1006, 1015) else 1000
                close_frame(self.client, self.protocol, code)
                return False
        return True

    def receive_outbound(self):
        chunk = self.upstream.recv(CHUNK)
        if not chunk:
            close_frame(self.client, self.protocol, 1000)
            return False
        self.client.sendall(self.protocol.send(BytesMessage(data=chunk)))
        return True

    def run(self):
        started = time.monotonic()
        idle_limit = started + HEADER_TIMEOUT
        self.selector.register(self.client, selectors.EVENT_READ, "client")
        while True:
            now = time.monotonic()
            remaining = min(idle_limit - now, started + MAX_SESSION_SECONDS - now)
            if self.expires is not None:
                remaining = min(remaining, self.expires - time.time())
            if remaining <= 0:
                close_frame(self.client, self.protocol, 1000, "session ended")
                return
            for key, _ in self.selector.select(remaining):
                keep_open = self.receive_client() if key.data == "client" else self.receive_outbound()
                if not keep_open:
                    return
                if self.upstream is not None:
                    idle_limit = time.monotonic() + IDLE_SECONDS


def relay(client, protocol, config):
    with selectors.DefaultSelector() as selector:
        tunnel = Tunnel(client, protocol, config, selector)
        try:
            tunnel.run()
        except TunnelPolicyError:
            close_frame(client, protocol, 1008, "connection rejected")
        except (LocalProtocolError, RemoteProtocolError):
            close_frame(client, protocol, 1002, "invalid websocket data")
        except OSError:
            close_frame(client, protocol, 1011, "connection unavailable")
        finally:
            if tunnel.upstream is not None:
                tunnel.upstream.close()
