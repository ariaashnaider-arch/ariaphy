#!/usr/bin/env python3
"""Aria Wasmer web panel and private VLESS WebSocket endpoint."""

import base64
from collections import deque
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
from threading import BoundedSemaphore, Lock
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "vendor"))

import h11
from wsproto import ConnectionType, WSConnection
from wsproto.events import AcceptConnection
from wsproto.utilities import LocalProtocolError, RemoteProtocolError

from edge_config import EdgeConfig, SESSION_SECONDS, WS_PATH
from edge_tunnel import relay

SESSION_COOKIE = "__Host-aria_session"
MAX_JSON = 4096
STATIC_ROOT = ROOT / "static"
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/static/style.css": ("style.css", "text/css; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/static/keys.js": ("keys.js", "text/javascript; charset=utf-8"),
    "/static/qr.js": ("qr.js", "text/javascript; charset=utf-8"),
    "/static/flame.svg": ("flame.svg", "image/svg+xml"),
    "/static/vazirmatn.woff2": ("vazirmatn.woff2", "font/woff2"),
}


class Server(ThreadingHTTPServer):
    request_queue_size = 32
    daemon_threads = True

    def __init__(self, address, config):
        self.config = config
        self.assets = {
            url: ((STATIC_ROOT / path).read_bytes(), mime)
            for url, (path, mime) in ASSETS.items()
        }
        self.workers = BoundedSemaphore(24)
        self.tunnels = BoundedSemaphore(12)
        self.login_lock = Lock()
        self.failures = deque()
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.workers.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.workers.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.workers.release()

    def authenticate(self, password):
        now = time.monotonic()
        with self.login_lock:
            while self.failures and self.failures[0] <= now - 45:
                self.failures.popleft()
            if len(self.failures) >= 14:
                return 429
            if self.config.check_password(password):
                return 200
            self.failures.append(now)
            return 401


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "AriaWasmer/1.0"
    sys_version = ""
    timeout = 8

    def log_message(self, *_args):
        pass

    @property
    def config(self):
        return self.server.config

    def send_bytes(self, status, body, mime, extra=()):
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "font-src 'self'; connect-src 'self' wss:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        )
        for name, value in extra:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, status, value, extra=()):
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_bytes(status, body, "application/json; charset=utf-8", extra)

    def error(self, status, message, extra=()):
        self.send_json(status, {"error": message}, extra)

    def logged_in(self):
        try:
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
        except CookieError:
            return False
        entry = cookie.get(SESSION_COOKIE)
        return entry is not None and self.config.valid_session(entry.value)

    def session_cookie(self, value, seconds):
        return ("Set-Cookie", f"{SESSION_COOKIE}={value}; Path=/; Max-Age={seconds}; Secure; HttpOnly; SameSite=Strict")

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == WS_PATH and self.command == "GET":
            self.websocket()
            return
        asset = self.server.assets.get(path)
        if asset is not None:
            body, mime = asset
            self.send_bytes(200, body, mime)
        elif path == "/health":
            self.send_json(200, {"app": "aria-wasmer", "configured": self.config.ready, "transport": "vless-ws-tcp"})
        elif path == "/api/session":
            self.send_json(200, {
                "configured": self.config.ready, "missing": self.config.errors,
                "authenticated": self.logged_in(), "host": self.config.host, "wsPath": WS_PATH,
            })
        else:
            self.error(404, "این مسیر وجود ندارد.")

    def read_json(self):
        if self.headers.get("Transfer-Encoding") or self.headers.get_content_type() != "application/json":
            raise ValueError("expected JSON body")
        length = self.headers.get_all("Content-Length", [])
        if len(length) != 1 or not length[0].isascii() or not length[0].isdigit():
            raise ValueError("invalid body length")
        remaining = int(length[0])
        if not 1 <= remaining <= MAX_JSON:
            raise ValueError("invalid body length")
        data = bytearray()
        while remaining:
            chunk = self.rfile.read(remaining)
            if not chunk:
                raise ValueError("incomplete body")
            data.extend(chunk)
            remaining -= len(chunk)
        result = json.loads(data)
        if not isinstance(result, dict):
            raise ValueError("expected JSON object")
        return result

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path not in ("/api/login", "/api/logout", "/api/issue"):
            self.error(404, "این مسیر وجود ندارد.")
            return
        if not self.config.ready:
            self.error(503, "متغیرهای راه‌اندازی هنوز کامل نیستند.")
            return
        if self.headers.get_all("Origin", []) != [self.config.origin]:
            self.error(403, "دامنهٔ درخواست با ARIA_PUBLIC_HOST مطابقت ندارد.")
            return
        if path != "/api/login" and not self.logged_in():
            self.error(401, "ابتدا وارد پنل شو.")
            return
        try:
            body = self.read_json()
        except (ValueError, OSError):
            self.error(400, "دادهٔ درخواست معتبر نیست.")
            return
        if path == "/api/login":
            self.login(body)
        elif path == "/api/logout":
            self.send_json(200, {"ok": True}, [self.session_cookie("", 0)])
        else:
            try:
                result = self.config.issue(body.get("name"), body.get("days"))
            except ValueError as error:
                self.error(400, str(error))
                return
            self.send_json(201, result)

    def login(self, body):
        password = body.get("password")
        if not isinstance(password, str) or len(password) > 256:
            self.error(400, "رمز معتبر وارد کن.")
            return
        status = self.server.authenticate(password)
        if status == 429:
            self.error(status, "چند لحظه صبر کن و دوباره وارد شو.", [("Retry-After", "45")])
        elif status == 401:
            self.error(status, "رمز مدیر درست نیست.")
        else:
            self.send_json(200, {"ok": True}, [self.session_cookie(self.config.new_session(), SESSION_SECONDS)])

    def upgrade(self):
        keys = self.headers.get_all("Sec-WebSocket-Key", [])
        if len(keys) != 1 or len(base64.b64decode(keys[0], validate=True)) != 16:
            raise ValueError("invalid websocket key")
        if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Length", "0") != "0":
            raise ValueError("unexpected websocket request body")
        protocol = WSConnection(ConnectionType.SERVER)
        names = ("Host", "Upgrade", "Connection", "Sec-WebSocket-Key", "Sec-WebSocket-Version")
        headers = [(name.lower().encode("ascii"), value.encode("ascii"))
                   for name in names for value in self.headers.get_all(name, [])]
        protocol.initiate_upgrade_connection(headers, WS_PATH)
        return protocol, protocol.send(AcceptConnection())

    def websocket(self):
        if not self.config.ready:
            self.error(503, "متغیرهای راه‌اندازی هنوز کامل نیستند.")
            return
        if not self.server.tunnels.acquire(blocking=False):
            self.error(503, "ظرفیت اتصال موقتاً تکمیل است.")
            return
        self.close_connection = True
        try:
            try:
                protocol, response = self.upgrade()
            except (ValueError, h11.ProtocolError, LocalProtocolError, RemoteProtocolError):
                self.error(400, "درخواست ارتقای WebSocket معتبر نیست.")
                return
            self.connection.sendall(response)
            relay(self.connection, protocol, self.config, reader=self.rfile)
        except OSError:
            pass
        finally:
            self.server.tunnels.release()


def main():
    config = EdgeConfig()
    port = int(os.environ.get("PORT") or "80")
    with Server(("0.0.0.0", port), config) as server:
        print(f"Aria Wasmer listening on {port}; configured={config.ready}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
