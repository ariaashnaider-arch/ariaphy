"""Environment, signed admin sessions, and expiring VLESS credentials."""

import base64
import hashlib
import hmac
import os
import re
import secrets
import time
from urllib.parse import quote, urlencode
from uuid import UUID

SESSION_SECONDS = 3600
MAX_DAYS = 90
WS_PATH = "/connect/aria"
DEFAULT_HOST = "ariaphy.wasmer.app"
HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)


def valid_domain(host):
    parts = host.split(".")
    return (
        len(host) <= 253 and len(parts) >= 2 and not parts[-1].isdigit()
        and all(HOST_LABEL.fullmatch(part) for part in parts)
    )


class EdgeConfig:
    def __init__(self, env=None):
        env = os.environ if env is None else env
        self.host = env.get("ARIA_PUBLIC_HOST", DEFAULT_HOST).strip().lower()
        self.errors = []
        if not valid_domain(self.host):
            self.errors.append("ARIA_PUBLIC_HOST")
        password = env.get("ARIA_ADMIN_PASSWORD", "")
        password_bytes = password.encode("utf-8")
        if len(password.strip()) < 16 or len(password_bytes) > 256:
            self.errors.append("ARIA_ADMIN_PASSWORD")
        key = env.get("ARIA_SIGNING_KEY", "")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", key):
            self.errors.append("ARIA_SIGNING_KEY")
        self.origin = f"https://{self.host}" if valid_domain(self.host) else ""
        if self.errors:
            return
        secret = bytes.fromhex(key)
        self.client_key = hmac.digest(secret, b"aria-wasmer/v1/vless-uuid", "sha256")
        self.session_key = hmac.digest(secret, b"aria-wasmer/v1/admin/" + password_bytes, "sha256")
        self.password_digest = hashlib.sha256(password_bytes).digest()

    @property
    def ready(self):
        return not self.errors

    def check_password(self, value):
        try:
            candidate = hashlib.sha256(value.encode("utf-8")).digest()
        except UnicodeError:
            return False
        return hmac.compare_digest(self.password_digest, candidate)

    def new_session(self):
        expires = int(time.time()) + SESSION_SECONDS
        message = expires.to_bytes(8, "big") + secrets.token_bytes(16)
        signature = hmac.digest(self.session_key, message, "sha256")
        return base64.urlsafe_b64encode(message + signature).decode("ascii")

    def valid_session(self, value):
        if not self.ready or len(value) != 76:
            return False
        try:
            data = base64.b64decode(value, altchars=b"-_", validate=True)
        except ValueError:
            return False
        if len(data) != 56 or int.from_bytes(data[:8], "big") <= time.time():
            return False
        return hmac.compare_digest(data[24:], hmac.digest(self.session_key, data[:24], "sha256"))

    def _client_tag(self, prefix):
        tag = hmac.digest(self.client_key, prefix, "sha256")[:9]
        # Use the RFC UUID variant. The other 70 signature bits are compared.
        return bytes([(tag[0] & 0x3f) | 0x80]) + tag[1:]

    def issue(self, name, days):
        if type(days) is not int or not 1 <= days <= MAX_DAYS:
            raise ValueError("اعتبار باید بین ۱ تا ۹۰ روز باشد.")
        if not isinstance(name, str):
            raise ValueError("نام اتصال معتبر نیست.")
        name = name.strip()
        if not 1 <= len(name) <= 64 or not name.replace("\u200c", "").isprintable():
            raise ValueError("نام اتصال باید ۱ تا ۶۴ نویسهٔ قابل‌نمایش داشته باشد.")

        expiry_hour = (int(time.time()) + days * 86400 + 3599) // 3600
        prefix = bytearray(expiry_hour.to_bytes(3, "big") + secrets.token_bytes(4))
        prefix[6] = (prefix[6] & 0x0f) | 0x40
        token = bytes(prefix) + self._client_tag(prefix)
        user_id = str(UUID(bytes=token))
        options = {
            "encryption": "none", "security": "tls", "sni": self.host,
            "type": "ws", "host": self.host, "path": WS_PATH,
        }
        link = f"vless://{user_id}@{self.host}:443?{urlencode(options)}#{quote(name, safe='')}"
        return {"name": name, "uuid": user_id, "expires": expiry_hour * 3600, "link": link}

    def client_expiry(self, token):
        if not self.ready or len(token) != 16 or token[6] & 0xf0 != 0x40:
            return None
        if not hmac.compare_digest(token[7:], self._client_tag(token[:7])):
            return None
        expires = int.from_bytes(token[:3], "big") * 3600
        return expires if time.time() < expires else None
