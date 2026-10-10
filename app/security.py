import base64
import binascii
import hashlib
import hmac
import ipaddress
import logging
import secrets
import socket
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qs
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings

logger = logging.getLogger(__name__)


SECRET_HEADER_MARKER = "enc:v1:"
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
}


def is_sensitive_header(name: str) -> bool:
    lowered = name.lower()
    return lowered in SENSITIVE_HEADERS or any(
        part in lowered for part in ("token", "secret", "password", "api-key", "apikey")
    )


def _fernet() -> Fernet:
    if not settings.encryption_key:
        raise ValueError("APP_ENCRYPTION_KEY ist für vertrauliche Header erforderlich.")
    try:
        return Fernet(settings.encryption_key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as error:
        raise ValueError("APP_ENCRYPTION_KEY ist ungültig.") from error


def encrypt_secret(value: str | None) -> str | None:
    if value is None:
        return None
    return SECRET_HEADER_MARKER + _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(value: str | None) -> str | None:
    if value is None or not value.startswith(SECRET_HEADER_MARKER):
        return value
    try:
        return _fernet().decrypt(value[len(SECRET_HEADER_MARKER):].encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError, ValueError) as error:
        raise ValueError("Ein vertraulicher Wert kann nicht entschlüsselt werden.") from error


def encrypt_header(name: str, value: str) -> str:
    if not is_sensitive_header(name):
        return value
    return SECRET_HEADER_MARKER + _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_header(name: str, value: str) -> str:
    if not is_sensitive_header(name) or not value.startswith(SECRET_HEADER_MARKER):
        return value
    return decrypt_secret(value)


def visible_headers(headers: dict[str, str]) -> dict[str, str]:
    return {key: value for key, value in headers.items() if not is_sensitive_header(key)}


def hash_password(password: str, *, iterations: int = 310_000) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        count = int(iterations)
        decoded_salt = base64.urlsafe_b64decode(salt)
        expected_digest = base64.urlsafe_b64decode(expected)
        if not 100_000 <= count <= 2_000_000 or len(decoded_salt) != 16 or len(expected_digest) != 32:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), decoded_salt, count)
        return hmac.compare_digest(actual, expected_digest)
    except (ValueError, TypeError, binascii.Error):
        return False


def _allowed_networks(allowed_private_targets: tuple[str, ...]):
    networks = []
    for value in allowed_private_targets:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as error:
            raise ValueError("APP_ALLOWED_PRIVATE_TARGETS muss IP-Adressen oder CIDR-Netze enthalten.") from error
        minimum_prefix = 24 if network.version == 4 else 64
        if not network.is_private or network.prefixlen < minimum_prefix:
            raise ValueError("Allowlist-Ziele müssen private IP-Netze mit mindestens /24 (IPv4) oder /64 (IPv6) sein.")
        networks.append(network)
    return networks


def safe_target(url: str, allowed_private_targets: tuple[str, ...] = ()) -> tuple[str, int, tuple[str, ...]]:
    """Validate a URL and return its hostname, port and DNS-pinned public addresses."""
    try:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("Nur vollständige HTTP- oder HTTPS-URLs sind zulässig.")
        if parts.username or parts.password or any(ord(char) < 32 for char in url):
            raise ValueError("Ungültige URL.")
        hostname = parts.hostname.rstrip(".").lower()
        if not hostname or "%" in hostname or any(char.isspace() for char in hostname):
            raise ValueError("Ungültiger Hostname.")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ValueError("Ungültiger Zielport.")
        try:
            literal = ipaddress.ip_address(hostname)
            addresses = {str(literal)}
        except ValueError:
            records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
            addresses = {record[4][0].split("%", 1)[0] for record in records}
        if not addresses:
            raise ValueError("Der Hostname konnte nicht aufgelöst werden.")
        networks = _allowed_networks(allowed_private_targets)
        for address in addresses:
            ip = ipaddress.ip_address(address)
            allowed = any(ip.version == network.version and ip in network for network in networks)
            if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
                raise ValueError("Loopback-, Link-local- und reservierte Ziele sind gesperrt.")
            if not ip.is_global and not (ip.is_private and allowed):
                raise ValueError("Das Ziel ist keine öffentliche IP-Adresse.")
        return hostname, port, tuple(sorted(addresses))
    except (ValueError, OSError, socket.gaierror) as error:
        if isinstance(error, ValueError) and str(error).startswith(("Nur ", "Ungültige", "Das Ziel", "Der Hostname")):
            raise
        raise ValueError("Ungültige oder nicht erreichbare Ziel-URL.") from error


def sanitized_host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "ungültig")[:255]
    except ValueError:
        return "ungültig"


def _session_cookie(expires: int) -> str:
    nonce = secrets.token_urlsafe(24)
    payload = f"{expires}.{nonce}"
    signature = hmac.new(settings.session_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def _valid_session(value: str) -> bool:
    try:
        expires, nonce, signature = value.split(".", 2)
        payload = f"{expires}.{nonce}"
        expected = hmac.new(settings.session_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return int(expires) > int(time.time()) and hmac.compare_digest(signature, expected)
    except (ValueError, TypeError):
        return False


def _cookie_value(headers, key: str) -> str:
    cookie = SimpleCookie()
    cookie.load(headers.get("cookie", ""))
    morsel = cookie.get(key)
    return morsel.value if morsel else ""


class AuthMiddleware:
    def __init__(self, app):
        self.app = app
        self.login_attempts: dict[str, list[float]] = {}

    async def __call__(self, scope, receive, send):
        if not settings.auth_enabled:
            await self.app(scope, receive, send)
            return
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return
        headers = {key.decode("latin1").lower(): value.decode("latin1") for key, value in scope.get("headers", [])}
        path = scope.get("path", "")
        if scope["type"] == "http" and path == "/healthz":
            await self.app(scope, receive, send)
            return
        if scope["type"] == "http" and path == "/login":
            await self._login(scope, receive, send, headers)
            return
        if not _valid_session(_cookie_value(headers, "scheduler_session")):
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 4401})
            else:
                await send({
                    "type": "http.response.start", "status": 303,
                    "headers": [(b"location", b"/login"), (b"content-length", b"0")],
                })
                await send({"type": "http.response.body", "body": b""})
            return
        if scope["type"] == "websocket":
            if not self._same_origin(scope, headers):
                await send({"type": "websocket.close", "code": 4403})
                return
        elif scope.get("method") in {"POST", "PUT", "PATCH", "DELETE"} and not self._same_origin(scope, headers):
            await send({
                "type": "http.response.start", "status": 403,
                "headers": [(b"content-length", b"0")],
            })
            await send({"type": "http.response.body", "body": b""})
            return
        await self.app(scope, receive, send)

    @staticmethod
    def _same_origin(scope, headers):
        origin = headers.get("origin")
        if not origin:
            return False
        scheme = headers.get("x-forwarded-proto", scope.get("scheme", "http")).split(",", 1)[0].strip()
        host = headers.get("host", "").split(",", 1)[0].strip()
        return origin.rstrip("/") == f"{scheme}://{host}".rstrip("/")

    async def _login(self, scope, receive, send, headers):
        method = scope.get("method")
        if method == "GET":
            token = secrets.token_urlsafe(24)
            body = (
                '<!doctype html><meta charset="utf-8"><title>Anmeldung</title>'
                '<form method="post"><h1>URL Scheduler</h1>'
                '<label>Benutzername <input name="username" autocomplete="username" required></label><br>'
                '<label>Passwort <input name="password" type="password" autocomplete="current-password" required></label>'
                f'<input type="hidden" name="csrf" value="{token}"><button>Anmelden</button></form>'
            ).encode()
            cookie = f"login_csrf={token}; Path=/login; Max-Age=300; HttpOnly; SameSite=Strict"
            if settings.cookie_secure:
                cookie += "; Secure"
            await send({
                "type": "http.response.start", "status": 200,
                "headers": [
                    (b"content-type", b"text/html; charset=utf-8"),
                    (b"content-length", str(len(body)).encode()),
                    (b"set-cookie", cookie.encode()),
                    (b"cache-control", b"no-store"),
                ],
            })
            await send({"type": "http.response.body", "body": body})
            return
        if method != "POST":
            await send({"type": "http.response.start", "status": 405, "headers": [(b"content-length", b"0")]})
            await send({"type": "http.response.body", "body": b""})
            return
        client = scope.get("client") or ("unknown", 0)
        now = time.monotonic()
        attempts = [stamp for stamp in self.login_attempts.get(client[0], []) if now - stamp < 60]
        if len(attempts) >= 10:
            self.login_attempts[client[0]] = attempts
            await send({"type": "http.response.start", "status": 429, "headers": [(b"content-length", b"0")]})
            await send({"type": "http.response.body", "body": b""})
            return
        attempts.append(now)
        if len(self.login_attempts) >= 5000 and client[0] not in self.login_attempts:
            oldest = min(self.login_attempts, key=lambda host: self.login_attempts[host][-1])
            self.login_attempts.pop(oldest, None)
        self.login_attempts[client[0]] = attempts
        body = bytearray()
        while True:
            message = await receive()
            body.extend(message.get("body", b""))
            if len(body) > 8192:
                await send({"type": "http.response.start", "status": 413, "headers": [(b"content-length", b"0")]})
                await send({"type": "http.response.body", "body": b""})
                return
            if not message.get("more_body", False):
                break
        try:
            form = parse_qs(body.decode("utf-8", errors="replace"), max_num_fields=10)
        except ValueError:
            form = {}
        csrf = form.get("csrf", [""])[0]
        if (
            self._same_origin(scope, headers)
            and hmac.compare_digest(csrf, _cookie_value(headers, "login_csrf"))
            and hmac.compare_digest(form.get("username", [""])[0], settings.auth_username)
            and verify_password(form.get("password", [""])[0], settings.auth_password_hash)
        ):
            expires = int(time.time()) + 3600
            cookie = f"scheduler_session={_session_cookie(expires)}; Path=/; Max-Age=3600; HttpOnly; SameSite=Strict"
            if settings.cookie_secure:
                cookie += "; Secure"
            await send({
                "type": "http.response.start", "status": 303,
                "headers": [(b"location", b"/"), (b"set-cookie", cookie.encode()), (b"content-length", b"0")],
            })
            await send({"type": "http.response.body", "body": b""})
            return
        response = b"Anmeldung fehlgeschlagen. <a href=\"/login\">Erneut versuchen</a>"
        logger.warning("Authentication failed client=%s", client[0])
        await send({
            "type": "http.response.start", "status": 401,
            "headers": [(b"content-type", b"text/html; charset=utf-8"), (b"content-length", str(len(response)).encode())],
        })
        await send({"type": "http.response.body", "body": response})


def sanitized_url(url: str) -> str:
    try:
        parts = urlsplit(url)
        query = []
        from urllib.parse import parse_qsl, urlencode

        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            query.append((key, "REDACTED" if any(
                token in key.lower() for token in ("token", "secret", "password", "key", "auth")
            ) else value))
        return parts._replace(query=urlencode(query)).geturl()[:2048]
    except ValueError:
        return "ungültig"


def redact_response(text: str, headers: dict[str, str], body: str | None, params: dict[str, str]) -> str:
    secrets_to_hide = [
        value for key, value in headers.items()
        if is_sensitive_header(key) and value
    ]
    if body:
        secrets_to_hide.append(body)
    secrets_to_hide.extend(
        value for key, value in params.items()
        if any(token in key.lower() for token in ("token", "secret", "password", "key", "auth")) and value
    )
    for secret in secrets_to_hide:
        text = text.replace(secret, "[REDACTED]")
    return text
