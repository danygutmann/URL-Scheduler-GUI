import base64
import hashlib
import hmac
import ipaddress
import secrets
import socket
from urllib.parse import urlsplit


def hash_password(password: str, *, iterations: int = 310_000) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), base64.urlsafe_b64decode(salt), int(iterations)
        )
        return hmac.compare_digest(actual, base64.urlsafe_b64decode(expected))
    except (ValueError, TypeError):
        return False


def safe_target(url: str, allowed_private_targets: tuple[str, ...] = ()) -> tuple[str, int, tuple[str, ...]]:
    """Validate a URL and return its hostname, port and DNS-pinned public addresses."""
    try:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("Nur vollständige HTTP- oder HTTPS-URLs sind zulässig.")
        if parts.username or parts.password or any(ord(char) < 32 for char in url):
            raise ValueError("Ungültige URL.")
        hostname = parts.hostname.rstrip(".").lower()
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
        explicitly_allowed = hostname in allowed_private_targets
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global and not explicitly_allowed:
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
