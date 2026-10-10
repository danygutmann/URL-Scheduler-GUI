import os
from dataclasses import dataclass
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def _boolean(name: str, default: bool) -> bool:
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    timezone: str
    data_dir: Path
    log_level: str
    auth_enabled: bool
    auth_username: str
    auth_password_hash: str
    session_secret: str
    cookie_secure: bool
    encryption_key: str
    max_concurrent_jobs: int
    default_timeout_seconds: float
    log_retention_days: int
    log_retention_max_runs: int
    allowed_private_targets: tuple[str, ...]
    response_preview_bytes: int = 4096
    max_request_body_bytes: int = 65536

    @property
    def database_url(self) -> str:
        return f"sqlite:///{self.data_dir / 'scheduler.db'}"

    @classmethod
    def from_env(cls) -> "Settings":
        auth_enabled = _boolean("APP_AUTH_ENABLED", True)
        username = os.getenv("APP_AUTH_USERNAME", "")
        password_hash = os.getenv("APP_AUTH_PASSWORD_HASH", "")
        session_secret = os.getenv("APP_SESSION_SECRET", "")
        if auth_enabled and (not username or not password_hash or len(session_secret) < 32):
            raise ValueError(
                "APP_AUTH_USERNAME, APP_AUTH_PASSWORD_HASH and a 32-character APP_SESSION_SECRET "
                "are required when authentication is enabled"
            )
        settings = cls(
            host=os.getenv("APP_HOST", "0.0.0.0"),
            port=int(os.getenv("APP_PORT", "8080")),
            timezone=os.getenv("APP_TIMEZONE", "Europe/Berlin"),
            data_dir=Path(os.getenv("APP_DATA_DIR", "./data")).expanduser(),
            log_level=os.getenv("APP_LOG_LEVEL", "INFO").upper(),
            auth_enabled=auth_enabled,
            auth_username=username,
            auth_password_hash=password_hash,
            session_secret=session_secret,
            cookie_secure=_boolean("APP_COOKIE_SECURE", False),
            encryption_key=os.getenv("APP_ENCRYPTION_KEY", ""),
            max_concurrent_jobs=max(1, int(os.getenv("MAX_CONCURRENT_JOBS", "4"))),
            default_timeout_seconds=float(os.getenv("DEFAULT_TIMEOUT_SECONDS", "15")),
            log_retention_days=max(0, int(os.getenv("LOG_RETENTION_DAYS", "90"))),
            log_retention_max_runs=max(0, int(os.getenv("LOG_RETENTION_MAX_RUNS", "10000"))),
            allowed_private_targets=tuple(
                value.strip()
                for value in os.getenv("APP_ALLOWED_PRIVATE_TARGETS", "").split(",")
                if value.strip()
            ),
            response_preview_bytes=max(0, int(os.getenv("APP_RESPONSE_PREVIEW_BYTES", "0"))),
        )
        if not 1 <= settings.port <= 65535:
            raise ValueError("APP_PORT must be between 1 and 65535")
        if settings.default_timeout_seconds <= 0:
            raise ValueError("DEFAULT_TIMEOUT_SECONDS must be positive")
        try:
            ZoneInfo(settings.timezone)
        except ZoneInfoNotFoundError as error:
            raise ValueError("APP_TIMEZONE must name a valid IANA time zone") from error
        if settings.log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("APP_LOG_LEVEL must be a valid logging level")
        return settings


settings = Settings.from_env()
