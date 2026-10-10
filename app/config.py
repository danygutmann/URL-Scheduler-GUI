import os
from dataclasses import dataclass
from pathlib import Path


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
        if auth_enabled and (not username or not password_hash):
            raise ValueError(
                "APP_AUTH_USERNAME and APP_AUTH_PASSWORD_HASH are required when authentication is enabled"
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
            max_concurrent_jobs=max(1, int(os.getenv("MAX_CONCURRENT_JOBS", "4"))),
            default_timeout_seconds=float(os.getenv("DEFAULT_TIMEOUT_SECONDS", "15")),
            log_retention_days=max(0, int(os.getenv("LOG_RETENTION_DAYS", "90"))),
            log_retention_max_runs=max(0, int(os.getenv("LOG_RETENTION_MAX_RUNS", "10000"))),
            allowed_private_targets=tuple(
                value.strip().lower()
                for value in os.getenv("APP_ALLOWED_PRIVATE_TARGETS", "").split(",")
                if value.strip()
            ),
        )
        if not 1 <= settings.port <= 65535:
            raise ValueError("APP_PORT must be between 1 and 65535")
        if settings.default_timeout_seconds <= 0:
            raise ValueError("DEFAULT_TIMEOUT_SECONDS must be positive")
        return settings


settings = Settings.from_env()
