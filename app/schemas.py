import json
from datetime import datetime
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class JobInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=1000)
    url: str = Field(min_length=8, max_length=2048)
    method: Literal["GET", "POST"] = "GET"
    schedule_type: Literal["interval", "cron", "once"]
    schedule_config: dict
    timezone: str = "Europe/Berlin"
    headers: dict[str, str] = Field(default_factory=dict)
    query_params: dict[str, str] = Field(default_factory=dict)
    request_body: str | None = Field(default=None, max_length=65536)
    body_format: Literal["json", "text"] = "json"
    retry_config: dict = Field(default_factory=lambda: {"max_attempts": 1, "allow_post": False})
    timeout_seconds: float = Field(default=15, gt=0, le=300)
    enabled: bool = True
    allow_parallel: bool = False

    @field_validator("headers", "query_params")
    @classmethod
    def limit_mapping(cls, value):
        if len(value) > 50 or any(len(str(k)) > 256 or len(str(v)) > 4096 for k, v in value.items()):
            raise ValueError("Maximal 50 Einträge; Schlüssel und Werte müssen kurz bleiben.")
        return value

    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, value):
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError as error:
            raise ValueError("Unbekannte Zeitzone.") from error
        return value

    @model_validator(mode="after")
    def validate_schedule(self):
        config = self.schedule_config
        try:
            zone = ZoneInfo(self.timezone)
            start_date = datetime.fromisoformat(config["start_at"]) if config.get("start_at") else None
            end_date = datetime.fromisoformat(config["end_at"]) if config.get("end_at") else None
            if start_date and end_date and end_date <= start_date:
                raise ValueError("Das Ende muss nach dem Start liegen.")
            if self.schedule_type == "interval":
                amount = int(config["value"])
                unit = config["unit"]
                if amount < 1 or unit not in {"seconds", "minutes", "hours", "days"}:
                    raise ValueError("Ungültiges Intervall.")
                IntervalTrigger(**{unit: amount}, timezone=zone, start_date=start_date, end_date=end_date)
            elif self.schedule_type == "cron":
                CronTrigger.from_crontab(config["expression"], timezone=zone, start_date=start_date, end_date=end_date)
            else:
                run_at = datetime.fromisoformat(config["run_at"])
                if run_at.tzinfo is None:
                    run_at = run_at.replace(tzinfo=zone)
                if end_date and run_at > end_date:
                    raise ValueError("Der Ausführungszeitpunkt liegt nach dem Ende.")
                DateTrigger(run_date=run_at, timezone=zone)
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f"Ungültiger Zeitplan: {error}") from error
        attempts = self.retry_config.get("max_attempts", 1)
        if not isinstance(attempts, int) or not 1 <= attempts <= 5:
            raise ValueError("Wiederholungen müssen zwischen 1 und 5 Versuchen liegen.")
        if self.method == "POST" and attempts > 1 and not self.retry_config.get("allow_post", False):
            self.retry_config = {"max_attempts": 1, "allow_post": False}
        if self.method == "GET" and self.request_body:
            raise ValueError("Ein Request-Body ist nur für POST erlaubt.")
        if self.request_body and self.body_format == "json":
            try:
                json.loads(self.request_body)
            except json.JSONDecodeError as error:
                raise ValueError("Der JSON-Body ist ungültig.") from error
        return self
