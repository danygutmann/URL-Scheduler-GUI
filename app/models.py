from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), default="", nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[str] = mapped_column(String(10), default="GET", nullable=False)
    schedule_type: Mapped[str] = mapped_column(String(20), nullable=False)
    schedule_config: Mapped[dict] = mapped_column(JSON, nullable=False)
    timezone: Mapped[str] = mapped_column(String(80), default="Europe/Berlin", nullable=False)
    headers: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    query_params: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    request_body: Mapped[str | None] = mapped_column(Text)
    body_format: Mapped[str] = mapped_column(String(10), default="json", nullable=False)
    retry_config: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    timeout_seconds: Mapped[float] = mapped_column(default=15, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    allow_parallel: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class JobRun(Base):
    __tablename__ = "job_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    job_name_snapshot: Mapped[str] = mapped_column(String(120), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    trigger_type: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    target_host: Mapped[str] = mapped_column(String(255), nullable=False)
    http_status_code: Mapped[int | None] = mapped_column(Integer)
    error_type: Mapped[str | None] = mapped_column(String(40))
    error_message: Mapped[str | None] = mapped_column(String(500))
    response_preview: Mapped[str | None] = mapped_column(Text)
    response_truncated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
