import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from app.config import settings
from app.database import session_scope
from app.models import Job, JobRun
from app.schemas import JobInput
from app.security import (
    decrypt_header,
    decrypt_secret,
    encrypt_header,
    encrypt_secret,
    is_sensitive_header,
)

logger = logging.getLogger(__name__)


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _encoded_headers(headers: dict[str, str], old_headers: dict[str, str] | None = None) -> dict[str, str]:
    result = {}
    old_secrets = {
        key: value for key, value in (old_headers or {}).items()
        if is_sensitive_header(key)
    }
    for key, value in headers.items():
        if is_sensitive_header(key):
            if value:
                result[key] = encrypt_header(key, value)
            else:
                old_secrets.pop(key, None)
        else:
            result[key] = value
    for key, value in old_secrets.items():
        result.setdefault(key, value)
    return result


def _job_values(data: JobInput, old_headers=None, old_query_params=None):
    values = data.model_dump()
    values["headers"] = _encoded_headers(data.headers, old_headers)
    values["query_params"] = _encoded_headers(data.query_params, old_query_params)
    values["request_body"] = encrypt_secret(data.request_body)
    values["updated_at"] = _now()
    return values


def create_job(data: JobInput) -> Job:
    now = _now()
    with session_scope() as session:
        job = Job(id=str(uuid.uuid4()), created_at=now, **_job_values(data))
        session.add(job)
    logger.info("Job created id=%s enabled=%s", job.id, job.enabled)
    _sync_scheduler(job)
    return job


def update_job(job_id: str, data: JobInput) -> Job:
    with session_scope() as session:
        job = session.get(Job, job_id)
        if job is None:
            raise LookupError("Job wurde nicht gefunden.")
        values = _job_values(data, dict(job.headers), dict(job.query_params))
        for key, value in values.items():
            setattr(job, key, value)
    logger.info("Job updated id=%s enabled=%s", job_id, job.enabled)
    _sync_scheduler(job)
    return job


def get_job(job_id: str) -> Job | None:
    with session_scope() as session:
        return session.get(Job, job_id)


def list_jobs() -> list[Job]:
    with session_scope() as session:
        return list(session.scalars(select(Job).order_by(Job.name)))


def set_job_enabled(job_id: str, enabled: bool) -> Job:
    with session_scope() as session:
        job = session.get(Job, job_id)
        if job is None:
            raise LookupError("Job wurde nicht gefunden.")
        job.enabled = enabled
        job.updated_at = _now()
    logger.info("Job %s id=%s", "enabled" if enabled else "paused", job_id)
    _sync_scheduler(job)
    return job


def delete_job(job_id: str) -> None:
    with session_scope() as session:
        job = session.get(Job, job_id)
        if job is None:
            return
        session.delete(job)
    from app.scheduler import scheduler

    scheduler.remove_job(job_id)
    logger.info("Job deleted id=%s", job_id)


def duplicate_job(job_id: str) -> Job:
    source = get_job(job_id)
    if source is None:
        raise LookupError("Job wurde nicht gefunden.")
    duplicate = JobInput(
        name=f"{source.name} (Kopie)"[:120],
        description=source.description,
        url=source.url,
        method=source.method,
        schedule_type=source.schedule_type,
        schedule_config=dict(source.schedule_config),
        timezone=source.timezone,
        headers={
            key: decrypt_header(key, value) for key, value in source.headers.items()
        },
        query_params={
            key: decrypt_header(key, value) for key, value in source.query_params.items()
        },
        request_body=decrypt_secret(source.request_body),
        body_format=source.body_format,
        retry_config=dict(source.retry_config or {"max_attempts": 1, "allow_post": False}),
        timeout_seconds=source.timeout_seconds,
        enabled=False,
        allow_parallel=source.allow_parallel,
    )
    clone = create_job(duplicate)
    return clone


def list_runs(
    job_id: str | None = None,
    limit: int = 500,
    status: str | None = None,
    trigger_type: str | None = None,
) -> list[JobRun]:
    with session_scope() as session:
        query = select(JobRun).order_by(JobRun.started_at.desc(), JobRun.id.desc()).limit(limit)
        if job_id:
            query = query.where(JobRun.job_id == job_id)
        if status and status != "Alle":
            query = query.where(JobRun.status == status)
        if trigger_type and trigger_type != "Alle":
            query = query.where(JobRun.trigger_type == trigger_type)
        return list(session.scalars(query))


def dashboard_data(failed_since_days: int = 30) -> dict:
    with session_scope() as session:
        total = session.scalar(select(func.count()).select_from(Job)) or 0
        enabled = session.scalar(select(func.count()).select_from(Job).where(Job.enabled.is_(True))) or 0
        failed_since = _now() - timedelta(days=failed_since_days)
        failures = session.scalar(
            select(func.count()).select_from(JobRun)
            .where(JobRun.started_at >= failed_since, JobRun.status != "success")
        ) or 0
        recent = list(session.scalars(select(JobRun).order_by(JobRun.started_at.desc()).limit(10)))
        last_runs = {}
        for run in session.scalars(select(JobRun).where(JobRun.job_id.is_not(None)).order_by(JobRun.started_at.desc())):
            last_runs.setdefault(run.job_id, run)
        jobs = list(session.scalars(select(Job)))
    from app.scheduler import next_run_time

    return {
        "total": total,
        "enabled": enabled,
        "paused": total - enabled,
        "failures": failures,
        "recent": recent,
        "jobs": jobs,
        "last_runs": last_runs,
        "next_run": next_run_time(),
    }


def prune_runs() -> int:
    """Apply time and count limits to run history without touching job configuration."""
    from app.database import engine

    removed = 0
    with engine.begin() as connection:
        if settings.log_retention_days:
            cutoff = _now() - timedelta(days=settings.log_retention_days)
            result = connection.execute(
                JobRun.__table__.delete().where(JobRun.started_at < cutoff)
            )
            removed += result.rowcount or 0
        if settings.log_retention_max_runs:
            excess = connection.execute(
                select(JobRun.id).order_by(JobRun.started_at.desc(), JobRun.id.desc())
                .offset(settings.log_retention_max_runs)
            ).scalars().all()
            if excess:
                result = connection.execute(JobRun.__table__.delete().where(JobRun.id.in_(excess)))
                removed += result.rowcount or 0
    if removed:
        logger.info("Run history retention removed count=%s", removed)
    return removed


def clear_old_runs(before: datetime) -> int:
    with session_scope() as session:
        result = session.execute(JobRun.__table__.delete().where(JobRun.started_at < before))
        return result.rowcount or 0


def _sync_scheduler(job: Job):
    from app.scheduler import scheduler

    scheduler.sync_job(job)
