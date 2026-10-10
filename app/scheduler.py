import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from zoneinfo import ZoneInfo

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger

from app.config import settings
from app.database import session_scope
from app.models import Job

logger = logging.getLogger(__name__)


def _local_datetime(value: str | None, zone: ZoneInfo):
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    return parsed.replace(tzinfo=zone) if parsed.tzinfo is None else parsed


def trigger_for(job: Job):
    zone = ZoneInfo(job.timezone)
    config = job.schedule_config
    start_date = _local_datetime(config.get("start_at"), zone)
    end_date = _local_datetime(config.get("end_at"), zone)
    if job.schedule_type == "interval":
        return IntervalTrigger(
            **{config["unit"]: int(config["value"])},
            timezone=zone,
            start_date=start_date,
            end_date=end_date,
        )
    if job.schedule_type == "cron":
        return CronTrigger.from_crontab(
            config["expression"], timezone=zone, start_date=start_date, end_date=end_date
        )
    return DateTrigger(run_date=_local_datetime(config["run_at"], zone), timezone=zone)


def _execute_job(job_id: str, trigger_type: str):
    from app.http_executor import execute_job

    execute_job(job_id, trigger_type)


def _cleanup():
    from app.services import prune_runs

    prune_runs()


class JobScheduler:
    def __init__(self):
        self.scheduler = BackgroundScheduler(
            timezone=ZoneInfo(settings.timezone),
            executors={"default": ThreadPoolExecutor(max_workers=settings.max_concurrent_jobs)},
            job_defaults={"coalesce": True, "misfire_grace_time": 1, "max_instances": 1},
        )

    def start(self):
        if self.scheduler.running:
            return
        self.scheduler.start()
        self.scheduler.add_job(
            _cleanup, "interval", hours=1, id="history-retention", replace_existing=True,
            max_instances=1, coalesce=True, misfire_grace_time=30,
        )
        with session_scope() as session:
            jobs = list(session.query(Job).filter(Job.enabled.is_(True)).all())
        for job in jobs:
            self.sync_job(job)
        logger.info("Scheduler started restored_jobs=%s", len(jobs))

    def shutdown(self):
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)
            logger.info("Scheduler stopped")

    def sync_job(self, job: Job):
        if not self.scheduler.running:
            return
        self.remove_job(job.id)
        if not job.enabled:
            return
        try:
            self.scheduler.add_job(
                _execute_job,
                trigger_for(job),
                args=[job.id, "scheduled"],
                id=job.id,
                replace_existing=True,
                coalesce=True,
                misfire_grace_time=1,
                max_instances=10 if job.allow_parallel else 1,
            )
            logger.info("Job scheduled id=%s type=%s", job.id, job.schedule_type)
        except Exception:
            logger.exception("Could not schedule job id=%s", job.id)
            raise

    def remove_job(self, job_id: str):
        if not self.scheduler.running:
            return
        try:
            self.scheduler.remove_job(job_id)
        except Exception as error:
            from apscheduler.jobstores.base import JobLookupError

            if not isinstance(error, JobLookupError):
                raise

    def run_now(self, job_id: str):
        if not self.scheduler.running:
            raise RuntimeError("Der Scheduler ist nicht gestartet.")
        if not self.scheduler.get_job(job_id):
            with session_scope() as session:
                if session.get(Job, job_id) is None:
                    raise LookupError("Job wurde nicht gefunden.")
        self.scheduler.add_job(
            _execute_job,
            "date",
            run_date=datetime.now(ZoneInfo(settings.timezone)),
            args=[job_id, "manual"],
            id=f"manual-{job_id}-{datetime.now().timestamp()}",
            replace_existing=False,
        )

    def next_run(self):
        next_times = [
            job.next_run_time for job in self.scheduler.get_jobs()
            if job.id != "history-retention" and job.next_run_time is not None
        ] if self.scheduler.running else []
        return min(next_times) if next_times else None


scheduler = JobScheduler()


def next_run_time():
    return scheduler.next_run()
