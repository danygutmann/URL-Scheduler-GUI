import json
import logging
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from fastapi import Request
from fastapi.responses import PlainTextResponse
from nicegui import app, ui

from app.config import settings
from app.database import initialize_database
from app.models import Job
from app.scheduler import scheduler
from app.schemas import JobInput
from app.security import (
    AuthMiddleware,
    decrypt_header,
    decrypt_secret,
    is_sensitive_header,
    sanitized_url,
    visible_headers,
)
from app.services import (
    create_job,
    clear_old_runs,
    dashboard_data,
    delete_job,
    duplicate_job,
    get_job,
    list_runs,
    set_job_enabled,
    update_job,
)

logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)
app.add_middleware(AuthMiddleware)


@app.get("/healthz", include_in_schema=False)
async def health():
    try:
        from app.database import engine

        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
        if not scheduler.scheduler.running:
            return PlainTextResponse("not ready", status_code=503)
        return PlainTextResponse("ok")
    except Exception:
        logger.exception("Health check failed")
        return PlainTextResponse("not ready", status_code=503)


def _display_time(value):
    if value is None:
        return "—"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(ZoneInfo(settings.timezone)).strftime("%d.%m.%Y %H:%M:%S")


def _job_input(form: dict, job: Job | None = None) -> JobInput:
    try:
        headers = {}
        if form.get("headers"):
            headers = json.loads(form["headers"])
        if job:
            existing = dict(job.headers)
            for key, value in existing.items():
                if is_sensitive_header(key):
                    headers.setdefault(key, decrypt_header(key, value))
        params = json.loads(form.get("query_params") or "{}")
        if job:
            for key, value in job.query_params.items():
                if is_sensitive_header(key):
                    params.setdefault(key, decrypt_header(key, value))
        schedule_config = json.loads(form.get("schedule_config") or "{}")
        retry_config = json.loads(form.get("retry_config") or '{"max_attempts":1,"allow_post":false}')
        return JobInput(
            name=form["name"],
            description=form.get("description", ""),
            url=form["url"],
            method=form["method"],
            schedule_type=form["schedule_type"],
            schedule_config=schedule_config,
            timezone=form.get("timezone") or settings.timezone,
            headers=headers,
            query_params=params,
            request_body=form.get("request_body") or None,
            body_format=form.get("body_format") or "json",
            timeout_seconds=float(form.get("timeout_seconds") or settings.default_timeout_seconds),
            retry_config=retry_config,
            enabled=bool(form.get("enabled")),
            allow_parallel=bool(form.get("allow_parallel")),
        )
    except (ValueError, KeyError, TypeError) as error:
        raise ValueError(f"Ungültige Formulareingabe: {error}") from error


@ui.page("/")
def dashboard_page():
    ui.label("URL Scheduler").classes("text-h4")
    ui.label("Zeitgesteuerte HTTP-Aufrufe im eigenen Netzwerk").classes("text-subtitle1")
    with ui.row():
        ui.button("Job erstellen", on_click=lambda: ui.navigate.to("/jobs/new"), icon="add")
        ui.button("Ausführungsprotokoll", on_click=lambda: ui.navigate.to("/history"), icon="history")
    data = dashboard_data()
    with ui.row().classes("w-full"):
        for title, value in (
            ("Jobs", data["total"]),
            ("Aktiv", data["enabled"]),
            ("Pausiert", data["paused"]),
            ("Fehler (30 Tage)", data["failures"]),
            ("Nächste Ausführung", _display_time(data["next_run"])),
        ):
            with ui.card().classes("min-w-40"):
                ui.label(title).classes("text-caption")
                ui.label(str(value)).classes("text-h6")
    ui.label("Jobs").classes("text-h5")
    _jobs_table(data["jobs"], data["last_runs"])
    ui.label("Zuletzt ausgeführt").classes("text-h5")
    _runs_table(data["recent"])


def _jobs_table(jobs, last_runs=None):
    last_runs = last_runs or {}
    rows = []
    for job in jobs:
        last_run = last_runs.get(job.id)
        rows.append({
            "id": job.id,
            "name": job.name,
            "method": job.method,
            "url": sanitized_url(job.url),
            "type": job.schedule_type,
            "schedule": _schedule_text(job),
            "enabled": "Aktiv" if job.enabled else "Pausiert",
            "last": _display_time(last_run.started_at) if last_run else "—",
            "result": last_run.status if last_run else "—",
            "next": _display_time(scheduler.scheduler.get_job(job.id).next_run_time)
            if scheduler.scheduler.get_job(job.id) else "—",
        })
    columns = [
        {"name": key, "label": label, "field": key, "align": "left"}
        for key, label in (
            ("name", "Name"), ("method", "Methode"), ("url", "Ziel-URL"),
            ("type", "Typ"), ("schedule", "Zeitplan"), ("enabled", "Status"),
            ("last", "Letzte Ausführung"), ("result", "Ergebnis"), ("next", "Nächste Ausführung"),
        )
    ]
    table = ui.table(columns=columns, rows=rows, row_key="id").classes("w-full")
    table.add_slot("body-cell-url", """
        <q-td :props="props"><span class="ellipsis" style="max-width: 240px; display:inline-block">
        {{ props.value }}</span></q-td>
    """)
    for job in jobs:
        with ui.row().classes("items-center gap-1"):
            ui.label(job.name).classes("text-weight-bold")
            ui.button("Bearbeiten", on_click=lambda job_id=job.id: ui.navigate.to(f"/jobs/{job_id}")).props("flat dense")
            ui.button("Starten", on_click=lambda job_id=job.id: _manual_run(job_id)).props("flat dense color=primary")
            ui.button("Pausieren" if job.enabled else "Aktivieren",
                      on_click=lambda job_id=job.id, enabled=job.enabled: _toggle_job(job_id, enabled)).props("flat dense")
            ui.button("Duplizieren", on_click=lambda job_id=job.id: _duplicate_job(job_id)).props("flat dense")
            ui.button("Protokoll", on_click=lambda job_id=job.id: ui.navigate.to(f"/history?job_id={job_id}")).props("flat dense")
            ui.button("Löschen", on_click=lambda job_id=job.id: _confirm_delete(job_id)).props("flat dense color=negative")


def _schedule_text(job):
    config = job.schedule_config
    if job.schedule_type == "interval":
        return f"alle {config.get('value')} {config.get('unit')}"
    if job.schedule_type == "cron":
        return config.get("expression", "")
    return config.get("run_at", "")


def _runs_table(runs):
    rows = [{
        "id": run.id,
        "job": run.job_name_snapshot,
        "trigger": "Manuell" if run.trigger_type == "manual" else "Geplant",
        "started": _display_time(run.started_at),
        "duration": f"{run.duration_ms} ms" if run.duration_ms is not None else "—",
        "status": run.status,
        "http": run.http_status_code or "—",
        "error": run.error_message or "",
    } for run in runs]
    ui.table(
        columns=[
            {"name": key, "label": label, "field": key, "align": "left"}
            for key, label in (
                ("job", "Job"), ("trigger", "Auslöser"), ("started", "Beginn"),
                ("duration", "Laufzeit"), ("status", "Ergebnis"), ("http", "HTTP"),
                ("error", "Meldung"),
            )
        ],
        rows=rows,
        row_key="id",
    ).classes("w-full")


def _manual_run(job_id):
    try:
        scheduler.run_now(job_id)
        ui.notify("Manueller Start wurde eingeplant.", type="positive")
    except Exception as error:
        ui.notify(str(error), type="negative")


def _toggle_job(job_id, was_enabled):
    try:
        set_job_enabled(job_id, not was_enabled)
        ui.notify("Jobstatus aktualisiert.", type="positive")
        ui.navigate.to("/")
    except Exception as error:
        ui.notify(str(error), type="negative")


def _duplicate_job(job_id):
    try:
        duplicate_job(job_id)
        ui.notify("Job wurde pausiert dupliziert.", type="positive")
        ui.navigate.to("/")
    except Exception as error:
        ui.notify(str(error), type="negative")


def _confirm_delete(job_id):
    with ui.dialog() as dialog, ui.card():
        ui.label("Job löschen? Das Ausführungsprotokoll bleibt erhalten.")
        with ui.row():
            ui.button("Abbrechen", on_click=dialog.close)
            ui.button("Löschen", color="negative", on_click=lambda: _delete_confirmed(job_id, dialog))
    dialog.open()


def _delete_confirmed(job_id, dialog):
    delete_job(job_id)
    dialog.close()
    ui.notify("Job gelöscht.", type="positive")
    ui.navigate.to("/")


@ui.page("/jobs/{job_id}")
def edit_job_page(job_id: str):
    if job_id == "new":
        _job_form(None)
        return
    job = get_job(job_id)
    if not job:
        ui.label("Job nicht gefunden.")
        return
    _job_form(job)


@ui.page("/jobs/new")
def new_job_page():
    _job_form(None)


def _job_form(job: Job | None):
    ui.label("Job bearbeiten" if job else "Neuen Job erstellen").classes("text-h4")
    defaults = {
        "name": job.name if job else "",
        "description": job.description if job else "",
        "url": job.url if job else "https://",
        "method": job.method if job else "GET",
        "schedule_type": job.schedule_type if job else "interval",
        "schedule_config": json.dumps(job.schedule_config if job else {"value": 5, "unit": "minutes"}),
        "timezone": job.timezone if job else settings.timezone,
        "headers": json.dumps(visible_headers(job.headers) if job else {}, ensure_ascii=False, indent=2),
        "query_params": json.dumps(
            visible_headers(job.query_params) if job else {}, ensure_ascii=False, indent=2
        ),
        "request_body": decrypt_secret(job.request_body) or "" if job else "",
        "body_format": job.body_format if job else "json",
        "timeout_seconds": str(job.timeout_seconds if job else settings.default_timeout_seconds),
        "retry_config": json.dumps(job.retry_config if job else {"max_attempts": 1, "allow_post": False}),
        "enabled": job.enabled if job else True,
        "allow_parallel": job.allow_parallel if job else False,
    }
    name = ui.input("Name *", value=defaults["name"]).classes("w-full")
    description = ui.input("Beschreibung", value=defaults["description"]).classes("w-full")
    url = ui.input("Ziel-URL *", value=defaults["url"]).classes("w-full")
    method = ui.select({"GET": "GET", "POST": "POST"}, label="HTTP-Methode", value=defaults["method"])
    schedule_type = ui.select(
        {"interval": "Intervall", "cron": "Cron", "once": "Einmalig"},
        label="Zeitplantyp", value=defaults["schedule_type"],
    )
    config = job.schedule_config if job else {"value": 5, "unit": "minutes"}
    with ui.column().classes("w-full"):
        interval_controls = ui.row().classes("w-full")
        with interval_controls:
            interval_value = ui.number("Intervall", value=int(config.get("value", 5)), min=1)
            interval_unit = ui.select(
                {"seconds": "Sekunden", "minutes": "Minuten", "hours": "Stunden", "days": "Tage"},
                label="Einheit", value=config.get("unit", "minutes"),
            )
        cron_expression = ui.input(
            "Cron-Ausdruck (Minute Stunde Tag Monat Wochentag)",
            value=config.get("expression", "0 8 * * 1"),
        ).classes("w-full")
        once_at = ui.input(
            "Ausführungszeitpunkt (ISO 8601)",
            value=config.get("run_at", ""),
            placeholder="2026-12-24T08:00:00",
        ).classes("w-full")
    interval_start = ui.input(
        "Startzeitpunkt optional (ISO 8601)", value=config.get("start_at", "")
    ).classes("w-full")
    interval_end = ui.input(
        "Enddatum optional (ISO 8601)", value=config.get("end_at", "")
    ).classes("w-full")

    def update_schedule_fields():
        interval_controls.set_visibility(schedule_type.value == "interval")
        interval_start.set_visibility(schedule_type.value != "once")
        interval_end.set_visibility(schedule_type.value != "once")
        cron_expression.set_visibility(schedule_type.value == "cron")
        once_at.set_visibility(schedule_type.value == "once")

    schedule_type.on_value_change(lambda _event: update_schedule_fields())
    update_schedule_fields()
    timezone = ui.input("Zeitzone", value=defaults["timezone"])
    enabled = ui.checkbox("Aktiviert", value=defaults["enabled"])
    allow_parallel = ui.checkbox("Parallele Ausführungen erlauben", value=defaults["allow_parallel"])
    with ui.expansion("Erweiterte HTTP-Einstellungen", icon="tune").classes("w-full"):
        ui.label("Header als JSON. Sensible Werte werden verschlüsselt gespeichert; vorhandene Geheimnisse nicht erneut anzeigen.")
        headers = ui.textarea("Header (JSON)", value=defaults["headers"]).classes("w-full")
        query_params = ui.textarea("Query-Parameter (JSON)", value=defaults["query_params"]).classes("w-full")
        request_body = ui.textarea("Request-Body", value=defaults["request_body"]).props("rows=6").classes("w-full")
        body_format = ui.select({"json": "JSON", "text": "Text"}, label="Body-Format", value=defaults["body_format"])
        timeout = ui.number("Timeout in Sekunden", value=float(defaults["timeout_seconds"]), min=1, max=300)
        ui.label("Wiederholungen werden bei GET standardmäßig unterstützt. POST-Wiederholung ist deaktiviert.")
        retry_config = ui.input("Wiederholungsoptionen (JSON)", value=defaults["retry_config"]).classes("w-full")
    def save():
        try:
            if schedule_type.value == "interval":
                schedule_config = {"value": interval_value.value, "unit": interval_unit.value}
            elif schedule_type.value == "cron":
                schedule_config = {"expression": cron_expression.value}
            else:
                schedule_config = {"run_at": once_at.value}
            if schedule_type.value != "once":
                if interval_start.value:
                    schedule_config["start_at"] = interval_start.value
                if interval_end.value:
                    schedule_config["end_at"] = interval_end.value
            data = _job_input({
                "name": name.value,
                "description": description.value,
                "url": url.value,
                "method": method.value,
                "schedule_type": schedule_type.value,
                "schedule_config": json.dumps(schedule_config),
                "timezone": timezone.value,
                "headers": headers.value,
                "query_params": query_params.value,
                "request_body": request_body.value,
                "body_format": body_format.value,
                "timeout_seconds": timeout.value,
                "retry_config": retry_config.value,
                "enabled": enabled.value,
                "allow_parallel": allow_parallel.value,
            }, job)
            if job:
                update_job(job.id, data)
            else:
                create_job(data)
            ui.notify("Job gespeichert.", type="positive")
            ui.navigate.to("/")
        except Exception as error:
            ui.notify(f"Fehler: {error}", type="negative", timeout=8000)
    ui.button("Speichern", on_click=save, icon="save")
    ui.button("Abbrechen", on_click=lambda: ui.navigate.to("/")).props("flat")


@ui.page("/history")
def history_page(request: Request):
    ui.label("Ausführungsprotokoll").classes("text-h4")
    job_id = request.query_params.get("job_id")
    status_filter = ui.select(
        {"Alle": "Alle", "success": "Erfolgreich", "http_error": "HTTP-Fehler",
         "connection_error": "Verbindungsfehler", "timeout": "Timeout",
         "configuration_error": "Konfigurationsfehler"},
        value=request.query_params.get("status", "Alle"),
        label="Ergebnis filtern",
    )
    trigger_filter = ui.select(
        {"Alle": "Alle", "scheduled": "Geplant", "manual": "Manuell"},
        value=request.query_params.get("trigger", "Alle"),
        label="Auslöser filtern",
    )
    ui.button("Filter anwenden", on_click=lambda: ui.navigate.to(
        f"/history?job_id={job_id or ''}&status={status_filter.value}&trigger={trigger_filter.value}"
    ))
    ui.button("Alte Protokolle löschen", on_click=_confirm_clear_runs).props("color=negative")
    rows = list_runs(
        job_id=job_id,
        limit=1000,
        status=status_filter.value,
        trigger_type=trigger_filter.value,
    )
    _runs_table(rows)


def _confirm_clear_runs():
    with ui.dialog() as dialog, ui.card():
        cutoff = ui.input(
            "Einträge vor diesem Zeitpunkt löschen (lokale Zeit, ISO 8601)",
            value=datetime.now(ZoneInfo(settings.timezone)).strftime("%Y-%m-%dT%H:%M"),
        ).classes("w-full")
        ui.label("Jobkonfigurationen bleiben erhalten.")
        with ui.row():
            ui.button("Abbrechen", on_click=dialog.close)

            def clear():
                try:
                    date = datetime.fromisoformat(cutoff.value)
                    if date.tzinfo is None:
                        date = date.replace(tzinfo=ZoneInfo(settings.timezone))
                    removed = clear_old_runs(date.astimezone(timezone.utc).replace(tzinfo=None))
                    dialog.close()
                    ui.notify(f"{removed} Protokolleinträge gelöscht.", type="positive")
                    ui.navigate.to("/history")
                except (TypeError, ValueError) as error:
                    ui.notify(f"Ungültiger Zeitpunkt: {error}", type="negative")

            ui.button("Löschen", color="negative", on_click=clear)
    dialog.open()


def start():
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    initialize_database()
    scheduler.start()
    logger.info("Application started host=%s port=%s", settings.host, settings.port)
    try:
        ui.run(
            host=settings.host,
            port=settings.port,
            title="URL Scheduler",
            reload=False,
            show=False,
            storage_secret=settings.session_secret or "local-development-only",
            favicon="⏱",
        )
    finally:
        scheduler.shutdown()


if __name__ in {"__main__", "__mp_main__"}:
    start()
