import json
import logging
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

import httpx
from sqlalchemy import select

from app.config import settings
from app.database import session_scope
from app.models import Job, JobRun
from app.security import decrypt_header, is_sensitive_header, safe_target, sanitized_host

logger = logging.getLogger(__name__)
_running: set[str] = set()
_running_lock = __import__("threading").Lock()
_slots = __import__("threading").BoundedSemaphore(settings.max_concurrent_jobs)


def _request_url(url: str, address: str, port: int) -> str:
    parts = urlsplit(url)
    host = f"[{address}]" if ":" in address else address
    default_port = 443 if parts.scheme == "https" else 80
    netloc = host if port == default_port else f"{host}:{port}"
    return urlunsplit((parts.scheme, netloc, parts.path or "/", "", ""))


def _execute_request(url, method, headers, params, body, body_format, timeout):
    current_url = url
    current_method = method
    current_body = body
    response = None
    deadline = time.monotonic() + timeout
    for redirect_index in range(6):
        hostname, port, addresses = safe_target(current_url, settings.allowed_private_targets)
        address = addresses[0]
        parts = urlsplit(current_url)
        current_headers = {
            key: decrypt_header(key, value) for key, value in headers.items()
        }
        current_headers["Host"] = (
            hostname if port == (443 if parts.scheme == "https" else 80) else f"{hostname}:{port}"
        )
        payload = None
        if current_body is not None:
            payload = json.loads(current_body) if body_format == "json" else current_body.encode("utf-8")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise httpx.TimeoutException("Request deadline exceeded")
        with httpx.Client(
            timeout=httpx.Timeout(remaining),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            request = client.build_request(
                current_method,
                _request_url(current_url, address, port),
                headers=current_headers,
                params=params if redirect_index == 0 else None,
                json=payload if body_format == "json" and payload is not None else None,
                content=payload if isinstance(payload, bytes) else None,
            )
            if parts.scheme == "https":
                request.extensions["sni_hostname"] = hostname.encode("ascii")
            response = client.send(request, stream=True)
            if response.status_code not in {301, 302, 303, 307, 308}:
                preview = bytearray()
                truncated = False
                limit = settings.response_preview_bytes
                for chunk in response.iter_bytes():
                    remaining_bytes = limit - len(preview)
                    if remaining_bytes > 0:
                        preview.extend(chunk[:remaining_bytes])
                    if len(chunk) > remaining_bytes or len(preview) >= limit:
                        truncated = True
                        break
                response.close()
                return response.status_code, bytes(preview).decode("utf-8", errors="replace"), truncated
            location = response.headers.get("location")
            response.close()
            if not location or redirect_index == 5:
                raise ValueError("Zu viele oder ungültige Weiterleitungen.")
            next_url = str(httpx.URL(current_url).join(location))
            safe_target(next_url, settings.allowed_private_targets)
            if response.status_code == 303 or (response.status_code in {301, 302} and current_method == "POST"):
                current_method, current_body = "GET", None
            current_url = next_url
            params = None
    raise ValueError("Weiterleitungslimit überschritten.")


def execute_job(job_id: str, trigger_type: str = "scheduled") -> dict:
    with session_scope() as session:
        job = session.get(Job, job_id)
        if job is None:
            return {"status": "configuration_error", "error": "Job wurde nicht gefunden."}
        snapshot = {
            "id": job.id, "name": job.name, "url": job.url, "method": job.method,
            "headers": dict(job.headers), "query_params": dict(job.query_params),
            "body": job.request_body, "body_format": job.body_format,
            "timeout": min(job.timeout_seconds, 300), "allow_parallel": job.allow_parallel,
            "retry_config": dict(job.retry_config or {}),
        }
    with _running_lock:
        if not snapshot["allow_parallel"] and snapshot["id"] in _running:
            logger.info("Job skipped because previous execution is still active id=%s", job_id)
            return {"status": "skipped"}
        if not _slots.acquire(blocking=False):
            logger.info("Job skipped because concurrency limit was reached id=%s", job_id)
            return {"status": "skipped"}
        _running.add(snapshot["id"])
    started = datetime.now(timezone.utc).replace(tzinfo=None)
    begin = time.monotonic()
    status, http_code, error_type, error_message, preview, truncated = "success", None, None, None, None, False
    try:
        max_attempts = int(snapshot["retry_config"].get("max_attempts", 1))
        if snapshot["method"] == "POST" and not snapshot["retry_config"].get("allow_post", False):
            max_attempts = 1
        for attempt in range(max(1, min(max_attempts, 5))):
            try:
                http_code, preview, truncated = _execute_request(
                    snapshot["url"], snapshot["method"], snapshot["headers"],
                    snapshot["query_params"], snapshot["body"], snapshot["body_format"],
                    snapshot["timeout"],
                )
                if http_code < 500 and http_code not in {408, 429}:
                    break
            except httpx.TimeoutException:
                if attempt + 1 >= max_attempts:
                    raise
            except httpx.RequestError:
                if attempt + 1 >= max_attempts:
                    raise
            if attempt + 1 < max_attempts:
                time.sleep(min(0.25 * (2 ** attempt), 2))
        if not 200 <= http_code < 300:
            status, error_type = "http_error", "HTTPError"
            error_message = f"HTTP-Status {http_code}"
    except httpx.TimeoutException:
        status, error_type, error_message = "timeout", "Timeout", "Zeitüberschreitung beim HTTP-Aufruf."
    except httpx.RequestError:
        status, error_type, error_message = "connection_error", "ConnectionError", "Verbindung zum Ziel fehlgeschlagen."
    except (ValueError, json.JSONDecodeError, socket.gaierror) as error:
        status, error_type = "configuration_error", "ConfigurationError"
        error_message = str(error)[:500] if isinstance(error, ValueError) else "URL, DNS oder Request-Konfiguration ist ungültig."
    except Exception as error:
        logger.warning("Job execution failed (%s)", type(error).__name__)
        status, error_type, error_message = "connection_error", "RequestError", "HTTP-Aufruf fehlgeschlagen."
    finally:
        with _running_lock:
            _running.discard(snapshot["id"])
            _slots.release()
    finished = datetime.now(timezone.utc).replace(tzinfo=None)
    duration_ms = int((time.monotonic() - begin) * 1000)
    run = JobRun(
        job_id=snapshot["id"], job_name_snapshot=snapshot["name"], started_at=started,
        finished_at=finished, duration_ms=duration_ms, trigger_type=trigger_type,
        status=status, method=snapshot["method"], target_host=sanitized_host(snapshot["url"]),
        http_status_code=http_code, error_type=error_type, error_message=error_message,
        response_preview=preview, response_truncated=truncated,
    )
    with session_scope() as session:
        session.add(run)
    logger.info(
        "Job execution completed id=%s trigger=%s status=%s http_status=%s duration_ms=%s",
        snapshot["id"], trigger_type, status, http_code, duration_ms,
    )
    return {"status": status, "http_status_code": http_code, "duration_ms": duration_ms}
