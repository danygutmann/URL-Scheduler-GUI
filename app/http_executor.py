import json
import logging
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.config import settings
from app.database import session_scope
from app.models import Job, JobRun
from app.security import safe_target, sanitized_host

logger = logging.getLogger(__name__)
SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}


def _request_url(url: str, address: str, port: int) -> str:
    parts = urlsplit(url)
    host = f"[{address}]" if ":" in address else address
    default_port = 443 if parts.scheme == "https" else 80
    netloc = host if port == default_port else f"{host}:{port}"
    return urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))


def _execute_request(url, method, headers, params, body, body_format, timeout):
    current_url = url
    current_method = method
    current_body = body
    response = None
    for redirect_index in range(6):
        hostname, port, addresses = safe_target(current_url, settings.allowed_private_targets)
        address = addresses[0]
        request_headers = {key: value for key, value in headers.items() if key.lower() not in SENSITIVE_HEADERS}
        request_headers.update({key: value for key, value in headers.items() if key.lower() in SENSITIVE_HEADERS})
        parts = urlsplit(current_url)
        host_header = hostname if port == (443 if parts.scheme == "https" else 80) else f"{hostname}:{port}"
        request_headers["Host"] = host_header
        payload = None
        if current_body is not None:
            if body_format == "json":
                payload = json.loads(current_body)
            else:
                payload = current_body.encode("utf-8")
        with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False) as client:
            request = client.build_request(
                current_method,
                _request_url(current_url, address, port),
                headers=request_headers,
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
                for chunk in response.iter_bytes():
                    available = settings.response_preview_bytes - len(preview)
                    preview.extend(chunk[:available])
                    if len(chunk) > available or len(preview) >= settings.response_preview_bytes:
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
            "timeout": job.timeout_seconds,
        }
    started = datetime.now(timezone.utc).replace(tzinfo=None)
    begin = time.monotonic()
    status, http_code, error_type, error_message, preview, truncated = "success", None, None, None, None, False
    try:
        http_code, preview, truncated = _execute_request(
            snapshot["url"], snapshot["method"], snapshot["headers"], snapshot["query_params"],
            snapshot["body"], snapshot["body_format"], snapshot["timeout"],
        )
        if not 200 <= http_code < 300:
            status, error_type = "http_error", "HTTPError"
            error_message = f"HTTP-Status {http_code}"
    except httpx.TimeoutException:
        status, error_type, error_message = "timeout", "Timeout", "Zeitüberschreitung beim HTTP-Aufruf."
    except httpx.RequestError:
        status, error_type, error_message = "connection_error", "ConnectionError", "Verbindung zum Ziel fehlgeschlagen."
    except (ValueError, json.JSONDecodeError, socket.gaierror):
        status, error_type, error_message = "configuration_error", "ConfigurationError", "URL, DNS oder Request-Konfiguration ist ungültig."
    except Exception as error:
        logger.warning("Job execution failed (%s)", type(error).__name__)
        status, error_type, error_message = "connection_error", "RequestError", "HTTP-Aufruf fehlgeschlagen."
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
    logger.info("Job execution completed status=%s http_status=%s duration_ms=%s", status, http_code, duration_ms)
    return {"status": status, "http_status_code": http_code, "duration_ms": duration_ms}
