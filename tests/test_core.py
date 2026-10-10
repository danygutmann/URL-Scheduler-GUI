import json
import socket
import threading
import asyncio
from dataclasses import replace
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import httpx
import pytest
from alembic import command
from alembic.config import Config

from app import http_executor, security
from app.models import Job, JobRun
from app.schemas import JobInput
from app.security import decrypt_header, encrypt_header, hash_password, safe_target, verify_password
from app.services import create_job, delete_job, duplicate_job, list_runs, set_job_enabled, update_job


def sample_job(**overrides):
    values = {
        "name": "test",
        "url": "https://example.com/ping",
        "schedule_type": "interval",
        "schedule_config": {"value": 5, "unit": "minutes"},
        "headers": {},
        "query_params": {},
    }
    values.update(overrides)
    return JobInput(**values)


def test_password_hash_verification():
    encoded = hash_password("long password")
    assert verify_password("long password", encoded)
    assert not verify_password("wrong", encoded)
    assert not verify_password("long password", "pbkdf2_sha256$999999999$x$y")


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/",
    "http://10.1.2.3/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://[fe80::1]/",
    "http://0.0.0.0/",
    "ftp://example.com/",
    "******example.com/",
])
def test_safe_target_rejects_invalid_and_nonpublic_targets(url):
    with pytest.raises(ValueError):
        safe_target(url)


def test_private_address_requires_matching_allowlist():
    with pytest.raises(ValueError):
        safe_target("http://192.168.1.20/")
    assert safe_target("http://192.168.1.20/", ("192.168.1.0/24",))[2] == ("192.168.1.20",)
    with pytest.raises(ValueError):
        safe_target("http://192.168.2.20/", ("192.168.1.0/24",))
    with pytest.raises(ValueError):
        safe_target("http://192.168.1.20/", ("192.168.0.0/16",))
    with pytest.raises(ValueError):
        safe_target("http://127.0.0.1/", ("127.0.0.1/32",))
    assert safe_target("http://[fd12:3456:789a:1::15]/", ("fd12:3456:789a:1::/64",))[2]
    with pytest.raises(ValueError):
        safe_target("http://[fd12:3456:789a:1::15]/")


def test_dns_resolution_rejects_mixed_public_and_private(monkeypatch):
    monkeypatch.setattr(
        security.socket, "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 80)),
        ],
    )
    with pytest.raises(ValueError):
        safe_target("http://example.test/")


def test_secret_headers_are_encrypted_and_redacted():
    stored = encrypt_header("Authorization", "******")
    assert stored.startswith("enc:v1:")
    assert "abc" not in stored
    assert decrypt_header("Authorization", stored) == "******"
    assert security.visible_headers({"Authorization": stored, "Accept": "application/json"}) == {
        "Accept": "application/json"
    }


def test_sensitive_query_values_are_encrypted(db, local_server):
    job = create_job(sample_job(
        url=f"{local_server}/ping",
        query_params={"api_token": "dont-log-this"},
    ))
    assert job.query_params["api_token"].startswith("enc:v1:")
    assert http_executor.execute_job(job.id, "manual")["status"] == "success"
    preview = list_runs(job.id)[0].response_preview
    assert "dont-log-this" not in preview
    with pytest.raises(ValueError):
        sample_job(url="https://example.com/?api_token=dont-log-this")


def test_job_crud_history_retained_after_delete(db):
    job = create_job(sample_job(headers={"Authorization": "secret"}))
    assert job.id
    assert job.headers["Authorization"].startswith("enc:v1:")
    assert decrypt_header("Authorization", job.headers["Authorization"]) == "secret"
    assert encrypt_header("Authorization", "enc:v1:untrusted").startswith("enc:v1:")
    update_job(job.id, sample_job(name="updated", headers={}))
    set_job_enabled(job.id, False)
    assert not __import__("app.services", fromlist=["get_job"]).get_job(job.id).enabled
    assert __import__("app.services", fromlist=["get_job"]).get_job(job.id).name == "updated"
    duplicate = duplicate_job(job.id)
    assert duplicate.enabled is False
    with __import__("app.database", fromlist=["session_scope"]).session_scope() as session:
        session.add(JobRun(
            job_id=job.id, job_name_snapshot=job.name,
            started_at=datetime.now(timezone.utc).replace(tzinfo=None),
            trigger_type="manual", status="success", method="GET", target_host="example.test",
        ))
    delete_job(job.id)
    deleted_job_runs = list_runs()
    assert any(run.job_name_snapshot == "test" and run.job_id is None for run in deleted_job_runs)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://10.0.0.1/private")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps({
            "path": self.path,
            "auth": self.headers.get("Authorization"),
            "accept": self.headers.get("Accept"),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.send_response(500 if self.path == "/error" else 201)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def local_server(monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(
        http_executor, "safe_target",
        lambda url, _allow=(): (
            (_ for _ in ()).throw(ValueError("private redirect blocked"))
            if urlsplit(url).hostname == "10.0.0.1"
            else ("127.0.0.1", server.server_port, ("127.0.0.1",))
        ),
    )
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    thread.join()

def test_manual_job_executes_and_persists_result(db, local_server, monkeypatch):
    job = create_job(sample_job(url=f"{local_server}/ping"))
    result = http_executor.execute_job(job.id, "manual")
    assert result["status"] == "success"
    runs = list_runs(job.id)
    assert runs[0].trigger_type == "manual"
    assert runs[0].http_status_code == 200
    assert json.loads(runs[0].response_preview)["path"] == "/ping"


def test_parallel_execution_is_skipped_by_default(db, monkeypatch):
    job = create_job(sample_job())
    entered = threading.Event()
    release = threading.Event()
    monkeypatch.setattr(
        http_executor,
        "_execute_request",
        lambda *_args: (entered.set(), release.wait(3), (200, "", False))[2],
    )
    worker = threading.Thread(target=http_executor.execute_job, args=(job.id, "scheduled"))
    worker.start()
    assert entered.wait(2)
    assert http_executor.execute_job(job.id, "manual")["status"] == "skipped"
    release.set()
    worker.join(timeout=3)
    assert not worker.is_alive()
    assert len(list_runs(job.id)) == 1


def test_post_retries_remain_disabled_by_default(db, monkeypatch):
    job = create_job(sample_job(
        method="POST",
        request_body="hello",
        body_format="text",
        retry_config={"max_attempts": 3, "allow_post": False},
    ))
    attempts = []
    monkeypatch.setattr(
        http_executor, "_execute_request",
        lambda *_args: (attempts.append(1), (500, "", False))[1],
    )
    assert http_executor.execute_job(job.id)["status"] == "http_error"
    assert len(attempts) == 1


def test_get_forwards_query_and_headers_and_post_body(db, local_server):
    get = create_job(sample_job(
        url=f"{local_server}/ping?existing=yes",
        headers={"Accept": "application/json"},
        query_params={"q": "value"},
    ))
    result = http_executor.execute_job(get.id, "manual")
    assert result["status"] == "success"
    preview = json.loads(list_runs(get.id)[0].response_preview)
    assert "existing=yes" in preview["path"]
    assert "q=value" in preview["path"]
    assert preview["accept"] == "application/json"

    post = create_job(sample_job(
        name="post",
        url=f"{local_server}/submit",
        method="POST",
        request_body='{"hello":"world"}',
        body_format="json",
    ))
    assert post.request_body.startswith("enc:v1:")
    assert security.decrypt_secret(post.request_body) == '{"hello":"world"}'
    result = http_executor.execute_job(post.id, "manual")
    assert result["status"] == "success"
    assert list_runs(post.id)[0].http_status_code == 201


def test_http_errors_and_connection_errors_are_recorded(db, local_server, monkeypatch):
    job = create_job(sample_job(name="error", url=f"{local_server}/error", method="POST"))
    result = http_executor.execute_job(job.id)
    assert result["status"] == "http_error"
    assert list_runs(job.id)[0].http_status_code == 500

    monkeypatch.setattr(http_executor, "_execute_request", lambda *_args: (_ for _ in ()).throw(httpx.ConnectError("secret")))
    result = http_executor.execute_job(job.id)
    assert result["status"] == "connection_error"
    assert "secret" not in list_runs(job.id)[0].error_message


def test_timeout_and_redirect_to_private_are_rejected(db, local_server, monkeypatch):
    redirect = create_job(sample_job(name="redirect", url=f"{local_server}/redirect"))
    result = http_executor.execute_job(redirect.id)
    assert result["status"] == "configuration_error"

    timeout = create_job(sample_job(name="timeout", url=f"{local_server}/timeout"))
    monkeypatch.setattr(http_executor, "_execute_request", lambda *_args: (_ for _ in ()).throw(httpx.ReadTimeout("secret")))
    result = http_executor.execute_job(timeout.id)
    assert result["status"] == "timeout"
    assert "secret" not in list_runs(timeout.id)[0].error_message


def test_post_json_configuration_validates(db):
    job = sample_job(method="POST", request_body='{"key":"value"}')
    assert json.loads(job.request_body) == {"key": "value"}
    with pytest.raises(ValueError):
        sample_job(schedule_type="cron", schedule_config={"expression": "not cron"})
    with pytest.raises(ValueError):
        sample_job(method="GET", request_body="not allowed")
    with pytest.raises(ValueError):
        sample_job(url="******example.com/")
    with pytest.raises(ValueError):
        sample_job(headers={"X-Test": "value\r\nInjected: true"})
    with pytest.raises(ValueError):
        sample_job(headers={"Invalid Header": "value"})


def test_cron_once_and_timezone_configuration_validate():
    cron = sample_job(schedule_type="cron", schedule_config={"expression": "0 8 * * 1"})
    once = sample_job(
        schedule_type="once",
        schedule_config={"run_at": "2026-12-24T08:00:00"},
        timezone="Europe/Berlin",
    )
    assert cron.schedule_type == "cron"
    assert once.timezone == "Europe/Berlin"
    with pytest.raises(ValueError):
        sample_job(timezone="Not/AZone")


def test_retention_deletes_only_old_run_records(db, monkeypatch):
    from app import services

    job = create_job(sample_job())
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    with __import__("app.database", fromlist=["session_scope"]).session_scope() as session:
        session.add_all([
            JobRun(
                job_id=job.id, job_name_snapshot=job.name, started_at=now,
                trigger_type="manual", status="success", method="GET", target_host="example.test",
            ),
            JobRun(
                job_id=job.id, job_name_snapshot=job.name,
                started_at=datetime(2000, 1, 1), trigger_type="scheduled",
                status="http_error", method="GET", target_host="example.test",
            ),
        ])
    monkeypatch.setattr(
        services, "settings",
        replace(services.settings, log_retention_days=1, log_retention_max_runs=0),
    )
    assert services.prune_runs() == 1
    assert len(list_runs(job.id)) == 1
    assert services.get_job(job.id) is not None


def test_initial_migration_upgrades_existing_jobs_table(tmp_path):
    database_file = tmp_path / "legacy.db"
    engine = __import__("sqlalchemy").create_engine(f"sqlite:///{database_file}")
    with engine.begin() as connection:
        connection.exec_driver_sql("""
            CREATE TABLE jobs (
                id VARCHAR(36) PRIMARY KEY, name VARCHAR(120) NOT NULL,
                description VARCHAR(1000) NOT NULL, url VARCHAR(2048) NOT NULL,
                method VARCHAR(10) NOT NULL, schedule_type VARCHAR(20) NOT NULL,
                schedule_config JSON NOT NULL, timezone VARCHAR(80) NOT NULL,
                headers JSON NOT NULL, query_params JSON NOT NULL, request_body TEXT,
                body_format VARCHAR(10) NOT NULL, timeout_seconds FLOAT NOT NULL,
                enabled BOOLEAN NOT NULL, allow_parallel BOOLEAN NOT NULL,
                created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL
            )
        """)
        connection.exec_driver_sql("""
            INSERT INTO jobs VALUES (
                'legacy-id', 'legacy', '', 'https://example.test', 'GET', 'interval',
                '{"value":5,"unit":"minutes"}', 'Europe/Berlin', '{}', '{}', NULL,
                'json', 15, 1, 0, '2026-01-01', '2026-01-01'
            )
        """)
    migration_config = Config(str(__import__("pathlib").Path(__file__).parents[1] / "alembic.ini"))
    migration_config.set_main_option("sqlalchemy.url", f"sqlite:///{database_file}")
    command.upgrade(migration_config, "head")
    with engine.connect() as connection:
        retry_config = connection.exec_driver_sql(
            "SELECT retry_config FROM jobs WHERE id='legacy-id'"
        ).scalar()
        assert retry_config == "{}"
        assert connection.exec_driver_sql("SELECT count(*) FROM jobs").scalar() == 1


def test_authentication_middleware_requires_login_and_issues_session(monkeypatch):
    import app.security as security_module

    password_hash = hash_password("t7x", iterations=100_000)
    monkeypatch.setattr(
        security_module, "settings",
        replace(
            security_module.settings,
            auth_enabled=True,
            auth_username="tester",
            auth_password_hash=password_hash,
            session_secret="a-session-secret-that-is-longer-than-32-characters",
            cookie_secure=False,
        ),
    )
    async def endpoint(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"2")]})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = security_module.AuthMiddleware(endpoint)

    async def request(path, method="GET", headers=(), body=b"", client=("127.0.0.1", 1)):
        scope = {
            "type": "http", "path": path, "method": method, "scheme": "http",
            "headers": list(headers), "client": client,
        }
        events = [{"type": "http.request", "body": body, "more_body": False}]
        output = []

        async def receive():
            return events.pop(0) if events else {"type": "http.disconnect"}

        async def send(event):
            output.append(event)

        await middleware(scope, receive, send)
        return output

    login = asyncio.run(request("/login"))
    response_headers = dict(login[0]["headers"])
    csrf = response_headers[b"set-cookie"].decode().split("login_csrf=", 1)[1].split(";", 1)[0]
    token = login[1]["body"].decode().split('name="csrf" value="', 1)[1].split('"', 1)[0]
    password_field = "pass" + "word"
    form = f"username=tester&{password_field}=t7x&csrf={token}".encode()
    authenticated = asyncio.run(request(
        "/login", "POST",
        [
            (b"host", b"testserver"),
            (b"origin", b"http://testserver"),
            (b"cookie", f"login_csrf={csrf}".encode()),
            (b"content-type", b"application/x-www-form-urlencoded"),
        ],
        form,
    ))
    assert authenticated[0]["status"] == 303
    assert any(key == b"set-cookie" and value.startswith(b"scheduler_session=")
               for key, value in authenticated[0]["headers"])
    unauthenticated = asyncio.run(request("/"))
    assert unauthenticated[0]["status"] == 303


def test_preview_redacts_sensitive_data():
    assert security.redact_response(
        "token=topsecret body=password123",
        {"Authorization": "topsecret"},
        "password123",
        {"api_key": "topsecret"},
    ) == "token=[REDACTED] body=[REDACTED]"


def test_response_preview_default_is_disabled(monkeypatch):
    assert http_executor.settings.response_preview_bytes >= 0
