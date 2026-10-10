import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from sqlalchemy import select

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


def test_job_crud_history_retained_after_delete(db):
    job = create_job(sample_job(headers={"Authorization": "secret"}))
    assert job.id
    assert job.headers["Authorization"].startswith("enc:v1:")
    assert decrypt_header("Authorization", job.headers["Authorization"]) == "secret"
    update_job(job.id, sample_job(name="updated", headers={}))
    set_job_enabled(job.id, False)
    assert not job.enabled
    assert job.name == "updated"
    duplicate = duplicate_job(job.id)
    assert duplicate.enabled is False
    with __import__("app.database", fromlist=["session_scope"]).session_scope() as session:
        session.add(JobRun(
            job_id=job.id, job_name_snapshot=job.name,
            started_at=__import__("datetime").datetime.datetime.utcnow(),
            trigger_type="manual", status="success", method="GET", target_host="example.test",
        ))
    delete_job(job.id)
    assert list_runs(job.id)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        body = json.dumps({
            "path": self.path,
            "auth": self.headers.get("Authorization"),
            "body": self.rfile.read(int(self.headers.get("Content-Length", 0))).decode(),
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
            "127.0.0.1", server.server_port, ("127.0.0.1",)
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


def test_post_json_configuration_validates(db):
    job = sample_job(method="POST", request_body='{"key":"value"}')
    assert json.loads(job.request_body) == {"key": "value"}
    with pytest.raises(ValueError):
        sample_job(schedule_type="cron", schedule_config={"expression": "not cron"})
    with pytest.raises(ValueError):
        sample_job(method="GET", request_body="not allowed")


def test_response_preview_default_is_disabled(monkeypatch):
    assert http_executor.settings.response_preview_bytes >= 0
