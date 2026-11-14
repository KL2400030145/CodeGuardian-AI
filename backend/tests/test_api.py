import io
import zipfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.engine import URL
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app


@pytest.fixture
def client(tmp_path):
    test_engine = create_engine(
        URL.create("sqlite", database=str(tmp_path / "codeguardian-test.db")),
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(test_engine, "connect")
    def enable_foreign_keys(connection, _record):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=test_engine)
    test_session = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)

    def override_db():
        db = test_session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


def register(client: TestClient, email: str = "owner@example.com") -> dict:
    response = client.post(
        "/api/auth/register",
        json={
            "full_name": "Code Owner",
            "email": email,
            "password": "SecurePassword123!",
            "terms_accepted": True,
        },
    )
    assert response.status_code == 201
    return response.json()


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_registration_login_protected_routes_and_logout(client: TestClient):
    assert client.get("/health").json()["status"] == "ok"
    session = register(client)
    token = session["access_token"]

    assert "password_hash" not in session["user"]
    assert client.get("/api/scans").status_code == 401
    assert client.get("/api/auth/me", headers=auth_headers(token)).status_code == 200
    assert client.get("/api/dashboard", headers=auth_headers(token)).status_code == 200
    assert client.get("/api/dashboard", headers=auth_headers("invalid-token")).status_code == 401

    duplicate = client.post(
        "/api/auth/register",
        json={
            "full_name": "Another Owner",
            "email": "OWNER@example.com",
            "password": "SecurePassword123!",
            "terms_accepted": True,
        },
    )
    assert duplicate.status_code == 409

    incorrect = client.post(
        "/api/auth/login",
        json={"email": "owner@example.com", "password": "WrongPassword123!"},
    )
    assert incorrect.status_code == 401

    login = client.post(
        "/api/auth/login",
        json={"email": "owner@example.com", "password": "SecurePassword123!", "remember_me": True},
    )
    assert login.status_code == 200
    assert "httponly" in login.headers["set-cookie"].lower()
    refreshed_login = client.post("/api/auth/refresh")
    assert refreshed_login.status_code == 200
    assert refreshed_login.json()["access_token"] != login.json()["access_token"]
    assert client.post("/api/auth/logout").status_code == 204
    assert client.get(
        "/api/auth/me", headers=auth_headers(refreshed_login.json()["access_token"])
    ).status_code == 401


def test_cors_allows_configured_development_frontend_origins(client: TestClient):
    for origin in ("http://localhost:5174", "http://127.0.0.1:5174"):
        for path in ("/api/auth/register", "/api/auth/refresh"):
            response = client.options(
                path,
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type,authorization",
                },
            )
            assert response.status_code == 200
            assert response.headers["access-control-allow-origin"] == origin
            assert response.headers["access-control-allow-credentials"] == "true"
            assert "POST" in response.headers["access-control-allow-methods"]
            allowed_headers = response.headers["access-control-allow-headers"].lower()
            assert "content-type" in allowed_headers
            assert "authorization" in allowed_headers


def test_refresh_rotates_session_and_revocation_invalidates_access(client: TestClient):
    first = register(client)
    old_token = first["access_token"]

    refreshed = client.post("/api/auth/refresh")
    assert refreshed.status_code == 200
    new_token = refreshed.json()["access_token"]
    assert new_token != old_token
    assert client.get("/api/auth/me", headers=auth_headers(old_token)).status_code == 401
    assert client.get("/api/auth/me", headers=auth_headers(new_token)).status_code == 200

    sessions = client.get("/api/auth/sessions", headers=auth_headers(new_token))
    assert sessions.status_code == 200
    assert len(sessions.json()) == 1

    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/api/auth/me", headers=auth_headers(new_token)).status_code == 401


def test_python_scan_persists_findings_and_downloadable_reports(client: TestClient):
    token = register(client)["access_token"]
    headers = auth_headers(token)
    response = client.post(
        "/api/scans",
        headers=headers,
        files={"file": ("sample.py", b"value = eval(input())\n", "text/x-python")},
    )
    assert response.status_code == 200
    scan = response.json()
    assert scan["findings"]
    assert any(item["rule_id"] == "CG001" for item in scan["findings"])
    assert any(item["source"] == "Bandit" for item in scan["findings"])
    assert scan["status"] in {"completed", "completed_with_skips", "partial"}
    assert "Bandit" in scan["scanners"]
    assert client.get("/api/scans", headers=headers).json()[0]["id"] == scan["id"]
    json_report = client.get(f"/api/scans/{scan['id']}/report.json", headers=headers)
    assert json_report.headers["content-type"].startswith("application/json")
    assert any(item["rule_id"] == "CG001" for item in json_report.json()["findings"])
    pdf = client.get(f"/api/scans/{scan['id']}/report.pdf", headers=headers)
    assert pdf.status_code == 200
    assert pdf.content.startswith(b"%PDF")


def test_zip_scan_and_unsafe_path_rejection(client: TestClient):
    token = register(client)["access_token"]
    headers = auth_headers(token)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("src/app.py", "password = 'example-secret'\n")
    response = client.post(
        "/api/scans",
        headers=headers,
        files={"file": ("repository.zip", archive.getvalue(), "application/zip")},
    )
    assert response.status_code == 200
    assert response.json()["findings"]

    unsafe = io.BytesIO()
    with zipfile.ZipFile(unsafe, "w") as zipped:
        zipped.writestr("../outside.py", "print('not extracted')\n")
    rejected = client.post(
        "/api/scans",
        headers=headers,
        files={"file": ("unsafe.zip", unsafe.getvalue(), "application/zip")},
    )
    assert rejected.status_code == 400


def test_projects_are_owned_and_dashboard_uses_saved_results(client: TestClient):
    first = register(client)
    first_headers = auth_headers(first["access_token"])
    project = client.post(
        "/api/projects",
        headers=first_headers,
        json={"name": "Payment service", "description": "Internal API"},
    )
    assert project.status_code == 201

    second = register(client, "other@example.org")
    second_headers = auth_headers(second["access_token"])
    assert client.get(f"/api/projects/{project.json()['id']}", headers=second_headers).status_code == 404

    scanned = client.post(
        f"/api/scans?project_id={project.json()['id']}",
        headers=first_headers,
        files={"file": ("app.py", b"eval('1')", "text/x-python")},
    )
    assert scanned.status_code == 200
    assert client.get("/api/scans", headers=second_headers).json() == []
    assert client.get(
        f"/api/scans/{scanned.json()['id']}", headers=second_headers
    ).status_code == 404
    dashboard = client.get("/api/dashboard", headers=first_headers).json()
    findings = scanned.json()["findings"]
    expected_severity_counts = {
        severity: sum(item["severity"] == severity for item in findings)
        for severity in ("critical", "high", "medium", "low")
    }
    assert dashboard["total_projects"] == 1
    assert dashboard["total_scans"] == 1
    assert dashboard["total_vulnerabilities"] == len(findings)
    assert dashboard["severity_counts"] == expected_severity_counts
    assert "20 per critical" in dashboard["score_calculation"]


def test_ai_explanation_is_explicitly_unavailable_without_key(client: TestClient, monkeypatch):
    token = register(client)["access_token"]
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    response = client.post(
        "/api/ai/explain",
        headers=auth_headers(token),
        json={"finding": "A real stored scanner finding", "snippet": "eval(input())"},
    )
    assert response.status_code == 503
    assert "OPENAI_API_KEY" in response.json()["detail"]
