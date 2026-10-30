"""Tests for the production HTTP API. Server checks are replaced by stubs."""
import pytest
from fastapi.testclient import TestClient

from app import main
from app.api_core import TTLCache

REPORT = {"host": "vcb-xacthuc.com", "shown_level": "dangerous",
          "verdict": "false_positive", "extension_version":"0.1.0"}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(main, "cache", TTLCache())
    monkeypatch.setattr(main, "age_cache", TTLCache())
    monkeypatch.setattr(main, "check_domain_age", lambda d: (35, "Domain was registered 3 days ago"))
    monkeypatch.setattr(main, "check_tls", lambda h: None)
    return TestClient(main.app)


def test_health(client):
    response = client.get("/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_reputation(client):
    response = client.get("/v1/reputation", params={"host": "Login.VCB-xacthuc.com"})
    assert response.status_code == 200
    body = response.json()
    assert body["host"] == "login.vcb-xacthuc.com"
    assert body["domain"] == "vcb-xacthuc.com"
    assert body["reasons"] == [{"rule": "domain_age", "points": 35, "reason": "Domain was registered 3 days ago"}]

@pytest.mark.parametrize("host", ["https://vcb-xacthuc.com/login?token=abc", "1.2.3.4", "localhost"])
def test_reputation_rejects_anything_but_a_hostname(client, host):
    assert client.get("/v1/reputation", params={"host": host}).status_code == 400

def test_reputation_requires_a_host(client):
    assert client.get("/v1/reputation").status_code == 422

def test_full_url_endpoint_is_gone(client):
    assert client.post("/check", json={"url": "https://a.com"}).status_code == 404

def test_report(client):
    assert client.post("/v1/report", json=REPORT).json() == {"received": True}

@pytest.mark.parametrize("field, value", [
    ("shown_level", "likely_safe"),
    ("verdict", "spam"),
    ("extension_version", "1.0\nINJECTED"),
])
def test_report_rejects_bad_fields(client, field, value):
    assert client.post("/v1/report", json={**REPORT, field: value}).status_code == 422

def test_report_rejects_a_full_url(client):
    assert client.post("/v1/report", json={**REPORT, "host": "https://a.com/x"}).status_code == 400

def test_docs_are_disabled_by_default(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404

def test_cors_rejects_unknown_origins(client):
    response = client.get("/v1/health", headers={"Origin": "https://evil.example"})
    assert "access_control_allow_origin" not in response.headers

def test_expand(client, monkeypatch):
    calls = []

    def fake_follow(url, method):
        calls.append((url, method))
        return {"chain": [url, "https://evil.example/login"], "final": "https://evil.example/login", "error": None}

    monkeypatch.setattr(main, "follow", fake_follow)
    monkeypatch.setattr(main, "expand_cache", main.TTLCache())

    r1 = client.get("/v1/expand", params={"url": "https://bit.ly/abc"}).json()
    r2 = client.get("/v1/expand", params={"url": "https://bit.ly/abc"}).json()
    assert r1["final"] == "https://evil.example/login"
    assert (r1["cached"], r2["cached"]) == (False, True)
    assert calls == [("https://bit.ly/abc", "HEAD")]

def test_expand_refuses_other_links(client):
    assert client.get("/v1/expand", params={"url": "https://evil.example/login"}).status_code == 400
