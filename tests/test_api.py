"""Tests for the production HTTP API. Server checks are replaced by stubs."""
import json
import pytest
from fastapi.testclient import TestClient

from app import main
from app.api_core import DailyBudget, TTLCache
from tests.test_page_analysis import AI_PHISH, PHISH_DOM

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

def test_confirmed_report_logs_a_medium_alert(client, caplog):
    body = {**REPORT, "verdict": "confirmed_phishing"}
    with caplog.at_level("WARNING", logger=main.log.name):
        assert client.post("/v1/report", json=body).status_code == 200
    line = next(m for m in caplog.messages if m.startswith("ALERT "))
    alert = json.loads(line.removeprefix("ALERT "))
    assert alert["severity"] == "medium"
    assert alert["risk_score"] is None
    assert alert["observables"] == [{"type": "domain", "value": "vcb-xacthuc.com"}]
    assert alert["recommended_actions"] == ["Review manually before blocking"]

def test_false_positive_report_logs_no_alert(client, caplog):
    with caplog.at_level("WARNING", logger=main.log.name):
        client.post("/v1/report", json=REPORT)
    assert not any(m.startswith("ALERT ") for m in caplog.messages)


PAGE = {"host": "vcb-secure.top", **PHISH_DOM}


@pytest.fixture
def page_client(client, monkeypatch):
    """Claude is a fake that counts its calls; the server must never download the page itself."""
    calls = {"ai": 0}

    def fake_claude(system, user, schema):
        calls["ai"] += 1
        return json.dumps(AI_PHISH)

    def no_download(*args, **kwargs):
        raise AssertionError("analyze-page must not download the page")

    monkeypatch.setattr(main, "follow", no_download)
    monkeypatch.setattr(main, "claude_extract", fake_claude)
    monkeypatch.setattr(main, "page_cache", TTLCache())
    monkeypatch.setattr(main, "ai_budget", DailyBudget(limit=1))

    return client, calls


def test_analyze_page_calls_ai_once_and_caches(page_client):
    client, calls = page_client
    r1 = client.post("/v1/analyze-page", json=PAGE).json()
    r2 = client.post("/v1/analyze-page", json=PAGE).json()
    assert r1["ai_summary"] == AI_PHISH["summary"]
    assert {"page_brand_login", "ai_impersonation_credentials"} <= {x["rule"] for x in r1["reasons"]}
    assert (r1["cached"], r2["cached"]) == (False, True)
    assert calls["ai"] == 1


def test_spent_budget_keeps_the_rules(page_client):
    client, calls = page_client
    client.post("/v1/analyze-page", json=PAGE)
    r = client.post("/v1/analyze-page", json={**PAGE, "host": "b.top"}).json()
    assert r["ai_summary"] is None and calls["ai"] == 1
    assert "page_brand_login" in {x["rule"] for x in r["reasons"]}


def test_analyze_page_without_a_key(page_client, monkeypatch):
    client, calls = page_client
    monkeypatch.setattr(main, "claude_extract", None)
    r = client.post("/v1/analyze-page", json=PAGE).json()
    assert r["ai_summary"] is None and r["reasons"] and calls["ai"] == 0


def test_analyze_page_official_site_is_clean(page_client):
    client, calls = page_client
    r = client.post("/v1/analyze-page", json={**PAGE, "host": "vietcombank.com.vn"}).json()
    assert (r["reasons"], calls["ai"]) == ([], 0)


def test_analyze_page_never_logs_the_page(page_client, caplog):
    client, _ = page_client
    with caplog.at_level("INFO", logger=main.log.name):
        client.post("/v1/analyze-page", json={**PAGE, "text": "Hello Nguyễn Văn A, s3cret code"})
    assert caplog.messages
    assert not any(s in caplog.text for s in ("vcb-secure", "Nguyễn", "s3cret", "Vietcombank"))


@pytest.mark.parametrize("host", ["https://vcb-secure.top/login", "1.2.3.4", "vcb-secure.top/x?token=1", ""])
def test_analyze_page_takes_a_hostname_only(page_client, host):
    client, _ = page_client
    assert client.post("/v1/analyze-page", json={**PAGE, "host": host}).status_code == 400


@pytest.mark.parametrize("field, value", [
    ("text", "x" * 3001),
    ("title", "x" * 301),
    ("inputs", [{"type": "text", "hints": ""}] * 51),
    ("form_hosts", ["a.top"] * 21),
])
def test_analyze_page_rejects_oversized_content(page_client, field, value):
    client, _ = page_client
    assert client.post("/v1/analyze-page", json={**PAGE, field: value}).status_code == 422
