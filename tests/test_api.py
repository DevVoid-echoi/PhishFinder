"""Tests for the HTTP API."""
import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_check_phishing_url(client):
    response = client.post("/check", json={"url": "http://vietcombank-xacthuc.com/dang-nhap"})
    assert response.status_code == 200
    body = response.json()
    assert body["level"] == "dangerous"
    assert body["reasons"][0]["rule"] == "check_lookalike"


def test_check_official_url(client):
    response = client.post("/check", json={"url": "https://vietcombank.com.vn"})
    assert response.status_code == 200
    assert response.json()["score"] == 0


@pytest.mark.parametrize("payload", [
    {},
    {"url": ""},
    {"url": 123},
    {"url": "http://a.com/" + "a" * 2048},
])
def test_invalid_payload_is_rejected(client, payload):
    assert client.post("/check", json=payload).status_code == 422


def test_url_without_hostname_returns_400(client):
    response = client.post("/check", json={"url": "http://"})
    assert response.status_code == 400
    assert "hostname" in response.json()["detail"]
