"""Tests for the RDAP domain-age check. No test reaches the network."""
from datetime import datetime, timedelta, timezone

import pytest

from app import online
from app.online import check_domain_age, evaluate_age, rdap_url, registration_date

NOW = datetime(2026, 10, 22, tzinfo=timezone.utc)
SERVERS = {"com": "https://rdap.example.com/com/v1/", "top": "https://rdap.example.top/top"}


@pytest.mark.parametrize("age_days, points", [
    (0, 35), (29, 35), (30, 15), (179, 15), (180, None), (-1, None),
])
def test_evaluate_age_boundaries(age_days, points):
    finding = evaluate_age(NOW - timedelta(days=age_days), now=NOW)
    assert (finding[0] if finding else None) == points

@pytest.mark.parametrize("event_date, expected", [
    ("2026-10-21T18:10:41Z", datetime(2026, 10, 21, 18, 10, 41, tzinfo=timezone.utc)),
    ("2026-10-21T18:10:41.123Z", datetime(2026, 10, 21, 18, 10, 41, 123000, tzinfo=timezone.utc)),
    ("2026-10-21T18:10:41", datetime(2026, 10, 21, 18, 10, 41, tzinfo=timezone.utc)),
])
def test_registration_date_formats(event_date, expected):
    rdap = {"events": [{"eventAction": "last changed", "eventDate": "2026-10-22T00:00:00Z"},
                       {"eventAction": "registration", "eventDate": event_date}]}
    assert registration_date(rdap) == expected

def test_registration_date_missing():
    assert registration_date({"event": [{"eventAction": "expiration", "eventDate":"2027-01-01"}]}) is None
    assert registration_date({}) is None

def test_rdap_url():
    assert rdap_url("vcb-xacthuc.com", SERVERS) == "https://rdap.example.com/com/v1/domain/vcb-xacthuc.com"
    assert rdap_url("96fj.top", SERVERS) == "https://rdap.example.top/top/domain/96fj.top"
    assert rdap_url("vietcombank.com.vn", SERVERS) is None

def test_young_domain_is_reported(monkeypatch):
    created = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    monkeypatch.setattr(online, "rdap_servers", lambda: SERVERS)
    monkeypatch.setattr(online, "fetch_json",
                        lambda url:{"events": [{"eventAction": "registration", "eventDate": created}]})
    points, reason = check_domain_age("vcb-xacthuc.com")
    assert points == 35
    assert "3 days" in reason

@pytest.mark.parametrize("error", [OSError("timeout"), ValueError("bad JSON"), KeyError("events")])
def test_lookup_errors_give_no_finding(monkeypatch, error):
    def failing(url):
        raise error

    monkeypatch.setattr(online, "rdap_servers", lambda: SERVERS)
    monkeypatch.setattr(online, "fetch_json", failing)
    assert check_domain_age("vcb-xacthuc.com") is None

def test_unsupported_tld_is_not_queried(monkeypatch):
    def unexpected(url):
        raise AssertionError("Should not query a TLD without RDAP")

    monkeypatch.setattr(online, "rdap_servers", lambda: SERVERS)
    monkeypatch.setattr(online, "fetch_json", unexpected)
    assert check_domain_age("vietcombank.com.vn") is None

def test_tests_cannot_reach_the_network():
    with pytest.raises(RuntimeError):
        online.fetch_json("https://data.iana.org/rdap/dns.json")
