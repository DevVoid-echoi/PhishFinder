import pytest

from app import lists
from app.lookalike import check_lookalike
from app.parser import parse_url
from app.scorer import analyze


def rules_of(url):
    return {r["rule"] for r in analyze(url)["reasons"]}

def test_allowlisted_domain_skips_checks_on_its_own_name(monkeypatch):
    assert "check_lookalike" in rules_of("https://facebook.de")
    monkeypatch.setattr(lists, "ALLOWLIST", {"facebook.de"})
    assert "check_lookalike" not in rules_of("https://facebook.de")

@pytest.mark.parametrize("url", [
    "https://vietcombank-xacthuc.wordpress.com",  # brand in a subdomain of a popular platform
    "https://vcb-login.eu.cc",                    # alias in a subdomain of a popular platform
])
def test_subdomain_checks_still_run_on_allowlisted_platforms(monkeypatch, url):
    monkeypatch.setattr(lists, "ALLOWLIST", {"wordpress.com", "eu.cc"})
    assert "check_lookalike" in rules_of(url)

def test_check_domain_false_keeps_only_subdomain_checks():
    assert check_lookalike(parse_url("https://fb.gg"), check_domain=False) is None
    assert check_lookalike(parse_url("https://fb.gg"))[0] == 35
    assert check_lookalike(parse_url("https://momo.vn.momo.com"), check_domain=False)[0] == 35
    assert check_lookalike(parse_url("https://momo.vn.momo.com"), check_domain=True)[0] == 40

def test_allowlist_does_not_disable_other_rules(monkeypatch):
    monkeypatch.setattr(lists, "ALLOWLIST", {"facebook.de"})
    assert "check_keywords" in rules_of("https://facebook.de/login")

def test_blacklist_beats_allowlist(monkeypatch):
    monkeypatch.setattr(lists, "ALLOWLIST", {"popular-demo.com"})
    monkeypatch.setattr(lists, "BLACKLIST", {"popular-demo.com"})
    assert analyze("https://popular-demo.com")["score"] == 100

def test_verified_skips_rules_but_not_blacklist(monkeypatch):
    monkeypatch.setattr(lists, "VERIFIED", {"vcb-xacthuc.com"})
    assert analyze("https://vcb-xacthuc.com/login")["score"] == 0
    monkeypatch.setattr(lists, "BLACKLIST", {"vcb-xacthuc.com"})
    assert analyze("https://vcb-xacthuc.com/login")["score"] == 100