"""Tests for the page measurement script. Downloads are fakes; nothing leaves the machine."""
from datetime import date

from scripts import measure_pages as mp
from tests.test_page_analysis import PHISH_HTML

TODAY = date(2026, 11, 8)


def test_sample_takes_fresh_phishing_once_per_domain():
    phishing = [("https://a.vcb-x.top/1", "2026-11-08"), ("https://b.vcb-x.top/2", "2026-11-08"),
                ("https://new.xyz/", "2026-11-07"), ("https://old.xyz/", "2026-11-01")]
    rows = mp.pick_sample(phishing, [], TODAY, 10)
    assert sorted(u for u, _ in rows) == ["https://a.vcb-x.top/1", "https://new.xyz/"]


def test_sample_mixes_warned_and_random_benign():
    benign = ["http://vietcombank-xacthuc.com/", "http://ok1.com/", "http://ok2.com/", "http://ok3.com/"]
    rows = mp.pick_sample([], benign, TODAY, 2)
    assert ("http://vietcombank-xacthuc.com/", "benign_warned") in rows
    assert [label for _, label in rows] == ["benign_warned", "benign_random"]


def test_sample_is_the_same_on_the_same_day():
    benign = [f"http://site{i}.com/" for i in range(50)]
    assert mp.pick_sample([], benign, TODAY, 10) == mp.pick_sample([], benign, TODAY, 10)


def test_measure_one_saves_rules_not_html(monkeypatch):
    monkeypatch.setattr(mp, "follow", lambda url, method: {"chain": [url], "final": url, "error": None,
                                                          "status": 200, "html": PHISH_HTML})
    row = mp.measure_one("https://vcb-secure.top/login", "phishing")
    assert row["rules"] == "page_asks_otp_card;page_brand_login;page_form_external"
    assert (row["points"], row["error"], row["ai_answered"]) == (90, "", False)
    assert "html" not in row


def test_measure_one_records_a_failed_download(monkeypatch):
    monkeypatch.setattr(mp, "follow", lambda url, method: {"chain": [url], "final": None,
                                                           "error": "Connection failed: TimeoutError"})
    row = mp.measure_one("https://dead.top/", "phishing")
    assert (row["error"], row["rules"], row["points"]) == ("Connection failed: TimeoutError", "", 0)


def test_measure_one_survives_an_unexpected_error(monkeypatch):
    def broken(url, method):
        raise RuntimeError("bug")

    monkeypatch.setattr(mp, "follow", broken)
    row = mp.measure_one("https://odd.top/", "phishing")
    assert (row["error"], row["rules"]) == ("Unexpected error: RuntimeError", "")


def test_summary_separates_rules_from_ai():
    rows = [{"label": "phishing", "error": "", "rules": "ai_urgency;page_brand_login", "ai_answered": "True"},
            {"label": "phishing", "error": "", "rules": "ai_urgency", "ai_answered": "True"},
            {"label": "phishing", "error": "Connection failed: TimeoutError", "rules": "", "ai_answered": "False"}]
    lines = mp.summarize(rows)
    assert lines[0] == ("phishing: 2 of 3 pages downloaded; flagged by rules 1, by rules or AI 2; "
                        "AI answered 2")
    assert "  not downloaded, Connection failed: 1" in lines
