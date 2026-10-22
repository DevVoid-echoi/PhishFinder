import pytest

from app import lists
from app.evaluation import (
    as_url,
    drop_conflicts,
    evaluate,
    is_vietnamese,
    load_benign,
    load_phishing,
    time_split
)
from app.parser import parse_url
from app.scorer import analyze, run_rules
from scripts.collect_fresh import collect


def test_bare_domain_gets_the_same_form_as_phishing_domains():
    assert as_url("example.com") == "http://example.com/"
    assert as_url("https://shopee.vn/sale") == "https://shopee.vn/sale"


def test_load_benign_merges_files_and_skips_comments(tmp_path):
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_text("# header\nexample.com\nshopee.vn # verified\n")
    b.write_text("example.com\nhttps://tiki.vn\n")
    assert load_benign(a, b, tmp_path / "missing.txt") == [
        "http://example.com/", "http://shopee.vn/", "https://tiki.vn"
    ]

def test_phishing_csv_round_trip(tmp_path):
    src, out = tmp_path / "feed.txt", tmp_path / "phishing.csv"
    src.write_text("https://a-scam.vn/login\n")
    collect([src], out, today="2026-10-21")
    assert load_phishing(out) == [("https://a-scam.vn/login", "2026-10-21")]

def test_time_split_keeps_newest_for_test():
    old, new = time_split([("a", "2026-01-01"), ("b", "2026-03-01"), ("c", "2026-02-01")], 0.3)
    assert new == ["b"]
    assert old == ["a", "c"]

def test_drop_conflicts_removes_hosts_labelled_phishing():
    benign = ["http://good.com/", "http://both.com/"]
    assert drop_conflicts(benign, ["https://both.com/login"]) == ["http://good.com/"]

@pytest.mark.parametrize("url, expected", [
    ("http://scam.com.vn/", True),
    ("https://abc.vn", True),
    ("https://vietcombank-xacthuc.com", False),
])
def test_vietnamese_subset_uses_suffix_only(url, expected):
    assert is_vietnamese(url) is expected

def test_metrics_with_english_levels():
    def fake(u):
        return {"level": "dangerous" if "bad" in u else "likely_safe"}

    r = evaluate(["good1", "good2", "bad-but-real"], ["bad1", "bad2.vn"], fake)
    assert r["fpr_red"] == pytest.approx(1/3)
    assert r["recall_red"] == 1.0
    assert r["false_positives"] == [("bad-but-real", "dangerous")]

def test_blacklist_hit_is_always_dangerous(monkeypatch):
    monkeypatch.setattr(lists, "BLACKLIST", {"shop-demo.com"})
    r = analyze("https://shop-demo.com")
    assert r["score"] == 100
    assert r["level"] == "dangerous"
    assert r["reasons"][0]["rule"] == "check_blacklist"

def test_rules_only_mode_ignores_the_blacklist(monkeypatch):
    monkeypatch.setattr(lists, "BLACKLIST", {"shop-demo.com"})
    assert analyze("https://shop-demo.com", use_blacklist=False)["score"] == 0
    assert run_rules(parse_url("https://shop-demo.com")) == []
