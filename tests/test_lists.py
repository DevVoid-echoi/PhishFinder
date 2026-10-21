import pytest

from app import lists
from app.lists import check_blacklist, load_domain_list, load_tranco, load_url_list, url_key
from app.parser import parse_url
from scripts.collect_fresh import collect, read_seen

def test_domain_list_formats(tmp_path):
    f = tmp_path / "bl.txt"
    f.write_text (
        "# comment\n! adblock comment\n"
        "127.0.0.1 localhost\n0.0.0.0 0.0.0.0\n"
        "evil.com\n0.0.0.0 scam.vn\n||phish.xyz^\n"
        "bad.top # inline comment\namiprotected.it\n"
    )
    assert load_domain_list(f) == {"evil.com", "scam.vn", "phish.xyz", "bad.top"}

def test_missing_file_gives_empty_set(tmp_path):
    assert load_domain_list(tmp_path / "missing.txt") == set()
    assert load_url_list(tmp_path / "missing.txt") == set()

def test_url_list_keeps_only_urls(tmp_path):
    f = tmp_path / "op.txt"
    f.write_text("https://a.com/x\n\nnot a url\nhttps://b.vn\n")
    assert load_url_list(f) == {"https://a.com/x", "https://b.vn"}

def test_tranco_skips_shared_hosting_and_bad_rows(tmp_path):
    f = tmp_path / "t.csv"
    f.write_text("1,google.com\n2,zalora.com\n\nrank,domain\n3,github.io\n4,example.org\n")
    assert load_tranco(f, top_n=3) == {"zalora.com"}

@pytest.mark.parametrize("variant", [
    "https://docs.google.com/forms/d/phish123",
    "http://docs.google.com/forms/d/phish123/",
    "https://DOCS.google.com/forms/d/phish123",
    "https://docs.google.com/forms/d/phish123?usp=sf_link",
])
def test_url_blacklist_resists_simple_variants(monkeypatch, variant):
    monkeypatch.setattr(lists, "BLACKLIST_URLS", {url_key("https://docs.google.com/forms/d/phish123")})
    assert check_blacklist(parse_url(variant))[0] == 100

def test_url_blacklist_does_not_block_whole_host(monkeypatch):
    monkeypatch.setattr(lists, "BLACKLIST_URLS", {url_key("https://docs.google.com/forms/d/phish123")})
    assert check_blacklist(parse_url("https://docs.google.com/document/d/abc")) is None

def test_url_with_query_in_list_needs_same_query(monkeypatch):
    monkeypatch.setattr(lists, "BLACKLIST_URLS", {url_key("https://shared.com/index.php?id=phish")})
    assert check_blacklist(parse_url("https://shared.com/index.php?id=phish"))[0] == 100
    assert check_blacklist(parse_url("https://shared.com/index.php?id=other")) is None

def test_domain_blacklist_covers_subdomains(monkeypatch):
    monkeypatch.setattr(lists, "BLACKLIST", {"vn-scam-demo.com"})
    assert check_blacklist(parse_url("https://shop.vn-scam-demo.com/login"))[0] == 100
    assert check_blacklist(parse_url("https://vn-scam-demo.com.vn")) is None

def test_collect_only_new_entries_get_today(tmp_path):
    src, out = tmp_path / "vn.txt", tmp_path / "phishing.csv"
    src.write_text("0.0.0.0 a-scam.vn\n0.0.0.0 b-scam.vn\n")
    assert collect([src], out, today="2026-10-17") == 2
    src.write_text("0.0.0.0 a-scam.vn\n0.0.0.0 b-scam.vn\n0.0.0.0 c-scam.vn\n")
    assert collect([src], out, today="2026-10-18") == 1
    assert collect([src], out, today="2026-10-19") == 0
    assert read_seen(out) == {"http://a-scam.vn/", "http://b-scam.vn/", "http://c-scam.vn/"}
    assert "http://c-scam.vn/,2026-10-18" in out.read_text()

