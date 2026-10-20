import pytest

from app.lookalike import BRANDS, unpunycode
from app.parser import parse_url
from app.scorer import analyze, score_to_level


def test_brands_loaded_from_json():
    assert "vcb" in BRANDS["vietcombank"]["aliases"]
    assert "vietcombank.com.vn" in BRANDS["vietcombank"]["official"]

@pytest.mark.parametrize("link", [
    "https://vcb-xacthuc.com",
    "https://fb.login-check.xyz",
])
def test_alias_as_token_is_caught(link):
    assert analyze(link)["score"] >= 35

@pytest.mark.parametrize("link", [
    "https://abctcbxyz.com",
    "https://tcbs.vn",
    "https://vcbs.com.vn",
    "https://fbi.gov",
])
def test_alias_inside_word_is_ignored(link):
    assert analyze(link)["score"] == 0

@pytest.mark.parametrize("url, registered_domain, suffix", [
    ("https://portal.hust.ac.vn", "hust.ac.vn", "ac.vn"),
    ("https://evil.github.io/login", "evil.github.io", "github.io"),
    ("http://192.168.1.10/login", "192.168.1.10", ""),
    ("https://abc.wordpress.com", "wordpress.com", "com"),
])
def test_public_suffix_list(url, registered_domain, suffix):
    u = parse_url(url)
    assert u.registered_domain == registered_domain
    assert u.suffix == suffix

@pytest.mark.parametrize("score, level", [
    (0, "likely_safe"),
    (29, "likely_safe"),
    (30, "suspicious"),
    (59, "suspicious"),
    (60, "dangerous"),
    (100, "dangerous"),
])
def test_score_to_level_boundaries(score, level):
    assert score_to_level(score) == level

@pytest.mark.parametrize("url, expected", [
    ("https://mоmо.vn", "xn--mm-fmcb.vn"),
    ("https://vіetcombank.com", "xn--vetcombank-x2i.com"),
    ("https://shopee.vn", "shopee.vn"),
])
def test_unicode_hostname_becomes_punycode(url, expected):
    assert parse_url(url).hostname == expected

@pytest.mark.parametrize("label, expected", [
    ("xn--vetcombank-x2i", "vietcombank"),
    ("xn--mm-fmcb", "momo"),
    ("xn--zzzz", "xn--zzzz"),
    ("shopee", "shopee"),
])
def test_unpunycode(label, expected):
    assert unpunycode(label) == expected

@pytest.mark.parametrize("url", [
    "https://vіetcombank.com",
    "https://xn--vetcombank-x2i.com",
    "https://mоmо.vn",
    "https://mоmо.vn.nhanqua.xyz",
])
def test_unicode_lookalike_is_dangerous(url):
    r = analyze(url)
    assert r["level"] == "dangerous"
    assert {"check_lookalike", "check_punycode"} <= {x["rule"] for x in r["reasons"]}

def test_legit_unicode_domain_is_not_flagged_as_brand():
    r = analyze("https://bücher.de")
    assert r["level"] == "likely_safe"
    assert "check_lookalike" not in {x["rule"] for x in r["reasons"]}

