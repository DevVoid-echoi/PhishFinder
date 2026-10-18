import pytest

from app.lookalike import BRANDS
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