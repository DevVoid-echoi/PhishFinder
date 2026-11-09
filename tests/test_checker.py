"""Core detection tests: parser, legitimate sites, phishing patterns, invalid input."""
import pytest

from app.parser import parse_url
from app.scorer import analyze


def rules_of(link):
    return {r["rule"] for r in analyze(link, use_blacklist=False)["reasons"]}


def test_vn_domain():
    u = parse_url("https://ebank.vietcombank.com.vn/login")
    assert u.registered_domain == "vietcombank.com.vn"
    assert u.domain_name == "vietcombank"
    assert u.subdomain == "ebank"


def test_missing_scheme():
    assert parse_url("shopee.vn").hostname == "shopee.vn"


@pytest.mark.parametrize("link", [
    "https://vietcombank.com.vn",
    "https://shopee.vn/sale",
    "https://www.facebook.com/groups/abc",
    "https://hust.edu.vn",
])
def test_official_sites_are_low_risk(link):
    assert analyze(link)["score"] < 30


def test_brand_in_fake_domain():
    r = analyze("http://vietcombank-xacthuc.com/dang-nhap")
    assert r["score"] >= 60
    assert r["level"] == "dangerous"


@pytest.mark.parametrize("link", ["https://vietcornbank.com", "https://sh0pee.vn"])
def test_typosquatting(link):
    assert analyze(link)["score"] >= 40


def test_brand_in_subdomain():
    assert analyze("https://momo.vn.nhanqua.xyz")["score"] >= 60


@pytest.mark.parametrize("link", ["http://192.168.1.10/login", "https://vietcombank.com.vn@evil.com"])
def test_ip_and_at_symbol(link):
    assert analyze(link)["score"] >= 30


def test_reasons_are_given():
    assert analyze("http://sh0pee-nhanqua.top")["reasons"]


@pytest.mark.parametrize("link", ["", " ", "http://"])
def test_no_hostname(link):
    assert "error" in analyze(link)


@pytest.mark.parametrize("link", ["https://zalora.com", "https://tikitaka.com", "https://bidvietnam.com"])
def test_short_brand_inside_word(link):
    assert analyze(link)["score"] < 30


@pytest.mark.parametrize("link", [
    "https://zalo-nhanqua.com",
    "https://tiki-hoantien.net",
    "https://bidv.secure-login.top",
])
def test_short_brand_as_token_still_caught(link):
    assert analyze(link)["score"] >= 40


@pytest.mark.parametrize("link", ["http://acb-xacthuc.com", "http://vib.online-verify.top", "http://scb.com-vn.vip"])
def test_three_letter_brand_as_token(link):
    assert "check_lookalike" in rules_of(link)

@pytest.mark.parametrize("link", ["https://shub.edu.vn", "https://npt.com.vn", "https://acbs.com.vn"])
def test_short_brand_needs_an_exact_token(link):
    assert "check_lookalike" not in rules_of(link)


# Real banks and wallets whose names contain another brand (vietbank, shopee)
@pytest.mark.parametrize("link", ["https://baovietbank.vn", "https://vietabank.com.vn", "https://shopeepay.vn"])
def test_official_name_containing_another_brand(link):
    assert "check_lookalike" not in rules_of(link)


@pytest.mark.parametrize("link", ["http://lpbank-xacthuc.com", "http://kienlongbank.secure-login.top",
                                  "http://pvcombank-ebanking.vip"])
def test_added_bank_brands_are_protected(link):
    assert "check_lookalike" in rules_of(link)

@pytest.mark.parametrize("link", [
    "http://scb.com.vn-ax.xyz", "http://scb.com-vn.vip", "http://techcombank.vn-iy.life",
    "http://mail.com.vn.evil.top",
])
def test_fake_vn_suffix(link):
    assert "check_fake_vn_suffix" in rules_of(link)

@pytest.mark.parametrize("link", ["https://vietcombank.com.vn", "https://dichvucong.gov.vn", "https://vn-express.net"])
def test_real_vn_suffix_is_not_caught(link):
    assert "check_fake_vn_suffix" not in rules_of(link)

def test_vietnamese_banking_keywords():
    assert "check_keywords" in rules_of("http://vaytinchap-nganhang24h.net")
