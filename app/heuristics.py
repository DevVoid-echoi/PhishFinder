import ipaddress
from typing import Optional, Tuple

from app.parser import ParsedURL

Finding = Optional[Tuple[int, str]]

SUSPICIOUS_TLDS = {"xyz", "top", "click", "icu", "buzz", "cfd", "sbs", "shop", "online", "site", "live", "vip"}

SUSPICIOUS_KEYWORDS = [
    "xacthuc", "xac-thuc", "dangnhap", "dang-nhap", "login", "verify",
    "khoa-tai-khoan", "mo-khoa", "nhanqua", "nhan-qua", "trungthuong",
    "hoantien", "hoan-tien", "update", "secure", "otp",
]

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "cutt.ly", "is.gd", "shorturl.at"}


def check_ip_host(u: ParsedURL) -> Finding:
    try:
        ipaddress.ip_address(u.hostname)
        return 30, "URL uses a raw IP address instead of a domain name"
    except ValueError:
        return None

def check_at_symbol(u: ParsedURL) -> Finding:
    if "@" in u.original.split("://", 1)[-1].split("/", 1)[0]:
        return 30, "URL contains '@' before the host, which can disguise the real domain"
    return None

def check_no_https(u: ParsedURL) -> Finding:
    if u.scheme == "http":
        return 10, "Connection is not encrypted (HTTP instead of HTTPS)"
    return None

def check_long_url(u: ParsedURL) -> Finding:
    if len(u.original) > 100:
        return 10, f"URL is unusually long ({len(u.original)} characters)"
    return None

def check_many_subdomains(u: ParsedURL) -> Finding:
    if u.subdomain.count(".") >= 2:
        return 15, f"Excessive number of subdomains ({u.subdomain})"
    return None

def check_suspicious_tld(u: ParsedURL) -> Finding:
    if u.suffix in SUSPICIOUS_TLDS:
        return 15, f"Top-level domain '.{u.suffix}' is frequently abused for phishing"
    return None

def check_keywords(u: ParsedURL) -> Finding:
    text = (u.hostname + u.path + u.query).lower()
    found = [k for k in SUSPICIOUS_KEYWORDS if k in text]
    if found:
        return min(10*len(found), 25), "Contains suspicious keywords: " + ", ".join(found)
    return None

def check_shortener(u: ParsedURL) -> Finding:
    if u.registered_domain in SHORTENERS or u.hostname in SHORTENERS:
        return 10, "URL shortener hides the final destination"
    return None

def check_punycode(u: ParsedURL) -> Finding:
    if "xn--" in u.hostname:
        return 25, "Hostname contains punycode (xn--), which may impersonate Latin characters"
    return None

ALL_CHECKS = [
    check_ip_host, check_at_symbol, check_no_https, check_long_url,
    check_many_subdomains, check_suspicious_tld, check_keywords,
    check_shortener, check_punycode,
]