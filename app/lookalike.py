from difflib import SequenceMatcher
from typing import Optional, Tuple

from app.parser import ParsedURL

BRANDS = {
    "vietcombank": {"vietcombank.com.vn"},
    "techcombank": {"techcombank.com.vn", "techcombank.com"},
    "bidv": {"bidv.com.vn"},
    "vietinbank": {"vietinbank.vn"},
    "agribank": {"agribank.com.vn"},
    "mbbank": {"mbbank.com.vn"},
    "vpbank": {"vpbank.com.vn"},
    "tpbank": {"tpb.vn"},
    "momo": {"momo.vn"},
    "zalopay": {"zalopay.vn"},
    "shopee": {"shopee.vn"},
    "lazada": {"lazada.vn"},
    "tiki": {"tiki.vn"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "zalo": {"zalo.me", "zalo.vn"},
    "vneid": {"vneid.gov.vn"},
    "gdt": {"gdt.gov.vn"},
}

HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s")]

Finding = Optional[Tuple[int, str]]


def normalize(s: str) -> str:
    s = s.lower().replace("-", "")
    for fake, real in HOMOGLYPHS:
        s = s.replace(fake, real)
    return s

def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()

def check_lookalike(u: ParsedURL) -> Finding:
    for brand, official in BRANDS.items():
        if u.registered_domain in official:
            return None

    name = normalize(u.domain_name)
    for brand in BRANDS:
        if len(brand) >= 4 and brand in name:
            return 40, f"Domain contains '{brand}' but is not an official {brand} domain"
        if similarity(name, brand) >= 0.85:
            return 40, f"Domain '{u.domain_name}' closely resembles '{brand}' (possible impersonation)"
    sub = normalize(u.subdomain)
    for brand in BRANDS:
        if len(brand) >= 4 and brand in sub:
            return 35, f"'{brand}' appears in the subdomain, but the registered domain is {u.registered_domain}"
    return None

