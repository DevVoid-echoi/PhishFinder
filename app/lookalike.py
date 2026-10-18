import json
import re
from difflib import SequenceMatcher
from pathlib import Path
from typing import Optional, Tuple

from app.parser import ParsedURL

BRANDS_FILE = Path(__file__).resolve().parent.parent / "data" / "brands.json"

def load_brands(path: Path = BRANDS_FILE) -> dict:
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    return {
        name: {"official": set(info["official"]), "aliases": set(info.get("aliases", []))}
        for name, info in raw.items()
    }

BRANDS = load_brands()

HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s")]

Finding = Optional[Tuple[int, str]]

SHORT_BRAND_LEN = 5

def normalize(s: str) -> str:
    s = s.lower().replace("-", "")
    for fake, real in HOMOGLYPHS:
        s = s.replace(fake, real)
    return s

def tokens(text: str) -> set:
    return {normalize(t) for t in re.split(r"[-.\s]", text.lower()) if t}

def contains_brand(brand: str, text: str) -> bool:
    if len(brand) <= SHORT_BRAND_LEN:
        return brand in tokens(text)
    return brand in normalize(text)

def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()

def is_official(registered_domain: str) -> bool:
    return any(registered_domain in info["official"] for info in BRANDS.values())

def check_lookalike(u: ParsedURL) -> Finding:
    if is_official(u.registered_domain):
        return None

    name = normalize(u.domain_name)
    for brand in BRANDS:
        if len(brand) >= 4 and contains_brand(brand, u.domain_name):
            return 40, f"Domain contains '{brand}' but is not an official {brand} domain"
        if similarity(name, brand) >= 0.85:
            return 40, f"Domain '{u.domain_name}' closely resembles '{brand}' (possible impersonation)"
    
    parts = tokens(u.domain_name) | tokens(u.subdomain)
    for brand, info in BRANDS.items():
        hit = info["aliases"] & parts
        if hit:
            return 35, f"Domain uses '{hit.pop()}', an abbreviation of {brand}, but is not an official {brand} domain"

    for brand in BRANDS:
        if len(brand) >= 4 and contains_brand(brand, u.subdomain):
            return 35, f"'{brand}' appears in the subdomain, but the registered domain is {u.registered_domain}"
    return None

