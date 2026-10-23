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

CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ο": "o", "ν": "v", "α": "a", "ı": "i",
})

Finding = Optional[Tuple[int, str]]

SHORT_BRAND_LEN = 5

def unpunycode(label: str) -> str:
    if label.startswith("xn--"):
        try:
            label = label.encode("ascii").decode("idna")
        except UnicodeError:
            return label
    return label.translate(CONFUSABLES)

def normalize(s: str) -> str:
    s = ".".join(unpunycode(p) for p in s.lower().split("."))
    s = s.replace("-", "")
    for fake, real in HOMOGLYPHS:
        s = s.replace(fake, real)
    return s

def tokens(text: str) -> set:
    labels = [unpunycode(p) for p in re.split(r"[.\s]", text.lower())]
    return {normalize(t) for label in labels for t in label.split("-") if t}

def contains_brand(brand: str, text: str) -> bool:
    if len(brand) <= SHORT_BRAND_LEN:
        return brand in tokens(text)
    return brand in normalize(text)

def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()

def is_official(registered_domain: str) -> bool:
    return any(registered_domain in info["official"] for info in BRANDS.values())

def check_lookalike(u: ParsedURL, check_domain: bool=True) -> Finding:
    """check_domain=False (allowlisted popular domain): skip the checks on the registered
    domain itself, but keep the subdomain checks, because anyone can create
    vietcombank-xacthuc.<platform> on a popular hosting platform."""
    if is_official(u.registered_domain):
        return None

    if check_domain:
        name = normalize(u.domain_name)
        for brand in BRANDS:
            if len(brand) >= 4 and contains_brand(brand, u.domain_name):
                return 40, f"Domain contains '{brand}' but is not an official {brand} domain"
            if similarity(name, brand) >= 0.85:
                return 40, f"Domain '{u.domain_name}' closely resembles '{brand}' (possible impersonation)"
    
    parts = tokens(u.subdomain) | (tokens(u.domain_name) if check_domain else set())
    for brand, info in BRANDS.items():
        hit = info["aliases"] & parts
        if hit:
            return 35, f"Domain uses '{sorted(hit)[0]}', an abbreviation of {brand}, but is not an official {brand} domain"

    for brand in BRANDS:
        if len(brand) >= 4 and contains_brand(brand, u.subdomain):
            return 35, f"'{brand}' appears in the subdomain, but the registered domain is {u.registered_domain}"
    return None

