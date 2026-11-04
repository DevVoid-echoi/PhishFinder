"""Checks on the hand-maintained blocklists. They need no downloaded data, so they run in CI."""
import re
from pathlib import Path

from app.lists import SHARED_HOSTING, load_domain_list
from app.lookalike import BRANDS
from app.parser import parse_url

DATA = Path(__file__).resolve().parent.parent / "data"
# The ChongLuaDao copy is local only; load_domain_list returns an empty set when it is missing
ENTRIES = sorted(load_domain_list(DATA / "blacklist_manual.txt")
                 | load_domain_list(DATA / "raw" / "chongluadao_manual.txt"))
OFFICIAL = {domain for info in BRANDS.values() for domain in info["official"]}


def test_manual_list_is_loaded():
    assert len(load_domain_list(DATA / "blacklist_manual.txt")) >= 100

def test_no_official_brand_domain_is_blocked():
    # cards.vpbank.com.vn would block the real VPBank
    assert [d for d in ENTRIES if parse_url(f"http://{d}/").registered_domain in OFFICIAL] == []

def test_no_whole_platform_is_blocked():
    # weebly.com would block every site on Weebly; list the attacker's subdomain instead
    assert [d for d in ENTRIES if d in SHARED_HOSTING] == []

def test_entries_are_bare_hostnames():
    assert [d for d in ENTRIES if not re.fullmatch(r"[a-z0-9_-]+(\.[a-z0-9_-]+)+", d)] == []
