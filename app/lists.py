import csv
from pathlib import Path

from app.parser import parse_url

DATA = Path(__file__).resolve().parent.parent / "data"
RAW = DATA / "raw"

# Entries that appear in hosts files or feeds but are never phishing domains
IGNORED_ENTRIES = {
    "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
    "0.0.0.0", "127.0.0.1", "::1",
    "amiprotected.it", "www.amiprotected.it",  # phishing.army filter test domains
}

# Platforms where anyone can publish a site: never allowlist the whole domain
SHARED_HOSTING = {
    "google.com", "github.io", "blogspot.com", "web.app", "firebaseapp.com",
    "pages.dev", "workers.dev", "vercel.app", "netlify.app", "weebly.com",
    "wixsite.com", "000webhostapp.com", "glitch.me", "herokuapp.com",
}


def load_domain_list(path: Path) -> set:
    """Read plain ('evil.com'), hosts ('0.0.0.0 evil.com') or adblock ('||evil.com^') lists."""
    domains = set()
    if not path.exists():
        return domains
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.split(" #", 1)[0].strip()
            if not line or line.startswith(("#", "!", "[")):
                continue
            if line.startswith("||"):
                line = line[2:].split("^", 1)[0]
            elif " " in line or "\t" in line:
                line = line.split()[1]
            domain = line.lower().rstrip(".")
            if domain not in IGNORED_ENTRIES:
                domains.add(domain)
    return domains

def load_url_list(path: Path) -> set:
    """Read a feed of full URLs (e.g. OpenPhish), one per line."""
    if not path.exists():
        return set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        return {line.strip() for line in f if line.startswith(("http://", "https://"))}

def load_tranco(path: Path, top_n: int = 10_000) -> set:
    """Read a Tranco file ('rank,domain' per line) and keep the top_n domains."""
    allow = set()
    if not path.exists():
        return allow
    with open(path, encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) != 2 or not row[0].isdigit():
                continue
            rank, domain = int(row[0]), row[1].lower()
            if rank > top_n:
                break
            if domain not in SHARED_HOSTING:
                allow.add(domain)
    return allow

def url_key(raw: str, with_query: bool=True) -> str:
    """Comparable form of a URL: scheme, case of the host and trailing slash are ignored."""
    u = parse_url(raw)
    key = u.hostname + u.path.rstrip("/")
    if with_query and u.query:
        key += "?" + u.query
    return key

BLACKLIST = load_domain_list(RAW / "vn_badsite.txt") | load_domain_list(DATA / "blacklist_manual.txt")
BLACKLIST_URLS = {url_key(u) for u in load_url_list(RAW / "openphish.txt")}
ALLOWLIST = load_tranco(DATA / "tranco_top.csv")
VERIFIED = load_domain_list(DATA / "verified_manual.txt")

def check_blacklist(u):
    # Match the reported URL exactly, or ignoring a query string the attacker appended
    if url_key(u.original) in BLACKLIST_URLS or url_key(u.original, with_query=False) in BLACKLIST_URLS:
        return 100, "URL is on a list of reported phishing pages (OpenPhish)"
    for d in (u.hostname, u.registered_domain):
        if d in BLACKLIST:
            return 100, f"Domain {d} is on a phishing blocklist"
    return None

def is_allowlisted(registered_domain: str) -> bool:
    return registered_domain in ALLOWLIST

def is_verified(registered_domain:  str) -> bool:
    return registered_domain in VERIFIED

