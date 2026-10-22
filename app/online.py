"""Domain age from RDAP, the successor of WHOIS.

RDAP returns JSON over HTTPS and is required for all ICANN gTLD registries,
which covers the cheap TLDs phishing favours (.com, .xyz, .top, .shop, .icu).
It is not available for .vn, so Vietnamese domains get no age finding.
"""
import json
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from functools import lru_cache
from typing import Optional, Tuple

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
TIMEOUT = 5
MAX_BYTES = 1_000_000

Finding = Optional[Tuple[int, str]]


def fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/rdap+json, application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"RDAP response larger than {MAX_BYTES} bytes")
    return json.loads(data)

@lru_cache(maxsize=1)
def rdap_servers() -> dict:
    """TLD -> RDAP base URL, from the IANA bootstrap file (fetched once per process)."""
    data = fetch_json(BOOTSTRAP_URL)
    return {tld: urls[0] for tlds, urls in data["services"] for tld in tlds}

def rdap_url(domain: str, servers: dict) -> Optional[str]:
    base = servers.get(domain.rsplit(".", 1)[-1])
    if base is None:
        return None
    return base.rstrip("/") + "/domain/" + urllib.parse.quote(domain)

def registration_date(rdap: dict) -> Optional[datetime]:
    for event in rdap.get("events", []):
        if event.get("eventAction") == "registration":
            created = datetime.fromisoformat(event["eventDate"])
            return created if created.tzinfo else created.replace(tzinfo=timezone.utc)
    return None

def evaluate_age(created: datetime, now: datetime=None) -> Finding:
    now = now or datetime.now(timezone.utc)
    age_days = (now - created).days
    if age_days < 0:
        return None
    if age_days < 30:
        return 35, f"Domain was registered {age_days} days ago"
    if age_days < 180:
        return 15, f"Domain is fairly new ({age_days} days old)"
    return None

def check_domain_age(domain: str) -> Finding:
    """domain: the registered domain (e.g. vcb-xacthuc.com). Any failure gives no finding."""
    try:
        url = rdap_url(domain, rdap_servers())
        if url is None:
            return None
        created = registration_date(fetch_json(url))
    except (OSError, ValueError, KeyError):
        return None
    return evaluate_age(created) if created else None

if __name__ == "__main__":
    import sys

    for d in sys.argv[1:]:
        print(d, check_domain_age(d))