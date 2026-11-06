"""Look up domain age (RDAP) and TLS for a sample of today's new phishing and of benign pages.

A phishing domain usually dies within days, so its server signals can only be measured right
after it is collected: run this after collect_fresh, every day. Results accumulate in
data/eval/signals.csv and feed calibration through load_signals. Hostnames only: no page is
downloaded, and the TLS check stops after the handshake.

Run: python -m scripts.collect_signals [count]     count phishing and count benign (default 100)
"""
import csv
import random
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from pathlib import Path

from app.evaluation import load_benign, load_phishing
from app.online import fetch_json, rdap_servers, rdap_url, registration_date
from app.parser import parse_url
from app.reputation import fetch_cert, resolve_public_ips

EVAL = Path(__file__).resolve().parent.parent / "data" / "eval"
OUT = EVAL / "signals.csv"
FIELDS = ["url", "label", "looked_up", "registered_domain", "created", "tls", "cert_issued"]


def domain_created(domain: str) -> str:
    try:
        url = rdap_url(domain, rdap_servers())
        created = registration_date(fetch_json(url)) if url else None
    except (OSError, ValueError, KeyError):
        return ""
    return created.date().isoformat() if created else ""


def tls_state(host: str) -> tuple:
    """("valid", issue date), ("invalid", "") or ("none", "") when nothing public answers on 443."""
    for ip in resolve_public_ips(host)[:2]:
        try:
            cert = fetch_cert(host, ip)
        except ssl.SSLCertVerificationError:
            return "invalid", ""
        except (OSError, ssl.SSLError, ValueError):
            continue
        issued = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc)
        return "valid", issued.date().isoformat()
    return "none", ""


def lookup(url: str, label: str, today: str) -> dict:
    u = parse_url(url)
    tls, issued = tls_state(u.hostname)
    return {"url": url, "label": label, "looked_up": today, "registered_domain": u.registered_domain,
            "created": domain_created(u.registered_domain), "tls": tls, "cert_issued": issued}


def pick(urls: list, done: set, count: int, seed: str) -> list:
    """A fixed random sample of the URLs not looked up yet (the seed is the date)."""
    todo = sorted(set(urls) - done)
    return random.Random(seed).sample(todo, min(count, len(todo)))


def main() -> int:
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    today = date.today().isoformat()
    done = set()
    if OUT.exists():
        with open(OUT, encoding="utf-8", newline="") as f:
            done = {row["url"] for row in csv.DictReader(f)}

    fresh = [u for u, first_seen in load_phishing(EVAL / "phishing.csv") if first_seen == today]
    benign = load_benign(EVAL / "benign.txt", EVAL / "benign_vn.txt")
    jobs = [(u, "phishing") for u in pick(fresh, done, count, today)]
    jobs += [(u, "benign") for u in pick(benign, done, count, today)]
    if not fresh:
        print("No phishing first seen today: run collect_fresh first")

    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(lambda job: lookup(job[0], job[1], today), jobs))

    new_file = not OUT.exists()
    with open(OUT, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        if new_file:
            writer.writeheader()
        writer.writerows(rows)
    for label in ("phishing", "benign"):
        mine = [r for r in rows if r["label"] == label]
        dated = [r for r in mine if r["created"]]
        print(f"{label:9} {len(mine):4} looked up, {len(dated):4} with a registration date, "
              f"{sum(r['tls'] == 'valid' for r in mine):4} with a valid certificate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
