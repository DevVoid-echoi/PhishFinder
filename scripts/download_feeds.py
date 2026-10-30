"""Download the phishing feeds into data/raw/. Run daily, before collect_fresh.

Run: python -m scripts.download_feeds
"""
import sys
import time
import urllib.request
from pathlib import Path

RAW = Path(__file__).resolve().parent.parent / "data" / "raw"
MAX_BYTES = 20 * 1024 * 1024

FEEDS = {
    # Vietnamese blocklist from ChongLuaDao. Frozen since 2025-05 (upstream API shut down)
    "vn_badsite.txt": "https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-domains.txt",
    # Aggregated domains (PhishTank, OpenPhish, CERT.PL...), refreshed every 4 hours
    "phishing_army.txt": "https://phishing.army/download/phishing_army_blocklist.txt",
    # Full phishing URLs, community feed
    "openphish.txt": "https://openphish.com/feed.txt",
}

def download(url: str, dest: Path) -> int:
    req = urllib.request.Request(url, headers={"User-Agent": "PhishFinder/0.1 (research)"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"larger than {MAX_BYTES} bytes")
    tmp = dest.with_suffix(".part")
    tmp.write_bytes(data)
    tmp.replace(dest)
    return len(data)

def download_with_retry(url: str, dest: Path, attempts: int = 3) -> int:
    for attempt in range(1, attempts + 1):
        try:
            return download(url, dest)
        except (OSError, ValueError):
            if attempt == attempts:
                raise
            time.sleep(5 * attempt)

def main() -> int:
    RAW.mkdir(parents=True, exist_ok=True)
    failed = 0
    for name, url in FEEDS.items():
        try:
            size = download_with_retry(url, RAW / name)
            print(f"OK    {name:20} {size:>10,} bytes")
        except (OSError, ValueError) as e:
            failed += 1
            print(f"FAIL  {name:20} {e}  (collect_fresh will reuse the previous file)")
    return 1 if failed == len(FEEDS) else 0

if __name__ == "__main__":
    sys.exit(main())