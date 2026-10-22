"""Record phishing entries the first time they are seen, with today's date. Run daily.

Public lists do not say when each entry appeared. This script compares the
downloaded files with what was already recorded and appends only new entries
to data/eval/phishing.csv. After a few weeks, the latest rows are the
"fresh phishing" used for the final measurement.

Run: python -m scripts.collect_fresh data/raw/phishing_army.txt data/raw/openphish.txt data/raw/vn_badsite.txt data/samples_phishing.txt
"""

import csv
import sys
from datetime import date
from pathlib import Path

from app.lists import load_domain_list, load_url_list

OUT = Path(__file__).resolve().parent.parent / "data" / "eval" / "phishing.csv"


def read_seen(path: Path) -> set:
    if not path.exists():
        return set()
    with open(path, encoding="utf-8", newline="") as f:
        return {row["url"] for row in csv.DictReader(f)}

def entries_from(path: Path) -> set:
    """URL feeds are kept as they are; domain lists become http://<domain>/."""
    urls = load_url_list(path)
    if urls:
        return urls
    return{f"http://{d}/" for d in load_domain_list(path)}

def collect(sources: list, out: Path = OUT, today: str=None) -> int:
    today = today or date.today().isoformat()
    seen = read_seen(out)
    found = set().union(*(entries_from(Path(s)) for s in sources)) if sources else set()
    new = sorted(found - seen)
    out.parent.mkdir(parents=True, exist_ok=True)
    first_time = not out.exists()
    with open(out, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if first_time:
            writer.writerow(["url", "first_seen"])
        for url in new:
            writer.writerow([url, today])
    return len(new)

if __name__ == "__main__":
    print(f"Added {collect(sys.argv[1:])} new entries to {OUT}")