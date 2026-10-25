import csv
import random
from pathlib import Path

from app.parser import parse_url

RED = {"dangerous"}
WARN = {"dangerous", "suspicious"}


def as_url(entry: str) -> str:
    """Bare domains become http://<domain>/, the same form collect_fresh gives phishing domains."""
    return entry if "://" in entry else f"http://{entry}/"

def load_benign(*paths: Path) -> list:
    """Each line: a URL or a domain of a LEGITIMATE site. Missing files are skipped."""
    entries = set()
    for path in paths:
        if not path.exists():
            continue
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.split(" #", 1)[0].strip()
                if line and not line.startswith("#"):
                    entries.add(as_url(line))
    return sorted(entries)

def load_phishing(path: Path) -> list:
    """CSV with columns url, first_seen (YYYY-MM-DD). Returns a list of (url, first_seen)."""
    with open(path, encoding="utf-8", newline="") as f:
        return [(row["url"], row["first_seen"]) for row in csv.DictReader(f)]

def drop_conflicts(benign: list, phishing_urls: list) -> list:
    """Remove benign entries whose hostname is also labelled phishing."""
    phish_hosts = {parse_url(u).hostname for u in phishing_urls}
    return [u for u in benign if parse_url(u).hostname not in phish_hosts]

def is_vietnamese(url: str) -> bool:
    """Vietnamese domain by suffix only, so the subset does not depend on the rules being measured."""
    suffix = parse_url(url).suffix
    return suffix == "vn" or suffix.endswith(".vn")

def time_split(phishing: list, test_ratio: float=0.3):
    """Split by TIME: older entries for tuning, the newest for the final measurement."""
    ordered = sorted(phishing, key=lambda x: (x[1], x[0]))
    cut = int(len(ordered) * (1-test_ratio))
    return [u for u, _ in ordered[:cut]], [u for u,_ in ordered[cut:]]

def fresh_split(phishing: list): 
    """Entries from the first collection day are "old" (a snapshot of everything already
    known); entries first seen on later days are genuinely fresh and form the test set."""
    first_day = min(d for _, d in phishing)
    old = sorted(u for u, d in phishing if d == first_day)
    fresh = sorted(u for u, d in phishing if d != first_day)
    return old, fresh

def random_split(items: list, test_ratio: float = 0.3, seed: int = 42):
    shuffled = items[:]
    random.Random(seed).shuffle(shuffled)
    cut = int(len(shuffled) * (1-test_ratio))
    return shuffled[:cut], shuffled[cut:]

def evaluate(benign: list, phishing: list, analyze_fn) -> dict:
    """analyze_fn(url) -> dict with 'level'. Rates of false alarms and detections at both levels."""
    benign_levels = [(u, analyze_fn(u).get("level")) for u in benign]
    phish_levels = [(u, analyze_fn(u).get("level")) for u in phishing]

    def rate(pairs, accepted):
        return sum(1 for _, level in pairs if level in accepted) / max(len(pairs), 1)

    vn_phish = [p for p in phish_levels if is_vietnamese(p[0])]
    return {
        "n_benign": len(benign),
        "n_phishing": len(phishing),
        "n_phishing_vn": len(vn_phish),
        "fpr_red": rate(benign_levels, RED),
        "fpr_any": rate(benign_levels, WARN),
        "recall_red": rate(phish_levels, RED),
        "recall_any": rate(phish_levels, WARN),
        "recall_any_vn": rate(vn_phish, WARN),
        "false_positives": [(u, level) for u, level in benign_levels if level in WARN],
    }

def print_report(r: dict, max_false_alarms: int = 50) -> None:
    print(f"Benign: {r['n_benign']:,}   Phishing: {r['n_phishing']:,} (Vietnamese: {r['n_phishing_vn']:,})")
    print(f"False alarms  red: {r['fpr_red']:.3%}   yellow or red: {r['fpr_any']:.3%}")
    print(f"Detected      red: {r['recall_red']:.1%}   yellow or red: {r['recall_any']:.1%}"
          f"   Vietnamese, yellow or red: {r['recall_any_vn']:.1%}")
    for url, level in r["false_positives"][:max_false_alarms]:
        print(f"  FALSE ALARM [{level}] {url}")
