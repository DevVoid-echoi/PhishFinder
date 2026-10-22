"""Measure the rule layer on the evaluation set.

Needs data/eval/phishing.csv (collect_fresh) and at least one benign file:
  data/eval/benign.txt          Tranco ranks 10,001-40,000 (update_tranco)
  data/eval/benign_vn.txt       Vietnamese sites listed by hand
  data/eval/benign_private.txt  links from your own browsing history (never committed)

Run: python -m scripts.evaluate
"""
from functools import partial
from pathlib import Path

from app.evaluation import (
    drop_conflicts,
    evaluate,
    load_benign,
    load_phishing,
    print_report,
    random_split,
    time_split
)
from app.scorer import analyze

EVAL = Path(__file__).resolve().parent.parent / "data" / "eval"


def main() -> None:
    phishing = load_phishing(EVAL / "phishing.csv")
    benign = load_benign(EVAL / "benign.txt", EVAL / "benign_vn.txt", EVAL / "benign_private.txt")
    benign = drop_conflicts(benign, [u for u, _ in phishing])

    phish_old, phish_new = time_split(phishing)
    # Fixed seed: the test half never changes, and is never used to tune rules or thresholds
    benign_train, benign_rest = random_split(benign, test_ratio=0.5)
    benign_val, benign_test = random_split(benign_rest, test_ratio=0.5)

    newest = sorted(d for _, d in phishing)
    print(f"Phishing first seen {newest[0]} .. {newest[-1]}; test set = newest {len(phish_new):,}")
    # Measure the RULES only: the blacklist trivially "detects" its own entries
    print_report(evaluate(benign_test, phish_new, partial(analyze, use_blacklist=False)))

if __name__ == "__main__":
    main()