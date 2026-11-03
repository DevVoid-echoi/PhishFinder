"""Measure the rule layer on PhishVN, phishing aimed at Vietnamese users (NCSC, 2020-2025).

Download PhishVN_v3.1.0_open.zip from https://doi.org/10.17632/b97hxbxtpd and extract
data/dataset_url.csv to data/raw/phishvn/. Run: python -m scripts.evaluate_phishvn
Misses are read from the train split; the test split is only measured.
"""
from collections import Counter, defaultdict
from pathlib import Path

from app.evaluation import WARN, load_phishvn
from app.scorer import analyze

DATASET = Path(__file__).resolve().parent.parent / "data" / "raw" / "phishvn" / "dataset_url.csv"


def detected(url: str) -> bool:
    return analyze(url, use_blacklist=False, weights={})["level"] in WARN


def rate(hits: int, total: int) -> str:
    return f"{hits:>5} / {total:<5} {hits / total:6.1%}" if total else "    - / 0"


def report(rows: list) -> None:
    by_scenario, by_source = defaultdict(Counter), defaultdict(Counter)
    for r in rows:
        group = by_scenario[r["scenario"]] if r["label"] == "phishing" else by_source[r["source"]]
        group[detected(r["url"])] += 1
    print("  Phishing detected (yellow or red), by scenario:")
    for name, c in sorted(by_scenario.items(), key=lambda kv: -sum(kv[1].values())):
        print(f"    {name:10} {rate(c[True], c[True] + c[False])}")
    total = sum((c for c in by_scenario.values()), Counter())
    print(f"    {'all':10} {rate(total[True], total[True] + total[False])}")
    print("  Benign false alarms (yellow or red), by source:")
    for name, c in sorted(by_source.items()):
        print(f"    {name:12} {rate(c[True], c[True] + c[False])}")


def main() -> None:
    rows = load_phishvn(DATASET)
    for split in ("train", "test"):
        print(f"\n== {split} split ==")
        report([r for r in rows if r["split"] == split])

    misses = [r for r in rows if r["split"] == "train" and r["label"] == "phishing" and not detected(r["url"])]
    print("\n== Missed phishing to read (train split, first 15 per scenario) ==")
    for scenario in sorted({r["scenario"] for r in misses}):
        sample = [r["url"] for r in misses if r["scenario"] == scenario][:15]
        print(f"  {scenario}: {' '.join(sample)}")


if __name__ == "__main__":
    main()
