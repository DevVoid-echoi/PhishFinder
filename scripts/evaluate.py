"""Measure the rule layer on the evaluation set, and optionally learn the rule weights.

Needs data/eval/phishing.csv (collect_fresh) and at least one benign file:
  data/eval/benign.txt          Tranco ranks 10,001-90,000 (update_tranco)
  data/eval/benign_vn.txt       Vietnamese sites listed by hand
  data/eval/benign_private.txt  links from your own browsing history (never committed)

Run: python -m scripts.evaluate              measure hand-written points and data/weights.json
     python -m scripts.evaluate --calibrate  learn weights, save data/weights.json, measure again
"""
import sys
from functools import partial
from pathlib import Path

from app.calibrate import calibrate, save
from app.evaluation import (
    drop_conflicts,
    evaluate,
    fresh_split,
    load_benign,
    load_phishing,
    print_report,
    random_split,
    time_split
)
from app.scorer import analyze, WEIGHTS, WEIGHTS_FILE

EVAL = Path(__file__).resolve().parent.parent / "data" / "eval"


def main() -> None:
    phishing = load_phishing(EVAL / "phishing.csv")
    benign = load_benign(EVAL / "benign.txt", EVAL / "benign_vn.txt", EVAL / "benign_private.txt")
    benign = drop_conflicts(benign, [u for u, _ in phishing])

    phish_old, phish_fresh = fresh_split(phishing)
    phish_train, phish_val = random_split(phish_old, test_ratio=0.2)
    # Fixed seed: the splits never change. Learn on train, pick thresholds on validation,
    # measure on test. The test split is never used to tune rules or thresholds.
    benign_train, benign_rest = random_split(benign, test_ratio=0.5)
    benign_val, benign_test = random_split(benign_rest, test_ratio=0.5)

    # Measure the RULES only: the blacklist trivially "detects" its own entries
    rules_only = partial(analyze, use_blacklist=False)
    print("\n== Hand-written points (test split) ==")
    print_report(evaluate(benign_test, phish_fresh, partial(rules_only, weights={})), max_false_alarms=0)

    model = WEIGHTS
    if "--calibrate" in sys.argv:
        model = calibrate(benign_train, phish_train, benign_val, phish_val)
        save(model, WEIGHTS_FILE)
        print(f"\nSaved {WEIGHTS_FILE}. L2: {model['l2']}  thresholds: {model['thresholds']}  "
              f"validation recall: {model['val_recall_yellow']:.1%}")
        for rule, weight in sorted(model["weights"].items(), key=lambda kv: -kv[1]):
            print(f"  {weight:+7.3f}  {rule}")
        print(f"  {model['bias']:+7.3f}  (bias)")
    if model:
        print("\n== Learned weights (test split, never used for learning) ==")
        print_report(evaluate(benign_test, phish_fresh, partial(rules_only, weights=model)), max_false_alarms=0)

    # Read false alarms from the VALIDATION split: studying test cases while tuning leaks them
    print("\n== False alarms to read (validation split) ==")
    val = evaluate(benign_val, [], partial(rules_only, weights=model or {}))
    print_report(val)

if __name__ == "__main__":
    main()