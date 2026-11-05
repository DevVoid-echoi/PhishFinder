"""Measure the rule layer on the evaluation set, and optionally learn the rule weights.

Needs data/eval/phishing.csv (collect_fresh) and at least one benign file:
  data/eval/benign.txt          Tranco ranks 10,001-90,000 (update_tranco)
  data/eval/benign_vn.txt       Vietnamese sites listed by hand
  data/eval/benign_private.txt  links from your own browsing history (never committed)
PhishVN (data/raw/phishvn/dataset_url.csv) is added to training, validation and test when present.

Run: python -m scripts.evaluate              measure hand-written points and data/weights.json
     python -m scripts.evaluate --calibrate  learn weights; save data/weights.json only if they beat
                                             the hand-written points on validation
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
    load_phishvn,
    phishvn_splits,
    print_report,
    random_split,
)
from app.scorer import analyze, WEIGHTS, WEIGHTS_FILE

EVAL = Path(__file__).resolve().parent.parent / "data" / "eval"
PHISHVN = EVAL.parent / "raw" / "phishvn" / "dataset_url.csv"


def detected(urls: list, analyze_fn) -> float:
    return evaluate([], urls, analyze_fn)["recall_any"] if urls else 0.0


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
    vn = phishvn_splits(load_phishvn(PHISHVN)) if PHISHVN.exists() else {}

    # Measure the RULES only: the blacklist trivially "detects" its own entries
    rules_only = partial(analyze, use_blacklist=False)
    print("\n== Hand-written points (test split) ==")
    hand = partial(rules_only, weights={})
    print_report(evaluate(benign_test, phish_fresh, hand), max_false_alarms=0)
    if vn:
        print("\n== Hand-written points, PhishVN (test split) ==")
        print_report(evaluate(vn["benign_test"], vn["phish_test"], hand), max_false_alarms=0)

    model = in_use = WEIGHTS
    if "--calibrate" in sys.argv:
        model = calibrate(benign_train + vn.get("benign_train", []), phish_train + vn.get("phish_train", []),
                          benign_val + vn.get("benign_val", []), phish_val + vn.get("phish_val", []))
        learned = partial(rules_only, weights=model)
        print(f"\nLearned: L2 {model['l2']}  thresholds {model['thresholds']}")
        for rule, weight in sorted(model["weights"].items(), key=lambda kv: -kv[1]):
            print(f"  {weight:+7.3f}  {rule}")
        print(f"  {model['bias']:+7.3f}  (bias)")
        # Adopt only if the model detects at least as much as the hand-written points on every
        # validation set; its thresholds already meet the false-alarm targets
        sets = {"feeds": phish_val, "PhishVN": vn.get("phish_val", [])}
        wins = True
        for name, urls in sets.items():
            if urls:
                h, m = detected(urls, hand), detected(urls, learned)
                wins = wins and m >= h
                print(f"  validation detection, {name}: hand-written {h:.1%}, learned {m:.1%}")
        if wins:
            save(model, WEIGHTS_FILE)
            in_use = model
            print(f"Saved {WEIGHTS_FILE}")
        else:
            print("Not saved: the learned weights detect less than the hand-written points on validation")
    if model:
        learned = partial(rules_only, weights=model)
        print("\n== Learned weights (test split, never used for learning) ==")
        print_report(evaluate(benign_test, phish_fresh, learned), max_false_alarms=0)
        if vn:
            print("\n== Learned weights, PhishVN (test split) ==")
            print_report(evaluate(vn["benign_test"], vn["phish_test"], learned), max_false_alarms=0)

    # Read false alarms from the VALIDATION split: studying test cases while tuning leaks them
    print("\n== False alarms to read (validation split) ==")
    val = evaluate(benign_val, [], partial(rules_only, weights=in_use or {}))
    print_report(val)

if __name__ == "__main__":
    main()