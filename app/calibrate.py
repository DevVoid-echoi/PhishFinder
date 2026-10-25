"""Learn one weight per rule with logistic regression, then pick the red and yellow thresholds.

Each URL is represented by the set of rules that fired. The model is
    P(phishing) = sigmoid(bias + sum of the weights of the fired rules)
so every warning stays explainable (one weight per rule), but the weights
come from data instead of hand-written points.
"""
import json
from collections import Counter

from app.parser import parse_url
from app.scorer import run_rules, sigmoid, weighted_score


def features(url: str, extra: dict = None) -> frozenset:
    """extra: {url: {"domain_age", "tls"}} for a sample looked up on the server (step 9.3)."""
    rules = {r["rule"] for r in run_rules(parse_url(url))}
    return frozenset(rules | set((extra or {}).get(url, ())))

def group(benign: list, phishing: list, extra: dict = None) -> Counter:
    """Count identical (rule set, label) pairs: the URLs share only a few dozen rule sets."""
    counts = Counter()
    for url in benign:
        counts[(features(url, extra), 0)] += 1
    for url in phishing:
        counts[(features(url, extra), 1)] += 1
    return counts

def train(benign: list, phishing: list, epochs: int=5000, lr: float=0.5, l2: float=0.001,
          extra: dict=None, counts: Counter=None) -> dict:
    counts = counts or group(benign, phishing, extra)
    rules = sorted({rule for (fired, _) in counts for rule in fired})
    n = {label: sum (c for (_, y), c in counts.items() if y == label) or 1 for label in (0,1)}
    total = n[0] + n[1]
    # Balance the classes: otherwise "always legitimate" already looks accurate
    class_weight = {0: total / (2 * n[0]), 1: total / (2 * n[1])}

    w = dict.fromkeys(rules, 0.0)
    b = 0.0
    for _ in range (epochs):
        grad_w = dict.fromkeys(rules, 0.0)
        grad_b = 0.0
        for (fired, y), count in counts.items():
            err = (sigmoid(b + sum(w[r] for r in fired)) - y) * class_weight[y] * count
            grad_b += err
            for r in fired:
                grad_w[r] += err
        b -= lr * grad_b / total
        for r in rules:
            w[r] -= lr * (grad_w[r] / total + l2 * w[r])
    return {"bias": b, "weights": w}

def pick_threshold(scores: list, max_rate: float) -> int:
    """Smallest threshold whose share of scores at or above it does not exceed max_rate."""
    for t in range(1, 101):
        if sum (1 for s in scores if s>=t) / max(len(scores), 1) <= max_rate:
            return t
    return 101 # no threshold meets the target: never warn at this level

def thresholds_for(model: dict, benign_val_features:list, red_fpr: float, yellow_fpr: float,
                  min_red: int, min_yellow:int) -> dict:
    scores = [weighted_score(model, f) for f in benign_val_features]
    # Floors: a red warning blocks the page, so it must never fire below min_red
    red = max(pick_threshold(scores, red_fpr), min_red)
    yellow = min(max(pick_threshold(scores, yellow_fpr), min_yellow), red)
    return {"red": red, "yellow": yellow}

def calibrate(benign_train: list, phish_train: list, benign_val: list, phish_val: list,
              red_fpr: float = 0.0005, yellow_fpr : float = 0.005, min_red: int = 70,
              min_yellow: int = 40, l2_grid: tuple = (0.01, 0.001, 0.0001, 0.00001),
              extra: dict = None) -> dict:
    """Train one model per L2 strength, pick thresholds on the benign validation split, and keep
    the model that detects the most validation phishing. The test split is never touched."""
    counts = group(benign_train, phish_train, extra)
    benign_val_f = [features(u,extra) for u in benign_val]
    phish_val_f = [features(u, extra) for u in phish_val]
    best = None
    for l2 in l2_grid:
        model = train(benign_train, phish_train, l2=l2, counts=counts)
        model["thresholds"] = thresholds_for(model, benign_val_f, red_fpr, yellow_fpr, min_red, min_yellow)
        caught = sum(1 for f in phish_val_f if weighted_score(model, f) >= model["thresholds"]["yellow"])
        model["l2"] = l2
        model["val_recall_yellow"] = caught / max(len(phish_val_f), 1)
        if best is None or model["val_recall_yellow"] > best["val_recall_yellow"]:
            best = model
    best["targets"] = {"red_fpr": red_fpr, "yellow_fpr": yellow_fpr}
    return best


def save(model: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(model, f, ensure_ascii=False, indent=4, sort_keys=True)
        f.write("\n")