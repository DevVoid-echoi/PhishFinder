"""Combine rule findings into a 0-100 risk score and a warning level.

Two modes:
- no data/weights.json: add the hand-written points (steps 3-5)
- data/weights.json (step 9): logistic regression on the fired rules, score = P(phishing)
"""
import json
import math
from pathlib import Path

from app.heuristics import ALL_CHECKS
from app.lists import check_blacklist, is_allowlisted, is_verified
from app.lookalike import check_lookalike
from app.parser import parse_url

WEIGHTS_FILE = Path(__file__).resolve().parent.parent / "data" / "weights.json"


def load_weights(path: Path=WEIGHTS_FILE):
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)

WEIGHTS = load_weights()

def sigmoid(z: float) -> float:
    """Numerically stable: math.exp never overflows, whatever the sign of z."""
    if z >= 0:
        return 1 / (1 + math.exp(-z))
    e = math.exp(z)
    return e / (1+e)

def weighted_score(model: dict, rules: set) -> int:
    z = model["bias"] + sum(model["weights"].get(r, 0.0) for r in rules)
    return round (100 * sigmoid(z))

def score_to_level(score: int, red: int = 60, yellow: int = 30) -> str:
    if score >= red:
        return "dangerous"
    if score >= yellow:
        return "suspicious"
    return "likely_safe"

def run_rules(u) -> list:
    """Run the heuristic rules (not the blacklist) and return their findings."""
    if is_verified(u.registered_domain):
        return []
    findings = []
    for check in ALL_CHECKS:
        result = check(u)
        if result:
            findings.append({"rule": check.__name__, "points": result[0], "reason": result[1]})
    # Popular (allowlisted) domains skip the lookalike checks on their own name only
    result = check_lookalike(u, check_domain=not is_allowlisted(u.registered_domain))
    if result:
        findings.append({"rule": "check_lookalike", "points": result[0], "reason": result[1]})
    return findings

def analyze(raw_url: str, use_blacklist: bool = True, weights: dict = None,
            extra_reasons: list = None) -> dict:
    """weights: None uses data/weights.json if present, {} forces the hand-written points.
    extra_reasons: findings returned by the server (domain age, TLS), same shape as reasons."""
    u = parse_url(raw_url)
    if not u.hostname:
        return {"url": raw_url, "error": "Could not extract a hostname from this URL"}
    model = WEIGHTS if weights is None else weights

    reasons = run_rules(u) + list(extra_reasons or [])
    hit = check_blacklist(u) if use_blacklist else None
    if hit:
        # Reported phishing: always dangerous, whatever the model says
        reasons.append({"rule": "check_blacklist", "points": hit[0], "reason": hit[1]})
        score, level = 100, "dangerous"
    elif model:
        score = weighted_score(model, {r["rule"] for r in reasons})
        level = score_to_level(score, **model["thresholds"])
    else:
        score = min(sum(r["points"] for r in reasons), 100)
        level = score_to_level(score)

    return {
        "url": raw_url,
        "domain": u.registered_domain,
        "score": score,
        "level": level,
        "reasons": sorted(reasons, key=lambda r: -r["points"]),
    }

if __name__ == "__main__":
    import json
    import sys

    for link in sys.argv[1:]:
        print(json.dumps(analyze(link), ensure_ascii=False, indent=4))