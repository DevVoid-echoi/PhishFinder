from app.heuristics import ALL_CHECKS
from app.lists import check_blacklist, is_allowlisted, is_verified
from app.lookalike import check_lookalike
from app.parser import parse_url


def score_to_level(score: int) -> str:
    if score >= 60:
        return "dangerous"
    if score >= 30:
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

def analyze(raw_url: str, use_blacklist: bool = True) -> dict:
    u = parse_url(raw_url)
    if not u.hostname:
        return {"url": raw_url, "error": "Could not extract a hostname from this URL"}

    reasons = run_rules(u)
    hit = check_blacklist(u) if use_blacklist else None
    if hit:
        reasons.append({"rule": "check_blacklist", "points": hit[0], "reason": hit[1]})
    score = min(sum(r["points"] for r in reasons), 100)

    return {
        "url": raw_url,
        "domain": u.registered_domain,
        "score": score,
        "level": score_to_level(score),
        "reasons": sorted(reasons, key=lambda r: -r["points"]),
    }

if __name__ == "__main__":
    import json
    import sys

    for link in sys.argv[1:]:
        print(json.dumps(analyze(link), ensure_ascii=False, indent=4))