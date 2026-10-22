from app.heuristics import ALL_CHECKS
from app.lists import check_blacklist
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
    findings = []
    for check in ALL_CHECKS + [check_lookalike]:
            result = check(u)
            if result:
                points, reason = result
                findings.append({"rule": check.__name__, "points": points, "reason": reason})
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