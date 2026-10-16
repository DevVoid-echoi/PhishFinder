from app.heuristics import ALL_CHECKS
from app.lookalike import check_lookalike
from app.parser import parse_url


def analyze(raw_url: str) -> dict:
    u = parse_url(raw_url)
    if not u.hostname:
        return {"url": raw_url, "error": "Could not extract a hostname from this URL"}

    reasons = []
    total = 0
    for check in ALL_CHECKS + [check_lookalike]:
        result = check(u)
        if result:
            points, reason = result
            total += points
            reasons.append({"rule": check.__name__, "points": points, "reason": reason})

    score = min(total, 100)
    if score >= 60:
        level = "dangerous"
    elif score >= 30:
        level = "suspicious"
    else:
        level = "likely_safe"

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