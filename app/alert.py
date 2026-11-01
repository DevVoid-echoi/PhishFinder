"""SOC alerts: turn an analysis result into an alert a SIEM can ingest.

Alerts are written as JSON Lines (one JSON object per line), which Wazuh and
Filebeat can tail directly. Run: python -m app.alert URL [URL ...]
"""
import ipaddress
import json
import uuid
from datetime import datetime, timezone

SEVERITY = {"dangerous": "high", "suspicious": "medium", "likely_safe": "low"}

# MITRE ATT&CK techniques for each place a link can be found
MITRE = {
    "url": [{"id": "T1566.002", "name": "Phishing: Spearphishing Link"}],
    "email": [{"id": "T1566", "name": "Phishing"}],
}
IMPERSONATION = {"id": "T1656", "name": "Impersonation"}
IMPERSONATION_RULES = {"check_lookalike", "check_display_name"}

ACTIONS = {
    "high": ["Block the domain or URL on the proxy or DNS filter",
             "Search other mailboxes for the same email or link",
             "Check whether any user clicked the link or entered credentials"],
    "medium": ["Review manually before blocking"],
    "low": ["No action needed; log only"],
}


def observable(value: str) -> dict:
    """Label a host as an IP address or a domain."""
    try:
        ipaddress.ip_address(value)
        return {"type": "ip", "value": value}
    except ValueError:
        return {"type": "domain", "value": value}


def to_alert(result: dict, source: str = "url", observables: list = None) -> dict:
    """Raises ValueError for an error result: there is nothing to alert on."""
    if "error" in result:
        raise ValueError(f"Cannot build an alert from an error result: {result['error']}")
    if source not in MITRE:
        raise ValueError(f"Unknown source: {source}")

    severity = SEVERITY[result["level"]]
    reasons = result.get("reasons", [])
    techniques = list(MITRE[source])
    if any(r["rule"] in IMPERSONATION_RULES for r in reasons):
        techniques.append(IMPERSONATION)

    if observables is None:
        observables = [{"type": "url", "value": result["url"]}]
        if result.get("domain"):
            observables.append(observable(result["domain"]))

    return {
        "alert_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "title": f"PhishFinder: possible phishing {source} ({severity})",
        "source": source,
        "severity": severity,
        "risk_score": result.get("score"),  # None when no score exists (user reports)
        "status": "new",
        "mitre_attack": techniques,
        "observables": observables,
        "evidence": [f"[{r['points']}] {r['reason']}" for r in reasons],
        "recommended_actions": list(ACTIONS[severity]),
    }


def write_alert(alert: dict, path: str = "alerts.jsonl") -> None:
    """Append one alert as one line."""
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    import sys

    from app.scorer import analyze

    for link in sys.argv[1:]:
        try:
            print(json.dumps(to_alert(analyze(link)), ensure_ascii=False, indent=4))
        except ValueError as e:
            print(f"{link}: {e}", file=sys.stderr)
