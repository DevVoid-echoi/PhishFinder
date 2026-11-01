"""Tests for SOC alerts."""
import json

import pytest

from app.alert import to_alert, write_alert
from app.scorer import analyze


def test_lookalike_is_high_with_impersonation():
    a = to_alert(analyze("http://vietcombank-xacthuc.com/dangnhap"))
    assert a["severity"] == "high"
    assert a["risk_score"] == 70
    assert [t["id"] for t in a["mitre_attack"]] == ["T1566.002", "T1656"]
    assert {"type": "domain", "value": "vietcombank-xacthuc.com"} in a["observables"]
    assert a["evidence"][0].startswith("[40] ")

def test_ip_host_is_an_ip_observable_without_impersonation():
    a = to_alert(analyze("http://1.2.3.4/login"))
    assert a["severity"] == "medium"
    assert {"type": "ip", "value": "1.2.3.4"} in a["observables"]
    assert [t["id"] for t in a["mitre_attack"]] == ["T1566.002"]

def test_likely_safe_is_low():
    a = to_alert(analyze("https://shopee.vn"))
    assert a["severity"] == "low"
    assert a["recommended_actions"] == ["No action needed; log only"]

def test_email_source_uses_t1566():
    a = to_alert(analyze("https://shopee.vn"), source="email")
    assert [t["id"] for t in a["mitre_attack"]] == ["T1566"]

@pytest.mark.parametrize("result", [analyze(":::"), {"url": "x", "error": "boom"}])
def test_error_results_raise(result):
    with pytest.raises(ValueError):
        to_alert(result)

def test_unknown_source_raises():
    with pytest.raises(ValueError):
        to_alert(analyze("https://shopee.vn"), source="sms")

def test_actions_are_copies():
    a = to_alert(analyze("https://shopee.vn"))
    a["recommended_actions"].append("changed")
    assert to_alert(analyze("https://shopee.vn"))["recommended_actions"] == ["No action needed; log only"]

def test_alert_ids_are_unique():
    assert to_alert(analyze("https://shopee.vn"))["alert_id"] != to_alert(analyze("https://shopee.vn"))["alert_id"]

def test_jsonl_one_alert_per_line(tmp_path):
    path = tmp_path / "alerts.jsonl"
    write_alert(to_alert(analyze("https://shopee.vn")), path)
    write_alert(to_alert(analyze("http://sh0pee.top")), path)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["severity"] for line in lines] == ["low", "high"]

def test_jsonl_keeps_vietnamese_text(tmp_path):
    path = tmp_path / "alerts.jsonl"
    alert = to_alert({"url": "x.vn", "domain": "x.vn", "score": 0, "level": "suspicious",
                      "reasons": [{"rule": "user_report", "points": 0, "reason": "Trang lừa đảo"}]})
    write_alert(alert, path)
    assert "Trang lừa đảo" in path.read_text(encoding="utf-8")
