"""Tests for server-signal collection: conversion to calibration features and sampling (offline)."""
import csv

from app.evaluation import load_signals
from scripts.collect_signals import FIELDS, pick

ROWS = [
    {"url": "http://new.top/", "created": "2026-11-01", "tls": "none", "cert_issued": ""},
    {"url": "http://old.com/", "created": "2015-01-01", "tls": "valid", "cert_issued": "2026-09-01"},
    {"url": "http://badcert.com/", "created": "", "tls": "invalid", "cert_issued": ""},
    {"url": "http://freshcert.com/", "created": "2015-01-01", "tls": "valid", "cert_issued": "2026-11-02"},
    {"url": "http://halfyear.com/", "created": "2026-06-01", "tls": "valid", "cert_issued": "2026-06-01"},
]


def write(tmp_path):
    path = tmp_path / "signals.csv"
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for row in ROWS:
            w.writerow({"label": "phishing", "looked_up": "2026-11-04", "registered_domain": "", **row})
    return path


def test_signals_become_server_findings(tmp_path):
    assert load_signals(write(tmp_path)) == {
        "http://new.top/": {"domain_age"},
        "http://old.com/": set(),
        "http://badcert.com/": {"tls"},
        "http://freshcert.com/": {"tls"},
        "http://halfyear.com/": {"domain_age"},
    }

def test_missing_file_gives_no_signals(tmp_path):
    assert load_signals(tmp_path / "none.csv") == {}

def test_pick_skips_done_and_is_repeatable():
    urls = [f"http://{i}.com/" for i in range(10)]
    first = pick(urls, {"http://0.com/"}, 3, "2026-11-04")
    assert first == pick(urls, {"http://0.com/"}, 3, "2026-11-04")
    assert len(first) == 3 and "http://0.com/" not in first

def test_pick_takes_what_is_left():
    assert pick(["http://a.com/"], set(), 100, "2026-11-04") == ["http://a.com/"]
