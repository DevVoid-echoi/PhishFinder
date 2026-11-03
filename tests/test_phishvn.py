"""Tests for the PhishVN loader. A small CSV is written under tmp_path."""
import csv

from app.evaluation import load_phishvn

COLUMNS = ["label", "source", "scenario", "collected_at", "split", "url", "tier"]
ROWS = [
    ["phishing", "tinnhiemmang", "bank", "18/02/2025", "test", "vcb-xacthuc.com", "gold"],
    ["phishing", "tinnhiemmang", "other", "03/11/2021", "train", "http://x.top/login", "silver"],
    ["phishing", "chongluadao", "other", "", "train", "old.example", "bronze"],
    ["benign", "tinnhiem_web", "other", "", "val", "mst.gov.vn", "gold"],
]


def write(tmp_path):
    path = tmp_path / "dataset_url.csv"
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(COLUMNS)
        w.writerows(ROWS)
    return path


def test_bronze_is_skipped(tmp_path):
    assert [r["url"] for r in load_phishvn(write(tmp_path))] == [
        "http://vcb-xacthuc.com/", "http://x.top/login", "http://mst.gov.vn/"]

def test_fields(tmp_path):
    first = load_phishvn(write(tmp_path))[0]
    assert first == {"url": "http://vcb-xacthuc.com/", "label": "phishing", "split": "test",
                     "source": "tinnhiemmang", "scenario": "bank", "date": "2025-02-18"}

def test_rows_without_a_date(tmp_path):
    assert load_phishvn(write(tmp_path))[-1]["date"] == ""

def test_tiers_can_be_chosen(tmp_path):
    assert len(load_phishvn(write(tmp_path), tiers=("bronze",))) == 1
