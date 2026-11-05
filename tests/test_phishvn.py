"""Tests for the PhishVN loader. A small CSV is written under tmp_path."""
import csv

from app.evaluation import load_phishvn, phishvn_splits

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


def row(label, split, url, date=""):
    return {"label": label, "split": split, "url": url, "date": date, "source": "", "scenario": ""}

def test_phishvn_splits_hold_out_the_newest_domains():
    rows = [row("phishing", "train", f"http://old{i}.com/", f"2021-01-{i + 1:02d}") for i in range(8)]
    rows += [row("phishing", "train", "http://new.com/", "2024-05-01"),
             row("phishing", "train", "http://a.new.com/", "2024-06-01"),
             row("phishing", "train", "http://old0.com/x", "2024-07-01"),  # same domain as an old row
             row("phishing", "test", "http://t.com/", "2025-01-01"),
             row("benign", "val", "http://ok.vn/")]
    s = phishvn_splits(rows, val_ratio=0.2)
    assert s["phish_val"] == ["http://old0.com/", "http://new.com/", "http://a.new.com/", "http://old0.com/x"]
    assert "http://old0.com/" not in s["phish_train"]  # a domain never sits on both sides
    assert len(s["phish_train"]) == 7
    assert (s["phish_test"], s["benign_val"]) == (["http://t.com/"], ["http://ok.vn/"])

def test_phishvn_splits_without_phishing():
    assert phishvn_splits([row("benign", "train", "http://ok.vn/")])["phish_train"] == []
