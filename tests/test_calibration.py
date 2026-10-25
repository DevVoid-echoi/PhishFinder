"""Tests for weight learning, threshold selection and weighted scoring (synthetic data)."""
import random

import pytest

from app import calibrate as cal
from app import lists
from app.evaluation import evaluate, random_split
from app.scorer import analyze, sigmoid, weighted_score

WORDS = ["sach", "nha", "xe", "hoc", "banh", "may", "tin", "tuc", "game", "du", "lich", "an", "uong",
         "the", "thao", "phim", "nhac", "cong", "nghe", "suc", "khoe", "thoi", "trang", "bao", "moi"]
BRANDS = ["vietcombank", "techcombank", "shopee", "momo", "zalopay", "agribank", "vcb"]
TRICKS = ["-xacthuc", "-nhanqua", "-hotro", "-khoa-tai-khoan", "-login", "-uudai"]


def synthetic(n_benign=2000, n_phish=400, seed=1):
    """Synthetic URLs to test the pipeline; never used to measure real accuracy."""
    rnd = random.Random(seed)
    benign = []

    for _ in range(n_benign):
        name = "".join(rnd.sample(WORDS, 2))
        tld = rnd.choice(["com", "vn", "com.vn", "net", "org", "shop", "xyz"])
        benign.append(f"http://{name}.{tld}/")
    phish = []

    for _ in range(n_phish):
        brand = rnd.choice(BRANDS)
        tld = rnd.choice(["com", "xyz", "top", "vip", "online"])
        host = rnd.choice([f"{brand}{rnd.choice(TRICKS)}.{tld}",
                           f"{brand}.vn.{rnd.choice(WORDS)}.{tld}"
                           f"{brand.replace('o', '0')}.{tld}"])
        phish.append(f"http://{host}/")

    return benign, phish

@pytest.fixture(scope="module")
def data():
    benign, phish = synthetic()
    b_train, b_rest = random_split(benign, 0.5)
    b_val, b_test = random_split(b_rest, 0.5)
    p_train, p_rest = random_split(phish, 0.5)
    p_val, p_test = random_split(p_rest, 0.5)
    return b_train, b_val, b_test, p_train, p_val, p_rest

@pytest.fixture(scope="module")
def model(data):
    b_train, b_val, _, p_train, p_val, _ = data
    return cal.calibrate(b_train, p_train, b_val, p_val, red_fpr=0.005, yellow_fpr=0.02)

@pytest.mark.parametrize("z", [-1000, -20, 0, 20, 1000])
def test_sigmoid_is_stale(z):
    assert -0.0 <= sigmoid(z) <=(1.0)

def test_identical_rule_sets_are_grouped():
    counts = cal.group(["http://a.com/", "http://b.com/"], ["http://vietcombank-xacthuc.com/"])
    assert sum(counts.values()) == 3
    assert len(counts) == 2

def test_lookalike_weight_is_strong(model):
    assert model["weights"]["check_lookalike"] > 1.0

def test_thresholds_respect_floors_and_order(model):
    t = model["thresholds"]
    assert t["red"] >= 70
    assert 40 <= t["yellow"] < t["red"]

def test_thresholds_meet_target_on_validation(data, model):
    _, b_val, _, _, _, _ = data
    scores = [weighted_score(model, cal.features(u)) for u in b_val]
    assert sum(s >= model["thresholds"]["red"] for s in scores) / len(scores) <= 0.005

def test_calibrated_model_on_unseen_data(data, model):
    _, _, b_test, _, _, p_test = data
    r = evaluate(b_test, p_test, lambda u: analyze(u, use_blacklist=False, weights=model))
    assert r["fpr_red"] <= 0.02
    assert r["recall_any"] >= 0.8

def test_no_threshold_meets_an_imposible_target():
    assert cal.pick_threshold([100] * 10, max_rate=0.0) == 101

def test_empty_weights_force_hand_written_points(model):
    url = "http://vietcombank-xacthuc.com/dang-nhap"
    assert analyze(url, weights={})["score"] == 70
    assert analyze(url, weights=model)["score"] != 70

def test_blacklist_overrides_the_model(monkeypatch, model):
    monkeypatch.setattr(lists, "BLACKLIST", {"quiet-demo.com"})
    r = analyze("https://quiet-demo.com", weights=model)
    assert (r["score"], r["level"]) == (100, "dangerous")

def test_server_reason_raises_the_score():
    benign = [f"http://shop{i}.vn/" for i in range(200)]
    phish = [f"http://khuyenmai{i}.vn/" for i in range(100)]
    extra = {u: {"domain_age"} for u in phish} # pretend RDAP showed every phishing domain is new
    model = cal.train(benign, phish, extra=extra)
    assert model["weights"]["domain_age"] > 1.0
    model["thresholds"] = {"red": 70, "yellow": 40}
    young = [{"rule": "domain_age", "points": 35, "reason": "Domain was registered 3 days ago"}]
    assert (analyze("https://abc.vn", weights=model, extra_reasons=young)["score"] > analyze("https://abc.vn", weights=model)["score"])

def test_level_uses_the_model_threshold():
    # Score 50 sits between the default thresholds (60/30) and the model's (95/90)
    model = {"bias": 0.0, "weights": {}, "thresholds": {"red": 95, "yellow": 90}}
    r = analyze("https://example.com", weights=model)
    assert r["score"] == 50
    assert r["level"] == "likely_safe"