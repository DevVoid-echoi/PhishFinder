from app.evaluation import fresh_split


def test_first_collection_day_is_old():
    old, fresh = fresh_split([("a", "2026-10-21"), ("c", "2026-10-23"), ("b", "2026-10-21"), ("d", "2026-10-22")])
    assert old == ["a", "b"]
    assert fresh == ["c", "d"]