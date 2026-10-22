import pytest

from app import lists


@pytest.fixture(autouse=True)
def empty_lists(monkeypatch):
    """Tests never see downloaded data: every list starts empty in every test."""
    for name in ("BLACKLIST", "BLACKLIST_URLS", "ALLOWLIST", "VERIFIED"):
        monkeypatch.setattr(lists, name, set())