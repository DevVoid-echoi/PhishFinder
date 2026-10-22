import pytest

from app import lists


@pytest.fixture(autouse=True)
def empty_lists(monkeypatch):
    """Tests never see downloaded data: every list starts empty in every test."""
    for name in ("BLACKLIST", "BLACKLIST_URLS", "ALLOWLIST", "VERIFIED"):
        monkeypatch.setattr(lists, name, set())

@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Fail loudly if code under test tries to reach the internet."""
    def blocked(*args, **kwargs):
        raise RuntimeError("network access is note allowed in tests")

    monkeypatch.setattr("urllib.request.urlopen", blocked)