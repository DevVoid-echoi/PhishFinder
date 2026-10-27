"""Tests for the framework-free API core."""
import threading

import pytest

from app.api_core import TTLCache, domain_reputation, normalize_host


@pytest.mark.parametrize("raw, host", [
    ("Shop.Example.VN.", "shop.example.vn"),
    ("  vcb-xacthuc.com ", "vcb-xacthuc.com"),
    ("xn--mm-fmcb.vn", "xn--mm-fmcb.vn"),
    ("evil.xn--p1ai", "evil.xn--p1ai"),
])
def test_normalize_host_accepts(raw, host):
    assert normalize_host(raw) == host

@pytest.mark.parametrize("bad", [
    "https://a.com/x", "a.com/path", "a.com?token=1", "user@a.com", "a.com:8080",
    "1.2.3.4", "::1", "localhost", "a b.com", "mоmо.vn", "-bad.com", "a..com", "", "a" * 250 + ".com",
])
def test_normalize_host_rejects(bad):
    with pytest.raises(ValueError):
        normalize_host(bad)

def test_cache_expired():
    now = [0]
    c = TTLCache(ttl_seconds=10, clock=lambda: now[0])
    c.set("k", 1)
    assert c.get("k") == 1
    now[0] = 11
    assert c.get("k") is None

def test_cache_drops_oldest_when_full():
    c = TTLCache(max_items=2)
    c.set("a", 1)
    c.set("b", 2)
    c.set("c", 3)
    assert c.get("a") is None
    assert (c.get("b"), c.get("c")) == (2, 3)

def test_cache_is_thread_safe():
    c = TTLCache(max_items=50)

    def write(start):
        for i in range(2000):
            c.set(f"{start}-{i}", i)
            c.get(f"{start}-{i-1}")

    threads = [threading.Thread(target=write, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(c._data) <= 50

@pytest.fixture
def caches():
    return TTLCache(), TTLCache()

def test_reputation_caches_and_survives_errors(caches):
    calls = []

    def age_fn(domain):
        calls.append(domain)
        return 35, "Domain was registered 3 days ago"

    def tls_fn(host):
        raise TimeoutError

    r1 = domain_reputation("login.vcb-xacthuc.com", age_fn, tls_fn, *caches)
    r2 = domain_reputation("login.vcb-xacthuc.com", age_fn, tls_fn, *caches)

    assert calls == ["vcb-xacthuc.com"]
    assert[x["rule"] for x in r1["reasons"]] == ["domain_age"]
    assert (r1["cached"], r2["cached"]) == (False, True)

def test_domain_age_is_shared_across_subdomains(caches):
    calls = []

    def age_fn(domain):
        calls.append(domain)
        return None

    domain_reputation("a.vcb-xacthuc.com", age_fn, lambda h: None, *caches)
    domain_reputation("b.vcb-xacthuc.com", age_fn, lambda h: None, *caches)

    assert calls == ["vcb-xacthuc.com"]

def test_failed_check_is_logged(caches, caplog):
    def broken(args):
        raise KeyError("boom")

    domain_reputation("example.com", broken, lambda h: None, *caches)
    assert "check domain_age failed" in caplog.text
    assert "example.com" not in caplog.text