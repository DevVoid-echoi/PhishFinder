"""Framework-free core of the production API, so it can be tested without FastAPI.

Privacy rule: the reputation endpoint accepts a hostname only, never a path or
query string, because those can carry reset tokens, emails or order numbers.
"""
import ipaddress
import logging
import re
import threading
import time

from app.parser import parse_url

log = logging.getLogger("phishfinder")

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")

def normalize_host(raw: str) -> str:
    """Accept one valid hostname only. Reject full URLs, IPs, ports, Unicode and odd characters."""
    host = raw.strip().lower().rstrip(".")
    if any(c in host for c in "/?#@:") or " " in host:
        raise ValueError("Send a hostname only, not a full URL")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("IP addressses are not looked up")
    if not HOST_RE.match(host):
        raise ValueError("Invalid hostname (Unicode names must be sent in punycode, xn--)")
    return host

class TTLCache:
    """In-memory cache with expiry, safe to use from FastAPI's worker threads."""
    def __init__(self, ttl_seconds: int = 6 * 3600, max_items: int = 10_000, clock=time.monotonic):
        self.ttl, self.max_items, self.clock = ttl_seconds, max_items, clock
        self._data = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            item = self._data.get(key)
            if item and self.clock() - item[0] < self.ttl:
                return item[1]
            self._data.pop(key, None)
            return None

    def set(self, key, value):
        with self._lock:
            self._data.pop(key, None)
            if len(self._data) >= self.max_items:
                self._data.pop(next(iter(self._data)))
            self._data[key] = (self.clock(), value)

def domain_reputation(host: str, age_fn, tls_fn, cache: TTLCache, age_cache: TTLCache) -> dict:
    """age_fn(registered_domain) and tls_fn(host) return (points, reason) or None.

    Domain age is cached per registered domain (one RDAP lookup serves every subdomain);
    the full result is cached per host.
    """
    cached = cache.get(host)
    if cached is not None:
        return {**cached, "cached": True}
    registered = parse_url(host).registered_domain

    age = age_cache.get(registered)
    if age is None:
        age = {"hit": _safe("domain_age", age_fn, registered)}
        age_cache.set(registered, age)

    reasons = []
    for rule, hit in (("domain_age", age["hit"]), ("tls", _safe("tls", tls_fn, host))):
        if hit:
            reasons.append({"rule": rule, "points": hit[0], "reason": hit[1]})
    result = {"host": host, "domain": registered, "reasons": reasons}
    cache.set(host, result)
    return {**result, "cached": False}

def _safe(rule: str, fn, arg):
    """An external service failing must not break the whole answer, but it must be visible"""
    try:
        return fn(arg)
    except Exception:
        log.exception("check %s failed", rule) # logs the error type, never the host
        return None
