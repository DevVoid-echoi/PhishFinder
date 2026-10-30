"""Tests for following redirects safely (step 7b). A fake HTTP server runs on 127.0.0.1."""
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app import page_fetch
from app.api_core import normalize_short_url
from app.page_fetch import follow
from app.reputation import resolve_public_ips


class Handler(BaseHTTPRequestHandler):
    routes = {"/short": "/step2", "/step2": "/landing", "/loop": "/loop",
              "/metadata": "http://169.254.169.254/latest/meta-data/",
              "/rebind": "http://rebind.test/landing", "/port": "http://fake.test:6379/",
              "/js": "javascript:alert(1)"}

    def _answer(self, with_body):
        target = self.routes.get(self.path)
        if target:
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "image/png" if self.path == "/img" else "text/html; charset=utf-8")
        self.end_headers()
        if with_body:
            self.wfile.write(("<title>x</title>" + "a" * (5000 if self.path == "/big" else 10)).encode())

    def do_HEAD(self):
        self._answer(False)

    def do_GET(self):
        self._answer(True)

    def log_message(self, *args):
        pass

@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_port
    srv.shutdown()

@pytest.fixture
def local(monkeypatch, server):
    """Allow connections to the fake server only; "fake.test" resolves to it."""
    def create_connection(address, timeout=None, *args, **kwargs):
        assert address[0] == "127.0.0.1", f"unexpected connection to {address}"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # no DNS lookup involved
        sock.settimeout(timeout)
        sock.connect(address)
        return sock

    monkeypatch.setattr(socket, "create_connection", create_connection)
    ports = (80, 443, server)

    def resolve(host):
        return ["127.0.0.1"] if host == "fake.test" else resolve_public_ips(host)

    def run(path, **kwargs):
        return follow(f"http://fake.test:{server}{path}", resolve=resolve, ports=ports, **kwargs)

    return run

def test_expand_short_link(local, server):
    r = local("/short")
    assert r["final"] == f"http://fake.test:{server}/landing"
    assert len(r["chain"]) == 3

def test_redirect_to_metadata_is_blocked(local):
    r = local("/metadata")
    assert r["final"] is None
    assert "169.254.169.254" in r["error"]

def test_redirect_to_a_name_that_resolves_internally_is_blocked(local, monkeypatch):
    def getaddrinfo(host, port, *args, **kwargs): #rebind.test points at the loopback address
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    r = local("/rebind")
    assert r["final"] is None
    assert "rebind.test is internal" in r["error"]

def test_redirect_to_another_port_is_blocked(local):
    assert "port 6379" in local("/port")["error"]

def test_redirect_to_another_scheme_is_blocked(local):
    assert "Unsupported scheme" in local("/js")["error"]

def test_redirect_loop_stops(local):
    r = local("/loop", max_hops=3)
    assert r["final"] is None
    assert len(r["chain"]) == 4

def test_get_with_limits(local):
    assert "<title>" in local("/short", method="GET")["html"]
    assert local("/big", method="GET", max_bytes=1000)["error"] == "Page too large"
    assert "Not an HTML page" in local("/img", method="GET")["error"]

def test_default_resolver_blocks_localhost(server):
    assert follow(f"http://localhost:{server}/short")["final"] is None
    assert follow(f"http://127.0.0.1:{server}/short")["final"] is None

def test_https_connects_to_the_checked_ip(monkeypatch):
    calls = []

    def create_connection(address, *args, **kwargs):
        calls.append(address)
        raise OSError("stop before the TLS handshake")

    monkeypatch.setattr(socket, "create_connection", create_connection)
    r = follow("https://bit.ly/abc", resolve=lambda host: ["93.184.216.34"])
    assert calls == [("93.184.216.34", 443)]
    assert r["error"] == "Connection failed: OSError"

@pytest.mark.parametrize("raw", ["https://bit.ly/abc", " https://tinyurl.com/x2y "])
def test_short_url_accepts_known_shorteners(raw):
    assert normalize_short_url(raw) == raw.strip()

@pytest.mark.parametrize("bad", [
    "https://evil.com/abc", "javascript:alert(1)", "https://user@bit.ly/x", "https://bit.ly:8080/x",
    "ftp://bit.ly/x", "https://bit.ly/" + "a" * 200,
])
def test_short_url_rejects_everything_else(bad):
    with pytest.raises(ValueError):
        normalize_short_url(bad)