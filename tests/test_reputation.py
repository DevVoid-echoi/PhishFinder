"""Tests for the TLS check and its SSRF protection. No test reaches the network."""
import socket
import ssl
from datetime import datetime, timedelta, timezone

import pytest

from app import reputation
from app.reputation import check_tls, evaluate_cert, is_public_address, resolve_public_ips

NOW = datetime(2026, 10, 22, tzinfo=timezone.utc)
ISSUER = ((("organizationName", "Let's Encrypt"),),)


def fake_getaddrinfo(*ips):
    def getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]
    return getaddrinfo

@pytest.mark.parametrize("ip, public", [
    ("8.8.8.8", True),
    ("2606:4700:4700::1111", True),
    ("127.0.0.1", False),
    ("10.0.0.5", False),
    ("192.168.1.1", False),
    ("169.254.169.254", False),  # cloud metadata service
    ("100.64.0.1", False),       # carrier-grade NAT, passed the guide's check
    ("0.0.0.0", False),
    ("224.0.0.1", False),        # multicast
    ("::1", False),
    ("::ffff:127.0.0.1", False),  # IPv4-mapped loopback
])
def test_is_public_address(ip, public):
    assert is_public_address(ip) is public

def test_resolve_keeps_only_fully_public_hosts(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo("8.8.8.8", "1.1.1.1"))
    assert resolve_public_ips("example.com") == ["1.1.1.1", "8.8.8.8"]

def test_one_internal_address_rejects_the_host(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo("8.8.8.8", "169.254.169.254"))
    assert resolve_public_ips("example.com") == []

def test_unresolvable_host(monkeypatch):
    def fail(*args, **kwargs):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    assert resolve_public_ips("example.com") == []

def test_connects_to_the_checked_ip_not_the_name(monkeypatch):
    calls = []

    def create_connection(address, timeout=None):
        calls.append(address)
        raise OSError("stop before the handshake")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo("8.8.8.8"))
    monkeypatch.setattr(socket, "create_connection", create_connection)
    assert check_tls("example.com") is None
    assert calls == [("8.8.8.8", 443)]

@pytest.mark.parametrize("issued, points", [
    ("Oct 22 00:00:00 2026 GMT", 20),
    ("Oct 16 00:00:00 2026 GMT", 20),
    ("Oct 15 00:00:00 2026 GMT", None),
    ("Oct 30 00:00:00 2026 GMT", None),  # issued in the future: bad data
])
def test_evaluate_cert(issued, points):
    finding = evaluate_cert({"notBefore": issued, "issuer": ISSUER}, now=NOW)
    assert(finding[0] if finding else None) == points

def test_new_cert_reason_names_the_issuer():
    _, reason = evaluate_cert({"notBefore": "Oct 21 00:00:00 2026 GMT", "issuer": ISSUER}, now = NOW)
    assert "Let's Encrypt" in reason

def test_invalid_certificate_is_reported(monkeypatch):
    def fetch_cert(hostname, ip):
        error = ssl.SSLCertVerificationError("certificate verify failed")
        error.verify_message = "certificate has expired"
        raise error

    monkeypatch.setattr(reputation, "resolve_public_ips", lambda host: ["8.8.8.8"])
    monkeypatch.setattr(reputation, "fetch_cert", fetch_cert)
    assert check_tls("example.com") == (30, "Invalid TLS certificate: certificate has expired")

def test_unreachable_address_falls_back_to_the_next(monkeypatch):
    def fetch_cert(hostname, ip):
        if ip == "1.1.1.1":
            raise TimeoutError()
        issued = datetime.now(timezone.utc) - timedelta(days=4)
        return {"notBefore": issued.strftime("%b %d %H:%M:%S %Y GMT"), "issuer": ISSUER}

    monkeypatch.setattr(reputation, "resolve_public_ips", lambda host: ["1.1.1.1", "8.8.8.8"])
    monkeypatch.setattr(reputation, "fetch_cert", fetch_cert)
    assert check_tls("example.com") == (20, "TLS certificate was issued 4 days ago by Let's Encrypt")

def test_internal_or_ip_hosts_are_never_contacted(monkeypatch):
    def unexpected(hostname , ip):
        raise AssertionError("must not connect")

    monkeypatch.setattr(reputation, "resolve_public_ips", lambda host: [])
    monkeypatch.setattr(reputation, "fetch_cert", unexpected)
    assert check_tls("127.0.0.1") is None
    assert check_tls("localhost") is None
