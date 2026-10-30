"""Follow redirects (step 7b) and download pages (step 7c), with SSRF protection on EVERY hop.

A valid bit.ly link can redirect to http://169.254.169.254/, the cloud metadata service
that hands out the server's credentials. So every hop is resolved and checked again, and
the request goes to the checked IP (hostname kept for Host and SNI), never to the name.
"""
import http.client
import socket
import time
from typing import override
from urllib.parse import urljoin, urlsplit

from app.reputation import resolve_public_ips

REDIRECT_CODES = {301, 302, 303, 307, 308}
ALLOWED_PORTS = (80, 443)
# A real browser: many phishing pages show harmless content to bots (cloaking)
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/130.0 Safari/537.36")

class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, ip, **kwargs):
        super().__init__(host, **kwargs)
        self._ip = ip

    @override
    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)

class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, ip, **kwargs):
        super().__init__(host, **kwargs)
        self._ip = ip

    @override
    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)

def _request(p, ip: str, method: str, timeout: float, max_bytes: int):
    conn_cls = _PinnedHTTPSConnection if p.scheme == "https" else _PinnedHTTPConnection
    conn = conn_cls(p.hostname, ip, port=p.port, timeout=timeout)
    path = (p.path or "/") + (f"?{p.query}" if p.query else "")
    try:
        conn.request(method, path, headers={"User-Agent": USER_AGENT, "Accept": "text/html"})
        resp = conn.getresponse()
        body = b""
        if method == "GET" and resp.status not in REDIRECT_CODES:
            body = resp.read(max_bytes + 1) # never read past the limit
        return resp.status, resp.getheader("Location"), resp.getheader("Content-Type") or "", body
    finally:
        conn.close()

def follow(url: str, method: str = "HEAD", max_hops: int = 5, timeout: float = 5.0,
           deadline: float = 15.0, max_bytes: int = 1_000_000,
           resolve=resolve_public_ips, ports=ALLOWED_PORTS) -> dict:
    """method="HEAD": only find the final page (expand a short link). method="GET": also download it."""
    chain = [url]
    stop_at = time.monotonic() + deadline
    for _ in range(max_hops + 1):
        p = urlsplit(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            return {"chain": chain, "final": None, "error": f"Unsupported scheme: {p.scheme or 'none'}"}
        if (p.port or (443 if p.scheme == "https" else 80)) not in ports:
            return {"chain": chain, "final": None, "error": f"Blocked: port {p.port} is not allowed"}
        # Check AGAIN at every hop: a short link may redirect to an internal address
        ips = resolve(p.hostname)
        if not ips:
            return {"chain": chain, "final": None,
                    "error": f"Blocked: {p.hostname} is internal or does not resolve"}
        remaining = stop_at - time.monotonic()
        if remaining <= 0:
            return {"chain": chain, "final": None, "error": f"Gave up after {deadline:.0f} s"}
        try:
            status, location, ctype, body = _request(p, ips[0], method, min(timeout, remaining), max_bytes) 
        except OSError as e:
            return {"chain": chain, "final": None, "error": f"Connection failed: {type(e).__name__}"}
        if status in REDIRECT_CODES and location:
            if len(chain) > max_hops:
                break
            url = urljoin(url, location)
            chain.append(url)
            continue
        result = {"chain": chain, "final": url, "error": None, "status": status}
        if method == "GET":
            if len(body) > max_bytes:
                return {**result, "error": "Page too large"}
            if "html" not in ctype.lower():
                return {**result, "error": f"Not an HTML page ({ctype or 'no content type'})"}
            result["html"] = body.decode("utf-8", errors="replace")
        return result
    return {"chain": chain, "final": None, "error": f"More than {max_hops} redirects"}
