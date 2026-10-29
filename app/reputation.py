"""TLS certificate check, with SSRF protection.

This is the first code that connects to a server the attacker controls, so:
- every address the name resolves to must be public; one internal address
  (127.0.0.1, 10.x, 169.254.169.254, 100.64.x ...) and the host is skipped
- the connection goes to the address that was checked, not to the name
  again, so a DNS answer cannot change between the check and the connect
"""
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional, Tuple

PORT = 443
TIMEOUT = 5.0
MAX_ADDRESSES = 2

Finding = Optional[Tuple[int, str]]


def is_public_address(ip: str) -> bool:
    addr= ipaddress.ip_address(ip)
    return addr.is_global and not addr.is_multicast

def resolve_public_ips(hostname: str) -> list:
    """All addresses of hostname, or [] if any of them is not public."""
    try:
        ip = ipaddress.ip_address(hostname) # an IP literal needs no DNS lookup
    except ValueError:
        pass
    else:
        return [str(ip)] if is_public_address(str(ip)) else []
    try:
        infos = socket.getaddrinfo(hostname, PORT, type=socket.SOCK_STREAM)
    except(socket.gaierror, UnicodeError):
        return []
    ips = sorted({info[4][0] for info in infos})
    if not ips or not all(is_public_address(ip) for ip in ips):
        return []
    return ips

def fetch_cert(hostname: str, ip: str) -> dict:
    """TLS handshake with ip, validating the certificate for hostname (SNI)."""
    ctx = ssl.create_default_context()
    with socket.create_connection((ip, PORT), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
            return tls.getpeercert()

def evaluate_cert(cert: dict, now: datetime = None) -> Finding:
    """Kept separate from the network code so it can be tested offline."""
    now = now or datetime.now(timezone.utc)
    issued = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc)
    age_days = (now - issued).days
    issuer = {key: value for rdn in cert.get("issuer", ()) for key, value in rdn}
    if 0 <= age_days < 7:
        return 20, f"TLS certificate was issued {age_days} days ago by {issuer.get('organizationName', 'an unknown issuer')}"
    return None

def check_tls(hostname: str) -> Finding:
    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass
    for ip in resolve_public_ips(hostname)[:MAX_ADDRESSES]:
        try:
            cert = fetch_cert(hostname, ip)
        except ssl.SSLCertVerificationError as e:
            return 30, f"Invalid TLS certificate: {getattr(e, 'verify_message', None) or 'verification failed'}"
        except (OSError, ssl.SSLError, ValueError):
            continue
        return evaluate_cert(cert)
    return None

if __name__ == "__main__":
    import sys

    for host in sys.argv[1:]:
        print(host, check_tls(host))