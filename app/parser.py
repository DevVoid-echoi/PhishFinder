from dataclasses import dataclass
from urllib.parse import urlparse

import tldextract

_extract = tldextract.TLDExtract(include_psl_private_domains=True, suffix_list_urls=())


@dataclass
class ParsedURL:
    original: str
    scheme: str
    hostname: str
    path: str
    query: str
    registered_domain: str
    domain_name: str
    suffix: str
    subdomain: str


def parse_url(raw: str) -> ParsedURL:
    url = raw.strip()

    if "://" not in url:
        url = "http://" + url

    parts = urlparse(url)
    hostname = (parts.hostname or "").lower().rstrip(".")
    ext = _extract(hostname)
    if ext.domain and ext.suffix:
        registered_domain = f"{ext.domain}.{ext.suffix}"
    else:
        registered_domain = hostname

    return ParsedURL(
        original=raw,
        scheme=parts.scheme,
        hostname=hostname,
        path=parts.path,
        query=parts.query,
        registered_domain=registered_domain,
        domain_name=ext.domain or hostname,
        suffix=ext.suffix,
        subdomain=ext.subdomain,
    )