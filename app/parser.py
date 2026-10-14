from dataclasses import dataclass
from urllib.parse import urlparse

MULTI_PART_SUFFIXES = {"com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn", "co.uk"}


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
    labels = hostname.split(".") if hostname else []

    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        suffix_len = 2
    else:
        suffix_len = 1
    suffix = ".".join(labels[-suffix_len:]) if labels else ""

    if len(labels) > suffix_len:
        domain_name = labels[-suffix_len -1]
        subdomain = ".".join(labels[: -suffix_len -1])
        registered_domain = f"{domain_name}.{suffix}"
    else:
        domain_name, subdomain, registered_domain = hostname, "", hostname

    return ParsedURL(
        original=raw,
        scheme=parts.scheme,
        hostname=hostname,
        path=parts.path,
        query=parts.query,
        registered_domain=registered_domain,
        domain_name=domain_name,
        suffix=suffix,
        subdomain=subdomain,
    )