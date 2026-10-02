"""Helpers for reasoning about hostnames (pure string logic - no DNS, no network)."""
import ipaddress
from typing import List, Tuple

from backend.utils.constants import BRAND_NAMES, LEET_MAP, TRUSTED_DOMAINS, TWO_LEVEL_SUFFIXES


def is_ip_address(host: str) -> bool:
    """True if `host` is a literal IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def split_host(host: str) -> Tuple[List[str], str, str]:
    """Split a hostname into (subdomain labels, registered domain, second-level label).

    'a.b.example.com' -> (['a', 'b'], 'example.com', 'example')
    This is a simplification; production code would use the Public Suffix List.
    """
    labels = [label for label in host.lower().strip(".").split(".") if label]
    if len(labels) < 2:
        return [], host.lower(), host.lower()
    k = 3 if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES else 2
    return labels[:-k], ".".join(labels[-k:]), labels[-k]


def is_trusted_domain(host: str) -> bool:
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in TRUSTED_DOMAINS)


def brand_findings(host: str) -> List[Tuple[str, str, int]]:
    """Detect brand impersonation in a hostname.

    Returns a list of (description, severity, points). Two cases:
      1. The brand name appears in a domain we do not trust.
      2. A character-swapped version (examp1ebank) contains the brand.
    """
    host = host.lower()
    if is_trusted_domain(host) or is_ip_address(host):
        return []
    results = []
    variants = {host.translate(LEET_MAP), host.translate(LEET_MAP).replace("rn", "m")}
    for brand in BRAND_NAMES:
        if brand in host:
            results.append((f"Brand name '{brand}' appears in a domain that is not on the trusted list", "high", 20))
        elif any(brand in v for v in variants):
            results.append((f"Domain looks like a character-swapped copy of '{brand}' (possible lookalike)", "high", 25))
    return results
