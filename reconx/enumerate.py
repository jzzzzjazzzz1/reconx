"""
Subdomain enumeration.

Two sources, combined and de-duplicated:
  1. Certificate Transparency logs (crt.sh) - passive, finds subdomains that
     have ever had a TLS certificate issued for them.
  2. DNS brute force against a wordlist - active, finds subdomains that
     resolve even if they never appeared in a certificate.

Both sources only PROPOSE names. Nothing here is "alive" or "risky" yet -
that is decided later, in probe.py and risk_checks.py, with evidence.
This module's only job is to produce a clean, deduplicated candidate list.
"""

from __future__ import annotations

import concurrent.futures
import re
import socket
from dataclasses import dataclass, field

import dns.resolver
import requests

USER_AGENT = "ReconX/1.0 (+authorized-security-assessment)"
CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
CRTSH_TIMEOUT = 20
DNS_TIMEOUT = 3.0
DNS_LIFETIME = 3.0
MAX_BRUTE_WORKERS = 40

# a valid DNS label: letters, digits, hyphens, 1-63 chars, no leading/trailing hyphen
_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


@dataclass
class EnumResult:
    domain: str
    candidates: set[str] = field(default_factory=set)
    crtsh_count: int = 0
    brute_force_count: int = 0
    crtsh_error: str | None = None


def _valid_subdomain(name: str, root_domain: str) -> bool:
    """Reject garbage before it ever reaches a network call.

    Certificate transparency logs are full of noise: wildcards, emails
    stuffed into CN fields, internal-only names, and typos. We only keep
    names that are syntactically valid DNS labels and actually belong to
    the target domain.
    """
    name = name.strip().lower().rstrip(".")
    if not name or "@" in name or "*" in name:
        return False
    if not name.endswith("." + root_domain) and name != root_domain:
        return False
    labels = name.split(".")
    return all(_LABEL_RE.match(label) for label in labels)


def from_certificate_transparency(domain: str) -> tuple[set[str], str | None]:
    """Query crt.sh for every name that has ever appeared on a certificate
    for *domain or any of its subdomains. Passive - never touches the
    target's own infrastructure.
    """
    found: set[str] = set()
    try:
        resp = requests.get(
            CRTSH_URL.format(domain=domain),
            headers={"User-Agent": USER_AGENT},
            timeout=CRTSH_TIMEOUT,
        )
        resp.raise_for_status()
        entries = resp.json()
    except requests.exceptions.RequestException as exc:
        return found, f"crt.sh request failed: {exc}"
    except ValueError:
        return found, "crt.sh returned a non-JSON / empty response"

    for entry in entries:
        name_value = entry.get("name_value", "")
        # crt.sh sometimes packs multiple SANs into one field, newline-separated
        for raw_name in name_value.split("\n"):
            raw_name = raw_name.strip().lower()
            if raw_name.startswith("*."):
                raw_name = raw_name[2:]  # drop wildcard prefix, keep the base name
            if _valid_subdomain(raw_name, domain):
                found.add(raw_name)

    return found, None


def _resolves(name: str) -> bool:
    """True only if the name has at least one A/AAAA/CNAME record.
    Uses a short, bounded timeout so one slow name can't stall the batch.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_LIFETIME
    for rtype in ("A", "AAAA", "CNAME"):
        try:
            resolver.resolve(name, rtype)
            return True
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            continue
        except Exception:
            continue
    return False


def from_dns_brute_force(domain: str, wordlist_path: str) -> set[str]:
    """Try each word in the wordlist as a subdomain label and keep only
    the ones that actually resolve. This catches subdomains that were
    never issued a public certificate (so crt.sh never saw them) -
    internal-sounding names, staging boxes, old infra, etc.
    """
    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            words = [w.strip() for w in f if w.strip() and not w.startswith("#")]
    except FileNotFoundError:
        return set()

    candidates = [f"{w}.{domain}" for w in words]
    found: set[str] = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_BRUTE_WORKERS) as pool:
        future_to_name = {pool.submit(_resolves, name): name for name in candidates}
        for future in concurrent.futures.as_completed(future_to_name):
            name = future_to_name[future]
            try:
                if future.result():
                    found.add(name)
            except Exception:
                continue

    return found


def enumerate_subdomains(domain: str, wordlist_path: str, skip_crtsh: bool = False) -> EnumResult:
    domain = domain.strip().lower().rstrip(".")
    result = EnumResult(domain=domain)

    if not skip_crtsh:
        crt_names, crt_error = from_certificate_transparency(domain)
        result.crtsh_count = len(crt_names)
        result.crtsh_error = crt_error
        result.candidates |= crt_names

    brute_names = from_dns_brute_force(domain, wordlist_path)
    result.brute_force_count = len(brute_names)
    result.candidates |= brute_names

    # always include the root domain itself
    result.candidates.add(domain)

    return result
