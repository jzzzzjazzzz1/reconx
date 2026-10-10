"""
Risk detection - the part of the tool that has to be right, not just loud.

Every check in this file follows the same rule: a finding is only reported
if there is concrete evidence attached to it (a response snippet, a status
code, a CNAME record) that a human can verify in five seconds by looking at
the report. No check "guesses". Specifically:

  1. Exposed .git repository
     - We request /.git/HEAD specifically (not just "/.git/") and only
       flag it if the body actually matches git's own HEAD file format
       (e.g. "ref: refs/heads/main"). A server that 200s on everything
       (see baseline check below) will not pass this, because its body
       won't match the signature.

  2. Exposed admin / management panel
     - We first fingerprint the host's own "not found" response (a
       baseline request to a random, near-certainly-nonexistent path).
       Many servers return HTTP 200 for every path (SPA routers, soft-404
       pages). If the admin-path response is byte-for-byte or near-identical
       to that baseline, it is NOT a real finding - it's the same catch-all
       page, so we discard it. Only a genuinely distinct response is kept.

  3. Subdomain takeover
     - We only ever flag this when ALL of the following are true:
         a) the hostname's DNS is a CNAME pointing at a known third-party
            service domain (fastly, github, herokuapp, etc. - from a
            vetted fingerprint table)
         b) an HTTP request to that hostname returns a status/body that
            matches that SPECIFIC service's documented "unclaimed" error
            signature (not just "any error")
       A CNAME alone proves nothing (the target could be actively in use).
       An error page alone proves nothing (could be a normal app error).
       Both together, matching a named provider's own documented signature,
       is the accepted standard for reporting a takeover candidate.
"""

from __future__ import annotations

import random
import re
import string
from dataclasses import dataclass, field

import dns.resolver
import requests

from .probe import USER_AGENT, REQUEST_TIMEOUT

# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Info"


@dataclass
class Finding:
    hostname: str
    category: str
    severity: str
    title: str
    evidence: str
    recommendation: str


# ---------------------------------------------------------------------------
# Baseline ("soft 404") fingerprinting - prerequisite for the admin-panel
# check. Prevents the single biggest source of false positives in tools
# like this: hosts that return HTTP 200 for literally any path.
# ---------------------------------------------------------------------------

def _random_path(length: int = 16) -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))


@dataclass
class Baseline:
    status_code: int | None
    body_length: int
    body_sample: str


def get_baseline(base_url: str) -> Baseline:
    """Request a near-certainly-nonexistent path and record how the host
    responds. Used to distinguish a real finding from a catch-all page.
    """
    probe_url = f"{base_url}/__reconx_baseline_{_random_path()}__"
    try:
        resp = requests.get(
            probe_url,
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        body = resp.text[:4096]
        return Baseline(status_code=resp.status_code, body_length=len(body), body_sample=body)
    except requests.exceptions.RequestException:
        return Baseline(status_code=None, body_length=0, body_sample="")


def _bodies_effectively_equal(a: str, b: str) -> bool:
    """True if two response bodies are close enough to call them 'the same
    page' (catch-all / soft-404), allowing for small dynamic bits like a
    timestamp or CSRF token. Pure length+prefix heuristic, deliberately
    conservative so we'd rather under-flag than over-flag.
    """
    if not a or not b:
        return False
    if abs(len(a) - len(b)) > max(50, 0.05 * max(len(a), len(b))):
        return False
    sample_len = min(300, len(a), len(b))
    return a[:sample_len] == b[:sample_len]


# ---------------------------------------------------------------------------
# Check 1: exposed .git repository
# ---------------------------------------------------------------------------

_GIT_HEAD_SIGNATURE = re.compile(r"^ref:\s*refs/", re.IGNORECASE)


def check_git_exposure(hostname: str, base_url: str, baseline: Baseline) -> Finding | None:
    url = f"{base_url}/.git/HEAD"
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
    except requests.exceptions.RequestException:
        return None

    if resp.status_code != 200:
        return None

    body = resp.text.strip()[:200]

    # Must match git's actual HEAD file format - not just "any 200 page".
    if not _GIT_HEAD_SIGNATURE.match(body):
        return None

    # Guard against a catch-all host that 200s everything with the SAME
    # content as its baseline 404.
    if _bodies_effectively_equal(body, baseline.body_sample):
        return None

    return Finding(
        hostname=hostname,
        category="Exposed Source Control",
        severity=SEVERITY_HIGH,
        title="Exposed .git repository (/.git/HEAD readable)",
        evidence=f"GET {url} -> HTTP {resp.status_code}, body starts with: {body!r}",
        recommendation=(
            "Block public access to the .git directory (deny in web server "
            "config) and rotate any credentials that were ever committed to "
            "the repository. Ideally .git should never be inside the web root."
        ),
    )


# ---------------------------------------------------------------------------
# Check 2: exposed admin / management panel
# ---------------------------------------------------------------------------

ADMIN_PATHS = [
    "/admin",
    "/administrator",
    "/wp-admin",
    "/wp-login.php",
    "/login",
    "/manager/html",      # Tomcat manager
    "/phpmyadmin",
    "/pma",
    "/cpanel",
    "/webmin",
    "/.env",
    "/server-status",      # Apache mod_status
    "/actuator",           # Spring Boot actuator
    "/actuator/env",
    "/console",             # various app consoles (e.g. H2, Jenkins script console)
    "/jenkins",
    "/_profiler",           # Symfony debug toolbar
]

# Status codes that are worth a second look (not an exhaustive "it's live" list -
# 401/403 shown here because a protected panel is still worth noting at Info level)
_INTERESTING_STATUSES = {200, 401, 403}


def check_admin_panels(hostname: str, base_url: str, baseline: Baseline) -> list[Finding]:
    findings: list[Finding] = []

    for path in ADMIN_PATHS:
        url = f"{base_url}{path}"
        try:
            # Follow redirects: many real admin paths 301 to a trailing-slash
            # or canonical login URL (e.g. /admin -> /admin/), and that
            # normalization is not itself a signal. What matters is where we
            # end up and what that final page looks like compared to baseline.
            resp = requests.get(
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
        except requests.exceptions.RequestException:
            continue

        if resp.status_code not in _INTERESTING_STATUSES:
            continue

        body = resp.text[:4096]

        # Discard if this host just returns the same page for everything
        # (soft-404 / SPA catch-all) - compare against the baseline, which
        # was fetched the same way (redirects followed).
        if resp.status_code == baseline.status_code and _bodies_effectively_equal(body, baseline.body_sample):
            continue

        location_note = f", followed redirect to {resp.url}" if resp.history else ""

        if resp.status_code == 200:
            severity = SEVERITY_MEDIUM
            title = f"Accessible management/admin interface at {path}"
        else:
            severity = SEVERITY_LOW
            title = f"Management/admin interface present (access-restricted) at {path}"

        findings.append(
            Finding(
                hostname=hostname,
                category="Exposed Admin Interface",
                severity=severity,
                title=title,
                evidence=(
                    f"GET {url} -> HTTP {resp.status_code}{location_note} "
                    f"(baseline for this host was HTTP {baseline.status_code})"
                ),
                recommendation=(
                    "Restrict this interface to an internal network or VPN, "
                    "put it behind authentication/MFA if it isn't already, "
                    "and confirm default credentials have been changed."
                ),
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Check 3: subdomain takeover candidates
# ---------------------------------------------------------------------------
# Each entry: service name, CNAME domain patterns, and a response-body
# signature that service shows ONLY when the referenced resource is
# unclaimed/not found. Both the CNAME match and the body signature match
# are required before we report anything.

TAKEOVER_FINGERPRINTS = [
    {
        "service": "GitHub Pages",
        "cname_patterns": [r"\.github\.io$"],
        "body_signatures": [r"there isn't a github pages site here"],
    },
    {
        "service": "Heroku",
        "cname_patterns": [r"\.herokuapp\.com$", r"\.herokudns\.com$"],
        "body_signatures": [r"no such app", r"heroku \| no such app"],
    },
    {
        "service": "AWS S3",
        "cname_patterns": [r"\.s3\.amazonaws\.com$", r"\.s3-website[.-]"],
        "body_signatures": [r"nosuchbucket", r"the specified bucket does not exist"],
    },
    {
        "service": "Shopify",
        "cname_patterns": [r"\.myshopify\.com$"],
        "body_signatures": [r"sorry, this shop is currently unavailable"],
    },
    {
        "service": "Fastly",
        "cname_patterns": [r"\.fastly\.net$"],
        "body_signatures": [r"fastly error: unknown domain"],
    },
    {
        "service": "Unbounce",
        "cname_patterns": [r"\.unbouncepages\.com$"],
        "body_signatures": [r"the requested url was not found on this server"],
    },
    {
        "service": "Zendesk",
        "cname_patterns": [r"\.zendesk\.com$"],
        "body_signatures": [r"help center closed"],
    },
    {
        "service": "Tilda",
        "cname_patterns": [r"\.tilda\.ws$"],
        "body_signatures": [r"please renew your domain"],
    },
    {
        "service": "Netlify",
        "cname_patterns": [r"\.netlify\.app$"],
        "body_signatures": [r"not found - request id"],
    },
    {
        "service": "Surge.sh",
        "cname_patterns": [r"\.surge\.sh$"],
        "body_signatures": [r"project not found"],
    },
]


def _get_cname(hostname: str) -> str | None:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0
    try:
        answer = resolver.resolve(hostname, "CNAME")
        return str(answer[0].target).rstrip(".").lower()
    except Exception:
        return None


def check_subdomain_takeover(hostname: str, body_sample: str) -> Finding | None:
    cname = _get_cname(hostname)
    if not cname:
        return None  # no CNAME at all -> this check does not apply

    for fp in TAKEOVER_FINGERPRINTS:
        cname_match = any(re.search(pat, cname) for pat in fp["cname_patterns"])
        if not cname_match:
            continue

        body_lower = (body_sample or "").lower()
        signature_match = any(re.search(sig, body_lower) for sig in fp["body_signatures"])
        if not signature_match:
            # CNAME points at the service, but the live-response signature for
            # "unclaimed" was not found -> likely still in active use. Do not flag.
            continue

        return Finding(
            hostname=hostname,
            category="Possible Subdomain Takeover",
            severity=SEVERITY_HIGH,
            title=f"Dangling CNAME pointing to {fp['service']} with an 'unclaimed' response",
            evidence=(
                f"{hostname} CNAME -> {cname}; live response body matched "
                f"{fp['service']}'s unclaimed-resource signature"
            ),
            recommendation=(
                f"Either remove the unused CNAME record pointing to {cname}, "
                f"or re-claim/re-register the resource on {fp['service']} "
                "under this organization's account before someone else does."
            ),
        )

    return None


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_all_checks(hostname: str, scheme: str, body_sample: str) -> list[Finding]:
    """Run every risk check for one live host and return the findings.
    body_sample is the body already captured by probe.py for the main
    page, reused here for the takeover check so we don't double-request.
    """
    base_url = f"{scheme}://{hostname}"
    findings: list[Finding] = []

    baseline = get_baseline(base_url)

    git_finding = check_git_exposure(hostname, base_url, baseline)
    if git_finding:
        findings.append(git_finding)

    findings.extend(check_admin_panels(hostname, base_url, baseline))

    takeover_finding = check_subdomain_takeover(hostname, body_sample)
    if takeover_finding:
        findings.append(takeover_finding)

    return findings
