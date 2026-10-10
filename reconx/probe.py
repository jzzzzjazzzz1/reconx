"""
Liveness probing and technology fingerprinting.

For every candidate subdomain we try HTTPS first, then HTTP, and record
exactly what came back: status code, headers, a body sample, and the
final URL after redirects. Everything downstream (risk_checks.py) works
off this recorded evidence instead of re-requesting pages, so the report
and the actual HTTP response always agree.
"""

from __future__ import annotations

import concurrent.futures
import re
from dataclasses import dataclass, field

import requests
from requests.exceptions import RequestException

USER_AGENT = "ReconX/1.0 (+authorized-security-assessment)"
REQUEST_TIMEOUT = 6
MAX_PROBE_WORKERS = 20
MAX_BODY_SAMPLE = 4096  # bytes kept per response for fingerprinting/evidence

# Lightweight, signature-based technology fingerprints.
# Each entry: (display name, header_regexes, body_regexes)
# A match requires a hit in the actual HTTP response - never guessed.
TECH_SIGNATURES: list[tuple[str, dict[str, str], list[str]]] = [
    ("Nginx", {"server": r"nginx"}, []),
    ("Apache httpd", {"server": r"apache"}, []),
    ("Microsoft IIS", {"server": r"microsoft-iis"}, []),
    ("Cloudflare", {"server": r"cloudflare"}, []),
    ("LiteSpeed", {"server": r"litespeed"}, []),
    ("Express (Node.js)", {"x-powered-by": r"express"}, []),
    ("PHP", {"x-powered-by": r"php"}, []),
    ("ASP.NET", {"x-powered-by": r"asp\.net", "x-aspnet-version": r".+"}, []),
    ("WordPress", {}, [r"wp-content/", r"wp-includes/"]),
    ("Drupal", {"x-generator": r"drupal"}, [r"sites/default/files", r"drupal\.js"]),
    ("Joomla", {}, [r"/media/jui/", r"joomla"]),
    ("React", {}, [r"__next_data__|react-root|data-reactroot"]),
    ("jQuery", {}, [r"jquery(\.min)?\.js"]),
    ("Bootstrap", {}, [r"bootstrap(\.min)?\.css"]),
    ("AWS S3 bucket", {"server": r"amazons3"}, []),
    ("AWS CloudFront", {"x-amz-cf-id": r".+", "via": r"cloudfront"}, []),
    ("GitHub Pages", {"server": r"github\.com"}, []),
    ("Vercel", {"server": r"vercel", "x-vercel-id": r".+"}, []),
    ("Netlify", {"server": r"netlify"}, []),
    ("Heroku", {"server": r"cowboy"}, []),
    ("Varnish Cache", {"via": r"varnish", "x-varnish": r".+"}, []),
]


@dataclass
class ProbeResult:
    hostname: str
    alive: bool = False
    scheme: str | None = None
    final_url: str | None = None
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body_sample: str = ""
    technologies: list[str] = field(default_factory=list)
    redirect_chain: list[str] = field(default_factory=list)
    error: str | None = None


def _fetch(url: str) -> requests.Response:
    return requests.get(
        url,
        headers={"User-Agent": USER_AGENT},
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True,
        stream=True,
        verify=True,
    )


def _detect_tech(headers: dict[str, str], body_sample: str) -> list[str]:
    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
    body_lower = body_sample.lower()
    found = []
    for name, header_patterns, body_patterns in TECH_SIGNATURES:
        matched = False
        for header_key, pattern in header_patterns.items():
            value = lower_headers.get(header_key)
            if value and re.search(pattern, value, re.IGNORECASE):
                matched = True
                break
        if not matched:
            for pattern in body_patterns:
                if re.search(pattern, body_lower, re.IGNORECASE):
                    matched = True
                    break
        if matched:
            found.append(name)
    return found


def probe_host(hostname: str) -> ProbeResult:
    """Try HTTPS, then fall back to HTTP. Only one of the two schemes is
    recorded as the 'alive' result - the one that actually answered.
    """
    result = ProbeResult(hostname=hostname)
    errors = []

    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"
        try:
            resp = _fetch(url)
            body_bytes = resp.raw.read(MAX_BODY_SAMPLE, decode_content=True)
            body_sample = body_bytes.decode("utf-8", errors="replace")

            result.alive = True
            result.scheme = scheme
            result.final_url = resp.url
            result.status_code = resp.status_code
            result.headers = dict(resp.headers)
            result.body_sample = body_sample
            result.redirect_chain = [r.url for r in resp.history]
            result.technologies = _detect_tech(result.headers, body_sample)
            resp.close()
            return result
        except RequestException as exc:
            errors.append(f"{scheme}: {exc.__class__.__name__}")
            continue

    result.alive = False
    result.error = "; ".join(errors) if errors else "no response on https or http"
    return result


def probe_all(hostnames: set[str]) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PROBE_WORKERS) as pool:
        futures = {pool.submit(probe_host, h): h for h in hostnames}
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                results.append(ProbeResult(hostname=futures[future], alive=False, error=str(exc)))
    results.sort(key=lambda r: r.hostname)
    return results
