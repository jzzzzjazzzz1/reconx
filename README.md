# ReconX — Subdomain & Exposure Recon Tool

A Python tool that automates the first phase of a penetration test / bug bounty
engagement: discovering a target's attack surface and flagging the most common,
highest-signal exposures — without drowning the output in false positives.

Given a domain, ReconX:

1. **Enumerates subdomains** from two sources:
   - Certificate Transparency logs (`crt.sh`) — passive, no traffic sent to the target
   - DNS brute force against a built-in wordlist (500+ common names) — active
2. **Probes every candidate** over HTTPS/HTTP to see which ones are alive, and
   fingerprints the technology stack from response headers and body signatures
   (Nginx, Apache, WordPress, Cloudflare, AWS S3/CloudFront, React, etc.)
3. **Runs three risk checks** on every live host:
   - Exposed `.git` repository (source code / secrets leak)
   - Exposed admin or management interfaces (`/admin`, `/phpmyadmin`, Spring
     Boot Actuator, Tomcat Manager, `.env`, etc.)
   - Dangling CNAME records that point to a third-party service and look
     takeover-ready (GitHub Pages, Heroku, AWS S3, Shopify, Netlify, etc.)
4. **Generates a clean, dark-themed HTML report** with severity ratings,
   evidence for every single finding, and a fix recommendation.

## Why this doesn't just spam false positives

Most quick recon scripts report a "finding" the moment a path returns HTTP 200.
That's wrong in practice — a huge number of real servers (SPAs, soft-404 pages,
catch-all routers) return `200 OK` for *every* path, which would make a naive
tool flag `/admin`, `/.git/HEAD`, and `/phpmyadmin` on literally every target.

ReconX avoids this with three deliberate design choices:

- **Baseline fingerprinting.** Before checking any "interesting" path, ReconX
  requests a random, near-certainly-nonexistent path on that same host and
  records exactly how it responds (status code + body). Every later check is
  compared against that baseline — if the "finding" looks the same as the
  host's own 404 behavior, it is discarded, not reported.
- **Signature verification, not status codes.** The `.git` exposure check
  doesn't trust `HTTP 200` alone — it checks that the response body actually
  matches Git's own `HEAD` file format (`ref: refs/heads/...`).
- **Two-factor takeover detection.** A subdomain takeover is only reported
  when *both* a CNAME to a known vulnerable provider *and* that provider's own
  documented "unclaimed resource" error text are present in the live response.
  A CNAME alone proves nothing; an error page alone proves nothing.

This is all automatically tested — see [Testing](#testing) below, including a
test against a host that returns `200` for every path, to prove it produces
**zero** false positives on that trap case.

## Installation

```bash
pip install -r requirements.txt
```

Requires Python 3.9+.

## Usage

```bash
python3 -m reconx.main example.com
```

You'll be asked to confirm you have authorization to scan the target (see
[Legal / Ethics](#legal--ethics)). Skip the prompt with `-y` when you already
know you're authorized (e.g. your own CI pipeline).

Options:

```
python3 -m reconx.main <domain> [options]

  --wordlist PATH     Custom subdomain wordlist (default: wordlists/subdomains_small.txt)
  --output PATH       Where to save the HTML report (default: output/<domain>_report.html)
  --skip-crtsh        Skip certificate transparency lookup, DNS brute force only
  -y, --yes           Skip the interactive authorization confirmation
```

Example:

```bash
python3 -m reconx.main mycompany.com --wordlist wordlists/subdomains_small.txt
# -> output/mycompany_com_report.html
```

Open the generated HTML file in a browser to view the report.

## How it works (architecture)

```
reconx/
  enumerate.py    - crt.sh query + DNS brute force -> candidate subdomain set
  probe.py        - HTTP/HTTPS liveness check + technology fingerprinting
  risk_checks.py  - baseline fingerprinting + the 3 risk checks
  report.py       - renders everything into a single HTML file
  main.py         - CLI entrypoint that wires the above together
wordlists/
  subdomains_small.txt - ~500 common subdomain names for brute forcing
output/
  (generated reports land here)
```

Each module has one job and produces evidence-bearing data structures
(`EnumResult`, `ProbeResult`, `Finding`) that the next stage consumes — no
stage re-does another stage's work or trusts an earlier stage's conclusion
without the underlying evidence.

## Testing

The `test_fixtures/` folder (not part of the tool itself, just test
scaffolding) contains the scripts used to verify correctness before you run
this on a real target:

- `run_test.py` — spins up two local HTTP servers: one genuinely vulnerable
  (exposed `.git`, a real admin panel) and one "catch-all" host that returns
  `200` with identical content for every path. Runs the real `risk_checks`
  module against both and asserts the vulnerable host is flagged while the
  catch-all host produces **zero** findings.
- `test_takeover_logic.py` — unit tests the subdomain-takeover check's two
  required conditions (CNAME match AND response-signature match) independently,
  with DNS/HTTP mocked out.

Run them yourself:

```bash
python3 test_fixtures/run_test.py
python3 test_fixtures/test_takeover_logic.py
```

## Limitations (be upfront about these on your CV / in interviews)

- DNS brute forcing only finds subdomains in the wordlist — it won't find
  something named `x7q2.internal.example.com`. This is standard for any
  recon tool; bigger wordlists trade time for coverage.
- The admin-panel check only covers a fixed list of common paths.
- The takeover check's fingerprint database covers ~10 common providers, not
  every service that has ever had a takeover advisory.
- Requires outbound internet access (crt.sh + DNS + HTTP). It will not run in
  a network-restricted sandbox.
- This is a recon/detection tool, not an exploitation framework — it never
  attempts to log in, write files, or alter anything on the target.

## Legal / Ethics

**Only run this against domains you own or have explicit written
authorization to test** (e.g. a bug bounty program's documented scope, or
your employer's own infrastructure). Active scanning — DNS brute forcing and
HTTP path probing — against systems you don't have permission for is illegal
in most jurisdictions (e.g. the U.S. Computer Fraud and Abuse Act, UK Computer
Misuse Act) regardless of intent. The CLI will ask you to confirm
authorization before it sends a single packet.

## Putting this on your CV

Suggested line:

> Built ReconX, a Python reconnaissance tool that automates subdomain
> enumeration (certificate transparency + DNS brute force), live-host
> fingerprinting, and exposure detection (exposed `.git` repos, admin panels,
> dangling-CNAME subdomain takeovers), with baseline-response fingerprinting
> to eliminate false positives; verified with an automated test suite
> including a false-positive trap case.

Be ready to explain in an interview:
- Why baseline fingerprinting matters (soft-404 / catch-all hosts)
- Why the takeover check needs two independent signals, not one
- What you'd add next (more wordlist entries, a `--threads` flag, JSON output
  for CI integration, Shodan/Censys as a third enumeration source)
