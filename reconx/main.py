#!/usr/bin/env python3
"""
ReconX — Subdomain & Exposure Recon Tool
Usage (after `pip install -e .` once, see README):
    reconx -d example.com
    reconx -d example.com --wordlist wordlists/subdomains_small.txt --output output/report.html

Also always works without installing, same flags:
    python -m reconx.main -d example.com

IMPORTANT: Only run this against a domain you own or have explicit written
authorization to test. Running active scans (DNS brute force, path probing)
against systems you don't have permission for is illegal in most jurisdictions.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from colorama import Fore, Style, init as colorama_init

from .enumerate import enumerate_subdomains
from .probe import probe_all
from .risk_checks import run_all_checks
from .report import build_html_report

colorama_init(autoreset=True)


def _banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
  ____                      __  __
 |  _ \ ___  ___ ___  _ __ \ \/ /
 | |_) / _ \/ __/ _ \| '_ \ \  /
 |  _ <  __/ (_| (_) | | | |/  \
 |_| \_\___|\___\___/|_| |_/_/\_\
  Subdomain & Exposure Recon Tool
""" + Style.RESET_ALL)


def _confirm_authorization(domain: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    print(Fore.YELLOW + f"You are about to actively scan: {domain}" + Style.RESET_ALL)
    answer = input("Do you own this domain or have explicit written authorization to test it? [y/N]: ")
    return answer.strip().lower() in ("y", "yes")


def main():
    parser = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX - subdomain enumeration + exposure recon tool (authorized use only).",
    )
    parser.add_argument("-d", "--domain", required=True, help="Target root domain, e.g. example.com")
    parser.add_argument(
        "--wordlist",
        default=os.path.join(os.path.dirname(__file__), "..", "wordlists", "subdomains_small.txt"),
        help="Path to a subdomain wordlist for DNS brute forcing.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Path to write the HTML report (default: output/<domain>_report.html)",
    )
    parser.add_argument("--skip-crtsh", action="store_true", help="Skip certificate transparency lookup (DNS brute force only).")
    parser.add_argument("-y", "--yes", action="store_true", help="Skip the interactive authorization prompt.")
    args = parser.parse_args()

    _banner()

    if not _confirm_authorization(args.domain, args.yes):
        print(Fore.RED + "Authorization not confirmed. Exiting." + Style.RESET_ALL)
        sys.exit(1)

    domain = args.domain.strip().lower()
    output_path = args.output or os.path.join("output", f"{domain.replace('.', '_')}_report.html")

    t0 = time.time()

    print(Fore.CYAN + f"\n[1/4] Enumerating subdomains for {domain} ..." + Style.RESET_ALL)
    enum_result = enumerate_subdomains(domain, args.wordlist, skip_crtsh=args.skip_crtsh)
    if enum_result.crtsh_error:
        print(Fore.YELLOW + f"  ! crt.sh lookup issue: {enum_result.crtsh_error}" + Style.RESET_ALL)
    print(
        f"  crt.sh candidates: {enum_result.crtsh_count}   "
        f"DNS brute-force hits: {enum_result.brute_force_count}   "
        f"Total unique candidates: {len(enum_result.candidates)}"
    )

    print(Fore.CYAN + f"\n[2/4] Probing {len(enum_result.candidates)} hosts for liveness + tech ..." + Style.RESET_ALL)
    probes = probe_all(enum_result.candidates)
    alive = [p for p in probes if p.alive]
    print(f"  Alive: {len(alive)} / {len(probes)}")

    print(Fore.CYAN + f"\n[3/4] Running risk checks (.git exposure, admin panels, takeover) on {len(alive)} live hosts ..." + Style.RESET_ALL)
    all_findings = []
    for i, p in enumerate(alive, 1):
        print(f"  [{i}/{len(alive)}] {p.hostname}", end="\r")
        findings = run_all_checks(p.hostname, p.scheme, p.body_sample)
        all_findings.extend(findings)
    print(" " * 80, end="\r")  # clear the progress line

    high = sum(1 for f in all_findings if f.severity == "High")
    medium = sum(1 for f in all_findings if f.severity == "Medium")
    low = sum(1 for f in all_findings if f.severity == "Low")
    print(f"  Findings: {Fore.RED}{high} High{Style.RESET_ALL}, {Fore.YELLOW}{medium} Medium{Style.RESET_ALL}, {Fore.BLUE}{low} Low{Style.RESET_ALL}")

    print(Fore.CYAN + "\n[4/4] Building HTML report ..." + Style.RESET_ALL)
    html_report = build_html_report(
        domain=domain,
        candidates=enum_result.candidates,
        probes=probes,
        findings=all_findings,
        crtsh_count=enum_result.crtsh_count,
        brute_force_count=enum_result.brute_force_count,
        crtsh_error=enum_result.crtsh_error,
    )

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_report)

    elapsed = time.time() - t0
    print(Fore.GREEN + Style.BRIGHT + f"\nDone in {elapsed:.1f}s. Report saved to: {output_path}" + Style.RESET_ALL)


if __name__ == "__main__":
    main()