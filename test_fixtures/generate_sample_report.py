"""Generates a real sample HTML report using the actual report.py renderer,
fed with the real findings/probes collected from the two local test hosts.
This is just to produce a sample artifact to show what the report looks like.
"""
import sys
sys.path.insert(0, "/home/claude/reconx")

from reconx.probe import probe_host
from reconx.risk_checks import run_all_checks
from reconx.report import build_html_report

hosts = ["127.0.0.1:8080", "127.0.0.1:8081"]
probes = [probe_host(h) for h in hosts]
findings = []
for p in probes:
    if p.alive:
        findings.extend(run_all_checks(p.hostname, p.scheme, p.body_sample))

html = build_html_report(
    domain="demo-target.test (local fixture demo)",
    candidates=set(hosts),
    probes=probes,
    findings=findings,
    crtsh_count=0,
    brute_force_count=2,
    crtsh_error=None,
)

with open("/home/claude/reconx/output/sample_report.html", "w") as f:
    f.write(html)

print(f"Sample report written with {len(findings)} findings from {len(probes)} probed hosts.")
