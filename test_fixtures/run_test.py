"""
Exercises the real reconx.risk_checks module against two local test hosts:

  127.0.0.1:8080  -> genuinely vulnerable (exposed .git, real admin panel)
  127.0.0.1:8081  -> catch-all host that returns 200 + identical body for
                     EVERY path (the classic false-positive trap)

Expected outcome:
  - vulnerable host  -> git exposure finding + admin panel finding
  - catch-all host   -> ZERO findings, because every "hit" matches its own
                         baseline and gets correctly discarded
"""
import sys
sys.path.insert(0, "/home/claude/reconx")

from reconx.risk_checks import run_all_checks
from reconx.probe import probe_host

print("=" * 70)
print("TEST 1: genuinely vulnerable host (127.0.0.1:8080)")
print("=" * 70)
probe = probe_host("127.0.0.1:8080")
print(f"alive={probe.alive} status={probe.status_code} tech={probe.technologies}")
findings = run_all_checks("127.0.0.1:8080", probe.scheme, probe.body_sample)
print(f"\n{len(findings)} finding(s):")
for f in findings:
    print(f"  [{f.severity}] {f.title}")
    print(f"      evidence: {f.evidence}")

print()
print("=" * 70)
print("TEST 2: catch-all / soft-404 host (127.0.0.1:8081) — false positive trap")
print("=" * 70)
probe2 = probe_host("127.0.0.1:8081")
print(f"alive={probe2.alive} status={probe2.status_code} tech={probe2.technologies}")
findings2 = run_all_checks("127.0.0.1:8081", probe2.scheme, probe2.body_sample)
print(f"\n{len(findings2)} finding(s): {findings2 if findings2 else '(none — correctly suppressed)'}")

print()
print("=" * 70)
print("RESULT")
print("=" * 70)
ok = True
if len(findings) < 2:
    print("FAIL: expected at least 2 findings (git + admin) on the vulnerable host")
    ok = False
else:
    print("PASS: vulnerable host correctly flagged")

if len(findings2) != 0:
    print("FAIL: catch-all host produced false positive findings:", findings2)
    ok = False
else:
    print("PASS: catch-all host correctly produced ZERO false positives")

sys.exit(0 if ok else 1)
