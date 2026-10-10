"""
Unit-style test for the subdomain takeover check's anti-false-positive logic.
Mocks DNS and HTTP so we can test both required conditions independently:

  Case A: CNAME to a known service, but body does NOT match the service's
          "unclaimed" signature (i.e. it's actively in use) -> must NOT flag
  Case B: CNAME to a known service, AND body matches the unclaimed
          signature -> MUST flag
  Case C: no CNAME at all -> must NOT flag (check doesn't apply)
"""
import sys
from unittest.mock import patch

sys.path.insert(0, "/home/claude/reconx")
from reconx import risk_checks


def fake_cname(target):
    def _inner(hostname):
        return target
    return _inner


print("Case A: CNAME to github.io but body is a normal, active GitHub Pages site")
with patch.object(risk_checks, "_get_cname", fake_cname("someuser.github.io")):
    result = risk_checks.check_subdomain_takeover(
        "blog.example.com",
        body_sample="<html><body>Welcome to my blog, built with Jekyll</body></html>",
    )
assert result is None, f"FAIL: should not flag an active site, got {result}"
print("  PASS: not flagged (active site, correctly ignored)\n")

print("Case B: CNAME to github.io AND body matches GitHub's unclaimed-page signature")
with patch.object(risk_checks, "_get_cname", fake_cname("someuser.github.io")):
    result = risk_checks.check_subdomain_takeover(
        "blog.example.com",
        body_sample="<html><body>404 - There isn't a GitHub Pages site here.</body></html>",
    )
assert result is not None, "FAIL: should have flagged a dangling CNAME with matching signature"
assert result.severity == "High"
print(f"  PASS: flagged correctly -> {result.title}")
print(f"  evidence: {result.evidence}\n")

print("Case C: no CNAME record at all")
with patch.object(risk_checks, "_get_cname", lambda hostname: None):
    result = risk_checks.check_subdomain_takeover(
        "www.example.com",
        body_sample="<html><body>anything</body></html>",
    )
assert result is None, "FAIL: should not run the check without a CNAME"
print("  PASS: not flagged (no CNAME, check correctly skipped)\n")

print("ALL TAKEOVER LOGIC TESTS PASSED")
