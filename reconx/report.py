"""
HTML report generation. Pure presentation - takes the data collected by
enumerate.py / probe.py / risk_checks.py and renders it. No new findings
or judgments are made here.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from .probe import ProbeResult
from .risk_checks import Finding, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO

SEVERITY_ORDER = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 2, SEVERITY_INFO: 3}
SEVERITY_COLOR = {
    SEVERITY_HIGH: "#f6465d",
    SEVERITY_MEDIUM: "#f7a74a",
    SEVERITY_LOW: "#4aa8f7",
    SEVERITY_INFO: "#8b93a1",
}
SEVERITY_BG = {
    SEVERITY_HIGH: "rgba(246,70,93,0.12)",
    SEVERITY_MEDIUM: "rgba(247,167,74,0.12)",
    SEVERITY_LOW: "rgba(74,168,247,0.12)",
    SEVERITY_INFO: "rgba(139,147,161,0.12)",
}

CATEGORY_ICON = {
    "Exposed Source Control": (
        '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<circle cx="12" cy="12" r="3"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="19" r="2"/>'
        '<path d="M12 9V5M9.5 11 7 17M14.5 11 17 17"/></svg>'
    ),
    "Exposed Admin Interface": (
        '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>'
    ),
    "Possible Subdomain Takeover": (
        '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M12 2 2 7l10 5 10-5-10-5Z"/><path d="M2 17l10 5 10-5M2 12l10 5 10-5"/></svg>'
    ),
}
DEFAULT_ICON = (
    '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" '
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M12 9v4M12 17h.01"/><circle cx="12" cy="12" r="10"/></svg>'
)

_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
  --bg: #0a0c10; --panel: #12151c; --panel-2: #171b24; --border: #242938;
  --text: #e8eaed; --muted: #8b93a1; --muted-2: #5e6675;
  --accent: #3ddc97; --accent-dim: rgba(61,220,151,0.12);
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0; background:
    radial-gradient(1200px 500px at 15% -10%, rgba(61,220,151,0.07), transparent),
    radial-gradient(900px 500px at 100% 0%, rgba(74,168,247,0.06), transparent),
    var(--bg);
  color: var(--text);
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}
code, .mono { font-family: 'JetBrains Mono', ui-monospace, monospace; }

header {
  padding: 48px 48px 36px; border-bottom: 1px solid var(--border);
}
.eyebrow {
  color: var(--accent); font-size: 12px; font-weight: 700; letter-spacing: 0.12em;
  text-transform: uppercase; margin-bottom: 10px; display: flex; align-items: center; gap: 8px;
}
.eyebrow::before { content: ''; width: 7px; height: 7px; border-radius: 50%; background: var(--accent); box-shadow: 0 0 10px var(--accent); }
header h1 { margin: 0 0 10px 0; font-size: 30px; font-weight: 800; letter-spacing: -0.02em; }
header h1 .domain { color: var(--accent); }
header .meta { color: var(--muted); font-size: 13.5px; }
header .meta span { color: var(--text); font-weight: 500; }

.container { max-width: 1120px; margin: 0 auto; padding: 40px 48px 90px; }

/* ---- risk overview ---- */
.overview {
  display: grid; grid-template-columns: 1.1fr 2fr; gap: 20px; margin-bottom: 44px;
}
.risk-card {
  background: var(--panel); border: 1px solid var(--border); border-radius: 16px;
  padding: 28px; display: flex; flex-direction: column; align-items: center; justify-content: center;
  text-align: center;
}
.risk-ring { position: relative; width: 132px; height: 132px; margin-bottom: 14px; }
.risk-ring svg { transform: rotate(-90deg); }
.risk-ring .ring-bg { fill: none; stroke: var(--panel-2); stroke-width: 10; }
.risk-ring .ring-fg { fill: none; stroke-width: 10; stroke-linecap: round; transition: stroke-dashoffset 1s ease; }
.risk-ring .ring-num {
  position: absolute; top: 0; right: 0; bottom: 0; left: 0; display: flex; flex-direction: column; align-items: center; justify-content: center;
}
.risk-ring .ring-num .score { font-size: 30px; font-weight: 800; }
.risk-ring .ring-num .max { font-size: 11px; color: var(--muted-2); }
.risk-label { font-size: 14px; font-weight: 700; padding: 5px 14px; border-radius: 999px; margin-top: 6px; }

.summary-grid {
  display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px;
}
.summary-card {
  background: var(--panel); border: 1px solid var(--border); border-radius: 14px;
  padding: 18px 20px; display: flex; flex-direction: column; justify-content: center;
}
.summary-card .num { font-size: 26px; font-weight: 800; line-height: 1; }
.summary-card .label { color: var(--muted); font-size: 12.5px; margin-top: 6px; }
.summary-card.hi .num { color: var(--sev-color, #f6465d); }

/* ---- severity bar ---- */
.severity-bar-wrap { grid-column: 1 / -1; background: var(--panel); border: 1px solid var(--border); border-radius: 14px; padding: 18px 22px; }
.severity-bar-wrap .sb-title { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; font-weight: 700; margin-bottom: 12px; }
.severity-bar { display: flex; height: 10px; border-radius: 999px; overflow: hidden; background: var(--panel-2); }
.severity-bar div { height: 100%; }
.severity-legend { display: flex; gap: 20px; margin-top: 12px; flex-wrap: wrap; }
.severity-legend .item { display: flex; align-items: center; gap: 7px; font-size: 12.5px; color: var(--muted); }
.severity-legend .dot { width: 9px; height: 9px; border-radius: 50%; }

/* ---- section headers ---- */
h2.section {
  font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em;
  color: var(--muted); margin: 48px 0 18px; padding-bottom: 12px; border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between;
}
h2.section .count { color: var(--text); background: var(--panel-2); border-radius: 999px; padding: 2px 10px; font-size: 12px; }

/* ---- finding cards ---- */
.finding {
  background: var(--panel); border: 1px solid var(--border); border-radius: 14px;
  padding: 18px 22px; margin-bottom: 12px; position: relative; overflow: hidden;
  transition: border-color .15s ease, transform .15s ease;
}
.finding::before { content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 3px; }
.finding:hover { border-color: var(--muted-2); }
.finding .top-row { display: flex; justify-content: space-between; align-items: flex-start; gap: 14px; flex-wrap: wrap; }
.finding .title-row { display: flex; align-items: center; gap: 10px; }
.finding .icon { display: flex; align-items: center; justify-content: center; width: 34px; height: 34px; border-radius: 9px; flex-shrink: 0; }
.finding .title-block .title { font-weight: 600; font-size: 14.5px; }
.finding .title-block .host { color: var(--accent); font-size: 12.5px; margin-top: 2px; }
.badge {
  display: inline-block; padding: 4px 12px; border-radius: 999px;
  font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; flex-shrink: 0;
}
.evidence {
  background: var(--panel-2); border: 1px solid var(--border); border-radius: 8px;
  padding: 12px 14px; margin-top: 12px; font-size: 12.5px;
  color: #c3cad6; white-space: pre-wrap; word-break: break-word;
}
.recommendation { margin-top: 10px; font-size: 13px; color: var(--muted); padding-left: 2px; }
.recommendation strong { color: var(--text); }

/* ---- tables ---- */
.table-wrap { background: var(--panel); border: 1px solid var(--border); border-radius: 14px; overflow: hidden; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 13px 18px; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; background: var(--panel-2); }
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover { background: var(--panel-2); }
.tech-pill {
  display: inline-block; background: var(--panel-2); border: 1px solid var(--border);
  border-radius: 999px; padding: 3px 10px; font-size: 11px; margin: 2px 3px 2px 0; color: var(--muted);
}
.empty-state {
  color: var(--muted); font-style: normal; padding: 28px; text-align: center; font-size: 13.5px;
  background: var(--panel); border: 1px dashed var(--border); border-radius: 14px;
}
.status-pill { font-weight: 700; font-family: 'JetBrains Mono', monospace; font-size: 12.5px; }
.status-2xx { color: var(--accent); } .status-3xx { color: #f7a74a; }
.status-4xx { color: var(--muted); } .status-5xx { color: #f6465d; }

footer {
  color: var(--muted-2); font-size: 12px; text-align: center; padding: 36px;
  border-top: 1px solid var(--border); max-width: 1120px; margin: 0 auto;
}
"""


def _esc(s: str) -> str:
    return html.escape(str(s), quote=True)


def _status_class(code: int | None) -> str:
    if code is None:
        return ""
    return f"status-{code // 100}xx"


def _risk_score(severity_counts: dict[str, int]) -> int:
    """Simple weighted score, capped at 100, purely for an at-a-glance gauge."""
    raw = severity_counts.get(SEVERITY_HIGH, 0) * 25 + severity_counts.get(SEVERITY_MEDIUM, 0) * 10 + severity_counts.get(SEVERITY_LOW, 0) * 3
    return min(100, raw)


def _risk_label(score: int) -> tuple[str, str]:
    if score == 0:
        return "Clean", "#3ddc97"
    if score < 20:
        return "Low Risk", "#4aa8f7"
    if score < 50:
        return "Moderate Risk", "#f7a74a"
    return "High Risk", "#f6465d"


def _render_risk_ring(score: int, color: str) -> str:
    radius = 56
    circumference = 2 * 3.14159265 * radius
    offset = circumference * (1 - score / 100)
    return f"""
    <div class="risk-ring">
      <svg width="132" height="132" viewBox="0 0 132 132">
        <circle class="ring-bg" cx="66" cy="66" r="{radius}"/>
        <circle class="ring-fg" cx="66" cy="66" r="{radius}" stroke="{color}"
          stroke-dasharray="{circumference:.1f}" stroke-dashoffset="{offset:.1f}"/>
      </svg>
      <div class="ring-num">
        <div class="score">{score}</div>
        <div class="max">/ 100</div>
      </div>
    </div>
    """


def _render_findings(findings: list[Finding]) -> str:
    if not findings:
        return '<div class="empty-state">No findings in this category — none of the checks produced verified evidence of a problem.</div>'

    parts = []
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
        color = SEVERITY_COLOR.get(f.severity, "#8b93a1")
        bg = SEVERITY_BG.get(f.severity, "rgba(139,147,161,0.12)")
        icon = CATEGORY_ICON.get(f.category, DEFAULT_ICON)
        parts.append(f"""
        <div class="finding" style="--before-color:{color}">
          <div class="top-row">
            <div class="title-row">
              <div class="icon" style="background:{bg}; color:{color}">{icon}</div>
              <div class="title-block">
                <div class="title">{_esc(f.title)}</div>
                <div class="host mono">{_esc(f.hostname)}</div>
              </div>
            </div>
            <span class="badge" style="background:{bg}; color:{color}">{_esc(f.severity)}</span>
          </div>
          <div class="evidence mono">{_esc(f.evidence)}</div>
          <div class="recommendation"><strong>Fix:</strong> {_esc(f.recommendation)}</div>
        </div>
        <style>.finding::before{{background:{color}}}</style>
        """)
    return "".join(parts)


def _render_inventory(probes: list[ProbeResult]) -> str:
    rows = []
    for p in probes:
        if not p.alive:
            continue
        techs = "".join(f'<span class="tech-pill">{_esc(t)}</span>' for t in p.technologies) or '<span style="color:var(--muted-2)">—</span>'
        status_class = _status_class(p.status_code)
        rows.append(f"""
        <tr>
          <td><code class="mono">{_esc(p.hostname)}</code></td>
          <td class="status-pill {status_class}">{p.status_code}</td>
          <td>{_esc(p.scheme.upper() if p.scheme else '')}</td>
          <td style="max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" class="mono">{_esc(p.final_url or '')}</td>
          <td>{techs}</td>
        </tr>
        """)
    if not rows:
        return '<div class="empty-state">No hosts responded over HTTP/HTTPS.</div>'
    return f"""
    <div class="table-wrap">
    <table>
      <thead><tr><th>Host</th><th>Status</th><th>Scheme</th><th>Final URL</th><th>Detected Tech</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
    </div>
    """


def _render_dead_hosts(probes: list[ProbeResult]) -> str:
    dead = [p for p in probes if not p.alive]
    if not dead:
        return ""
    items = "".join(
        f'<tr><td><code class="mono">{_esc(p.hostname)}</code></td><td class="mono" style="color:var(--muted)">{_esc(p.error or "no response")}</td></tr>'
        for p in dead
    )
    return f"""
    <h2 class="section">Resolved but not reachable <span class="count">{len(dead)}</span></h2>
    <p style="color:var(--muted); font-size:13px; margin-top:-8px; margin-bottom:16px;">
      These subdomains exist in DNS but did not respond on port 80/443 within the timeout.
      Listed for completeness, not flagged as risks.
    </p>
    <div class="table-wrap">
    <table>
      <thead><tr><th>Host</th><th>Detail</th></tr></thead>
      <tbody>{items}</tbody>
    </table>
    </div>
    """


def build_html_report(
    domain: str,
    candidates: set[str],
    probes: list[ProbeResult],
    findings: list[Finding],
    crtsh_count: int,
    brute_force_count: int,
    crtsh_error: str | None,
) -> str:
    alive_count = sum(1 for p in probes if p.alive)
    severity_counts = {s: 0 for s in (SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO)}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    crtsh_note = (
        f'<p style="color:var(--muted); font-size:12px; margin-top:10px;">Note: certificate transparency lookup issue — {_esc(crtsh_error)}</p>'
        if crtsh_error else ""
    )

    score = _risk_score(severity_counts)
    risk_text, risk_color = _risk_label(score)

    total_findings = sum(severity_counts.values()) or 1
    bar_segments = "".join(
        f'<div style="width:{severity_counts[s]/total_findings*100:.1f}%; background:{SEVERITY_COLOR[s]}"></div>'
        for s in (SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO) if severity_counts[s] > 0
    ) or '<div style="width:100%; background:var(--panel-2)"></div>'

    legend = "".join(
        f'<div class="item"><span class="dot" style="background:{SEVERITY_COLOR[s]}"></span>{s}: {severity_counts[s]}</div>'
        for s in (SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW)
    )

    summary_cards = [
        ("Subdomains Found", len(candidates), None),
        ("Alive Hosts", alive_count, None),
        ("High Severity", severity_counts[SEVERITY_HIGH], SEVERITY_COLOR[SEVERITY_HIGH]),
        ("Medium Severity", severity_counts[SEVERITY_MEDIUM], SEVERITY_COLOR[SEVERITY_MEDIUM]),
    ]
    summary_html = "".join(
        f'<div class="summary-card{" hi" if color else ""}" style="--sev-color:{color or ""}"><div class="num">{v}</div><div class="label">{_esc(k)}</div></div>'
        for k, v, color in summary_cards
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ReconX Report — {_esc(domain)}</title>
<style>{_CSS}</style>
</head>
<body>
<header>
  <div class="eyebrow">ReconX &middot; Recon Report</div>
  <h1>Attack Surface Report for <span class="domain">{_esc(domain)}</span></h1>
  <div class="meta">Generated <span>{generated_at}</span> &nbsp;&middot;&nbsp; Sources: crt.sh (<span>{crtsh_count}</span>) + DNS brute force (<span>{brute_force_count}</span>)</div>
  {crtsh_note}
</header>
<div class="container">

  <div class="overview">
    <div class="risk-card">
      {_render_risk_ring(score, risk_color)}
      <div class="risk-label" style="background:{risk_color}22; color:{risk_color}">{risk_text}</div>
    </div>
    <div class="summary-grid">
      {summary_html}
      <div class="severity-bar-wrap">
        <div class="sb-title">Findings by Severity</div>
        <div class="severity-bar">{bar_segments}</div>
        <div class="severity-legend">{legend}</div>
      </div>
    </div>
  </div>

  <h2 class="section">High Severity <span class="count">{severity_counts[SEVERITY_HIGH]}</span></h2>
  {_render_findings([f for f in findings if f.severity == SEVERITY_HIGH])}

  <h2 class="section">Medium Severity <span class="count">{severity_counts[SEVERITY_MEDIUM]}</span></h2>
  {_render_findings([f for f in findings if f.severity == SEVERITY_MEDIUM])}

  <h2 class="section">Low / Informational <span class="count">{severity_counts[SEVERITY_LOW] + severity_counts[SEVERITY_INFO]}</span></h2>
  {_render_findings([f for f in findings if f.severity in (SEVERITY_LOW, SEVERITY_INFO)])}

  <h2 class="section">Live Host Inventory <span class="count">{alive_count}</span></h2>
  {_render_inventory(probes)}

  {_render_dead_hosts(probes)}

</div>
<footer>
  Generated by ReconX — an authorized-use reconnaissance tool. Every finding above is backed by a recorded
  HTTP response or DNS record shown in its evidence line. Only run this against domains you own or have
  explicit written permission to test.
</footer>
</body>
</html>
"""