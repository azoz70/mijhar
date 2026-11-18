"""HTML report generation (self-contained, no external assets)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Template

from mijhar import __app_name__, __author__, __author_linkedin__, __slogan__, __tagline__, __version__
from mijhar.reports import finding_dicts

_SEVERITY_CLASS = {
    "critical": "sev-critical",
    "high": "sev-high",
    "medium": "sev-medium",
    "low": "sev-low",
    "informational": "sev-info",
}
_STATUS_CLASS = {
    "pass": "st-pass",
    "fail": "st-fail",
    "warning": "st-warning",
    "not_supported": "st-na",
    "not_applicable": "st-na",
    "error": "st-error",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{ title }}</title>
<style>
:root { color-scheme: dark; }
body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif; margin: 0; background: #0b0f14; color: #d8dee9; }
header { background: #0f1720; border-bottom: 1px solid #1f2a36; padding: 24px 32px; }
h1 { margin: 0; font-size: 22px; letter-spacing: 2px; color: #22d3ee; }
.tagline { color: #6b7a8a; margin: 4px 0 0; }
main { padding: 24px 32px; }
h2 { color: #22d3ee; font-size: 15px; letter-spacing: 1px; text-transform: uppercase; margin: 28px 0 12px; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #1f2a36; vertical-align: top; }
th { color: #9fb3c8; font-weight: 600; background: #0f1720; }
.summary { display: flex; gap: 16px; flex-wrap: wrap; }
.stat { background: #0f1720; border: 1px solid #1f2a36; border-radius: 8px; padding: 14px 18px; min-width: 90px; }
.stat .n { font-size: 22px; font-weight: 700; }
.stat .l { color: #6b7a8a; font-size: 12px; text-transform: uppercase; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 700; }
.sev-critical { background: #7f1d1d; color: #fecaca; }
.sev-high { background: #991b1b; color: #fecaca; }
.sev-medium { background: #854d0e; color: #fde68a; }
.sev-low { background: #1e3a8a; color: #bfdbfe; }
.sev-info { background: #134e4a; color: #99f6e4; }
.st-pass { background: #14532d; color: #bbf7d0; }
.st-fail { background: #7f1d1d; color: #fecaca; }
.st-warning { background: #854d0e; color: #fde68a; }
.st-na { background: #1f2937; color: #9ca3af; }
.st-error { background: #581c87; color: #e9d5ff; }
.note { color: #6b7a8a; font-size: 12px; }
footer { color: #475569; font-size: 12px; padding: 20px 32px; border-top: 1px solid #1f2a36; }
</style>
</head>
<body>
<header>
  <h1>{{ app_name }}</h1>
  <p class="tagline">v{{ version }} — {{ tagline }}</p>
</header>
<main>
  {% if scope %}
  <h2>Assessment Scope</h2>
  <table>
    <tbody>
      <tr><th>Asset</th><td>{{ scope.asset }}</td><th>Platform</th><td>{{ scope.platform | upper }}</td></tr>
      <tr><th>Started</th><td>{{ scope.started }}</td><th>Ended</th><td>{{ scope.ended }}</td></tr>
    </tbody>
  </table>
  {% endif %}

  <h2>Scan Summary</h2>
  <div class="summary">
    {% for label, value in summary.items() %}
    <div class="stat"><div class="n">{{ value }}</div><div class="l">{{ label }}</div></div>
    {% endfor %}
  </div>

  {% if severity %}
  <h2>Severity Distribution</h2>
  <div class="summary">
    {% for label, value in severity.items() %}
    <div class="stat"><div class="n">{{ value }}</div><div class="l">{{ label }}</div></div>
    {% endfor %}
  </div>
  {% endif %}

  {% if review %}
  <h2>Review Status</h2>
  <p>Findings reviewed: <strong>{{ review.reviewed }}</strong> of {{ review.total }}. Unreviewed findings require human validation.</p>
  {% endif %}

  {% if remediation %}
  <h2>Remediation Tracking</h2>
  <div class="summary">
    {% for label, value in remediation.items() %}
    <div class="stat"><div class="n">{{ value }}</div><div class="l">{{ label }}</div></div>
    {% endfor %}
  </div>
  {% endif %}

  <h2>Findings</h2>
  <table>
    <thead><tr><th>ID</th><th>Configuration</th><th>Severity</th><th>Status</th><th>Observed</th><th>Framework</th></tr></thead>
    <tbody>
    {% for f in findings %}
      <tr>
        <td>{{ f.rule_id }}</td>
        <td>{{ f.title }}</td>
        <td><span class="badge {{ severity_class(f.severity) }}">{{ f.severity | upper }}</span></td>
        <td><span class="badge {{ status_class(f.status) }}">{{ f.status | upper }}</span></td>
        <td>{{ f.observed_value }}</td>
        <td class="note">{{ framework_cell(f) }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>

  {% if compliance %}
  <h2>Compliance</h2>
  <table>
    <thead><tr><th>Framework</th><th>Applicable</th><th>Compliant</th><th>Non-Compliant</th><th>Partial</th><th>Not Assessed</th><th>Compliance %</th></tr></thead>
    <tbody>
    {% for c in compliance %}
      <tr>
        <td>{{ c.framework_id }}</td>
        <td>{{ c.applicable_controls }}</td>
        <td>{{ c.compliant }}</td>
        <td>{{ c.non_compliant }}</td>
        <td>{{ c.partially_compliant }}</td>
        <td>{{ c.not_assessed }}</td>
        <td>{{ c.compliance_pct }}%</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}

  {% if exclusions %}
  <h2>Excluded Checks (Scope Transparency)</h2>
  <table>
    <thead><tr><th>Rule</th><th>Title</th><th>Reason</th><th>Detail</th></tr></thead>
    <tbody>
    {% for e in exclusions %}
      <tr>
        <td class="note">{{ e.rule_id }}</td>
        <td>{{ e.title }}</td>
        <td>{{ e.reason }}</td>
        <td class="note">{{ e.detail }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}
  <p class="note">Automated technical assessment only — not a definitive compliance determination. Non-compliant and partial results require human review.</p>
</main>
<footer>{{ app_name }} v{{ version }} — Created by <a href="{{ linkedin }}" target="_blank" rel="noopener">{{ author }}</a></footer>
</body>
</html>
"""

_template = Template(HTML_TEMPLATE)


def _framework_cell(finding: dict) -> str:
    refs = finding.get("framework_refs") or {}
    if not refs:
        return "-"
    parts = []
    for framework, ids in refs.items():
        joined = ", ".join(ids) if isinstance(ids, list) else str(ids)
        parts.append(f"{framework}: {joined}")
    return "; ".join(parts)


def render_html(
    findings: List[Any],
    summary: Optional[Dict[str, Any]] = None,
    compliance: Optional[List[Any]] = None,
    title: Optional[str] = None,
    scope: Optional[Dict[str, Any]] = None,
    severity: Optional[Dict[str, int]] = None,
    review: Optional[Dict[str, int]] = None,
    remediation: Optional[Dict[str, int]] = None,
    exclusions: Optional[List[Dict[str, Any]]] = None,
) -> str:
    summaries = [c.as_dict() if hasattr(c, "as_dict") else c for c in (compliance or [])]
    return _template.render(
        app_name=__app_name__,
        version=__version__,
        tagline=__tagline__,
        slogan=__slogan__,
        author=__author__,
        linkedin=__author_linkedin__,
        title=title or f"{__app_name__} Security Assessment Report",
        summary=summary or {},
        scope=scope or {},
        severity=severity or {},
        review=review or {},
        remediation=remediation or {},
        findings=finding_dicts(findings),
        compliance=summaries,
        exclusions=exclusions or [],
        severity_class=lambda s: _SEVERITY_CLASS.get(s, "sev-info"),
        status_class=lambda s: _STATUS_CLASS.get(s, "st-na"),
        framework_cell=_framework_cell,
    )


def write_html(
    path: Path | str,
    findings: List[Any],
    summary: Optional[Dict[str, Any]] = None,
    compliance: Optional[List[Any]] = None,
    scope: Optional[Dict[str, Any]] = None,
    severity: Optional[Dict[str, int]] = None,
    review: Optional[Dict[str, int]] = None,
    remediation: Optional[Dict[str, int]] = None,
    exclusions: Optional[List[Dict[str, Any]]] = None,
) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        render_html(findings, summary, compliance, scope=scope, severity=severity, review=review, remediation=remediation, exclusions=exclusions),
        encoding="utf-8",
    )
