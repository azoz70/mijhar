"""Rich terminal reporting: scan summary and findings tables."""

from __future__ import annotations

from typing import Any, Dict, List

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mijhar.cli.console import (
    console,
    severity_label,
    status_label,
    style_for_severity,
    style_for_status,
)
from mijhar.core.config import Status
from mijhar.reports import finding_dicts

_REASON_LABEL = {
    "platform_incompatible": "platform",
    "not_assessable": "not-assessable",
    "missing_prerequisite": "no-prereq",
    "unsupported": "unsupported",
    "outside_scope": "out-of-scope",
    "disabled": "disabled",
}


def _reason_label(reason: str) -> str:
    key = reason.split(":", 1)[0].strip()
    return _REASON_LABEL.get(key, key)


def _framework_cell(finding: dict) -> str:
    refs = finding.get("framework_refs") or {}
    if not refs:
        return "-"
    parts = []
    for framework, control_ids in refs.items():
        ids = ", ".join(control_ids) if isinstance(control_ids, list) else str(control_ids)
        parts.append(f"{framework}: {ids}")
    return "; ".join(parts)


def findings_table(findings: List[Any]) -> Table:
    """Build a Rich table of findings (ID | Configuration | Severity | Status | Framework)."""
    table = Table(
        title="MIJHAR — Security Findings",
        box=box.ROUNDED,
        title_style="mijhar.title",
        header_style="bold cyan",
        border_style="mijhar.subtle",
    )
    table.add_column("ID", style="mijhar.subtle", no_wrap=True)
    table.add_column("Configuration", style="white")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Framework", style="mijhar.subtle")

    for finding in finding_dicts(findings):
        severity = finding.get("severity", "")
        status = finding.get("status", "")
        table.add_row(
            finding.get("rule_id", finding.get("id", "")),
            finding.get("title", ""),
            Text(severity_label(severity), style=style_for_severity(severity)),
            Text(status_label(status), style=style_for_status(status)),
            _framework_cell(finding),
        )
    return table


def scan_summary_panel(scan_id: str, platform: str, counts: Dict[str, int]) -> Panel:
    """Build the final scan summary panel."""
    body = (
        f"[bold]SYSTEM[/]        : {platform.upper()}\n"
        f"[bold]SCAN ID[/]       : {scan_id}\n"
        f"[bold]SCAN STATUS[/]   : [mijhar.pass]COMPLETED[/mijhar.pass]\n"
        f"[bold]CHECKS RUN[/]    : {counts.get('total', 0)}\n"
        f"[bold]PASSED[/]        : [mijhar.pass]{counts.get('passed', 0)}[/mijhar.pass]\n"
        f"[bold]FAILED[/]        : [mijhar.fail]{counts.get('failed', 0)}[/mijhar.fail]\n"
        f"[bold]WARNINGS[/]      : [mijhar.warning]{counts.get('warnings', 0)}[/mijhar.warning]\n"
        f"[bold]NOT SUPPORTED[/] : [mijhar.not_supported]{counts.get('not_supported', 0)}[/mijhar.not_supported]\n"
        f"[bold]ERRORS[/]        : [mijhar.error]{counts.get('errors', 0)}[/mijhar.error]\n"
        f"[bold]EXCLUDED[/]      : [mijhar.subtle]{counts.get('excluded', 0)}[/mijhar.subtle]"
    )
    return Panel(body, title="MIJHAR SECURITY ASSESSMENT", title_align="left", border_style="mijhar.primary")


def exclusions_table(exclusions: List[Dict[str, Any]]) -> Table:
    """Build a Rich table of excluded checks with their reasons."""
    table = Table(
        title="MIJHAR — Excluded Checks (Scope Transparency)",
        box=box.ROUNDED,
        title_style="mijhar.title",
        header_style="bold cyan",
        border_style="mijhar.subtle",
    )
    table.add_column("Rule", style="mijhar.subtle", no_wrap=True)
    table.add_column("Title", style="white")
    table.add_column("Reason", style="mijhar.accent", no_wrap=True)
    table.add_column("Detail", style="mijhar.subtle")
    for exc in exclusions:
        table.add_row(
            exc.get("rule_id", ""),
            exc.get("title", ""),
            exc.get("reason", ""),
            exc.get("detail", ""),
        )
    return table


def print_exclusions(exclusions: List[Dict[str, Any]]) -> None:
    if exclusions:
        console.print(exclusions_table(exclusions))


def compliance_table(summaries: List[Any]) -> Table:
    """Build a Rich table of per-framework compliance summaries."""
    table = Table(
        title="MIJHAR — Compliance Overview",
        box=box.ROUNDED,
        title_style="mijhar.title",
        header_style="bold cyan",
        border_style="mijhar.subtle",
    )
    columns = [
        "Framework",
        "Applicable",
        "Compliant",
        "Non-Compliant",
        "Partial",
        "Not Assessed",
        "Compliance %",
        "Evidence %",
    ]
    for column in columns:
        table.add_column(column, no_wrap=True)

    for summary in summaries:
        data = summary.as_dict() if hasattr(summary, "as_dict") else summary
        table.add_row(
            data.get("framework_id", ""),
            str(data.get("applicable_controls", 0)),
            f"[green]{data.get('compliant', 0)}[/green]",
            f"[red]{data.get('non_compliant', 0)}[/red]",
            f"[yellow]{data.get('partially_compliant', 0)}[/yellow]",
            str(data.get("not_assessed", 0)),
            f"{data.get('compliance_pct', 0)}%",
            f"{data.get('evidence_coverage_pct', 0)}%",
        )
    return table


def frameworks_table(frameworks: List[Any]) -> Table:
    """Build a Rich table listing registered frameworks."""
    table = Table(
        title="MIJHAR — Supported Compliance Frameworks",
        box=box.ROUNDED,
        title_style="mijhar.title",
        header_style="bold cyan",
        border_style="mijhar.subtle",
    )
    table.add_column("ID", style="mijhar.accent")
    table.add_column("Name", style="white")
    table.add_column("Version")
    table.add_column("Controls")
    for framework in frameworks:
        table.add_row(
            framework.id,
            framework.name,
            framework.version,
            str(len(framework.controls)),
        )
    return table


def print_findings(findings: List[Any]) -> None:
    console.print(findings_table(findings))


def print_scan_summary(scan_id: str, platform: str, counts: Dict[str, int]) -> None:
    console.print(scan_summary_panel(scan_id, platform, counts))


def print_compliance(summaries: List[Any]) -> None:
    console.print(compliance_table(summaries))


def print_frameworks(frameworks: List[Any]) -> None:
    console.print(frameworks_table(frameworks))


def rules_table(rules: List[Any]) -> Table:
    """Build a Rich table of loaded rules."""
    table = Table(
        title="MIJHAR — Security Rules",
        box=box.ROUNDED,
        title_style="mijhar.title",
        header_style="bold cyan",
        border_style="mijhar.subtle",
    )
    table.add_column("ID", style="mijhar.accent", no_wrap=True)
    table.add_column("Title", style="white")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Platforms")
    table.add_column("Check")
    for rule in rules:
        check = f"{rule.check.fact} {rule.check.operator}"
        table.add_row(
            rule.id,
            rule.title,
            Text(severity_label(rule.severity.value), style=style_for_severity(rule.severity.value)),
            ", ".join(p.value for p in rule.platforms),
            check,
        )
    return table


def controls_table(assessments: List[Any]) -> Table:
    """Build a Rich table of per-control assessment status."""
    table = Table(
        title="MIJHAR — Control Assessment",
        box=box.ROUNDED,
        title_style="mijhar.title",
        header_style="bold cyan",
        border_style="mijhar.subtle",
    )
    table.add_column("Control", style="mijhar.accent")
    table.add_column("Title", style="white")
    table.add_column("Status", no_wrap=True)
    table.add_column("Pass", no_wrap=True)
    table.add_column("Fail", no_wrap=True)
    table.add_column("Warn", no_wrap=True)
    table.add_column("Review", no_wrap=True)
    table.add_column("Manual", no_wrap=True)

    status_style = {
        "compliant": "mijhar.pass",
        "non_compliant": "mijhar.fail",
        "partially_compliant": "mijhar.warning",
        "not_assessed": "mijhar.na",
        "not_applicable": "mijhar.na",
    }
    for assessment in assessments:
        status_text = assessment.status.value
        if getattr(assessment, "manual_review", False):
            status_text += " (manual)"
        # Surface *why* an excluded control was left out (platform-incompatible,
        # unsupported, non-technical, ...) instead of a bare "not_applicable".
        reason = getattr(assessment, "excluded_reason", "")
        if getattr(assessment, "excluded", False) and reason:
            short = _reason_label(reason)
            status_text = f"{status_text} ({short})"
        table.add_row(
            assessment.control_id,
            assessment.title,
            Text(status_text, style=status_style.get(assessment.status.value, "")),
            str(assessment.pass_count),
            str(assessment.fail_count),
            str(assessment.warning_count),
            "Y" if assessment.needs_review else "",
            "Y" if getattr(assessment, "manual_review", False) else "",
        )
    return table


def print_rules(rules: List[Any]) -> None:
    console.print(rules_table(rules))


def print_controls(assessments: List[Any]) -> None:
    console.print(controls_table(assessments))
