"""CLI command implementations for scan, results, history, rules, frameworks,
compliance, and report."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import typer
from rich import box
from rich.table import Table

from mijhar.cli.console import console
from mijhar.compliance.assessment import ControlStatus
from mijhar.compliance.registry import FrameworkRegistry
from mijhar.core.config import Platform, get_config
from mijhar.core.scanner import Scanner
from mijhar.database.models import Database
from mijhar.reports import csv_report, html_report, json_report
from mijhar.reports import terminal as term
from mijhar.rules.loader import RuleLoader


def _scanner() -> Scanner:
    return Scanner()


def _db() -> Database:
    return Database(get_config().db_path)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _apply_reviews(assessments, framework_id: str) -> None:
    """Overlay manual reviewer determinations onto automated assessments."""
    reviews = _db().reviews_for_framework(framework_id)
    for assessment in assessments:
        review = reviews.get(assessment.control_id)
        if review:
            try:
                assessment.status = ControlStatus(review["status"])
            except ValueError:
                continue
            assessment.manual_review = True
            assessment.reviewer = review.get("reviewer", "")
            assessment.review_notes = review.get("notes", "")
            assessment.needs_review = False


def _print_framework_assessment(scanner, findings, framework_id: str) -> None:
    """Print the detailed per-control assessment for one framework."""
    try:
        fw, assessments, summary = scanner.assess_framework(
            findings, framework_id, included_rule_ids={f.rule_id for f in findings}
        )
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    _apply_reviews(assessments, framework_id)
    console.print(
        f"[bold cyan]{fw.name}[/bold cyan] [mijhar.subtle]({fw.version})[/mijhar.subtle]"
    )
    if fw.mapping_note:
        console.print(f"[mijhar.subtle]{fw.mapping_note}[/mijhar.subtle]")
    term.print_compliance([summary])
    term.print_controls(assessments)


def _require_scan(scanner: Scanner, scan_id: Optional[str]) -> str:
    resolved = scan_id or scanner.latest_scan_id()
    if not resolved:
        console.print("[yellow]No scans found. Run 'mijhar scan' first.[/yellow]")
        raise typer.Exit(1)
    return resolved


def _resolve_frameworks(framework_ids: Optional[str]) -> Optional[List[str]]:
    """Parse and validate a comma-separated framework selection.

    Returns ``None`` for "all frameworks", or a validated list of framework ids.
    """
    registry = FrameworkRegistry(get_config().frameworks_dir)
    registry.load()
    valid = set(registry.ids())
    if not framework_ids:
        return None
    selected = [f.strip().lower() for f in framework_ids.split(",") if f.strip()]
    for fid in selected:
        if fid not in valid:
            console.print(f"[red]Unknown framework '{fid}'. Available: {', '.join(sorted(valid))}.[/red]")
            raise typer.Exit(1)
    return selected


def scan_command(
    target: str = typer.Option("local", "--target", help="Scan target: local or remote."),
    platform: str = typer.Option(..., "--platform", "-p", help="Target platform: macos or linux."),
    host: Optional[str] = typer.Option(None, "--host", help="Remote host (required for remote targets)."),
    user: Optional[str] = typer.Option(None, "--user", "-u", help="Remote SSH username."),
    port: int = typer.Option(22, "--port", help="Remote SSH port."),
    frameworks: Optional[str] = typer.Option(
        None, "--frameworks",
        help="Comma-separated frameworks to assess (nca-ecc, sama-csf, cis, iso27001). Default: all.",
    ),
    framework: Optional[str] = typer.Option(
        None, "--framework", "-f",
        help="Show detailed compliance for one framework: nca-ecc, sama-csf, cis, iso27001.",
    ),
) -> None:
    """Run a platform-aware configuration security scan."""
    try:
        plat = Platform(platform.lower())
    except ValueError:
        console.print(f"[red]Invalid platform '{platform}'. Use 'macos' or 'linux'.[/red]")
        raise typer.Exit(1)

    framework_ids = _resolve_frameworks(frameworks)

    kwargs: dict = {}
    if target == "remote":
        if not host:
            console.print("[red]--host is required for remote scans.[/red]")
            raise typer.Exit(1)
        if plat is not Platform.LINUX:
            console.print("[red]Remote scanning currently supports Linux targets only.[/red]")
            raise typer.Exit(1)
        kwargs = {"host": host, "user": user, "port": port}
        console.print(
            f"[mijhar.subtle]Connecting to {host} via SSH (key-based, read-only).[/mijhar.subtle]"
        )
    elif target != "local":
        console.print(f"[red]Invalid target '{target}'. Use 'local' or 'remote'.[/red]")
        raise typer.Exit(1)

    scanner = _scanner()
    with console.status("[bold cyan]Running MIJHAR scan..."):
        result = scanner.run(plat, target=target, collector_kwargs=kwargs, framework_ids=framework_ids)

    term.print_scan_summary(result.scan_id, plat.value, result.counts)
    term.print_findings(result.findings)
    term.print_exclusions(result.exclusion_dicts())
    if framework:
        _print_framework_assessment(scanner, result.findings, framework)
    elif result.compliance:
        term.print_compliance(list(result.compliance.values()))


def results_command(
    scan_id: Optional[str] = typer.Option(None, "--scan-id", help="Scan ID (defaults to the latest)."),
) -> None:
    """Show findings for a scan."""
    scanner = _scanner()
    resolved = _require_scan(scanner, scan_id)
    data = scanner.build_report_data(resolved)
    term.print_scan_summary(resolved, data["platform"], data["counts"])
    term.print_findings(data["findings"])


def history_command() -> None:
    """Show scan history."""
    scanner = _scanner()
    scans = scanner.list_scans()
    if not scans:
        console.print("[yellow]No scan history yet.[/yellow]")
        return
    table = Table(title="MIJHAR — Scan History", box=box.ROUNDED, title_style="mijhar.title", header_style="bold cyan")
    for column in ("Scan ID", "Asset", "Platform", "Started", "Status", "Checks", "Passed", "Failed"):
        table.add_column(column)
    for scan in scans:
        table.add_row(
            scan["id"],
            scan["asset_id"],
            scan["platform"] or "-",
            scan["started_at"],
            scan["status"] or "-",
            str(scan["checks_total"]),
            str(scan["passed"]),
            str(scan["failed"]),
        )
    console.print(table)


def rules_list_command() -> None:
    """List all security rules."""
    rules = RuleLoader(get_config().rules_dir).load()
    term.print_rules(rules)


def frameworks_list_command() -> None:
    """List supported compliance frameworks."""
    registry = FrameworkRegistry(get_config().frameworks_dir)
    registry.load()
    term.print_frameworks(registry.list())


def theme_list_command() -> None:
    """List the available visual theme (MIJHAR uses a single consistent theme)."""
    from rich.text import Text

    from mijhar.cli import logo

    table = Table(title="MIJHAR — Visual Theme", box=box.ROUNDED, title_style="mijhar.title", header_style="bold cyan")
    table.add_column("ID", style="mijhar.accent")
    table.add_column("Name")
    table.add_column("Primary (sample)")
    for i in range(logo.count_themes()):
        t = logo.get_theme(i)
        table.add_row(t.id, t.name, Text(t.name, style=t.primary))
    console.print(table)
    console.print("[mijhar.subtle]MIJHAR uses a single Cool Arctic Cyan theme across all screens.[/mijhar.subtle]")


# ---------------------------------------------------------------------------
# Interactive menus (target selection + main menu) live in `cli/menu.py`.
# ---------------------------------------------------------------------------


def about_command() -> None:
    """Show MIJHAR identity, creator, and supported scope."""
    from rich.panel import Panel

    from mijhar import (
        __app_name__,
        __author__,
        __author_linkedin__,
        __slogan__,
        __tagline__,
        __version__,
    )

    body = (
        f"[bold cyan]{__app_name__}[/bold cyan] v{__version__}\n"
        f"[mijhar.accent]{__slogan__}[/mijhar.accent]\n\n"
        f"{__tagline__} — a read-only Technical Security Assessment & GRC framework "
        f"mapping configuration findings to NCA ECC, SAMA CSF, CIS Benchmarks, and "
        f"ISO/IEC 27001:2022.\n\n"
        f"[bold]Created by[/bold] {__author__}\n"
        f"[mijhar.subtle]{__author_linkedin__}[/mijhar.subtle]\n\n"
        f"[bold]Implemented modules:[/bold] macOS, Linux, remote Linux (SSH).\n"
        f"[bold]Planned modules:[/bold] Windows, network devices, cloud (AWS/Azure/GCP), "
        f"containers/Kubernetes, web/API, databases, email/M365."
    )
    console.print(Panel(body, title=f"About {__app_name__}", border_style="mijhar.accent"))


def compliance_command(
    framework: str = typer.Option(..., "--framework", help="Framework id: nca-ecc, sama-csf, cis, iso27001."),
) -> None:
    """Show compliance assessment for a framework (latest scan)."""
    scanner = _scanner()
    resolved = _require_scan(scanner, None)
    findings = scanner.findings_objects_for_scan(resolved)
    _print_framework_assessment(scanner, findings, framework)


def report_command(
    format: str = typer.Option(..., "--format", "-f", help="Report format: json, csv, html."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write report to a file."),
    scan_id: Optional[str] = typer.Option(None, "--scan-id", help="Scan ID (defaults to the latest)."),
) -> None:
    """Generate a report for the latest (or specified) scan."""
    fmt = format.lower()
    if fmt not in ("json", "csv", "html"):
        console.print(f"[red]Invalid format '{format}'. Use json, csv, or html.[/red]")
        raise typer.Exit(1)

    scanner = _scanner()
    resolved = _require_scan(scanner, scan_id)
    data = scanner.build_report_data(resolved)
    findings = data["findings"]
    summary = data["counts"]
    compliance = list(data["compliance"].values())
    exclusions = data.get("exclusions", [])
    scope = {
        "asset": data["asset_id"],
        "platform": data["platform"],
        "started": data["started_at"],
        "ended": data["ended_at"],
    }
    severity = data["severity_distribution"]
    review = data["review"]
    remediation = data["remediation"]

    if fmt == "json":
        content = json_report.report_json(data)
        if output:
            json_report.write_json(Path(output), data)
    elif fmt == "csv":
        content = csv_report.findings_csv(findings)
        if output:
            csv_report.write_csv(Path(output), findings)
    else:
        display_summary = {
            "CHECKS": summary["total"],
            "PASSED": summary["passed"],
            "FAILED": summary["failed"],
            "WARNINGS": summary["warnings"],
            "NOT SUPPORTED": summary.get("not_supported", 0),
            "ERRORS": summary["errors"],
            "EXCLUDED": summary.get("excluded", 0),
        }
        content = html_report.render_html(
            findings, summary=display_summary, compliance=compliance,
            scope=scope, severity=severity, review=review, remediation=remediation,
            exclusions=exclusions,
        )
        if output:
            html_report.write_html(
                Path(output), findings, summary=display_summary, compliance=compliance,
                scope=scope, severity=severity, review=review, remediation=remediation,
                exclusions=exclusions,
            )

    if output:
        console.print(f"[green]Report written to {output}[/green]")
    else:
        # Machine-readable output must be written raw (no Rich wrapping/markup).
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")


def _valid_framework_control(framework_id: str, control_id: str) -> bool:
    registry = FrameworkRegistry(get_config().frameworks_dir)
    registry.load()
    framework = registry.get(framework_id)
    return framework is not None and framework.get_control(control_id) is not None


def review_set_command(
    framework: str = typer.Option(..., "--framework", help="Framework id (nca-ecc, sama-csf, cis, iso27001)."),
    control: str = typer.Option(..., "--control", help="Control or sub-control ID."),
    status: str = typer.Option(..., "--status", help="Manual status: compliant, non_compliant, partially_compliant, not_applicable."),
    reviewer: str = typer.Option("", "--reviewer", help="Reviewer name."),
    notes: str = typer.Option("", "--notes", help="Review justification/notes."),
) -> None:
    """Record a manual reviewer determination for a framework control."""
    valid = {s.value for s in ControlStatus}
    if status not in valid:
        console.print(f"[red]Invalid status '{status}'. Use one of {sorted(valid)}.[/red]")
        raise typer.Exit(1)
    if not _valid_framework_control(framework, control):
        console.print(f"[red]Unknown control '{control}' in framework '{framework}'.[/red]")
        raise typer.Exit(1)
    with _db() as db:
        review_id = db.upsert_review(framework, control, status, reviewer, notes, _now_iso())
    console.print(f"[green]Review recorded for {framework}:{control} -> {status}[/green] ({review_id})")


def review_list_command(
    framework: Optional[str] = typer.Option(None, "--framework", help="Filter by framework id."),
) -> None:
    """List manual reviewer determinations."""
    with _db() as db:
        reviews = db.list_reviews(framework)
    if not reviews:
        console.print("[yellow]No manual reviews yet. Use 'mijhar review set'.[/yellow]")
        return
    table = Table(title="MIJHAR — Manual Reviews", box=box.ROUNDED, title_style="mijhar.title", header_style="bold cyan")
    for column in ("Framework", "Control", "Status", "Reviewer", "Notes", "When"):
        table.add_column(column)
    for review in reviews:
        table.add_row(
            review["framework_id"],
            review["control_id"],
            review["status"],
            review["reviewer"] or "-",
            review["notes"] or "-",
            review["created_at"],
        )
    console.print(table)


def remediations_list_command(
    all: bool = typer.Option(False, "--all", help="Include closed remediations."),
) -> None:
    """List remediation items (open by default)."""
    with _db() as db:
        remediations = db.list_remediations(open_only=not all)
    if not remediations:
        console.print("[yellow]No remediation items.[/yellow]")
        return
    table = Table(title="MIJHAR — Remediation Tracking", box=box.ROUNDED, title_style="mijhar.title", header_style="bold cyan")
    for column in ("ID", "Finding", "Recommendation", "Status"):
        table.add_column(column)
    for item in remediations:
        table.add_row(item["id"], item["finding_id"], item["recommendation"], item["status"])
    console.print(table)


def remediations_close_command(
    id: str = typer.Option(..., "--id", help="Remediation record ID."),
) -> None:
    """Mark a remediation item as closed."""
    with _db() as db:
        closed = db.close_remediation(id)
    if closed:
        console.print(f"[green]Remediation {id} closed.[/green]")
    else:
        console.print(f"[red]Remediation {id} not found.[/red]")
        raise typer.Exit(1)


def evidence_verify_command() -> None:
    """Verify the integrity (SHA-256) of all stored evidence."""
    with _db() as db:
        tampered = db.verify_evidence()
    if not tampered:
        console.print("[green]All stored evidence passes integrity verification.[/green]")
        return
    console.print(f"[red]{len(tampered)} evidence record(s) FAILED integrity verification:[/red]")
    table = Table(box=box.ROUNDED, header_style="bold cyan")
    for column in ("ID", "Finding", "Key", "Stored SHA-256"):
        table.add_column(column)
    for record in tampered:
        table.add_row(record["id"], record["finding_id"], record["key"], record["sha256"][:16] + "…")
    console.print(table)
    raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Remediation tracking (statuses / owner / due date).
# ---------------------------------------------------------------------------
_REMEDIATION_STATUSES = {"open", "in_progress", "pending_validation", "resolved", "accepted_risk"}
_REVIEW_DECISIONS = {"accept", "reject", "needs_evidence"}
_RISK_TREATMENTS = {"mitigate", "accept", "transfer", "avoid"}


def remediations_set_command(
    id: str = typer.Option(..., "--id", help="Remediation record ID."),
    status: str = typer.Option(..., "--status", help="open, in_progress, pending_validation, resolved, accepted_risk."),
    owner: str = typer.Option("", "--owner", help="Remediation owner."),
    due: str = typer.Option("", "--due", help="Target completion date (YYYY-MM-DD)."),
) -> None:
    """Update a remediation item's status, owner, and target date."""
    if status not in _REMEDIATION_STATUSES:
        console.print(f"[red]Invalid status '{status}'. Use one of {sorted(_REMEDIATION_STATUSES)}.[/red]")
        raise typer.Exit(1)
    with _db() as db:
        updated = db.set_remediation_status(id, status, owner, due)
    if updated:
        console.print(f"[green]Remediation {id} -> {status}[/green]")
    else:
        console.print(f"[red]Remediation {id} not found.[/red]")
        raise typer.Exit(1)


def review_finding_command(
    finding_id: str = typer.Option(..., "--finding", help="Finding ID."),
    decision: str = typer.Option(..., "--decision", help="accept, reject, or needs_evidence."),
    reviewer: str = typer.Option("", "--reviewer", help="Reviewer name."),
    comment: str = typer.Option("", "--comment", help="Review comment."),
) -> None:
    """Record a reviewer decision on a finding (accept/reject/request evidence)."""
    if decision not in _REVIEW_DECISIONS:
        console.print(f"[red]Invalid decision '{decision}'. Use one of {sorted(_REVIEW_DECISIONS)}.[/red]")
        raise typer.Exit(1)
    with _db() as db:
        review_id = db.add_finding_review(finding_id, decision, reviewer, comment, _now_iso())
    console.print(f"[green]Finding {finding_id} -> {decision}[/green] ({review_id})")


def risk_list_command() -> None:
    """List risk records and treatment decisions."""
    with _db() as db:
        records = db.list_risk_records()
    if not records:
        console.print("[yellow]No risk records yet. Use 'mijhar risk accept'.[/yellow]")
        return
    table = Table(title="MIJHAR — Risk Records", box=box.ROUNDED, title_style="mijhar.title", header_style="bold cyan")
    for column in ("Finding", "Severity", "Treatment", "Status", "Accepted By", "Notes"):
        table.add_column(column)
    for r in records:
        table.add_row(r["finding_id"], r["severity"], r["treatment"], r["status"], r["accepted_by"] or "-", r["notes"] or "-")
    console.print(table)


def risk_accept_command(
    finding_id: str = typer.Option(..., "--finding", help="Finding ID."),
    severity: str = typer.Option("high", "--severity", help="Risk severity (critical/high/medium/low/informational)."),
    notes: str = typer.Option("", "--notes", help="Acceptance justification."),
    accepted_by: str = typer.Option("", "--accepted-by", help="Approving person/role."),
) -> None:
    """Record a human-approved risk acceptance for a finding."""
    with _db() as db:
        record_id = db.add_risk_record(finding_id, severity, "accept", "accepted", accepted_by, notes, _now_iso())
    console.print(f"[green]Risk acceptance recorded for {finding_id}[/green] ({record_id})")


def evidence_export_command(
    format: str = typer.Option("json", "--format", "-f", help="Export format: json or csv."),
    output: str = typer.Option(..., "--output", "-o", help="Output file path."),
) -> None:
    """Export stored evidence to JSON or CSV."""
    with _db() as db:
        evidence = db.list_evidence()
    if not evidence:
        console.print("[yellow]No evidence stored yet.[/yellow]")
        raise typer.Exit(1)
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    if format == "json":
        json_report.write_json(path, evidence)
    elif format == "csv":
        csv_report.write_csv(path, evidence)
    else:
        console.print("[red]Invalid format. Use json or csv.[/red]")
        raise typer.Exit(1)
    console.print(f"[green]Exported {len(evidence)} evidence record(s) to {output}[/green]")


# ---------------------------------------------------------------------------
# Intelligence & framework data management.
# ---------------------------------------------------------------------------
def _intel():
    from mijhar.intel import IntelManager

    return IntelManager()


def intel_sources_command() -> None:
    """List supported intelligence/framework data sources."""
    sources = _intel().sources()
    table = Table(title="MIJHAR — Intelligence Sources", box=box.ROUNDED, title_style="mijhar.title", header_style="bold cyan")
    for column in ("ID", "Name", "Type", "Access", "License"):
        table.add_column(column)
    for s in sources:
        table.add_row(s["id"], s["name"], s["type"], s["access"], s["license"])
    console.print(table)


def intel_status_command(
    source: Optional[str] = typer.Option(None, "--source", help="Filter by source id."),
) -> None:
    """Show locally stored intelligence datasets and their validation status."""
    datasets = _intel().status(source)
    if not datasets:
        console.print("[yellow]No intelligence datasets stored. Use 'mijhar intel import'.[/yellow]")
        return
    table = Table(title="MIJHAR — Intelligence Status", box=box.ROUNDED, title_style="mijhar.title", header_style="bold cyan")
    for column in ("Source", "Version", "Records", "Retrieved", "Validated", "Active"):
        table.add_column(column)
    for d in datasets:
        table.add_row(
            d["source"], d["version"], str(d["record_count"]), d["retrieved_at"],
            "yes" if d["validated"] else "no", "yes" if d["active"] else "no",
        )
    console.print(table)


def intel_import_command(
    source: str = typer.Option(..., "--source", help="Source id (see 'mijhar intel sources')."),
    file: str = typer.Option(..., "--file", help="Local JSON dataset file."),
    version: str = typer.Option("", "--version", help="Dataset version (defaults to the file's 'version' field or timestamp)."),
) -> None:
    """Import a local JSON dataset (read-only; no scripts/binaries executed)."""
    try:
        result = _intel().import_file(source, file, version)
    except (ValueError, OSError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    console.print(
        f"[green]Imported {result['record_count']} record(s) for {source} "
        f"(version {result['version']}).[/green]"
    )
    console.print("[mijhar.subtle]Dataset is unvalidated — review with 'mijhar intel validate'.[/mijhar.subtle]")


def intel_update_command(
    source: str = typer.Option(..., "--source", help="Source id to update."),
) -> None:
    """Show how to update a source (no automatic download)."""
    try:
        info = _intel().update(source)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    console.print(f"[bold cyan]{source}[/bold cyan] — {info['access']}")
    console.print(f"[mijhar.subtle]{info['guidance']}[/mijhar.subtle]")


def intel_validate_command(
    source: str = typer.Option(..., "--source", help="Source id."),
    version: str = typer.Option(..., "--version", help="Dataset version to validate."),
    by: str = typer.Option("", "--by", help="Reviewer name."),
) -> None:
    """Mark a dataset as validated after human review."""
    if _intel().validate(source, version, by):
        console.print(f"[green]Validated {source}:{version}.[/green]")
    else:
        console.print(f"[red]Dataset {source}:{version} not found.[/red]")
        raise typer.Exit(1)


def intel_rollback_command(
    source: str = typer.Option(..., "--source", help="Source id."),
) -> None:
    """Restore the previous dataset version for a source."""
    version = _intel().rollback(source)
    if version:
        console.print(f"[green]Rolled back {source} to version {version}.[/green]")
    else:
        console.print("[yellow]No previous version to roll back to.[/yellow]")


def intel_history_command() -> None:
    """Show intelligence update history."""
    updates = _intel().history()
    if not updates:
        console.print("[yellow]No update history.[/yellow]")
        return
    table = Table(title="MIJHAR — Intelligence Update History", box=box.ROUNDED, title_style="mijhar.title", header_style="bold cyan")
    for column in ("Source", "Action", "Version", "When"):
        table.add_column(column)
    for u in updates:
        table.add_row(u["source"], u["action"], u["version"], u["at"])
    console.print(table)
