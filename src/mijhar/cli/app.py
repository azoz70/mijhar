"""MIJHAR command-line application definition.

The Typer app registers every user-facing command. The callback prints the
startup identity screen (to stderr) before subcommands, opens the interactive
main menu when MIJHAR is launched with no subcommand, and handles
``--version`` / ``--no-banner``.
"""

from __future__ import annotations

import typer
from mijhar import __app_name__, __author__, __author_linkedin__, __slogan__, __tagline__, __version__
from mijhar.cli import logo
from mijhar.cli.commands import (
    about_command,
    compliance_command,
    evidence_export_command,
    evidence_verify_command,
    frameworks_list_command,
    history_command,
    intel_history_command,
    intel_import_command,
    intel_rollback_command,
    intel_sources_command,
    intel_status_command,
    intel_update_command,
    intel_validate_command,
    remediations_close_command,
    remediations_list_command,
    remediations_set_command,
    report_command,
    results_command,
    review_finding_command,
    review_list_command,
    review_set_command,
    risk_accept_command,
    risk_list_command,
    rules_list_command,
    scan_command,
    theme_list_command,
)
from mijhar.cli.console import console
from mijhar.cli.menu import menu_command
from mijhar.cli.system_info import system_info_command

app = typer.Typer(
    name="mijhar",
    help=(
        f"{__app_name__} — Technical Security Assessment Framework.\n{__slogan__}"
    ),
    add_completion=False,
    no_args_is_help=False,
    rich_markup_mode="rich",
)


@app.callback(invoke_without_command=True)
def _callback(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-V", help="Show the MIJHAR version and exit."
    ),
    no_banner: bool = typer.Option(
        False, "--no-banner", help="Suppress the startup identity screen."
    ),
) -> None:
    """MIJHAR — See What Others Miss."""
    if version:
        console.print(f"[mijhar.title]{__app_name__}[/mijhar.title] [bold cyan]{__version__}[/bold cyan]")
        console.print(f"[mijhar.accent]{__slogan__}[/mijhar.accent]")
        console.print(f"[mijhar.subtle]Created by {__author__} · {__author_linkedin__}[/mijhar.subtle]")
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        # Bare `mijhar` opens the interactive main menu (never auto-starts a scan).
        menu_command()
        raise typer.Exit()

    if not no_banner:
        logo.print_startup()


# Top-level commands
app.command(name="system-info", help="Display system and MIJHAR environment information.")(
    system_info_command
)
app.command(name="about", help="About MIJHAR, its creator, and supported scope.")(about_command)
app.command(name="menu", help="Open the interactive main menu.")(menu_command)
app.command(name="scan", help="Run a configuration security scan.")(scan_command)
app.command(name="results", help="Show findings for a scan (default: latest).")(results_command)
app.command(name="history", help="Show scan history.")(history_command)
app.command(name="compliance", help="Show a framework compliance assessment.")(compliance_command)
app.command(name="report", help="Generate a JSON, CSV, or HTML report.")(report_command)

# Sub-app: rules
rules_app = typer.Typer(help="Manage security rules.", no_args_is_help=True)
rules_app.command(name="list", help="List all security rules.")(rules_list_command)
app.add_typer(rules_app, name="rules")

# Sub-app: frameworks
frameworks_app = typer.Typer(help="Manage compliance frameworks.", no_args_is_help=True)
frameworks_app.command(name="list", help="List supported compliance frameworks.")(frameworks_list_command)
app.add_typer(frameworks_app, name="frameworks")

# Sub-app: review (manual assessment workflow)
review_app = typer.Typer(help="Manual reviewer assessment overrides.", no_args_is_help=True)
review_app.command(name="set", help="Record a manual control determination.")(review_set_command)
review_app.command(name="list", help="List manual reviewer determinations.")(review_list_command)
review_app.command(name="finding", help="Accept/reject/request-evidence on a finding.")(review_finding_command)
app.add_typer(review_app, name="review")

# Sub-app: remediations
remediations_app = typer.Typer(help="Remediation tracking.", no_args_is_help=True)
remediations_app.command(name="list", help="List remediation items.")(remediations_list_command)
remediations_app.command(name="set", help="Set status/owner/due-date on a remediation item.")(remediations_set_command)
remediations_app.command(name="close", help="Mark a remediation item as resolved.")(remediations_close_command)
app.add_typer(remediations_app, name="remediations")

# Sub-app: risk
risk_app = typer.Typer(help="Risk records and treatment decisions.", no_args_is_help=True)
risk_app.command(name="list", help="List risk records.")(risk_list_command)
risk_app.command(name="accept", help="Record a human-approved risk acceptance.")(risk_accept_command)
app.add_typer(risk_app, name="risk")

# Sub-app: evidence
evidence_app = typer.Typer(help="Evidence integrity verification and export.", no_args_is_help=True)
evidence_app.command(name="verify", help="Verify SHA-256 integrity of stored evidence.")(evidence_verify_command)
evidence_app.command(name="export", help="Export stored evidence to JSON/CSV.")(evidence_export_command)
app.add_typer(evidence_app, name="evidence")

# Sub-app: theme
theme_app = typer.Typer(help="Visual theme selection.", no_args_is_help=True)
theme_app.command(name="list", help="List available visual themes.")(theme_list_command)
app.add_typer(theme_app, name="theme")

# Sub-app: intel (intelligence & framework data management)
intel_app = typer.Typer(help="Intelligence and framework dataset management.", no_args_is_help=True)
intel_app.command(name="sources", help="List supported data sources.")(intel_sources_command)
intel_app.command(name="status", help="Show stored datasets and validation status.")(intel_status_command)
intel_app.command(name="import", help="Import a local JSON dataset.")(intel_import_command)
intel_app.command(name="update", help="Show how to update a source.")(intel_update_command)
intel_app.command(name="validate", help="Mark a dataset as validated.")(intel_validate_command)
intel_app.command(name="rollback", help="Restore the previous dataset version.")(intel_rollback_command)
intel_app.command(name="history", help="Show update history.")(intel_history_command)
app.add_typer(intel_app, name="intel")
