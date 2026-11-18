"""MIJHAR interactive main menu.

The main menu is the primary entry point: it shows the startup identity, then
waits for the user to choose one of eight options. No security scan is ever
started automatically, and every option maps to real functionality.
"""

from __future__ import annotations

from typing import List, Optional

from rich import box
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from mijhar import __app_name__, __author__, __author_linkedin__, __slogan__, __version__
from mijhar.cli.console import PRIMARY, SECONDARY, SUPPORTING, TEXT, console
from mijhar.cli.logo import PRODUCT_DESCRIPTION, print_startup
from mijhar.compliance.registry import FrameworkRegistry
from mijhar.core.config import (
    IMPLEMENTED_MODULES,
    PLANNED_MODULES,
    Platform,
    detect_platform,
    get_config,
    implemented_module_count,
    implemented_platform_count,
)

_MENU = [
    ("Start Security Assessment", "Select a target, choose framework(s), detect the platform, and run applicable checks."),
    ("Supported Platforms & Scan Types", "Show implemented and planned assessment platforms and modules."),
    ("Framework Coverage", "Explore supported frameworks, controls, and mappings."),
    ("View Previous Assessments", "Review past scans, findings, evidence, and summaries."),
    ("Remediation & Findings", "Review findings, severity, fixes, and remediation progress."),
    ("Help & Usage Guide", "Explain what MIJHAR does and how to use it."),
    ("About MIJHAR", "Product description, version, creator, and LinkedIn profile."),
    ("Exit", "Leave MIJHAR."),
]


def menu_table() -> Table:
    table = Table(
        title="MIJHAR — Main Menu",
        box=box.ROUNDED,
        title_style="bold " + PRIMARY,
        header_style="bold " + SECONDARY,
        border_style=SUPPORTING,
    )
    table.add_column("#", style=SUPPORTING, no_wrap=True, justify="right")
    table.add_column("Option", style=TEXT)
    table.add_column("Description", style=SUPPORTING)
    for idx, (name, desc) in enumerate(_MENU, start=1):
        table.add_row(str(idx), name, desc)
    return table


def _framework_ids() -> List[str]:
    registry = FrameworkRegistry(get_config().frameworks_dir)
    registry.load()
    return [fw.id for fw in registry.list()]


def _select_frameworks() -> Optional[List[str]]:
    """Ask the user which framework(s) to assess; ``None`` = all."""
    registry = FrameworkRegistry(get_config().frameworks_dir)
    registry.load()
    table = Table(title="Select Frameworks to Assess", box=box.ROUNDED,
                  title_style="bold " + PRIMARY, header_style="bold " + SECONDARY)
    table.add_column("ID", style=TEXT, no_wrap=True)
    table.add_column("Name", style=TEXT)
    table.add_column("Version", style=SUPPORTING)
    table.add_column("Controls", style=SUPPORTING, justify="right")
    for fw in registry.list():
        table.add_row(fw.id, fw.name, fw.version, str(len(fw.controls)))
    console.print(table)
    console.print(
        f"[{SUPPORTING}]Enter comma-separated framework IDs, or 'all' (default) to assess every framework.[/{SUPPORTING}]"
    )

    valid = set(registry.ids())
    while True:
        raw = Prompt.ask("Frameworks", default="all").strip().lower()
        if raw in ("", "all"):
            return None
        selected = [x.strip() for x in raw.split(",") if x.strip()]
        unknown = [fid for fid in selected if fid not in valid]
        if unknown:
            console.print(
                f"[{SUPPORTING}]Unknown framework(s): {', '.join(unknown)}. "
                f"Available: {', '.join(sorted(valid))}.[/{SUPPORTING}]"
            )
            continue
        return selected


def _start_assessment() -> None:
    """Option 1: select a target and run an assessment."""
    targets = [
        ("macOS (local)", Platform.MACOS, "local"),
        ("Linux (local)", Platform.LINUX, "local"),
        ("Linux (remote over SSH)", Platform.LINUX, "remote"),
    ]
    table = Table(title="Select Assessment Target", box=box.ROUNDED,
                  title_style="bold " + PRIMARY, header_style="bold " + SECONDARY)
    table.add_column("#", style=SUPPORTING, no_wrap=True)
    table.add_column("Target", style=TEXT)
    table.add_column("Mode", style=SUPPORTING, no_wrap=True)
    for idx, (name, _plat, mode) in enumerate(targets, start=1):
        table.add_row(str(idx), name, mode.upper())
    console.print(table)
    console.print(f"[{SUPPORTING}]Select a target number (or 4 to go back).[/{SUPPORTING}]")

    choices = [str(n) for n in range(1, len(targets) + 2)]
    choice = Prompt.ask("Target", choices=choices, default=str(len(targets) + 1))
    idx = int(choice) - 1
    if idx >= len(targets):
        return
    name, platform, mode = targets[idx]

    console.print(f"\n[bold {TEXT}]Selected target:[/bold {TEXT}] {name}")

    # Optional component / scope information for the user.
    console.print(f"[{SUPPORTING}]Detected local platform: {detect_platform().value}.[/{SUPPORTING}]")

    framework_ids = _select_frameworks()
    frameworks_arg = ",".join(framework_ids) if framework_ids else None

    if mode == "remote":
        host = Prompt.ask("Remote host", default="")
        if not host:
            console.print(f"[{SUPPORTING}]No host provided; returning to menu.[/{SUPPORTING}]")
            return
        user = Prompt.ask("SSH username", default="")
        port = Prompt.ask("SSH port", default="22")
        try:
            port_int = int(port)
        except ValueError:
            port_int = 22
        confirmed = Confirm.ask(f"Start read-only assessment of {host}?", default=True)
        if not confirmed:
            console.print(f"[{SUPPORTING}]Cancelled.[/{SUPPORTING}]")
            return
        console.print()
        from mijhar.cli.commands import scan_command

        scan_command(target="remote", platform=platform.value, host=host,
                     user=user or None, port=port_int, frameworks=frameworks_arg,
                     framework=None)
        return

    confirmed = Confirm.ask(f"Start {name} assessment?", default=True)
    if not confirmed:
        console.print(f"[{SUPPORTING}]Cancelled.[/{SUPPORTING}]")
        return
    console.print()
    from mijhar.cli.commands import scan_command

    scan_command(target="local", platform=platform.value, frameworks=frameworks_arg,
                 framework=None)


def _show_platforms() -> None:
    """Option 2: implemented vs planned platforms/modules."""
    table = Table(title="Supported Platforms & Scan Types", box=box.ROUNDED,
                  title_style="bold " + PRIMARY, header_style="bold " + SECONDARY)
    table.add_column("Module", style=TEXT)
    table.add_column("Platforms", style=TEXT)
    table.add_column("Status", no_wrap=True)
    table.add_column("Scope", style=SUPPORTING)

    for mod in IMPLEMENTED_MODULES:
        plats = ", ".join(p.value for p in mod.platforms)
        targets = ", ".join(mod.targets)
        table.add_row(mod.name, plats, f"[{PRIMARY}]IMPLEMENTED[/{PRIMARY}] ({targets})", mod.description)
    for mod in PLANNED_MODULES:
        table.add_row(mod.name, "-", f"[{SUPPORTING}]PLANNED[/{SUPPORTING}]", mod.description)
    console.print(table)
    console.print(
        f"[{SUPPORTING}]Implemented platforms: {implemented_platform_count()} · "
        f"Implemented modules: {implemented_module_count()}. Planned modules are "
        f"not selectable for assessment.[/{SUPPORTING}]"
    )


def _framework_coverage() -> None:
    """Option 3: explore framework coverage and controls."""
    from mijhar.cli.commands import frameworks_list_command

    frameworks_list_command()
    console.print(f"[{SUPPORTING}]Use `mijhar compliance --framework <id>` after a scan "
                  f"for per-control detail, or `mijhar frameworks list` for the catalog.[/{SUPPORTING}]")


def _previous_assessments() -> None:
    """Option 4: view scan history and results."""
    from mijhar.cli.commands import history_command

    history_command()
    console.print(f"[{SUPPORTING}]Use `mijhar results [--scan-id S-...]` to inspect a "
                  f"specific scan's findings.[/{SUPPORTING}]")


def _remediation_findings() -> None:
    """Option 5: review findings and remediation progress."""
    from mijhar.cli.commands import remediations_list_command, results_command

    results_command()
    console.print()
    remediations_list_command()


def _help_guide() -> None:
    """Option 6: the usage guide."""
    console.print(help_text())


def _about() -> None:
    """Option 7: about MIJHAR."""
    body = (
        f"[bold {PRIMARY}]{__app_name__}[/bold {PRIMARY}] v{__version__}\n"
        f"[{SECONDARY}]{__slogan__}[/{SECONDARY}]\n\n"
        f"{PRODUCT_DESCRIPTION}\n\n"
        f"[bold {TEXT}]Created by[/bold {TEXT}] {__author__}\n"
        f"[{SUPPORTING}]LinkedIn:[/{SUPPORTING}] [link={__author_linkedin__}]{__author_linkedin__}[/link]"
    )
    console.print(Panel(body, title=f"About {__app_name__}", border_style=PRIMARY))


def help_text() -> Panel:
    """Return the MIJHAR usage guide as a Rich panel."""
    lines = [
        f"[bold {PRIMARY}]What MIJHAR does[/bold {PRIMARY}]",
        "MIJHAR is a read-only Technical Security Assessment Framework. It inspects "
        "system configurations, identifies security weaknesses, collects technical "
        "evidence, and maps findings to compliance frameworks. It does not exploit "
        "vulnerabilities and never changes your configuration.",
        "",
        f"[bold {PRIMARY}]What it can assess[/bold {PRIMARY}]",
        "Implemented today: macOS (FileVault, firewall, Gatekeeper, SIP, updates, "
        "screen lock, admin accounts, remote login) and Linux (SSH, firewall, "
        "users/groups, password policy, file permissions, services, audit logging, "
        "updates) — locally, or Linux remotely over key-based SSH.",
        "",
        f"[bold {PRIMARY}]Selecting a target[/bold {PRIMARY}]",
        "Choose 'Start Security Assessment' from the main menu, then pick macOS, "
        "Linux (local), or Linux (remote over SSH). For a remote target you will be "
        "asked for the host, username, and port.",
        "",
        f"[bold {PRIMARY}]Starting an assessment[/bold {PRIMARY}]",
        "MIJHAR never starts a scan on its own. After you confirm, it detects the "
        "platform and any optional components, then runs only the checks that are "
        "relevant to that platform.",
        "",
        f"[bold {PRIMARY}]Reading results[/bold {PRIMARY}]",
        "PASS — the check condition holds.  FAIL — it does not hold.  WARNING — "
        "below policy but not a hard failure.  NOT SUPPORTED — MIJHAR cannot "
        "assess this on the target. Excluded checks are listed separately with a "
        "reason and are never reported as compliant.",
        "",
        f"[bold {PRIMARY}]Reviewing findings & evidence[/bold {PRIMARY}]",
        "Use 'View Previous Assessments' and 'Remediation & Findings'. Stored "
        "evidence is SHA-256 protected; verify it with `mijhar evidence verify`.",
        "",
        f"[bold {PRIMARY}]Exporting reports[/bold {PRIMARY}]",
        "`mijhar report --format json|csv|html [--output file] [--scan-id S-...]`.",
        "",
        f"[bold {PRIMARY}]Limitations[/bold {PRIMARY}]",
        "A single endpoint scan cannot prove enterprise-wide compliance. Windows, "
        "network devices, cloud, and containers are not yet implemented. Results "
        "are technical evidence, not a full compliance determination.",
        "",
        f"[bold {PRIMARY}]Authorization[/bold {PRIMARY}]",
        "Only assess systems you own or are authorized to test. Remote scans use "
        "your existing SSH key (read-only, BatchMode) and require an already-trusted "
        "host; MIJHAR never prompts for or stores passwords.",
    ]
    return Panel("\n".join(lines), title="MIJHAR — Help & Usage Guide", border_style=PRIMARY)


def run_main_menu() -> None:
    """Print the startup identity once, then loop on the main menu."""
    print_startup()
    while True:
        console.print(menu_table())
        choice = Prompt.ask("Menu", choices=[str(n) for n in range(1, len(_MENU) + 1)],
                            default=str(len(_MENU)))
        idx = int(choice) - 1
        name = _MENU[idx][0]

        if name == "Exit":
            console.print(f"[{SUPPORTING}]Goodbye.[/{SUPPORTING}]")
            return
        if name == "Start Security Assessment":
            _start_assessment()
        elif name == "Supported Platforms & Scan Types":
            _show_platforms()
        elif name == "Framework Coverage":
            _framework_coverage()
        elif name == "View Previous Assessments":
            _previous_assessments()
        elif name == "Remediation & Findings":
            _remediation_findings()
        elif name == "Help & Usage Guide":
            _help_guide()
        elif name == "About MIJHAR":
            _about()
        console.print()


def menu_command() -> None:
    """CLI entry: open the interactive main menu (prints the startup screen)."""
    run_main_menu()
