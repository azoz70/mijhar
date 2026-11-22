"""CLI integration tests for MIJHAR Phase 1."""

from __future__ import annotations

from typer.testing import CliRunner

from mijhar.cli.app import app
from mijhar.cli.console import console

runner = CliRunner()


def test_help_lists_system_info():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "system-info" in result.output
    assert "MIJHAR" in result.output


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "0.2.0" in result.output
    assert "SEE WHAT OTHERS MISS" in result.output
    assert "Abdulaziz" in result.output


def test_about_command():
    result = runner.invoke(app, ["--no-banner", "about"])
    assert result.exit_code == 0
    assert "Abdulaziz" in result.output
    assert "linkedin.com" in result.output
    assert "MIJHAR" in result.output


def test_system_info_command_runs():
    result = runner.invoke(app, ["--no-banner", "system-info"])
    assert result.exit_code == 0
    assert "System Information" in result.output
    assert "Detected Platform" in result.output


def test_unknown_command_errors():
    result = runner.invoke(app, ["definitely-not-a-command"])
    assert result.exit_code != 0


def test_console_theme_registered():
    # The MIJHAR theme must expose our shared severity styles.
    style = console.get_style("mijhar.critical")
    assert style is not None


def test_rules_list_command():
    result = runner.invoke(app, ["--no-banner", "rules", "list"])
    assert result.exit_code == 0
    assert "SSH-001" in result.output


def test_frameworks_list_command():
    result = runner.invoke(app, ["--no-banner", "frameworks", "list"])
    assert result.exit_code == 0
    assert "nca-ecc" in result.output


def test_report_without_scans_errors(tmp_path):
    result = runner.invoke(
        app,
        ["--no-banner", "report", "--format", "json"],
        env={"MIJHAR_HOME": str(tmp_path)},
    )
    assert result.exit_code == 1
    assert "No scans found" in result.output


def test_report_rejects_bad_format(tmp_path):
    result = runner.invoke(
        app,
        ["--no-banner", "report", "--format", "xml"],
        env={"MIJHAR_HOME": str(tmp_path)},
    )
    assert result.exit_code == 1
    assert "Invalid format" in result.output


def test_review_set_and_list(tmp_path):
    env = {"MIJHAR_HOME": str(tmp_path)}
    result = runner.invoke(
        app,
        ["--no-banner", "review", "set", "--framework", "nca-ecc", "--control", "2-8-3-3",
         "--status", "compliant", "--reviewer", "auditor", "--notes", "verified"],
        env=env,
    )
    assert result.exit_code == 0
    listing = runner.invoke(app, ["--no-banner", "review", "list"], env=env)
    assert listing.exit_code == 0
    assert "2-8-3-3" in listing.output
    assert "compliant" in listing.output


def test_review_set_rejects_bad_status(tmp_path):
    result = runner.invoke(
        app,
        ["--no-banner", "review", "set", "--framework", "nca-ecc", "--control", "2-8-3-3", "--status", "bogus"],
        env={"MIJHAR_HOME": str(tmp_path)},
    )
    assert result.exit_code == 1


def test_review_set_rejects_unknown_control(tmp_path):
    result = runner.invoke(
        app,
        ["--no-banner", "review", "set", "--framework", "nca-ecc", "--control", "9-9-9", "--status", "compliant"],
        env={"MIJHAR_HOME": str(tmp_path)},
    )
    assert result.exit_code == 1
    assert "Unknown control" in result.output


def test_remediations_list_empty(tmp_path):
    result = runner.invoke(app, ["--no-banner", "remediations", "list"], env={"MIJHAR_HOME": str(tmp_path)})
    assert result.exit_code == 0
    assert "No remediation items" in result.output


def test_evidence_verify_empty(tmp_path):
    result = runner.invoke(app, ["--no-banner", "evidence", "verify"], env={"MIJHAR_HOME": str(tmp_path)})
    assert result.exit_code == 0
    assert "passes integrity" in result.output


def test_menu_lists_options_and_exits():
    result = runner.invoke(app, ["--no-banner", "menu"], input="8\n")
    assert result.exit_code == 0
    assert "Main Menu" in result.output
    assert "Start Security Assessment" in result.output
    assert "Supported Platforms & Scan Types" in result.output
    assert "Framework Coverage" in result.output
    assert "Help & Usage Guide" in result.output
    assert "Exit" in result.output


def test_menu_help_option():
    # Select "Help & Usage Guide" (6), then "Exit" (8).
    result = runner.invoke(app, ["--no-banner", "menu"], input="6\n8\n")
    assert result.exit_code == 0
    assert "Help & Usage Guide" in result.output
    assert "read-only" in result.output


def test_theme_list_command():
    result = runner.invoke(app, ["--no-banner", "theme", "list"])
    assert result.exit_code == 0
    assert "Cool Arctic Cyan" in result.output
    assert "arctic-cyan" in result.output


def test_scan_rejects_unknown_framework(tmp_path):
    result = runner.invoke(
        app,
        ["--no-banner", "scan", "--target", "local", "--platform", "macos", "--frameworks", "bogus"],
        env={"MIJHAR_HOME": str(tmp_path)},
    )
    assert result.exit_code == 1
    assert "Unknown framework" in result.output


def test_scan_framework_option_is_listed_in_help():
    # Rich help can truncate or wrap long option names in narrow CI terminals.
    # Set an explicit width and suppress the startup banner.
    result = runner.invoke(
        app, ["--no-banner", "scan", "--help"],
        env={"COLUMNS": "160", "TERM": "dumb"},
        terminal_width=160,
    )
    assert result.exit_code == 0
    assert "--frameworks" in result.output


def test_menu_start_assessment_passes_framework_none(monkeypatch):
    """Regression: the menu must call scan_command with framework=None, not a
    Typer OptionInfo object (which produced 'unknown framework: <OptionInfo>')."""
    from mijhar.cli import commands

    captured = {}

    def fake_scan_command(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(commands, "scan_command", fake_scan_command)
    result = runner.invoke(app, ["--no-banner", "menu"], input="1\n1\nall\ny\n8\n")
    assert result.exit_code == 0
    assert captured.get("target") == "local"
    assert captured.get("platform") == "macos"
    assert captured.get("framework") is None
    assert "unknown framework" not in result.output


def test_review_finding_command(tmp_path):
    env = {"MIJHAR_HOME": str(tmp_path)}
    r = runner.invoke(app, ["--no-banner", "review", "finding", "--finding", "F-1", "--decision", "accept", "--reviewer", "bob"], env=env)
    assert r.exit_code == 0
    assert "accept" in r.output


def test_review_finding_rejects_bad_decision(tmp_path):
    r = runner.invoke(app, ["--no-banner", "review", "finding", "--finding", "F-1", "--decision", "maybe"], env={"MIJHAR_HOME": str(tmp_path)})
    assert r.exit_code == 1


def test_remediations_set_command(tmp_path):
    env = {"MIJHAR_HOME": str(tmp_path)}
    r = runner.invoke(app, ["--no-banner", "remediations", "set", "--id", "R-1", "--status", "in_progress", "--owner", "alice", "--due", "2026-03-01"], env=env)
    # R-1 does not exist, so this should exit 1.
    assert r.exit_code == 1
    assert "not found" in r.output


def test_risk_accept_and_list(tmp_path):
    env = {"MIJHAR_HOME": str(tmp_path)}
    r = runner.invoke(app, ["--no-banner", "risk", "accept", "--finding", "F-1", "--severity", "high", "--accepted-by", "CISO"], env=env)
    assert r.exit_code == 0
    listing = runner.invoke(app, ["--no-banner", "risk", "list"], env=env)
    assert listing.exit_code == 0
    assert "F-1" in listing.output
    assert "accept" in listing.output


def test_evidence_export_empty(tmp_path):
    r = runner.invoke(app, ["--no-banner", "evidence", "export", "--format", "json", "--output", str(tmp_path / "ev.json")], env={"MIJHAR_HOME": str(tmp_path)})
    assert r.exit_code == 1
    assert "No evidence stored" in r.output
