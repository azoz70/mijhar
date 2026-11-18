"""Tests for the scan orchestration (Scanner) using a mocked collector."""

from __future__ import annotations

from pathlib import Path

from mijhar.collectors.macos import MacOSCollector
from mijhar.core.config import Platform
from mijhar.core.scanner import Scanner
from tests.conftest import FakeRunner, result

REPO_ROOT = Path(__file__).resolve().parents[1]


def _macos_runner() -> FakeRunner:
    return FakeRunner(
        {
            ("sw_vers", "-productVersion"): result(0, "14.5"),
            ("uname", "-m"): result(0, "arm64"),
            ("fdesetup", "status"): result(0, "FileVault is Off."),
            ("defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"): result(0, "1"),
            ("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"): result(0, "Firewall is enabled."),
            ("spctl", "--status"): result(0, "assessments enabled"),
            ("csrutil", "status"): result(0, "System Integrity Protection status: enabled."),
            ("defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"): result(0, "1"),
            ("defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload"): result(0, "1"),
            ("defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall"): result(0, "1"),
            ("defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"): result(0, "1"),
            ("defaults", "-currentHost", "read", "com.apple.screensaver", "askForPassword"): result(0, "1"),
            ("defaults", "-currentHost", "read", "com.apple.screensaver", "askForPasswordDelay"): result(0, "300"),
            ("dscl", ".", "-read", "/Groups/admin", "GroupMembership"): result(0, "GroupMembership: root admin"),
            ("systemsetup", "-getremotelogin"): result(0, "Remote Login: Off"),
        }
    )


def test_scanner_runs_and_persists(tmp_path, monkeypatch):
    scanner = Scanner(
        rules_dir=REPO_ROOT / "rules",
        frameworks_dir=REPO_ROOT / "frameworks",
        db_path=tmp_path / "mijhar.db",
    )
    monkeypatch.setattr(scanner, "make_collector", lambda platform, target="local", **kw: MacOSCollector(_macos_runner()))

    result_ = scanner.run(Platform.MACOS, asset_id="test-mac")

    assert result_.scan_id.startswith("S-")
    assert len(result_.findings) == 6
    assert result_.counts["failed"] >= 1  # FileVault is Off -> FAIL
    assert set(result_.compliance) == {"cis", "iso27001", "nca-ecc", "sama-csf"}

    # Persisted scan is queryable.
    assert scanner.latest_scan_id() == result_.scan_id
    report = scanner.build_report_data(result_.scan_id)
    assert report["asset_id"] == "test-mac"
    assert len(report["findings"]) == 6
    assert set(report["compliance"]) == {"cis", "iso27001", "nca-ecc", "sama-csf"}

    # Remediation records are auto-generated for failed findings.
    from mijhar.database.models import Database
    with Database(tmp_path / "mijhar.db") as db:
        remediations = db.list_remediations()
        assert remediations, "expected auto-generated remediations"
        assert all(r["status"] == "open" for r in remediations)


def test_scanner_rejects_unsupported_local_platform(tmp_path):
    scanner = Scanner(
        rules_dir=REPO_ROOT / "rules",
        frameworks_dir=REPO_ROOT / "frameworks",
        db_path=tmp_path / "mijhar.db",
    )
    try:
        scanner.run(Platform.WINDOWS)
    except ValueError as exc:
        assert "unsupported platform" in str(exc)
    else:
        raise AssertionError("expected ValueError for unsupported platform")
