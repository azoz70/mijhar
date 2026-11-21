"""Tests for the scan orchestration (Scanner) using a mocked collector."""

from __future__ import annotations

import sqlite3

from mijhar.collectors.macos import MacOSCollector
from mijhar.core.config import Platform
from mijhar.core.scanner import Scanner
from mijhar.database.models import Database
from mijhar.reports.json_report import report_json
from tests.conftest import FakeRunner, result

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
    scanner = Scanner(db_path=tmp_path / "mijhar.db")
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
    with Database(tmp_path / "mijhar.db") as db:
        remediations = db.list_remediations()
        assert remediations, "expected auto-generated remediations"
        assert all(r["status"] == "open" for r in remediations)


def test_scanner_rejects_unsupported_local_platform(tmp_path):
    scanner = Scanner(db_path=tmp_path / "mijhar.db")
    try:
        scanner.run(Platform.WINDOWS)
    except ValueError as exc:
        assert "unsupported platform" in str(exc)
    else:
        raise AssertionError("expected ValueError for unsupported platform")


def test_report_remediations_are_scoped_to_the_scan(tmp_path, monkeypatch):
    scanner = Scanner(db_path=tmp_path / "mijhar.db")
    monkeypatch.setattr(scanner, "make_collector", lambda *args, **kwargs: MacOSCollector(_macos_runner()))

    first = scanner.run(Platform.MACOS, asset_id="first")
    first_counts = scanner.build_report_data(first.scan_id)["remediation"]
    second = scanner.run(Platform.MACOS, asset_id="second")
    with Database(scanner.db_path) as db:
        assert len(db.list_remediations()) == 2 * first_counts["open"]
        for remediation in db.list_remediations(scan_id=second.scan_id):
            db.close_remediation(remediation["id"])

    assert first_counts["open"] > 0
    assert scanner.build_report_data(first.scan_id)["remediation"] == first_counts
    assert scanner.build_report_data(second.scan_id)["remediation"]["resolved"] == first_counts["open"]


def test_raw_evidence_is_redacted_in_storage_and_reports(tmp_path, monkeypatch):
    scanner = Scanner(db_path=tmp_path / "mijhar.db")
    runner = _macos_runner()
    runner.responses[("fdesetup", "status")] = result(0, "FileVault is Off. password=fixture-secret")
    monkeypatch.setattr(scanner, "make_collector", lambda *args, **kwargs: MacOSCollector(runner))

    scan = scanner.run(Platform.MACOS)
    assert "fixture-secret" not in report_json(scan)
    assert any("password=[REDACTED]" in record.content and record.redacted for record in scan.evidence)
    with sqlite3.connect(scanner.db_path) as conn:
        assert not conn.execute(
            "SELECT id FROM findings WHERE evidence LIKE '%fixture-secret%' OR observed_value LIKE '%fixture-secret%'"
        ).fetchall()
        assert not conn.execute(
            "SELECT id FROM evidence WHERE content LIKE '%fixture-secret%'"
        ).fetchall()
        # Simulate a finding created before evidence redaction was enforced.
        conn.execute(
            "UPDATE findings SET observed_value=?, evidence=? WHERE rule_id='MAC-001'",
            ('{"token": "legacy-secret"}', '{"raw": "password=legacy-secret"}'),
        )

    report = scanner.build_report_data(scan.scan_id)
    finding = next(finding for finding in report["findings"] if finding["rule_id"] == "MAC-001")
    assert finding["observed_value"] == {"token": "[REDACTED]"}
    assert finding["evidence"]["raw"] == "password=[REDACTED]"
    assert "legacy-secret" not in report_json(report)
