"""Tests for the platform-aware applicability engine and scanner integration."""

from __future__ import annotations

from pathlib import Path

import pytest

from mijhar.applicability.engine import (
    ApplicabilityEngine,
    ExclusionReason,
    detect_capabilities,
)
from mijhar.collectors.base import Fact
from mijhar.collectors.macos import MacOSCollector
from mijhar.core.config import Platform
from mijhar.core.scanner import Scanner
from mijhar.rules.loader import RuleLoader, rule_from_dict
from tests.conftest import FakeRunner, result

REPO_ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = REPO_ROOT / "rules"
FRAMEWORKS_DIR = REPO_ROOT / "frameworks"


def _all_rules():
    return RuleLoader(RULES_DIR).load()


def _rule(**overrides):
    base = {
        "id": "T-1",
        "title": "Test",
        "severity": "high",
        "platforms": ["linux"],
        "check": {"fact": "a.b", "operator": "equals", "value": True},
    }
    base.update(overrides)
    return rule_from_dict(base, "test")


# -- capability detection -----------------------------------------------------


def test_detect_capabilities_ssh():
    facts = [Fact(key="ssh.config", value={"PermitRootLogin": "no"}, source="file:/etc/ssh/sshd_config")]
    caps = detect_capabilities(facts, Platform.LINUX)
    assert "ssh" in caps


def test_detect_capabilities_missing_ssh():
    facts = [Fact(key="ssh.config", value={}, source="file:/etc/ssh/sshd_config", error="no such file")]
    caps = detect_capabilities(facts, Platform.LINUX)
    assert "ssh" not in caps


def test_detect_capabilities_firewall():
    facts = [Fact(key="firewall.any_active", value=True, source="aggregate")]
    assert "firewall" in detect_capabilities(facts, Platform.LINUX)


# -- applicability engine -----------------------------------------------------


def test_macos_scan_does_not_load_linux_rules():
    engine = ApplicabilityEngine(Platform.MACOS, _all_rules())
    result = engine.evaluate()
    included = result.included_ids
    assert all(r.startswith("MAC-") for r in included)
    assert "SSH-001" not in included
    assert "FILE-001" not in included
    assert "FW-001" not in included
    # Linux-only rules are excluded as platform-incompatible, not dropped.
    linux_excluded = [e for e in result.excluded if e.reason is ExclusionReason.PLATFORM_INCOMPATIBLE]
    assert any(e.rule_id == "SSH-001" for e in linux_excluded)


def test_linux_scan_does_not_load_macos_rules():
    engine = ApplicabilityEngine(Platform.LINUX, _all_rules(), capabilities={"ssh", "firewall"})
    result = engine.evaluate()
    included = result.included_ids
    assert "MAC-001" not in included
    assert "SSH-001" in included
    assert "FW-001" in included


def test_linux_scan_excludes_component_dependent_rules_when_absent():
    # No SSH/firewall component detected -> those rules are excluded.
    engine = ApplicabilityEngine(Platform.LINUX, _all_rules(), capabilities=set())
    result = engine.evaluate()
    assert "SSH-001" not in result.included_ids
    assert "FW-001" not in result.included_ids
    reasons = {e.rule_id: e.reason for e in result.excluded}
    assert reasons["SSH-001"] is ExclusionReason.MISSING_PREREQUISITE
    assert reasons["FW-001"] is ExclusionReason.MISSING_PREREQUISITE


def test_windows_scan_loads_no_platform_specific_rules():
    engine = ApplicabilityEngine(Platform.WINDOWS, _all_rules())
    result = engine.evaluate()
    assert "MAC-001" not in result.included_ids
    assert "SSH-001" not in result.included_ids


def test_required_component_missing_is_excluded():
    rule = _rule(id="SSH-X", platforms=["linux"], required_components=["ssh"])
    engine = ApplicabilityEngine(Platform.LINUX, [rule], capabilities=set())
    result = engine.evaluate()
    assert result.included_ids == []
    exc = result.excluded[0]
    assert exc.reason is ExclusionReason.MISSING_PREREQUISITE
    assert "ssh" in exc.detail


def test_required_component_present_is_included():
    rule = _rule(id="SSH-X", platforms=["linux"], required_components=["ssh"])
    engine = ApplicabilityEngine(Platform.LINUX, [rule], capabilities={"ssh"})
    assert engine.evaluate().included_ids == ["SSH-X"]


def test_disabled_rule_is_excluded():
    rule = _rule(id="D-1", platforms=["linux"], enabled=False)
    result = ApplicabilityEngine(Platform.LINUX, [rule]).evaluate()
    assert result.excluded[0].reason is ExclusionReason.DISABLED


def test_not_assessable_rule_is_excluded_not_assessed():
    rule = _rule(id="ORG-1", platforms=["linux"], technical_assessability="not_assessable")
    result = ApplicabilityEngine(Platform.LINUX, [rule]).evaluate()
    assert result.excluded[0].reason is ExclusionReason.NOT_ASSESSABLE


def test_unsupported_rule_is_excluded():
    rule = _rule(id="U-1", platforms=["linux"], technical_assessability="unsupported")
    result = ApplicabilityEngine(Platform.LINUX, [rule]).evaluate()
    assert result.excluded[0].reason is ExclusionReason.UNSUPPORTED


def test_outside_scope_is_excluded():
    rule = _rule(id="S-1", platforms=["linux"], assessment_type="presence")
    result = ApplicabilityEngine(Platform.LINUX, [rule], scope={"configuration"}).evaluate()
    assert result.excluded[0].reason is ExclusionReason.OUTSIDE_SCOPE


# -- scanner integration ------------------------------------------------------


def _macos_runner() -> FakeRunner:
    return FakeRunner(
        {
            ("sw_vers", "-productVersion"): result(0, "14.5"),
            ("uname", "-m"): result(0, "arm64"),
            ("fdesetup", "status"): result(0, "FileVault is On."),
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


def test_scanner_macos_does_not_load_linux_rules(tmp_path, monkeypatch):
    scanner = Scanner(rules_dir=RULES_DIR, frameworks_dir=FRAMEWORKS_DIR, db_path=tmp_path / "mijhar.db")
    monkeypatch.setattr(scanner, "make_collector", lambda platform, target="local", **kw: MacOSCollector(_macos_runner()))

    result = scanner.run(Platform.MACOS, asset_id="test-mac")

    rule_ids = {f.rule_id for f in result.findings}
    assert rule_ids == {"MAC-001", "MAC-002", "MAC-003", "MAC-004", "MAC-005", "MAC-006"}
    # Linux-only rules are excluded with a reason, not executed.
    linux_excluded = [e for e in result.exclusions if e.reason is ExclusionReason.PLATFORM_INCOMPATIBLE]
    assert any(e.rule_id == "SSH-001" for e in linux_excluded)
    # Exclusions are persisted and recoverable (scope transparency).
    report = scanner.build_report_data(result.scan_id)
    assert report["exclusions"]
    assert any(e["rule_id"] == "SSH-001" for e in report["exclusions"])
    assert report["counts"]["excluded"] == len(result.exclusions)


def test_framework_control_mapping_to_other_platform_is_not_applicable():
    from mijhar.compliance.registry import FrameworkRegistry
    from mijhar.compliance.assessment import ControlAssessor, ControlStatus

    registry = FrameworkRegistry(FRAMEWORKS_DIR)
    registry.load()
    cis = registry.get("cis")
    assessor = ControlAssessor()
    # During a macOS scan, CIS 5.2.8 (SSH root login) maps only to the Linux
    # rule SSH-001, so it must be not-applicable — never silently "not assessed"
    # and never compliant.
    assessments = assessor.assess(cis, [], included_rule_ids={"MAC-001"})
    ssh_root = next(a for a in assessments if a.control_id == "5.2.8")
    assert ssh_root.status is ControlStatus.NOT_APPLICABLE
    assert ssh_root.excluded is True
    assert "platform_incompatible" in ssh_root.excluded_reason


def test_unchecked_control_is_never_compliant():
    from mijhar.compliance.assessment import ControlAssessor, ControlStatus
    from mijhar.compliance.registry import Control, ControlMapping, Domain, Framework, MappingType

    control = Control(id="C-1", title="No finding", mappings=[ControlMapping(rule_id="R-1", mapping_type=MappingType.DIRECT)])
    framework = Framework(id="t", name="T", version="1", domains=[Domain(id="d", name="D", controls=[control])])
    assessor = ControlAssessor()
    assessment = assessor.assess_control(control, [])
    assert assessment.status is not ControlStatus.COMPLIANT


# -- framework selection -------------------------------------------------------


def test_scanner_framework_filter_restricts_compliance(tmp_path, monkeypatch):
    scanner = Scanner(rules_dir=RULES_DIR, frameworks_dir=FRAMEWORKS_DIR, db_path=tmp_path / "mijhar.db")
    monkeypatch.setattr(scanner, "make_collector", lambda platform, target="local", **kw: MacOSCollector(_macos_runner()))

    result = scanner.run(Platform.MACOS, asset_id="test-mac", framework_ids=["cis"])
    assert set(result.compliance) == {"cis"}

    # The selection is persisted and reflected in the report.
    report = scanner.build_report_data(result.scan_id)
    assert set(report["compliance"]) == {"cis"}
    assert report["frameworks"] == ["cis"]


def test_scanner_framework_filter_all_by_default(tmp_path, monkeypatch):
    scanner = Scanner(rules_dir=RULES_DIR, frameworks_dir=FRAMEWORKS_DIR, db_path=tmp_path / "mijhar.db")
    monkeypatch.setattr(scanner, "make_collector", lambda platform, target="local", **kw: MacOSCollector(_macos_runner()))

    result = scanner.run(Platform.MACOS, asset_id="test-mac")
    assert set(result.compliance) == {"cis", "iso27001", "nca-ecc", "sama-csf"}
