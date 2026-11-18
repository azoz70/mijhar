"""Tests for the YAML rule loader and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from mijhar.core.config import Platform, Severity, Status
from mijhar.rules.loader import RuleLoader, RuleValidationError, rule_from_dict

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


def _rule(**overrides):
    base = {
        "id": "T-1",
        "title": "Test rule",
        "severity": "medium",
        "platforms": ["linux"],
        "check": {"fact": "a.b", "operator": "equals", "value": True},
    }
    base.update(overrides)
    return base


def test_loads_bundled_rules():
    loader = RuleLoader(RULES_DIR)
    rules = loader.load()
    ids = {r.id for r in rules}
    assert len(rules) == 14
    assert {"MAC-001", "MAC-006", "SSH-001", "SSH-003", "PASS-001", "FILE-001", "FW-001"} <= ids


def test_string_rule_values_are_not_boolean_coerced():
    loader = RuleLoader(RULES_DIR)
    rules = {r.id: r for r in loader.load()}
    assert rules["SSH-002"].check.value == "no"
    assert isinstance(rules["SSH-002"].check.value, str)
    assert rules["SSH-001"].check.value == ["yes", "without-password"]


def test_platform_filtering():
    rule = rule_from_dict(_rule(platforms=["macos"]), "test")
    assert rule.applies_to(Platform.MACOS) is True
    assert rule.applies_to(Platform.LINUX) is False
    any_rule = rule_from_dict(_rule(platforms=["any"]), "test")
    assert any_rule.applies_to(Platform.LINUX) is True


def test_fail_status_defaults_to_fail():
    rule = rule_from_dict(_rule(), "test")
    assert rule.check.fail_status is Status.FAIL


def test_warning_fail_status_parsed():
    rule = rule_from_dict(_rule(check={"fact": "a", "operator": "exists", "fail_status": "warning"}), "test")
    assert rule.check.fail_status is Status.WARNING


def test_missing_id_raises():
    data = _rule()
    del data["id"]
    with pytest.raises(RuleValidationError, match="id"):
        rule_from_dict(data, "test")


def test_invalid_severity_raises():
    with pytest.raises(RuleValidationError, match="severity"):
        rule_from_dict(_rule(severity="extreme"), "test")


def test_invalid_operator_raises():
    with pytest.raises(RuleValidationError, match="operator"):
        rule_from_dict(_rule(check={"fact": "a", "operator": "frobnicate"}), "test")


def test_missing_check_raises():
    data = _rule()
    del data["check"]
    with pytest.raises(RuleValidationError, match="check"):
        rule_from_dict(data, "test")


def test_severity_is_enum():
    rule = rule_from_dict(_rule(severity="critical"), "test")
    assert rule.severity is Severity.CRITICAL
