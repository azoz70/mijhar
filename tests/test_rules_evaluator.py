"""Tests for the rule evaluator."""

from __future__ import annotations

from mijhar.collectors.base import Fact
from mijhar.core.config import Platform, Severity, Status
from mijhar.rules.evaluator import RuleEvaluator
from mijhar.rules.loader import rule_from_dict


def _rule(**overrides):
    base = {
        "id": "T-1",
        "title": "Test rule",
        "severity": "high",
        "platforms": ["linux"],
        "description": "desc",
        "remediation": "fix it",
        "check": {"fact": "a.b", "operator": "equals", "value": True},
    }
    base.update(overrides)
    return rule_from_dict(base, "test")


def _facts(**kwargs):
    return [Fact(key=k, value=v, source="test") for k, v in kwargs.items()]


def test_pass_when_condition_holds():
    evaluator = RuleEvaluator()
    finding = evaluator.evaluate(_rule(), _facts(**{"a.b": True}))
    assert finding.status is Status.PASS


def test_fail_when_condition_false():
    evaluator = RuleEvaluator()
    finding = evaluator.evaluate(_rule(), _facts(**{"a.b": False}))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.HIGH


def test_warning_fail_status():
    rule = _rule(check={"fact": "n", "operator": "less_than_or_equal", "value": 90, "fail_status": "warning"})
    evaluator = RuleEvaluator()
    finding = evaluator.evaluate(rule, _facts(n=120))
    assert finding.status is Status.WARNING


def test_not_in_operator():
    rule = _rule(check={"fact": "root", "operator": "not_in", "value": ["yes", "without-password"]})
    evaluator = RuleEvaluator()
    assert evaluator.evaluate(rule, _facts(root="no")).status is Status.PASS
    assert evaluator.evaluate(rule, _facts(root="yes")).status is Status.FAIL


def test_missing_fact_is_not_applicable():
    evaluator = RuleEvaluator()
    finding = evaluator.evaluate(_rule(), _facts())
    assert finding.status is Status.NOT_APPLICABLE


def test_error_fact_is_error_status():
    evaluator = RuleEvaluator()
    fact = Fact(key="a.b", value=None, source="test", error="permission denied")
    finding = evaluator.evaluate(_rule(), [fact])
    assert finding.status is Status.ERROR


def test_incomparable_value_is_error_status():
    rule = _rule(check={"fact": "n", "operator": "less_than", "value": 10})
    evaluator = RuleEvaluator()
    finding = evaluator.evaluate(rule, _facts(n="not-a-number"))
    assert finding.status is Status.ERROR


def test_finding_carries_metadata():
    evaluator = RuleEvaluator()
    finding = evaluator.evaluate(_rule(), _facts(**{"a.b": False}), asset_id="srv-1")
    assert finding.asset_id == "srv-1"
    assert finding.rule_id == "T-1"
    assert finding.remediation == "fix it"
    assert finding.framework_refs == {}
    assert finding.detected_at


def test_evaluate_all_filters_by_platform():
    mac_rule = _rule(id="MAC", platforms=["macos"])
    linux_rule = _rule(id="LIN", platforms=["linux"])
    evaluator = RuleEvaluator()
    findings = evaluator.evaluate_all([mac_rule, linux_rule], _facts(**{"a.b": True}), platform=Platform.LINUX)
    assert [f.rule_id for f in findings] == ["LIN"]
