"""Tests for risk scoring and remediation prioritization."""

from __future__ import annotations

from mijhar.core.config import Severity
from mijhar.risk.scoring import (
    RiskConfig,
    RiskScorer,
    default_impact,
    risk_level,
)
from tests.conftest import make_finding


def test_score_is_weight_times_multiplier_capped():
    config = RiskConfig()
    # high * high = 80 * 1.3 = 104 -> capped at 100
    assert config.score(Severity.HIGH, "high") == 100.0
    # medium * medium = 55 * 1.0 = 55
    assert config.score(Severity.MEDIUM, "medium") == 55.0
    # low * low = 30 * 0.6 = 18
    assert config.score(Severity.LOW, "low") == 18.0


def test_default_impact_from_severity():
    assert default_impact(Severity.CRITICAL) == "high"
    assert default_impact(Severity.MEDIUM) == "medium"
    assert default_impact(Severity.LOW) == "low"
    assert default_impact(Severity.INFORMATIONAL) == "informational"


def test_risk_level_bands():
    assert risk_level(95.0) is Severity.CRITICAL
    assert risk_level(75.0) is Severity.HIGH
    assert risk_level(50.0) is Severity.MEDIUM
    assert risk_level(20.0) is Severity.LOW
    assert risk_level(5.0) is Severity.INFORMATIONAL


def test_assess_returns_structured_risk():
    scorer = RiskScorer()
    assessment = scorer.assess(make_finding(severity=Severity.HIGH), impact="high")
    assert assessment.severity is Severity.HIGH
    assert assessment.score == 100.0
    assert assessment.level is Severity.CRITICAL


def test_severity_and_compliance_status_are_distinct():
    # A FAILed low-severity finding and a PASSed critical-severity finding
    # must not be conflated: severity != status.
    scorer = RiskScorer()
    low = scorer.assess(make_finding(rule_id="L", severity=Severity.LOW, status="fail"))
    assert low.severity is Severity.LOW
    assert low.score == 18.0


def test_prioritize_orders_and_numbers():
    scorer = RiskScorer()
    assessments = scorer.assess_all(
        [
            make_finding(rule_id="low", severity=Severity.LOW),
            make_finding(rule_id="crit", severity=Severity.CRITICAL),
            make_finding(rule_id="med", severity=Severity.MEDIUM),
        ]
    )
    assert [a.rule_id for a in assessments] == ["crit", "med", "low"]
    assert [a.priority for a in assessments] == [1, 2, 3]


def test_configurable_weights():
    config = RiskConfig(severity_weights={Severity.HIGH: 50.0})
    assert config.score(Severity.HIGH, "medium") == 50.0
