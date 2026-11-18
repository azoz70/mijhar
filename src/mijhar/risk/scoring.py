"""Transparent, configurable risk scoring and remediation prioritization.

Risk is modelled as ``severity weight * business-impact multiplier``, capped
at a maximum score. Severity (technical likelihood/impact of a
misconfiguration) and business impact (organizational consequence) are kept
deliberately separate, and both are explicitly configurable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from mijhar.core.config import Severity, severity_rank
from mijhar.core.models import Finding

# Default severity weights (0-100). Documented; override via RiskConfig.
DEFAULT_SEVERITY_WEIGHTS: Dict[Severity, float] = {
    Severity.CRITICAL: 100.0,
    Severity.HIGH: 80.0,
    Severity.MEDIUM: 55.0,
    Severity.LOW: 30.0,
    Severity.INFORMATIONAL: 10.0,
}

# Business-impact multipliers. An impact is an organizational judgement, not a
# technical property of the finding.
DEFAULT_IMPACT_MULTIPLIERS: Dict[str, float] = {
    "critical": 1.6,
    "high": 1.3,
    "medium": 1.0,
    "low": 0.6,
    "informational": 0.3,
}

# Score bands mapping a numeric score back to a risk level.
SCORE_BANDS = [
    (90.0, Severity.CRITICAL),
    (70.0, Severity.HIGH),
    (40.0, Severity.MEDIUM),
    (15.0, Severity.LOW),
]


def default_impact(severity: Severity) -> str:
    """Infer a conservative default business impact from technical severity."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "high"
    if severity is Severity.MEDIUM:
        return "medium"
    if severity is Severity.LOW:
        return "low"
    return "informational"


def risk_level(score: float) -> Severity:
    """Map a numeric risk score to a risk level band."""
    for threshold, level in SCORE_BANDS:
        if score >= threshold:
            return level
    return Severity.INFORMATIONAL


@dataclass(frozen=True)
class RiskConfig:
    """Configurable risk scoring parameters."""

    severity_weights: Dict[Severity, float] = field(default_factory=lambda: dict(DEFAULT_SEVERITY_WEIGHTS))
    impact_multipliers: Dict[str, float] = field(default_factory=lambda: dict(DEFAULT_IMPACT_MULTIPLIERS))
    max_score: float = 100.0

    def score(self, severity: Severity, impact: Optional[str] = None) -> float:
        resolved_impact = impact or default_impact(severity)
        weight = self.severity_weights.get(Severity(severity), 0.0)
        multiplier = self.impact_multipliers.get(resolved_impact, self.impact_multipliers["medium"])
        return round(min(self.max_score, weight * multiplier), 1)


@dataclass
class RiskAssessment:
    """The computed risk for one finding."""

    finding_id: str
    rule_id: str
    severity: Severity
    impact: str
    score: float
    level: Severity
    priority: int = 0

    def as_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "impact": self.impact,
            "score": self.score,
            "level": self.level.value,
            "priority": self.priority,
        }


class RiskScorer:
    """Score findings and order them by remediation priority."""

    def __init__(self, config: Optional[RiskConfig] = None) -> None:
        self.config = config or RiskConfig()

    def assess(self, finding: Finding, impact: Optional[str] = None) -> RiskAssessment:
        score = self.config.score(finding.severity, impact)
        resolved_impact = impact or default_impact(finding.severity)
        return RiskAssessment(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            severity=finding.severity,
            impact=resolved_impact,
            score=score,
            level=risk_level(score),
        )

    def assess_all(
        self,
        findings: Iterable[Finding],
        impacts: Optional[Dict[str, str]] = None,
    ) -> List[RiskAssessment]:
        """Assess every finding; ``impacts`` maps rule_id -> impact override."""
        impact_map = impacts or {}
        assessments = [self.assess(f, impact_map.get(f.rule_id)) for f in findings]
        return self.prioritize(assessments)

    @staticmethod
    def prioritize(assessments: Iterable[RiskAssessment]) -> List[RiskAssessment]:
        """Order assessments by severity rank, then score, and number priority."""
        ordered = sorted(
            assessments,
            key=lambda a: (severity_rank(a.severity), a.score),
            reverse=True,
        )
        for position, assessment in enumerate(ordered, start=1):
            assessment.priority = position
        return ordered
