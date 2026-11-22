"""Shared domain models used across MIJHAR modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict

from mijhar.core.config import Severity, Status


@dataclass
class Finding:
    """A single security finding produced by evaluating a rule against facts.

    A finding carries the technical result (status/severity), observed
    evidence, and the remediation/framework references needed by downstream
    risk, compliance, and reporting engines.
    """

    id: str
    rule_id: str
    asset_id: str
    title: str
    description: str
    severity: Severity
    status: Status
    fact_key: str
    observed_value: Any
    evidence: Dict[str, Any]
    technical_impact: str = ""
    security_impact: str = ""
    remediation: str = ""
    framework_refs: Dict[str, Any] = field(default_factory=dict)
    detected_at: str = ""

    @property
    def is_failed(self) -> bool:
        return self.status in (Status.FAIL, Status.WARNING)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Reconstruct a Finding from a persisted dict (e.g. a DB row)."""
        return cls(
            id=data["id"],
            rule_id=data["rule_id"],
            asset_id=data["asset_id"],
            title=data.get("title", ""),
            description=data.get("description", ""),
            severity=Severity(data["severity"]),
            status=Status(data["status"]),
            fact_key=data.get("fact_key", ""),
            observed_value=data.get("observed_value"),
            evidence=data.get("evidence") or {},
            technical_impact=data.get("technical_impact", ""),
            security_impact=data.get("security_impact", ""),
            remediation=data.get("remediation", ""),
            framework_refs=data.get("framework_refs") or {},
            detected_at=data.get("detected_at", ""),
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "asset_id": self.asset_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "fact_key": self.fact_key,
            "observed_value": self.observed_value,
            "evidence": self.evidence,
            "technical_impact": self.technical_impact,
            "security_impact": self.security_impact,
            "remediation": self.remediation,
            "framework_refs": self.framework_refs,
            "detected_at": self.detected_at,
        }
