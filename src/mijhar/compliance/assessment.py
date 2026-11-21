"""Control assessment, gap identification, and compliance summary.

The assessor derives a *technical* control status from automated findings but
deliberately does not claim definitive framework compliance: any
non-compliant/partially-compliant result is flagged for human review, and
unverified mappings are surfaced explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from mijhar.compliance.registry import Control, Framework
from mijhar.core.config import Platform, Status
from mijhar.core.models import Finding


class ControlStatus(str, Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_ASSESSED = "not_assessed"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class ControlAssessment:
    """The automated assessment result for one framework control."""

    control_id: str
    title: str
    domain: str
    subdomain: str
    level: str
    status: ControlStatus
    mapped_findings: List[Finding] = field(default_factory=list)
    pass_count: int = 0
    fail_count: int = 0
    warning_count: int = 0
    error_count: int = 0
    needs_review: bool = False
    verified: bool = True
    pending_verification: bool = False
    manual_review: bool = False
    reviewer: str = ""
    review_notes: str = ""
    excluded: bool = False
    excluded_reason: str = ""

    def as_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "domain": self.domain,
            "level": self.level,
            "status": self.status.value,
            "pass_count": self.pass_count,
            "fail_count": self.fail_count,
            "warning_count": self.warning_count,
            "error_count": self.error_count,
            "needs_review": self.needs_review,
            "verified": self.verified,
            "pending_verification": self.pending_verification,
            "excluded": self.excluded,
            "excluded_reason": self.excluded_reason,
            "finding_ids": [f.id for f in self.mapped_findings],
            "remediation": [f.remediation for f in self.mapped_findings if f.remediation],
        }


@dataclass
class ComplianceSummary:
    """Aggregate compliance numbers for a framework."""

    framework_id: str
    framework_name: str
    framework_version: str
    total_controls: int = 0
    applicable_controls: int = 0
    compliant: int = 0
    non_compliant: int = 0
    partially_compliant: int = 0
    not_assessed: int = 0
    not_applicable: int = 0
    evidence_covered: int = 0
    pending_verification: int = 0

    @property
    def compliance_pct(self) -> float:
        """Compliant / assessed-with-outcome, expressed as a percentage.

        Not-assessed and not-applicable controls are excluded so a small
        automated scan cannot be mistaken for full framework compliance.
        """
        denominator = self.compliant + self.non_compliant + self.partially_compliant
        if denominator == 0:
            return 0.0
        return round(self.compliant / denominator * 100, 1)

    @property
    def evidence_coverage_pct(self) -> float:
        if self.applicable_controls == 0:
            return 0.0
        return round(self.evidence_covered / self.applicable_controls * 100, 1)

    def as_dict(self) -> dict:
        return {
            "framework_id": self.framework_id,
            "framework_name": self.framework_name,
            "framework_version": self.framework_version,
            "total_controls": self.total_controls,
            "applicable_controls": self.applicable_controls,
            "compliant": self.compliant,
            "non_compliant": self.non_compliant,
            "partially_compliant": self.partially_compliant,
            "not_assessed": self.not_assessed,
            "not_applicable": self.not_applicable,
            "evidence_covered": self.evidence_covered,
            "evidence_coverage_pct": self.evidence_coverage_pct,
            "compliance_pct": self.compliance_pct,
            "pending_verification": self.pending_verification,
        }


class ControlAssessor:
    """Assess framework controls against a set of technical findings."""

    def assess(
        self,
        framework: Framework,
        findings: List[Finding],
        platform: Optional[Platform] = None,
        included_rule_ids: Optional[set] = None,
    ) -> List[ControlAssessment]:
        return [
            self.assess_control(control, findings, included_rule_ids=included_rule_ids)
            for control in framework.controls
        ]

    def assess_control(
        self,
        control: Control,
        findings: List[Finding],
        included_rule_ids: Optional[set] = None,
    ) -> ControlAssessment:
        if not control.technical:
            return ControlAssessment(
                control_id=control.id,
                title=control.title,
                domain=control.domain,
                subdomain=control.subdomain,
                level=control.level,
                status=ControlStatus.NOT_APPLICABLE,
                verified=control.verified,
                pending_verification=control.pending_verification,
                excluded=True,
                excluded_reason=control.excluded_reason or "non-technical/organizational control",
            )

        if not control.applicable:
            return ControlAssessment(
                control_id=control.id,
                title=control.title,
                domain=control.domain,
                subdomain=control.subdomain,
                level=control.level,
                status=ControlStatus.NOT_APPLICABLE,
                verified=control.verified,
                pending_verification=control.pending_verification,
            )

        rule_ids = control.rule_ids
        if not rule_ids:
            # No implemented technical check maps to this control.
            return ControlAssessment(
                control_id=control.id,
                title=control.title,
                domain=control.domain,
                subdomain=control.subdomain,
                level=control.level,
                status=ControlStatus.NOT_ASSESSED,
                verified=control.verified,
                pending_verification=control.pending_verification,
                excluded_reason="unsupported: no implemented technical check for this control",
            )

        # Platform awareness: when the scan tells us which rules were actually
        # selected, a control whose mappings point only to *other* platforms is
        # not applicable to this platform (never silently "not assessed").
        if included_rule_ids is not None and not any(rid in included_rule_ids for rid in rule_ids):
            return ControlAssessment(
                control_id=control.id,
                title=control.title,
                domain=control.domain,
                subdomain=control.subdomain,
                level=control.level,
                status=ControlStatus.NOT_APPLICABLE,
                verified=control.verified,
                pending_verification=control.pending_verification,
                excluded=True,
                excluded_reason="platform_incompatible: control maps only to checks for another platform",
            )

        expected_rule_ids = set(rule_ids)
        if included_rule_ids is not None:
            expected_rule_ids &= included_rule_ids
        mapped = [f for f in findings if f.rule_id in expected_rule_ids]
        if not mapped:
            return ControlAssessment(
                control_id=control.id,
                title=control.title,
                domain=control.domain,
                subdomain=control.subdomain,
                level=control.level,
                status=ControlStatus.NOT_ASSESSED,
                verified=control.verified,
                pending_verification=control.pending_verification,
            )

        pass_count = sum(1 for f in mapped if f.status is Status.PASS)
        fail_count = sum(1 for f in mapped if f.status is Status.FAIL)
        warning_count = sum(1 for f in mapped if f.status is Status.WARNING)
        error_count = sum(
            1 for f in mapped
            if f.status in (Status.ERROR, Status.NOT_APPLICABLE, Status.NOT_SUPPORTED)
        )
        missing_results = expected_rule_ids - {f.rule_id for f in mapped}

        if fail_count > 0:
            status = ControlStatus.NON_COMPLIANT
        elif warning_count > 0 or (pass_count > 0 and (error_count or missing_results)):
            status = ControlStatus.PARTIALLY_COMPLIANT
        elif pass_count > 0:
            status = ControlStatus.COMPLIANT
        else:
            status = ControlStatus.NOT_ASSESSED

        # Automated results are never a full compliance determination on their
        # own; flag non-compliant/partial results for human review.
        needs_review = status in (ControlStatus.NON_COMPLIANT, ControlStatus.PARTIALLY_COMPLIANT)

        return ControlAssessment(
            control_id=control.id,
            title=control.title,
            domain=control.domain,
            subdomain=control.subdomain,
            level=control.level,
            status=status,
            mapped_findings=mapped,
            pass_count=pass_count,
            fail_count=fail_count,
            warning_count=warning_count,
            error_count=error_count,
            needs_review=needs_review,
            verified=control.verified,
            pending_verification=control.pending_verification or any(
                not m.verified for m in control.mappings
            ),
        )

    def summary(self, framework: Framework, assessments: List[ControlAssessment]) -> ComplianceSummary:
        by_status: Dict[ControlStatus, int] = {s: 0 for s in ControlStatus}
        for a in assessments:
            by_status[a.status] += 1
        applicable = sum(
            1 for a in assessments if a.status is not ControlStatus.NOT_APPLICABLE
        )
        evidence = sum(1 for a in assessments if a.mapped_findings)
        pending = sum(1 for a in assessments if a.pending_verification)
        return ComplianceSummary(
            framework_id=framework.id,
            framework_name=framework.name,
            framework_version=framework.version,
            total_controls=len(assessments),
            applicable_controls=applicable,
            compliant=by_status[ControlStatus.COMPLIANT],
            non_compliant=by_status[ControlStatus.NON_COMPLIANT],
            partially_compliant=by_status[ControlStatus.PARTIALLY_COMPLIANT],
            not_assessed=by_status[ControlStatus.NOT_ASSESSED],
            not_applicable=by_status[ControlStatus.NOT_APPLICABLE],
            evidence_covered=evidence,
            pending_verification=pending,
        )

    def gaps(self, assessments: List[ControlAssessment]) -> List[ControlAssessment]:
        """Return controls that represent compliance gaps (non/partial compliance)."""
        return [
            a
            for a in assessments
            if a.status in (ControlStatus.NON_COMPLIANT, ControlStatus.PARTIALLY_COMPLIANT)
        ]
