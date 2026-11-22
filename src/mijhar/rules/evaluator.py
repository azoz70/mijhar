"""Rule evaluation: map a rule + collected facts to a :class:`Finding`."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from mijhar.collectors.base import Fact
from mijhar.core.config import Platform, Status
from mijhar.core.models import Finding
from mijhar.rules.loader import Rule


def _apply(operator: str, actual: Any, expected: Any) -> Optional[bool]:
    """Apply a comparison operator; ``None`` means 'cannot be determined'."""
    if operator == "equals":
        return actual == expected
    if operator == "not_equals":
        return actual != expected
    if operator == "in":
        return actual in expected
    if operator == "not_in":
        return actual not in expected
    if operator == "less_than":
        return actual < expected
    if operator == "less_than_or_equal":
        return actual <= expected
    if operator == "greater_than":
        return actual > expected
    if operator == "greater_than_or_equal":
        return actual >= expected
    if operator == "exists":
        return actual is not None
    if operator == "not_exists":
        return actual is None
    if operator == "contains":
        return expected in actual
    if operator == "not_contains":
        return expected not in actual
    raise ValueError(f"unknown operator: {operator}")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class RuleEvaluator:
    """Evaluate rules against a set of collected facts."""

    def evaluate(
        self,
        rule: Rule,
        facts: List[Fact],
        asset_id: str = "local",
        now: Optional[str] = None,
    ) -> Finding:
        fact_map: Dict[str, Fact] = {f.key: f for f in facts}
        fact = fact_map.get(rule.check.fact)
        observed: Any = None
        status: Status
        evidence: Dict[str, Any] = {"fact": rule.check.fact}

        if fact is None:
            status = Status.NOT_APPLICABLE
            evidence["reason"] = "fact not collected"
        elif fact.error:
            status = Status.ERROR
            evidence["reason"] = fact.error
            evidence["raw"] = fact.raw
        elif fact.value is None:
            status = Status.NOT_APPLICABLE
            evidence["reason"] = "fact collected but value is unknown"
        else:
            observed = fact.value
            evidence["value"] = observed
            evidence["raw"] = fact.raw
            evidence["source"] = fact.source
            try:
                passed = _apply(rule.check.operator, observed, rule.check.value)
            except (TypeError, ValueError):
                status = Status.ERROR
                evidence["reason"] = "incomparable value for operator"
            else:
                if passed is None:
                    status = Status.NOT_APPLICABLE
                    evidence["reason"] = "operator could not determine a result"
                elif passed:
                    status = Status.PASS
                else:
                    status = rule.check.fail_status

        return Finding(
            id=f"F-{uuid.uuid4().hex[:10]}",
            rule_id=rule.id,
            asset_id=asset_id,
            title=rule.title,
            description=rule.description,
            severity=rule.severity,
            status=status,
            fact_key=rule.check.fact,
            observed_value=observed,
            evidence=evidence,
            technical_impact=rule.technical_impact,
            security_impact=rule.security_impact,
            remediation=rule.remediation,
            framework_refs=dict(rule.references),
            detected_at=now or _now_iso(),
        )

    def evaluate_all(
        self,
        rules: List[Rule],
        facts: List[Fact],
        asset_id: str = "local",
        platform: Optional[Platform] = None,
    ) -> List[Finding]:
        """Evaluate all applicable rules and return the resulting findings."""
        findings: List[Finding] = []
        for rule in rules:
            if platform is not None and not rule.applies_to(platform):
                continue
            findings.append(self.evaluate(rule, facts, asset_id=asset_id))
        return findings
