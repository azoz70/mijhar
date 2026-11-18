"""Compliance mapping: connect technical rules/findings to framework controls."""

from __future__ import annotations

from typing import Dict, List, Optional

from mijhar.compliance.registry import Control, ControlMapping, Framework, MappingType
from mijhar.core.models import Finding
from mijhar.rules.loader import Rule


class ComplianceMapper:
    """Map rules and findings to framework controls."""

    def controls_for_rule(self, rule_id: str, framework: Framework) -> List[Control]:
        return [c for c in framework.controls if rule_id in c.rule_ids]

    def controls_for_finding(self, finding: Finding, framework: Framework) -> List[Control]:
        return self.controls_for_rule(finding.rule_id, framework)

    def mappings_for_rule(self, rule_id: str, framework: Framework) -> List[ControlMapping]:
        mappings: List[ControlMapping] = []
        for control in framework.controls:
            for mapping in control.mappings:
                if mapping.rule_id == rule_id:
                    mappings.append(mapping)
        return mappings

    def unmapped_rules(self, rules: List[Rule], framework: Framework) -> List[str]:
        """Return rule ids not referenced by any control in the framework."""
        referenced = {m.rule_id for c in framework.controls for m in c.mappings}
        return [r.id for r in rules if r.id not in referenced]

    def rule_to_controls(self, framework: Framework) -> Dict[str, List[Control]]:
        return framework.rule_to_controls()

    def direct_mappings(self, framework: Framework) -> List[ControlMapping]:
        return self._mappings_by_type(framework, MappingType.DIRECT)

    def partial_mappings(self, framework: Framework) -> List[ControlMapping]:
        return self._mappings_by_type(framework, MappingType.PARTIAL)

    def supporting_mappings(self, framework: Framework) -> List[ControlMapping]:
        return self._mappings_by_type(framework, MappingType.SUPPORTING_EVIDENCE)

    @staticmethod
    def _mappings_by_type(framework: Framework, mapping_type: MappingType) -> List[ControlMapping]:
        return [
            m
            for c in framework.controls
            for m in c.mappings
            if m.mapping_type is mapping_type
        ]

    def technical_controls(self, framework: Framework) -> List[Control]:
        """Controls within MIJHAR's technical assessment scope."""
        return [c for c in framework.controls if c.technical]

    def excluded_controls(self, framework: Framework) -> List[Control]:
        """Controls excluded from technical assessment (with reason)."""
        return [c for c in framework.controls if not c.technical]

    def pending_verification_controls(self, framework: Framework) -> List[Control]:
        """Return controls whose mapping/identifiers are still pending verification."""
        return [
            c
            for c in framework.controls
            if c.pending_verification or any(not m.verified for m in c.mappings)
        ]
