"""YAML rule loading and validation for the MIJHAR rules engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from mijhar.core.config import Platform, Severity, Status

VALID_OPERATORS = {
    "equals",
    "not_equals",
    "in",
    "not_in",
    "less_than",
    "less_than_or_equal",
    "greater_than",
    "greater_than_or_equal",
    "exists",
    "not_exists",
    "contains",
    "not_contains",
}


class RuleValidationError(ValueError):
    """Raised when a rule document is missing or has invalid fields."""


@dataclass
class RuleCheck:
    """The evaluation condition of a rule."""

    fact: str
    operator: str
    value: Any = None
    fail_status: Status = Status.FAIL


@dataclass
class Rule:
    """A single security configuration check.

    A rule *passes* when its check condition holds against the collected fact;
    otherwise it fails (or warns, per ``check.fail_status``).

    In addition to the execution condition, a rule carries structured
    applicability metadata that the :class:`~mijhar.applicability.ApplicabilityEngine`
    uses to decide — *before* any check runs — whether the rule is eligible for
    the selected platform, what components/prerequisites it needs, and how it
    maps to framework controls.
    """

    id: str
    title: str
    severity: Severity
    platforms: List[Platform]
    check: RuleCheck
    description: str = ""
    technical_impact: str = ""
    security_impact: str = ""
    remediation: str = ""
    references: Dict[str, List[str]] = field(default_factory=dict)
    # -- applicability / capability metadata ---------------------------------
    rule_version: str = "1.0"
    enabled: bool = True
    required_components: List[str] = field(default_factory=list)
    assessment_type: str = "configuration"
    technical_assessability: str = "assessable"
    prerequisites: List[str] = field(default_factory=list)
    required_permissions: List[str] = field(default_factory=list)
    evidence_requirements: List[str] = field(default_factory=list)
    remediation_guidance: str = ""

    def applies_to(self, platform: Platform) -> bool:
        return Platform.UNKNOWN in self.platforms or platform in self.platforms

    @property
    def framework_mappings(self) -> Dict[str, List[str]]:
        """Alias for ``references`` (framework id -> control/sub-control ids)."""
        return self.references


def _require(mapping: dict, key: str, source: str) -> Any:
    if key not in mapping or mapping[key] in (None, ""):
        raise RuleValidationError(f"{source}: missing required field '{key}'")
    return mapping[key]


def rule_from_dict(data: dict, source: str) -> Rule:
    """Build and validate a :class:`Rule` from a parsed YAML mapping."""
    if not isinstance(data, dict):
        raise RuleValidationError(f"{source}: rule must be a mapping, got {type(data).__name__}")

    rule_id = str(_require(data, "id", source))
    title = str(_require(data, "title", source))
    severity_raw = str(_require(data, "severity", source)).lower()
    if severity_raw not in {s.value for s in Severity}:
        raise RuleValidationError(
            f"{source}: invalid severity '{severity_raw}' (expected one of "
            f"{[s.value for s in Severity]})"
        )

    platforms_raw = data.get("platforms", ["any"])
    if isinstance(platforms_raw, str):
        platforms_raw = [platforms_raw]
    platforms: List[Platform] = []
    for p in platforms_raw:
        p = str(p).lower()
        if p in ("any", "*"):
            platforms.append(Platform.UNKNOWN)
        elif p in {x.value for x in Platform}:
            platforms.append(Platform(p))
        else:
            raise RuleValidationError(f"{source}: invalid platform '{p}'")

    check_raw = _require(data, "check", source)
    if not isinstance(check_raw, dict):
        raise RuleValidationError(f"{source}: 'check' must be a mapping")
    fact = str(_require(check_raw, "fact", source))
    operator = str(_require(check_raw, "operator", source)).lower()
    if operator not in VALID_OPERATORS:
        raise RuleValidationError(
            f"{source}: invalid operator '{operator}' (expected one of {sorted(VALID_OPERATORS)})"
        )
    fail_status_raw = str(check_raw.get("fail_status", "fail")).lower()
    if fail_status_raw not in {s.value for s in Status}:
        raise RuleValidationError(f"{source}: invalid fail_status '{fail_status_raw}'")

    references = data.get("references", {})
    if not isinstance(references, dict):
        raise RuleValidationError(f"{source}: 'references' must be a mapping")

    def _str_list(key: str, default=None) -> List[str]:
        raw = data.get(key, default)
        if raw is None:
            return []
        if isinstance(raw, str):
            return [raw]
        if isinstance(raw, list):
            return [str(x) for x in raw]
        raise RuleValidationError(f"{source}: '{key}' must be a string or list")

    enabled = data.get("enabled", True)
    if not isinstance(enabled, bool):
        raise RuleValidationError(f"{source}: 'enabled' must be a boolean")

    assessability = str(data.get("technical_assessability", "assessable")).lower()
    valid_assessability = {"assessable", "not_assessable", "unsupported"}
    if assessability not in valid_assessability:
        raise RuleValidationError(
            f"{source}: invalid technical_assessability '{assessability}'"
        )

    return Rule(
        id=rule_id,
        title=title,
        severity=Severity(severity_raw),
        platforms=platforms,
        check=RuleCheck(
            fact=fact,
            operator=operator,
            value=check_raw.get("value"),
            fail_status=Status(fail_status_raw),
        ),
        description=str(data.get("description", "")),
        technical_impact=str(data.get("technical_impact", "")),
        security_impact=str(data.get("security_impact", "")),
        remediation=str(data.get("remediation", "")),
        references={str(k): [str(v) for v in vs] for k, vs in references.items()},
        rule_version=str(data.get("rule_version", "1.0")),
        enabled=enabled,
        required_components=_str_list("required_components"),
        assessment_type=str(data.get("assessment_type", "configuration")),
        technical_assessability=assessability,
        prerequisites=_str_list("prerequisites"),
        required_permissions=_str_list("required_permissions"),
        evidence_requirements=_str_list("evidence_requirements"),
        remediation_guidance=str(data.get("remediation_guidance", "")),
    )


def _documents_from_content(content: str) -> List[dict]:
    loaded = yaml.safe_load(content)
    if loaded is None:
        return []
    if isinstance(loaded, list):
        return [item for item in loaded]
    if isinstance(loaded, dict) and "rules" in loaded:
        return list(loaded["rules"])
    return [loaded]


class RuleLoader:
    """Load and validate YAML rules from a directory tree."""

    def __init__(self, rules_dir: Optional[Path] = None) -> None:
        self.rules_dir = rules_dir

    def load(self) -> List[Rule]:
        if self.rules_dir is None or not self.rules_dir.is_dir():
            return []
        rules: List[Rule] = []
        for path in sorted(self.rules_dir.rglob("*")):
            if path.suffix.lower() not in (".yaml", ".yml"):
                continue
            rules.extend(self.load_file(path))
        return rules

    def load_file(self, path: Path) -> List[Rule]:
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuleValidationError(f"{path}: cannot read file: {exc}") from exc
        rules = []
        documents = _documents_from_content(content)
        for index, doc in enumerate(documents):
            source = f"{path}" if len(documents) == 1 else f"{path}#{index}"
            rules.append(rule_from_dict(doc, source))
        return rules
