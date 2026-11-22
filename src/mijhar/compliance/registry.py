"""Framework registry: data models and YAML loading for compliance frameworks."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

import yaml


class MappingType(str, Enum):
    """How a technical check relates to a framework control.

    ``direct`` — the technical check directly verifies the requirement.
    ``partial`` — the technical check verifies only part of the requirement.
    ``supporting_evidence`` — the check provides evidence but cannot establish
    compliance by itself.
    """

    DIRECT = "direct"
    PARTIAL = "partial"
    SUPPORTING_EVIDENCE = "supporting_evidence"


@dataclass
class ControlMapping:
    """A link from a framework control to a technical rule."""

    rule_id: str
    mapping_type: MappingType = MappingType.SUPPORTING_EVIDENCE
    source: str = ""
    verified: bool = False
    notes: str = ""
    confidence: str = ""


@dataclass
class Control:
    """A single framework control / recommendation."""

    id: str
    title: str
    description: str = ""
    domain: str = ""
    subdomain: str = ""
    level: str = ""
    applicable: bool = True
    verified: bool = True
    pending_verification: bool = False
    notes: str = ""
    # Technical-assessment scope metadata.
    technical: bool = True
    excluded_reason: str = ""
    assessment_objective: str = ""
    inspection: str = ""
    evidence: str = ""
    method: str = ""
    expected_config: str = ""
    severity: str = ""
    remediation: str = ""
    mappings: List[ControlMapping] = field(default_factory=list)

    @property
    def rule_ids(self) -> List[str]:
        return [m.rule_id for m in self.mappings]


@dataclass
class Domain:
    """A grouping of controls within a framework (e.g. SAMA domain, NCA section)."""

    id: str
    name: str
    controls: List[Control] = field(default_factory=list)


@dataclass
class Framework:
    """A named, versioned compliance framework."""

    id: str
    name: str
    version: str
    description: str = ""
    mapping_note: str = ""
    domains: List[Domain] = field(default_factory=list)

    @property
    def controls(self) -> List[Control]:
        return [c for d in self.domains for c in d.controls]

    def get_control(self, control_id: str) -> Optional[Control]:
        for control in self.controls:
            if control.id == control_id:
                return control
        return None

    def rule_to_controls(self) -> Dict[str, List[Control]]:
        """Map rule_id -> the controls that reference it."""
        result: Dict[str, List[Control]] = {}
        for control in self.controls:
            for mapping in control.mappings:
                result.setdefault(mapping.rule_id, []).append(control)
        return result


def _parse_mapping(data: dict, source: str) -> ControlMapping:
    if not isinstance(data, dict) or "rule_id" not in data:
        raise ValueError(f"{source}: mapping requires 'rule_id'")
    mapping_type = data.get("type", "supporting_evidence").lower()
    if mapping_type not in {m.value for m in MappingType}:
        raise ValueError(f"{source}: invalid mapping type '{mapping_type}'")
    return ControlMapping(
        rule_id=str(data["rule_id"]),
        mapping_type=MappingType(mapping_type),
        source=str(data.get("source", "")),
        verified=bool(data.get("verified", False)),
        notes=str(data.get("notes", "")),
        confidence=str(data.get("confidence", "")),
    )


def _parse_control(data: dict, source: str, domain_name: str = "") -> Control:
    if not isinstance(data, dict):
        raise ValueError(f"{source}: control must be a mapping")
    if "id" not in data or "title" not in data:
        raise ValueError(f"{source}: control requires 'id' and 'title'")
    return Control(
        id=str(data["id"]),
        title=str(data["title"]),
        description=str(data.get("description", "")),
        domain=str(data.get("domain", domain_name)),
        subdomain=str(data.get("subdomain", "")),
        level=str(data.get("level", "")),
        applicable=bool(data.get("applicable", True)),
        verified=bool(data.get("verified", True)),
        pending_verification=bool(data.get("pending_verification", False)),
        notes=str(data.get("notes", "")),
        technical=bool(data.get("technical", True)),
        excluded_reason=str(data.get("excluded_reason", "")),
        assessment_objective=str(data.get("assessment_objective", "")),
        inspection=str(data.get("inspection", "")),
        evidence=str(data.get("evidence", "")),
        method=str(data.get("method", "")),
        expected_config=str(data.get("expected_config", "")),
        severity=str(data.get("severity", "")),
        remediation=str(data.get("remediation", "")),
        mappings=[_parse_mapping(m, source) for m in data.get("mappings", [])],
    )


def framework_from_dict(data: dict, source: str) -> Framework:
    """Build and validate a :class:`Framework` from a parsed YAML mapping."""
    if not isinstance(data, dict):
        raise ValueError(f"{source}: framework must be a mapping")
    for key in ("id", "name", "version"):
        if key not in data:
            raise ValueError(f"{source}: framework requires '{key}'")

    domains: List[Domain] = []
    raw_domains = data.get("domains", [])
    if raw_domains:
        for d in raw_domains:
            domains.append(
                Domain(
                    id=str(d.get("id", "")),
                    name=str(d.get("name", "")),
                    controls=[_parse_control(c, source, str(d.get("name", ""))) for c in d.get("controls", [])],
                )
            )
    else:
        domains.append(
            Domain(
                id="default",
                name=data.get("name", ""),
                controls=[_parse_control(c, source) for c in data.get("controls", [])],
            )
        )

    return Framework(
        id=str(data["id"]),
        name=str(data["name"]),
        version=str(data["version"]),
        description=str(data.get("description", "")),
        mapping_note=str(data.get("mapping_note", "")),
        domains=domains,
    )


class FrameworkRegistry:
    """Load and query all bundled compliance frameworks."""

    def __init__(self, frameworks_dir: Optional[Path] = None) -> None:
        self.frameworks_dir = frameworks_dir
        self._frameworks: Dict[str, Framework] = {}

    def load(self) -> List[Framework]:
        if self.frameworks_dir is None or not self.frameworks_dir.is_dir():
            return []
        for path in sorted(self.frameworks_dir.rglob("*")):
            if path.suffix.lower() not in (".yaml", ".yml"):
                continue
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                continue
            framework = framework_from_dict(data, str(path))
            self._frameworks[framework.id] = framework
        return list(self._frameworks.values())

    def get(self, framework_id: str) -> Optional[Framework]:
        return self._frameworks.get(framework_id)

    def list(self) -> List[Framework]:
        return list(self._frameworks.values())

    def ids(self) -> List[str]:
        return sorted(self._frameworks)
