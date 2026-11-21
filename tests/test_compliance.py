"""Tests for the GRC compliance engine: registry, mapper, and assessor."""

from __future__ import annotations

from pathlib import Path

import pytest

from mijhar.compliance.assessment import ControlAssessor, ControlStatus
from mijhar.compliance.mapper import ComplianceMapper
from mijhar.compliance.registry import (
    Control,
    ControlMapping,
    Domain,
    Framework,
    FrameworkRegistry,
    MappingType,
)
from mijhar.core.config import Status
from tests.conftest import make_finding

FRAMEWORKS_DIR = Path(__file__).resolve().parents[1] / "src" / "mijhar" / "compliance" / "data"


def _registry() -> FrameworkRegistry:
    registry = FrameworkRegistry(FRAMEWORKS_DIR)
    registry.load()
    return registry


def _framework(controls):
    return Framework(
        id="test",
        name="Test Framework",
        version="1.0",
        domains=[Domain(id="d", name="Domain", controls=controls)],
    )


def _control(control_id="C-1", rule_ids=None, applicable=True):
    return Control(
        id=control_id,
        title="Control",
        applicable=applicable,
        mappings=[ControlMapping(rule_id=r, mapping_type=MappingType.DIRECT) for r in (rule_ids or [])],
    )


# -- registry ----------------------------------------------------------------


def test_registry_loads_four_frameworks():
    registry = _registry()
    assert set(registry.ids()) == {"cis", "nca-ecc", "sama-csf", "iso27001"}


def test_cis_has_expected_controls():
    cis = _registry().get("cis")
    assert cis is not None
    assert {c.id for c in cis.controls} >= {"5.2.8", "5.2.4", "3.5.1.1"}


def test_nca_and_sama_verification_status():
    registry = _registry()
    # SAMA CSF: 32 subdomains + 220 control considerations (verified hierarchy
    # from the Rulebook); rule links unverified.
    sama = registry.get("sama-csf")
    subdomains = [c for c in sama.controls if c.level != "consideration"]
    considerations = [c for c in sama.controls if c.level == "consideration"]
    assert len(subdomains) == 32
    assert len(considerations) == 220
    assert all(c.verified for c in sama.controls)
    assert all(not m.verified for c in sama.controls for m in c.mappings)
    # NCA ECC-2:2024: 108 main controls + 91 sub-controls, verified from the
    # official document; rule-to-control links are interpretive (unverified).
    nca = registry.get("nca-ecc")
    assert nca.version == "ECC-2:2024"
    assert len(nca.controls) == 199
    assert any(c.mappings for c in nca.controls)
    assert all(not m.verified for c in nca.controls for m in c.mappings)


# -- mapper ------------------------------------------------------------------


def test_controls_for_rule():
    cis = _registry().get("cis")
    mapper = ComplianceMapper()
    controls = mapper.controls_for_rule("SSH-001", cis)
    assert [c.id for c in controls] == ["5.2.8"]


def test_unmapped_rules_within_framework():
    from mijhar.rules.loader import rule_from_dict

    rule = rule_from_dict(
        {
            "id": "NO-MAP",
            "title": "unmapped",
            "severity": "low",
            "platforms": ["linux"],
            "check": {"fact": "a", "operator": "exists"},
        },
        "test",
    )
    nca = _registry().get("nca-ecc")
    mapper = ComplianceMapper()
    assert "NO-MAP" in mapper.unmapped_rules([rule], nca)


def test_iso_mappings_classification():
    iso = _registry().get("iso27001")
    mapper = ComplianceMapper()
    direct = mapper.direct_mappings(iso)
    # The only direct ISO mapping is the privileged-access (SSH root login) link.
    assert {(m.rule_id) for m in direct} == {"SSH-001"}
    # Partial/supporting mappings exist for other rules.
    assert any(
        m.mapping_type in (MappingType.PARTIAL, MappingType.SUPPORTING_EVIDENCE)
        for c in iso.controls
        for m in c.mappings
    )


# -- assessor ----------------------------------------------------------------


def test_assess_compliant():
    framework = _framework([_control("C-1", ["R-1"])])
    assessor = ControlAssessor()
    assessment = assessor.assess_control(framework.controls[0], [make_finding(rule_id="R-1", status=Status.PASS)])
    assert assessment.status is ControlStatus.COMPLIANT
    assert assessment.needs_review is False


@pytest.mark.parametrize("status", [Status.ERROR, Status.NOT_APPLICABLE, Status.NOT_SUPPORTED, None])
def test_assess_pass_with_incomplete_results_requires_review(status):
    control = _control("C-1", ["R-1", "R-2"])
    findings = [make_finding(rule_id="R-1", status=Status.PASS)]
    if status is not None:
        findings.append(make_finding(rule_id="R-2", status=status))

    assessment = ControlAssessor().assess_control(control, findings, included_rule_ids={"R-1", "R-2"})

    assert assessment.status is ControlStatus.PARTIALLY_COMPLIANT
    assert assessment.needs_review


def test_assess_non_compliant_requires_review():
    framework = _framework([_control("C-1", ["R-1"])])
    assessor = ControlAssessor()
    assessment = assessor.assess_control(framework.controls[0], [make_finding(rule_id="R-1", status=Status.FAIL)])
    assert assessment.status is ControlStatus.NON_COMPLIANT
    assert assessment.needs_review is True


def test_assess_partially_compliant_on_warning():
    framework = _framework([_control("C-1", ["R-1"])])
    assessor = ControlAssessor()
    assessment = assessor.assess_control(framework.controls[0], [make_finding(rule_id="R-1", status=Status.WARNING)])
    assert assessment.status is ControlStatus.PARTIALLY_COMPLIANT


def test_assess_not_assessed_without_mappings():
    framework = _framework([_control("C-1", [])])
    assessor = ControlAssessor()
    assessment = assessor.assess_control(framework.controls[0], [])
    assert assessment.status is ControlStatus.NOT_ASSESSED


def test_assess_not_applicable():
    framework = _framework([_control("C-1", ["R-1"], applicable=False)])
    assessor = ControlAssessor()
    assessment = assessor.assess_control(framework.controls[0], [make_finding(rule_id="R-1", status=Status.PASS)])
    assert assessment.status is ControlStatus.NOT_APPLICABLE


def test_summary_counts_and_percentages():
    framework = _framework(
        [
            _control("C-1", ["R-1"]),   # pass
            _control("C-2", ["R-2"]),   # fail
            _control("C-3", ["R-3"]),   # warning
            _control("C-4", []),        # not assessed
        ]
    )
    assessor = ControlAssessor()
    findings = [
        make_finding(rule_id="R-1", status=Status.PASS),
        make_finding(rule_id="R-2", status=Status.FAIL),
        make_finding(rule_id="R-3", status=Status.WARNING),
    ]
    assessments = assessor.assess(framework, findings)
    summary = assessor.summary(framework, assessments)
    assert summary.total_controls == 4
    assert summary.compliant == 1
    assert summary.non_compliant == 1
    assert summary.partially_compliant == 1
    assert summary.not_assessed == 1
    # 1 compliant out of 3 assessed-with-outcome -> 33.3%
    assert summary.compliance_pct == 33.3
    assert summary.evidence_covered == 3
    assert summary.evidence_coverage_pct == 75.0


def test_gaps_returns_only_non_and_partial():
    framework = _framework(
        [
            _control("C-1", ["R-1"]),
            _control("C-2", ["R-2"]),
            _control("C-3", ["R-3"]),
        ]
    )
    assessor = ControlAssessor()
    findings = [
        make_finding(rule_id="R-1", status=Status.PASS),
        make_finding(rule_id="R-2", status=Status.FAIL),
        make_finding(rule_id="R-3", status=Status.WARNING),
    ]
    gaps = assessor.gaps(assessor.assess(framework, findings))
    assert [g.control_id for g in gaps] == ["C-2", "C-3"]


def test_mapping_types_are_direct_partial_supporting():
    assert {m.value for m in MappingType} == {
        "direct",
        "partial",
        "supporting_evidence",
    }


def test_technical_and_excluded_controls():
    mapper = ComplianceMapper()
    registry = _registry()

    # NCA ECC-2:2024: governance/BCM/physical/third-party controls are excluded.
    nca = registry.get("nca-ecc")
    excluded = mapper.excluded_controls(nca)
    assert excluded, "NCA should have excluded non-technical controls"
    assert all(c.excluded_reason for c in excluded)
    assert len(mapper.technical_controls(nca)) + len(excluded) == len(nca.controls)

    # SAMA CSF: 17 excluded subdomains; 15 technical subdomains + 220
    # control considerations.
    sama = registry.get("sama-csf")
    assert len(mapper.excluded_controls(sama)) == 17
    assert len(mapper.technical_controls(sama)) == 235

    # CIS: representative technical subset — all technical.
    cis = registry.get("cis")
    assert len(mapper.technical_controls(cis)) == len(cis.controls)

    # ISO: A.5.24 excluded (organizational incident planning).
    iso = registry.get("iso27001")
    iso_excluded = {c.id for c in mapper.excluded_controls(iso)}
    assert iso_excluded == {"A.5.24"}


def test_non_technical_control_is_excluded_from_assessment():
    control = Control(
        id="GOV-1",
        title="Governance control",
        technical=False,
        excluded_reason="Governance — outside technical scope.",
    )
    framework = _framework([control])
    assessor = ControlAssessor()
    assessment = assessor.assess_control(framework.controls[0], [])
    assert assessment.status is ControlStatus.NOT_APPLICABLE
    assert assessment.excluded is True
    assert assessment.excluded_reason == "Governance — outside technical scope."
