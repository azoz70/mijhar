"""Structural integrity checks for bundled NCA/SAMA mapping catalogs.

These checks do NOT validate the regulatory meaning of a mapping. Human
review against the official framework is still required.
"""

from __future__ import annotations

from collections import Counter

import pytest

from mijhar.compliance.registry import FrameworkRegistry
from mijhar.core.config import get_config
from mijhar.rules.loader import RuleLoader


@pytest.mark.parametrize("framework_id", ["nca-ecc", "sama-csf"])
def test_framework_mapping_structural_integrity(framework_id):
    config = get_config()
    registry = FrameworkRegistry(config.frameworks_dir)
    registry.load()
    framework = registry.get(framework_id)
    assert framework is not None
    assert framework.controls

    ids = [control.id for control in framework.controls]
    duplicates = [name for name, count in Counter(ids).items() if count > 1]
    assert not duplicates, f"Duplicate {framework_id} control IDs: {duplicates}"

    rule_ids = {rule.id for rule in RuleLoader(config.rules_dir).load()}
    broken = sorted({
        mapping.rule_id
        for control in framework.controls
        for mapping in control.mappings
        if mapping.rule_id not in rule_ids
    })
    assert not broken, f"{framework_id} mappings reference absent technical rules: {broken}"

    assert all(
        not mapping.verified
        for control in framework.controls
        for mapping in control.mappings
    ), "Interpretive links must remain unverified pending official review"


def test_nca_sama_framework_catalogs_are_not_equated_with_compliance():
    """Presence of all framework records is not a technical coverage claim."""
    registry = FrameworkRegistry(get_config().frameworks_dir)
    registry.load()
    for framework_id in ("nca-ecc", "sama-csf"):
        controls = registry.get(framework_id).controls
        assert any(not control.mappings for control in controls)
        assert any(not control.technical for control in controls)
