"""Centralized platform applicability and capability engine.

This package decides — *before* any check executes — which technical
assessment rules are eligible for a selected platform and target, records the
reason every excluded rule was left out, and detects optional components so
dependent checks are only loaded when their prerequisite product/service is
actually present.

It keeps applicability decisions strictly separate from check execution, and
framework catalogs strictly separate from executable technical rules.
"""

from mijhar.applicability.engine import (
    ApplicabilityEngine,
    ApplicabilityResult,
    Exclusion,
    ExclusionReason,
    detect_capabilities,
)

__all__ = [
    "ApplicabilityEngine",
    "ApplicabilityResult",
    "Exclusion",
    "ExclusionReason",
    "detect_capabilities",
]
