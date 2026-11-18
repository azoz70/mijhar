"""Reporting engine: terminal, JSON, CSV, and HTML output."""

from __future__ import annotations

from typing import Any, List


def finding_dicts(findings: List[Any]) -> List[dict]:
    """Normalize a list of Finding objects or dicts into dicts."""
    return [f.as_dict() if hasattr(f, "as_dict") else dict(f) for f in findings]
