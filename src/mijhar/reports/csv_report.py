"""CSV report generation."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any, List

from mijhar.reports import finding_dicts

FIELD_ORDER = [
    "id",
    "rule_id",
    "asset_id",
    "title",
    "severity",
    "status",
    "fact_key",
    "observed_value",
    "technical_impact",
    "security_impact",
    "remediation",
    "detected_at",
]


def findings_csv(findings: List[Any]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=FIELD_ORDER, extrasaction="ignore")
    writer.writeheader()
    for finding in finding_dicts(findings):
        row = {k: finding.get(k, "") for k in FIELD_ORDER}
        observed = row.get("observed_value")
        row["observed_value"] = (
            json.dumps(observed, default=str) if observed is not None else ""
        )
        writer.writerow(row)
    return buffer.getvalue()


def write_csv(path: Path | str, findings: List[Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(findings_csv(findings), encoding="utf-8")
