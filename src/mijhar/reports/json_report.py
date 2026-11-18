"""JSON report generation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List

from mijhar.reports import finding_dicts


def findings_json(findings: List[Any], pretty: bool = True) -> str:
    return json.dumps(
        finding_dicts(findings),
        indent=2 if pretty else None,
        sort_keys=True,
        default=str,
    )


def report_json(scan_result: Any, pretty: bool = True) -> str:
    data = scan_result.as_dict() if hasattr(scan_result, "as_dict") else scan_result
    return json.dumps(data, indent=2 if pretty else None, sort_keys=True, default=str)


def write_json(path: Path | str, data: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )
