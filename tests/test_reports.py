"""Tests for JSON, CSV, and HTML report generation."""

from __future__ import annotations

import json

from mijhar.core.config import Severity, Status
from mijhar.reports import csv_report, html_report, json_report
from tests.conftest import make_finding


def _findings():
    return [
        make_finding(rule_id="MAC-001", severity=Severity.HIGH, status=Status.FAIL, observed_value=False),
        make_finding(rule_id="MAC-002", severity=Severity.HIGH, status=Status.PASS, observed_value=True),
    ]


def test_json_report_is_valid_and_complete():
    text = json_report.findings_json(_findings())
    data = json.loads(text)
    assert len(data) == 2
    assert data[0]["rule_id"] == "MAC-001"
    assert data[0]["severity"] == "high"
    assert data[0]["observed_value"] is False


def test_csv_report_has_header_and_rows():
    text = csv_report.findings_csv(_findings())
    lines = text.strip().splitlines()
    assert lines[0].startswith("id,rule_id,asset_id")
    assert len(lines) == 3
    assert "MAC-001" in lines[1]


def test_html_report_contains_findings_and_metadata():
    html = html_report.render_html(_findings(), summary={"CHECKS": 2, "FAILED": 1})
    assert "<html" in html
    assert "MIJHAR" in html
    assert "MAC-001" in html
    assert "FAIL" in html or "fail" in html
    assert "CHECKS" in html


def test_html_report_escapes_severity_classes():
    html = html_report.render_html(_findings())
    assert "sev-high" in html
    assert "st-fail" in html


def test_report_json_roundtrip_for_scan_dict():
    data = {"scan_id": "S-1", "counts": {"total": 1}, "findings": [{"rule_id": "X"}]}
    text = json_report.report_json(data)
    assert json.loads(text)["scan_id"] == "S-1"
