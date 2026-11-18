"""Tests for evidence redaction and integrity verification."""

from __future__ import annotations

from mijhar.evidence.storage import (
    EvidenceStore,
    compute_hash,
    redact,
    to_evidence_text,
)
from tests.conftest import make_finding


def test_compute_hash_is_stable_and_sensitive():
    assert compute_hash("abc") == compute_hash("abc")
    assert compute_hash("abc") != compute_hash("abd")


def test_redact_assignments():
    assert "hunter2" not in redact("password=hunter2")
    assert "password=[REDACTED]" in redact("password=hunter2")
    out = redact("Authorization: Bearer abc123xyz")
    assert "Authorization=[REDACTED]" in out
    assert "abc123xyz" not in out


def test_redact_aws_key_and_long_tokens():
    assert redact("AKIAIOSFODNN7EXAMPLE") == "[REDACTED-AWS-KEY]"
    token = "A" * 48
    assert redact(token) == "[REDACTED-TOKEN]"


def test_store_add_and_verify():
    store = EvidenceStore()
    record = store.add("F-1", "local", "a.b", {"value": "secret"}, redact_content=False)
    assert store.verify(record.id) is True


def test_store_redacts_by_default():
    store = EvidenceStore()
    record = store.add("F-1", "local", "a.b", "password=supersecret")
    assert record.redacted is True
    assert "supersecret" not in record.content


def test_tampering_is_detected():
    store = EvidenceStore()
    record = store.add("F-1", "local", "a.b", "original")
    store.tamper(record.id, "modified")
    assert store.verify(record.id) is False
    assert store.verify_all() == [record.id]


def test_add_for_finding_serializes_evidence():
    store = EvidenceStore()
    finding = make_finding(evidence={"fact": "a.b", "value": False})
    record = store.add_for_finding(finding, "local")
    assert record.finding_id == finding.id
    assert record.key == "a.b"
    assert store.verify(record.id) is True


def test_to_evidence_text():
    assert to_evidence_text("plain") == "plain"
    assert to_evidence_text({"b": 1, "a": 2}) == '{"a": 2, "b": 1}'
