"""Evidence collection, redaction, and integrity verification.

Evidence is stored with a SHA-256 digest so tampering can be detected later.
Sensitive material (passwords, tokens, keys) is redacted on a best-effort
basis before storage; the original is never persisted.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from mijhar.core.models import Finding

_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|credential|authorization)\b\s*[=:]\s*\S+"
)
_AUTH_BEARER = re.compile(r"(?i)\b(authorization)\s*[=:]\s*(?:bearer|basic)\s+\S+")
_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_LONG_TOKEN = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")


def compute_hash(content: str) -> str:
    """Return the hex SHA-256 digest of ``content``."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def redact(content: str) -> str:
    """Best-effort redaction of common secrets in evidence text."""
    if not content:
        return content
    text = _AUTH_BEARER.sub(lambda m: f"{m.group(1)}=[REDACTED]", content)
    text = _SENSITIVE_ASSIGNMENT.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    text = _AWS_KEY.sub("[REDACTED-AWS-KEY]", text)
    text = _LONG_TOKEN.sub("[REDACTED-TOKEN]", text)
    return text


def to_evidence_text(value: Any) -> str:
    """Serialize a structured evidence value into a stable string."""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return str(value)


@dataclass
class EvidenceRecord:
    """One piece of collected evidence, integrity-protected by its digest."""

    id: str
    finding_id: str
    asset_id: str
    key: str
    content: str
    sha256: str
    collected_at: str
    redacted: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "asset_id": self.asset_id,
            "key": self.key,
            "content": self.content,
            "sha256": self.sha256,
            "collected_at": self.collected_at,
            "redacted": self.redacted,
        }


class EvidenceStore:
    """In-memory evidence store with integrity verification."""

    def __init__(self) -> None:
        self._records: Dict[str, EvidenceRecord] = {}

    def add(
        self,
        finding_id: str,
        asset_id: str,
        key: str,
        content: Any,
        redact_content: bool = True,
        collected_at: Optional[str] = None,
    ) -> EvidenceRecord:
        text = to_evidence_text(content)
        stored = redact(text) if redact_content else text
        record = EvidenceRecord(
            id=f"E-{uuid.uuid4().hex[:10]}",
            finding_id=finding_id,
            asset_id=asset_id,
            key=key,
            content=stored,
            sha256=compute_hash(stored),
            collected_at=collected_at or datetime.now(timezone.utc).isoformat(),
            redacted=stored != text,
        )
        self._records[record.id] = record
        return record

    def add_for_finding(self, finding: Finding, asset_id: str) -> EvidenceRecord:
        return self.add(
            finding_id=finding.id,
            asset_id=asset_id,
            key=finding.fact_key,
            content=finding.evidence,
        )

    def get(self, record_id: str) -> Optional[EvidenceRecord]:
        return self._records.get(record_id)

    def all(self) -> List[EvidenceRecord]:
        return list(self._records.values())

    def verify(self, record_id: str) -> bool:
        record = self._records.get(record_id)
        if record is None:
            return False
        return compute_hash(record.content) == record.sha256

    def verify_all(self) -> List[str]:
        """Return ids of records whose stored content no longer matches its digest."""
        return [rid for rid, rec in self._records.items() if compute_hash(rec.content) != rec.sha256]

    def tamper(self, record_id: str, new_content: str) -> None:
        """Test helper: mutate content without updating the digest."""
        self._records[record_id].content = new_content
