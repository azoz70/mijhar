"""SQLite database layer for MIJHAR.

Data models cover assets, scans (which double as scan history), rules,
findings, evidence, frameworks, controls, compliance mappings, and
remediation records. All access goes through the :class:`Database` class,
which uses SQLite via the standard library.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from mijhar.compliance.registry import Framework
from mijhar.core.models import Finding
from mijhar.evidence.storage import EvidenceRecord, compute_hash, redact_finding_evidence, redact_value

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    platform TEXT,
    hostname TEXT,
    os_version TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    platform TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    status TEXT,
    checks_total INTEGER DEFAULT 0,
    passed INTEGER DEFAULT 0,
    failed INTEGER DEFAULT 0,
    warnings INTEGER DEFAULT 0,
    errors INTEGER DEFAULT 0,
    frameworks TEXT
);

CREATE TABLE IF NOT EXISTS scan_exclusions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    rule_id TEXT,
    title TEXT,
    reason TEXT,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    title TEXT,
    severity TEXT,
    platforms TEXT,
    fact TEXT,
    operator TEXT,
    check_value TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    rule_id TEXT,
    asset_id TEXT,
    title TEXT,
    description TEXT,
    severity TEXT,
    status TEXT,
    fact_key TEXT,
    observed_value TEXT,
    evidence TEXT,
    technical_impact TEXT,
    security_impact TEXT,
    remediation TEXT,
    framework_refs TEXT,
    detected_at TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    finding_id TEXT,
    asset_id TEXT,
    key TEXT,
    content TEXT,
    sha256 TEXT,
    collected_at TEXT,
    redacted INTEGER
);

CREATE TABLE IF NOT EXISTS frameworks (
    id TEXT PRIMARY KEY,
    name TEXT,
    version TEXT,
    description TEXT,
    mapping_note TEXT
);

CREATE TABLE IF NOT EXISTS controls (
    id TEXT PRIMARY KEY,
    framework_id TEXT,
    control_id TEXT,
    title TEXT,
    description TEXT,
    domain TEXT,
    subdomain TEXT,
    level TEXT,
    applicable INTEGER,
    verified INTEGER,
    pending_verification INTEGER
);

CREATE TABLE IF NOT EXISTS control_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    control_id TEXT,
    rule_id TEXT,
    mapping_type TEXT,
    source TEXT,
    verified INTEGER
);

CREATE TABLE IF NOT EXISTS remediations (
    id TEXT PRIMARY KEY,
    finding_id TEXT,
    recommendation TEXT,
    status TEXT,
    owner TEXT,
    due_date TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS control_reviews (
    id TEXT PRIMARY KEY,
    framework_id TEXT,
    control_id TEXT,
    status TEXT,
    reviewer TEXT,
    notes TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS finding_reviews (
    id TEXT PRIMARY KEY,
    finding_id TEXT,
    decision TEXT,
    reviewer TEXT,
    comment TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS risk_records (
    id TEXT PRIMARY KEY,
    finding_id TEXT,
    severity TEXT,
    treatment TEXT,
    status TEXT,
    accepted_by TEXT,
    notes TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS intel_datasets (
    id TEXT PRIMARY KEY,
    source TEXT,
    version TEXT,
    record_count INTEGER,
    retrieved_at TEXT,
    validated INTEGER,
    validated_by TEXT,
    file_path TEXT,
    active INTEGER,
    metadata TEXT
);

CREATE TABLE IF NOT EXISTS intel_updates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT,
    action TEXT,
    version TEXT,
    at TEXT
);

CREATE VIEW IF NOT EXISTS scan_history AS SELECT * FROM scans;

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_controls_framework ON controls(framework_id);
"""


def _dumps(value: Any) -> Optional[str]:
    if value is None:
        return None
    return json.dumps(value, sort_keys=True, default=str)


def _loads(text: Optional[str]) -> Any:
    if text is None:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return text


def _ensure_columns(conn, table: str, columns: dict) -> None:
    """Add missing columns to an existing table (idempotent migration)."""
    try:
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    except sqlite3.OperationalError:
        return  # table does not exist yet; SCHEMA will create it
    for column, ddl in columns.items():
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


class Database:
    """A thin, connection-scoped SQLite store for MIJHAR data."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise PermissionError(
                f"Cannot create MIJHAR data directory '{self.db_path.parent}': {exc}. "
                "Set the MIJHAR_HOME environment variable to a writable directory."
            ) from exc
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after earlier releases, for existing databases."""
        _ensure_columns(self._conn, "remediations", {"owner": "TEXT", "due_date": "TEXT"})
        _ensure_columns(self._conn, "controls", {"subdomain": "TEXT"})
        _ensure_columns(self._conn, "scans", {"frameworks": "TEXT"})

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- assets -------------------------------------------------------------

    def upsert_asset(self, asset_id: str, name: str, platform: str = "", hostname: str = "", os_version: str = "", created_at: str = "") -> None:
        self._conn.execute(
            "INSERT INTO assets (id, name, platform, hostname, os_version, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET name=excluded.name, platform=excluded.platform, "
            "hostname=excluded.hostname, os_version=excluded.os_version",
            (asset_id, name, platform, hostname, os_version, created_at),
        )
        self._conn.commit()

    def list_assets(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._conn.execute("SELECT * FROM assets ORDER BY created_at")]

    # -- scans --------------------------------------------------------------

    def create_scan(self, scan_id: str, asset_id: str, platform: str = "", started_at: str = "") -> None:
        self._conn.execute(
            "INSERT INTO scans (id, asset_id, platform, started_at, status) VALUES (?, ?, ?, ?, 'running')",
            (scan_id, asset_id, platform, started_at),
        )
        self._conn.commit()

    def finalize_scan(self, scan_id: str, ended_at: str, status: str, counts: Dict[str, int]) -> None:
        self._conn.execute(
            "UPDATE scans SET ended_at=?, status=?, checks_total=?, passed=?, failed=?, warnings=?, errors=? WHERE id=?",
            (
                ended_at,
                status,
                counts.get("total", 0),
                counts.get("passed", 0),
                counts.get("failed", 0),
                counts.get("warnings", 0),
                counts.get("errors", 0),
                scan_id,
            ),
        )
        self._conn.commit()

    def set_scan_frameworks(self, scan_id: str, framework_ids: Optional[List[str]]) -> None:
        """Record which frameworks a scan assessed (``None``/empty = all)."""
        stored = _dumps(framework_ids) if framework_ids else None
        self._conn.execute(
            "UPDATE scans SET frameworks=? WHERE id=?", (stored, scan_id)
        )
        self._conn.commit()

    def list_scans(self, limit: int = 100) -> List[Dict[str, Any]]:
        return [
            dict(r)
            for r in self._conn.execute("SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,))
        ]

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        row = self._conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None

    # -- scan exclusions (scope transparency) ------------------------------

    def insert_exclusion(self, scan_id: str, rule_id: str, title: str, reason: str, detail: str) -> None:
        self._conn.execute(
            "INSERT INTO scan_exclusions (scan_id, rule_id, title, reason, detail) VALUES (?, ?, ?, ?, ?)",
            (scan_id, rule_id, title, reason, detail),
        )
        self._conn.commit()

    def exclusions_for_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT rule_id, title, reason, detail FROM scan_exclusions WHERE scan_id=? ORDER BY id",
            (scan_id,),
        )
        return [dict(r) for r in rows]

    # -- rules --------------------------------------------------------------

    def insert_rule(self, rule_id: str, title: str, severity: str, platforms: Any, fact: str, operator: str, check_value: Any) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO rules (id, title, severity, platforms, fact, operator, check_value) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (rule_id, title, severity, _dumps(platforms), fact, operator, _dumps(check_value)),
        )
        self._conn.commit()

    # -- findings -----------------------------------------------------------

    def insert_finding(self, finding: Finding) -> None:
        self._conn.execute(
            "INSERT INTO findings (id, scan_id, rule_id, asset_id, title, description, severity, status, "
            "fact_key, observed_value, evidence, technical_impact, security_impact, remediation, "
            "framework_refs, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                finding.id,
                getattr(finding, "scan_id", ""),
                finding.rule_id,
                finding.asset_id,
                finding.title,
                finding.description,
                finding.severity.value,
                finding.status.value,
                finding.fact_key,
                _dumps(redact_value(finding.observed_value, key=finding.fact_key)),
                _dumps(redact_finding_evidence(finding.evidence, finding.fact_key)),
                finding.technical_impact,
                finding.security_impact,
                finding.remediation,
                _dumps(finding.framework_refs),
                finding.detected_at,
            ),
        )
        self._conn.commit()

    def set_finding_scan(self, finding_id: str, scan_id: str) -> None:
        self._conn.execute("UPDATE findings SET scan_id=? WHERE id=?", (scan_id, finding_id))
        self._conn.commit()

    def findings_for_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY severity, status", (scan_id,))
        return [self._finding_from_row(r) for r in rows]

    def all_findings(self) -> List[Dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM findings ORDER BY detected_at DESC")
        return [self._finding_from_row(r) for r in rows]

    @staticmethod
    def _finding_from_row(row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["observed_value"] = redact_value(_loads(data.get("observed_value")), key=data["fact_key"])
        data["evidence"] = redact_finding_evidence(_loads(data.get("evidence")), data["fact_key"])
        data["framework_refs"] = _loads(data.get("framework_refs"))
        return data

    # -- evidence -----------------------------------------------------------

    def insert_evidence(self, record: EvidenceRecord) -> None:
        self._conn.execute(
            "INSERT INTO evidence (id, finding_id, asset_id, key, content, sha256, collected_at, redacted) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.id,
                record.finding_id,
                record.asset_id,
                record.key,
                record.content,
                record.sha256,
                record.collected_at,
                int(record.redacted),
            ),
        )
        self._conn.commit()

    def evidence_for_finding(self, finding_id: str) -> List[Dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM evidence WHERE finding_id=?", (finding_id,))
        return [dict(r) for r in rows]

    # -- frameworks / controls / mappings -----------------------------------

    def save_framework(self, framework: Framework) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO frameworks (id, name, version, description, mapping_note) "
            "VALUES (?, ?, ?, ?, ?)",
            (framework.id, framework.name, framework.version, framework.description, framework.mapping_note),
        )
        for control in framework.controls:
            control_pk = f"{framework.id}:{control.id}"
            self._conn.execute(
                "INSERT OR REPLACE INTO controls (id, framework_id, control_id, title, description, domain, "
                "subdomain, level, applicable, verified, pending_verification) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    control_pk,
                    framework.id,
                    control.id,
                    control.title,
                    control.description,
                    control.domain,
                    control.subdomain,
                    control.level,
                    int(control.applicable),
                    int(control.verified),
                    int(control.pending_verification),
                ),
            )
            for mapping in control.mappings:
                self._conn.execute(
                    "INSERT INTO control_mappings (control_id, rule_id, mapping_type, source, verified) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (control_pk, mapping.rule_id, mapping.mapping_type.value, mapping.source, int(mapping.verified)),
                )
        self._conn.commit()

    def list_frameworks(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._conn.execute("SELECT * FROM frameworks ORDER BY id")]

    # -- remediations -------------------------------------------------------

    def insert_remediation(self, remediation_id: str, finding_id: str, recommendation: str, status: str = "open", created_at: str = "", owner: str = "", due_date: str = "") -> None:
        self._conn.execute(
            "INSERT INTO remediations (id, finding_id, recommendation, status, owner, due_date, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (remediation_id, finding_id, recommendation, status, owner, due_date, created_at),
        )
        self._conn.commit()

    def list_remediations(self, open_only: bool = False, *, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT * FROM remediations"
        conditions = []
        params = []
        if scan_id is not None:
            conditions.append("finding_id IN (SELECT id FROM findings WHERE scan_id=?)")
            params.append(scan_id)
        if open_only:
            conditions.append("status NOT IN ('resolved', 'closed')")
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY created_at DESC"
        return [dict(r) for r in self._conn.execute(query, params)]

    def set_remediation_status(self, remediation_id: str, status: str, owner: str = "", due_date: str = "") -> bool:
        cur = self._conn.execute(
            "UPDATE remediations SET status=?, owner=?, due_date=? WHERE id=?",
            (status, owner, due_date, remediation_id),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def close_remediation(self, remediation_id: str) -> bool:
        return self.set_remediation_status(remediation_id, "resolved")

    # -- manual reviews (control-level override) ----------------------------

    def upsert_review(
        self,
        framework_id: str,
        control_id: str,
        status: str,
        reviewer: str = "",
        notes: str = "",
        created_at: str = "",
    ) -> str:
        review_id = f"{framework_id}:{control_id}"
        self._conn.execute(
            "INSERT INTO control_reviews (id, framework_id, control_id, status, reviewer, notes, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET status=excluded.status, reviewer=excluded.reviewer, "
            "notes=excluded.notes, created_at=excluded.created_at",
            (review_id, framework_id, control_id, status, reviewer, notes, created_at),
        )
        self._conn.commit()
        return review_id

    def list_reviews(self, framework_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if framework_id:
            rows = self._conn.execute(
                "SELECT * FROM control_reviews WHERE framework_id=? ORDER BY created_at DESC",
                (framework_id,),
            )
        else:
            rows = self._conn.execute("SELECT * FROM control_reviews ORDER BY created_at DESC")
        return [dict(r) for r in rows]

    def reviews_for_framework(self, framework_id: str) -> Dict[str, Dict[str, Any]]:
        """Return {control_id: review} for a framework."""
        return {r["control_id"]: r for r in self.list_reviews(framework_id)}

    # -- finding reviews (accept / reject / needs-evidence) ------------------

    def add_finding_review(self, finding_id: str, decision: str, reviewer: str = "", comment: str = "", created_at: str = "") -> str:
        review_id = f"FR-{finding_id}-{len(self.list_finding_reviews(finding_id)) + 1}"
        self._conn.execute(
            "INSERT INTO finding_reviews (id, finding_id, decision, reviewer, comment, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (review_id, finding_id, decision, reviewer, comment, created_at),
        )
        self._conn.commit()
        return review_id

    def list_finding_reviews(self, finding_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if finding_id:
            rows = self._conn.execute(
                "SELECT * FROM finding_reviews WHERE finding_id=? ORDER BY created_at DESC", (finding_id,)
            )
        else:
            rows = self._conn.execute("SELECT * FROM finding_reviews ORDER BY created_at DESC")
        return [dict(r) for r in rows]

    # -- risk records & acceptance ------------------------------------------

    def add_risk_record(self, finding_id: str, severity: str, treatment: str = "mitigate", status: str = "open", accepted_by: str = "", notes: str = "", created_at: str = "") -> str:
        record_id = f"R-{finding_id}"
        self._conn.execute(
            "INSERT OR REPLACE INTO risk_records (id, finding_id, severity, treatment, status, accepted_by, notes, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (record_id, finding_id, severity, treatment, status, accepted_by, notes, created_at),
        )
        self._conn.commit()
        return record_id

    def list_risk_records(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._conn.execute("SELECT * FROM risk_records ORDER BY created_at DESC")]

    # -- intelligence datasets ---------------------------------------------

    def upsert_intel_dataset(self, source: str, version: str, record_count: int, retrieved_at: str, file_path: str = "", metadata: str = "") -> None:
        dataset_id = f"{source}:{version}"
        # deactivate previous active dataset for this source
        self._conn.execute("UPDATE intel_datasets SET active=0 WHERE source=? AND active=1", (source,))
        self._conn.execute(
            "INSERT INTO intel_datasets (id, source, version, record_count, retrieved_at, validated, validated_by, file_path, active, metadata) "
            "VALUES (?, ?, ?, ?, ?, 0, '', ?, 1, ?) "
            "ON CONFLICT(id) DO UPDATE SET record_count=excluded.record_count, retrieved_at=excluded.retrieved_at, active=1, metadata=excluded.metadata",
            (dataset_id, source, version, record_count, retrieved_at, file_path, metadata),
        )
        self._conn.commit()

    def list_intel_datasets(self, source: Optional[str] = None) -> List[Dict[str, Any]]:
        if source:
            rows = self._conn.execute("SELECT * FROM intel_datasets WHERE source=? ORDER BY retrieved_at DESC", (source,))
        else:
            rows = self._conn.execute("SELECT * FROM intel_datasets ORDER BY source, retrieved_at DESC")
        return [dict(r) for r in rows]

    def set_intel_validation(self, source: str, version: str, validated: bool, validated_by: str = "") -> bool:
        cur = self._conn.execute(
            "UPDATE intel_datasets SET validated=?, validated_by=? WHERE id=?",
            (int(validated), validated_by, f"{source}:{version}"),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def set_intel_active(self, source: str, version: str) -> bool:
        self._conn.execute("UPDATE intel_datasets SET active=0 WHERE source=?", (source,))
        cur = self._conn.execute("UPDATE intel_datasets SET active=1 WHERE id=?", (f"{source}:{version}",))
        self._conn.commit()
        return cur.rowcount > 0

    def record_intel_update(self, source: str, action: str, version: str, at: str) -> None:
        self._conn.execute(
            "INSERT INTO intel_updates (source, action, version, at) VALUES (?, ?, ?, ?)",
            (source, action, version, at),
        )
        self._conn.commit()

    def list_intel_updates(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._conn.execute("SELECT * FROM intel_updates ORDER BY id DESC LIMIT ?", (limit,))]

    # -- evidence integrity -------------------------------------------------

    def verify_evidence(self) -> List[Dict[str, Any]]:
        """Return evidence records whose stored content no longer matches its digest."""
        tampered: List[Dict[str, Any]] = []
        for row in self._conn.execute("SELECT * FROM evidence"):
            record = dict(row)
            if compute_hash(record["content"] or "") != record["sha256"]:
                tampered.append(record)
        return tampered

    def list_evidence(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._conn.execute("SELECT * FROM evidence ORDER BY collected_at")]

    def scan_summary(self, scan_id: str) -> Dict[str, int]:
        row = self._conn.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN status='pass' THEN 1 ELSE 0 END) AS passed, "
            "SUM(CASE WHEN status='fail' THEN 1 ELSE 0 END) AS failed, "
            "SUM(CASE WHEN status='warning' THEN 1 ELSE 0 END) AS warnings, "
            "SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) AS errors "
            "FROM findings WHERE scan_id=?",
            (scan_id,),
        ).fetchone()
        return {k: (int(v) if v is not None else 0) for k, v in dict(row).items()}
