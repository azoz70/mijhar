"""Tests for the SQLite database layer."""

from __future__ import annotations

from mijhar.compliance.registry import (
    Control,
    ControlMapping,
    Domain,
    Framework,
    MappingType,
)
from mijhar.core.config import Status
from mijhar.database.models import Database
from mijhar.evidence.storage import EvidenceStore
from tests.conftest import make_finding


def test_asset_and_scan_lifecycle(tmp_path):
    db = Database(tmp_path / "test.db")
    try:
        db.upsert_asset("asset-1", "web-01", platform="linux", hostname="web01", os_version="22.04", created_at="2026-01-01")
        assets = db.list_assets()
        assert assets[0]["id"] == "asset-1"
        assert assets[0]["platform"] == "linux"

        db.create_scan("scan-1", "asset-1", platform="linux", started_at="2026-01-01T00:00:00Z")
        db.finalize_scan("scan-1", "2026-01-01T00:01:00Z", "completed", {"total": 4, "passed": 2, "failed": 1, "warnings": 1, "errors": 0})
        scan = db.get_scan("scan-1")
        assert scan["status"] == "completed"
        assert scan["passed"] == 2
        assert len(db.list_scans()) == 1
    finally:
        db.close()


def test_finding_json_roundtrip(tmp_path):
    db = Database(tmp_path / "test.db")
    try:
        db.create_scan("scan-1", "a", started_at="2026-01-01T00:00:00Z")
        finding = make_finding(
            rule_id="MAC-001",
            status=Status.FAIL,
            observed_value=False,
            evidence={"fact": "filevault.enabled", "value": False},
            framework_refs={"cis": ["2.6.1"]},
        )
        db.insert_finding(finding)
        db.set_finding_scan(finding.id, "scan-1")

        rows = db.findings_for_scan("scan-1")
        assert len(rows) == 1
        assert rows[0]["observed_value"] is False
        assert rows[0]["evidence"]["value"] is False
        assert rows[0]["framework_refs"]["cis"] == ["2.6.1"]
        assert rows[0]["status"] == "fail"

        summary = db.scan_summary("scan-1")
        assert summary == {"total": 1, "passed": 0, "failed": 1, "warnings": 0, "errors": 0}
    finally:
        db.close()


def test_evidence_roundtrip(tmp_path):
    db = Database(tmp_path / "test.db")
    try:
        store = EvidenceStore()
        record = store.add("F-1", "local", "a.b", "password=secret", redact_content=False)
        db.insert_evidence(record)
        rows = db.evidence_for_finding("F-1")
        assert rows[0]["sha256"] == record.sha256
        assert rows[0]["content"] == "password=secret"
    finally:
        db.close()


def test_framework_controls_mappings_persist(tmp_path):
    db = Database(tmp_path / "test.db")
    try:
        framework = Framework(
            id="cis",
            name="CIS",
            version="1",
            domains=[
                Domain(
                    id="d",
                    name="Domain",
                    controls=[
                        Control(
                            id="5.2.8",
                            title="Disable SSH root login",
                            mappings=[ControlMapping(rule_id="SSH-001", mapping_type=MappingType.DIRECT, verified=True)],
                        )
                    ],
                )
            ],
        )
        db.save_framework(framework)
        frameworks = db.list_frameworks()
        assert frameworks[0]["id"] == "cis"
        row = db._conn.execute("SELECT * FROM controls WHERE control_id='5.2.8'").fetchone()
        assert row["pending_verification"] == 0
        mapping = db._conn.execute("SELECT * FROM control_mappings WHERE rule_id='SSH-001'").fetchone()
        assert mapping["mapping_type"] == "direct"
    finally:
        db.close()


def test_remediation_persists(tmp_path):
    db = Database(tmp_path / "test.db")
    try:
        db.insert_remediation("R-1", "F-1", "Enable FileVault", status="open", created_at="2026-01-01")
        assert db.list_remediations()[0]["recommendation"] == "Enable FileVault"
    finally:
        db.close()


def test_remediation_close_and_open_filter(tmp_path):
    db = Database(tmp_path / "test.db")
    try:
        db.insert_remediation("R-1", "F-1", "Fix A", status="open")
        db.insert_remediation("R-2", "F-2", "Fix B", status="open")
        assert db.close_remediation("R-1") is True
        open_items = db.list_remediations(open_only=True)
        assert [r["id"] for r in open_items] == ["R-2"]
        assert db.close_remediation("missing") is False
    finally:
        db.close()


def test_control_review_upsert_and_overwrite(tmp_path):
    db = Database(tmp_path / "test.db")
    try:
        db.upsert_review("nca-ecc", "2-8-3-3", "compliant", reviewer="alice", notes="verified")
        db.upsert_review("nca-ecc", "2-8-3-3", "non_compliant", reviewer="bob", notes="re-checked")
        reviews = db.list_reviews("nca-ecc")
        assert len(reviews) == 1
        assert reviews[0]["status"] == "non_compliant"
        assert reviews[0]["reviewer"] == "bob"
        assert db.reviews_for_framework("nca-ecc")["2-8-3-3"]["status"] == "non_compliant"
    finally:
        db.close()


def test_evidence_integrity_verification(tmp_path):
    db = Database(tmp_path / "test.db")
    try:
        store = EvidenceStore()
        record = store.add("F-1", "local", "a.b", "password=secret", redact_content=False)
        db.insert_evidence(record)
        assert db.verify_evidence() == []
        # Tamper with the stored content directly.
        db._conn.execute("UPDATE evidence SET content='tampered' WHERE id=?", (record.id,))
        db._conn.commit()
        tampered = db.verify_evidence()
        assert [r["id"] for r in tampered] == [record.id]
    finally:
        db.close()


def test_remediation_status_owner_due(tmp_path):
    db = Database(tmp_path / "test.db")
    try:
        db.insert_remediation("R-1", "F-1", "Fix A", status="open")
        assert db.set_remediation_status("R-1", "in_progress", owner="alice", due_date="2026-03-01") is True
        items = db.list_remediations()
        assert items[0]["status"] == "in_progress"
        assert items[0]["owner"] == "alice"
        assert items[0]["due_date"] == "2026-03-01"
        assert db.close_remediation("R-1") is True
        assert db.list_remediations(open_only=True) == []
    finally:
        db.close()


def test_finding_review(tmp_path):
    db = Database(tmp_path / "test.db")
    try:
        rid = db.add_finding_review("F-1", "accept", reviewer="bob", comment="verified")
        assert db.list_finding_reviews("F-1")[0]["decision"] == "accept"
        db.add_finding_review("F-1", "needs_evidence", reviewer="carol", comment="more logs")
        assert len(db.list_finding_reviews("F-1")) == 2
    finally:
        db.close()


def test_risk_record_and_acceptance(tmp_path):
    db = Database(tmp_path / "test.db")
    try:
        db.add_risk_record("F-1", "high", "accept", "accepted", accepted_by="CISO", notes="compensating controls")
        records = db.list_risk_records()
        assert records[0]["treatment"] == "accept"
        assert records[0]["accepted_by"] == "CISO"
    finally:
        db.close()


def test_migration_adds_missing_columns(tmp_path):
    import sqlite3

    # Simulate a database created by an older MIJHAR release (no owner/due_date,
    # no controls.subdomain).
    db_path = tmp_path / "old.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE remediations (id TEXT PRIMARY KEY, finding_id TEXT, recommendation TEXT, status TEXT, created_at TEXT)"
    )
    conn.execute(
        "CREATE TABLE controls (id TEXT PRIMARY KEY, framework_id TEXT, control_id TEXT, title TEXT, "
        "description TEXT, domain TEXT, level TEXT, applicable INTEGER, verified INTEGER, pending_verification INTEGER)"
    )
    conn.execute("INSERT INTO remediations (id, finding_id, recommendation, status, created_at) VALUES ('R-1','F-1','Fix','open','')")
    conn.commit()
    conn.close()

    db = Database(db_path)
    try:
        assert db.list_remediations()[0]["id"] == "R-1"
        assert db.set_remediation_status("R-1", "in_progress", owner="alice", due_date="2026-01-01") is True
        assert db.list_remediations()[0]["owner"] == "alice"
        cols = {r["name"] for r in db._conn.execute("PRAGMA table_info(controls)")}
        assert "subdomain" in cols
        cols = {r["name"] for r in db._conn.execute("PRAGMA table_info(remediations)")}
        assert {"owner", "due_date"} <= cols
    finally:
        db.close()
