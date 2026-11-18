"""Intelligence & framework data management.

A controlled update mechanism for vulnerability intelligence and framework
datasets. Every dataset records its source, version, retrieval date, validation
status, and provenance. Updates are versioned so a previous validated dataset
can be restored. Network fetch is intentionally not bundled — datasets are
imported from local files to avoid auto-downloading or executing untrusted
content.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from mijhar.core.config import get_config
from mijhar.database.models import Database

# Registered sources (metadata only; fetching is manual/local).
SOURCES = [
    {"id": "nvd", "name": "NVD / CVE", "type": "vulnerability", "access": "network API (JSON)", "license": "Public domain (NIST)", "note": "Fetch the NVD CVE JSON feed and import it."},
    {"id": "cisa-kev", "name": "CISA Known Exploited Vulnerabilities", "type": "vulnerability", "access": "network (JSON feed)", "license": "Public (US Gov)", "note": "Fetch the CISA KEV JSON and import it."},
    {"id": "osv", "name": "OSV (Open Source Vulnerabilities)", "type": "vulnerability", "access": "network API (JSON)", "license": "Apache-2.0", "note": "Fetch OSV records and import them."},
    {"id": "nca-ecc", "name": "NCA Essential Cybersecurity Controls", "type": "framework", "access": "official document", "license": "Public (TLP:White)", "note": "Import the official ECC-2:2024 dataset."},
    {"id": "sama-csf", "name": "SAMA Cyber Security Framework", "type": "framework", "access": "official Rulebook", "license": "Public", "note": "Import the official SAMA CSF dataset."},
    {"id": "cis", "name": "CIS Benchmarks", "type": "framework", "access": "licensed", "license": "CIS (licensed)", "note": "Import CIS benchmark data subject to your license."},
    {"id": "iso27001", "name": "ISO/IEC 27001:2022", "type": "framework", "access": "licensed standard", "license": "ISO (licensed)", "note": "Import ISO 27001:2022 Annex A data subject to license."},
]

_SOURCE_IDS = {s["id"] for s in SOURCES}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class IntelManager:
    """Manage local intelligence datasets with provenance and versioning."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or get_config().db_path

    def sources(self) -> List[Dict[str, str]]:
        return SOURCES

    def source(self, source_id: str) -> Optional[Dict[str, str]]:
        for s in SOURCES:
            if s["id"] == source_id:
                return s
        return None

    def status(self, source_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with Database(self.db_path) as db:
            return db.list_intel_datasets(source_id)

    def history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with Database(self.db_path) as db:
            return db.list_intel_updates(limit)

    def import_file(self, source_id: str, path: Path | str, version: str = "") -> Dict[str, Any]:
        """Import a local JSON dataset (controlled, read-only, no execution)."""
        if source_id not in _SOURCE_IDS:
            raise ValueError(f"unknown source: {source_id}")
        path = Path(path)
        raw = path.read_text(encoding="utf-8")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON: {exc}") from exc

        records = data.get("records", data) if isinstance(data, dict) else data
        if not isinstance(records, list):
            raise ValueError("dataset must be a JSON object with a 'records' list, or a JSON list")
        resolved_version = version or data.get("version") if isinstance(data, dict) else version
        resolved_version = resolved_version or _now()

        with Database(self.db_path) as db:
            db.upsert_intel_dataset(
                source=source_id,
                version=str(resolved_version),
                record_count=len(records),
                retrieved_at=_now(),
                file_path=str(path),
                metadata=json.dumps({"records": records}),
            )
            db.record_intel_update(source_id, "import", str(resolved_version), _now())
        return {"source": source_id, "version": str(resolved_version), "record_count": len(records)}

    def update(self, source_id: str) -> Dict[str, str]:
        """Return guidance for updating a source (no automatic download)."""
        src = self.source(source_id)
        if src is None:
            raise ValueError(f"unknown source: {source_id}")
        return {
            "source": source_id,
            "access": src["access"],
            "guidance": f"Update '{src['name']}' by downloading/obtaining the official data, then run `mijhar intel import --source {source_id} --file <path>`.",
        }

    def validate(self, source_id: str, version: str, by: str = "") -> bool:
        with Database(self.db_path) as db:
            updated = db.set_intel_validation(source_id, version, True, by)
            if updated:
                db.record_intel_update(source_id, "validate", version, _now())
        return updated

    def rollback(self, source_id: str) -> Optional[str]:
        """Activate the previous validated dataset for a source."""
        datasets = self.status(source_id)
        active = [d for d in datasets if d["active"]]
        if len(datasets) < 2:
            return None
        previous = datasets[1] if active and datasets[0]["active"] else datasets[-1]
        with Database(self.db_path) as db:
            db.set_intel_active(source_id, previous["version"])
            db.record_intel_update(source_id, "rollback", previous["version"], _now())
        return previous["version"]
