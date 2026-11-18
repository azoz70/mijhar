"""Tests for the intelligence & framework data management subsystem."""

from __future__ import annotations

import json

from mijhar.intel import IntelManager


def _write_dataset(tmp_path, name, version, n):
    path = tmp_path / name
    path.write_text(json.dumps({"version": version, "records": [{"id": f"r{i}"} for i in range(n)]}))
    return path


def test_sources_registry():
    manager = IntelManager()
    sources = {s["id"] for s in manager.sources()}
    assert {"nvd", "cisa-kev", "osv", "nca-ecc", "sama-csf", "cis", "iso27001"} <= sources


def test_import_and_status(tmp_path):
    manager = IntelManager(tmp_path / "intel.db")
    path = _write_dataset(tmp_path, "nvd.json", "2024.1", 3)
    result = manager.import_file("nvd", path, version="2024.1")
    assert result["record_count"] == 3
    datasets = manager.status("nvd")
    assert len(datasets) == 1
    assert datasets[0]["source"] == "nvd"
    assert datasets[0]["validated"] == 0
    assert datasets[0]["active"] == 1


def test_import_rejects_bad_json(tmp_path):
    manager = IntelManager(tmp_path / "intel.db")
    path = tmp_path / "bad.json"
    path.write_text("not json")
    try:
        manager.import_file("nvd", path)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for invalid JSON")


def test_import_rejects_unknown_source(tmp_path):
    manager = IntelManager(tmp_path / "intel.db")
    path = _write_dataset(tmp_path, "x.json", "1", 1)
    try:
        manager.import_file("bogus", path)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for unknown source")


def test_validate_and_rollback(tmp_path):
    manager = IntelManager(tmp_path / "intel.db")
    v1 = _write_dataset(tmp_path, "a.json", "v1", 2)
    v2 = _write_dataset(tmp_path, "b.json", "v2", 3)
    manager.import_file("nvd", v1, version="v1")
    manager.import_file("nvd", v2, version="v2")

    # v2 is active; validate it, then roll back to v1.
    assert manager.validate("nvd", "v2", by="auditor") is True
    rolled_back = manager.rollback("nvd")
    assert rolled_back == "v1"
    active = [d for d in manager.status("nvd") if d["active"]]
    assert active[0]["version"] == "v1"
    assert manager.history(), "update history should be recorded"


def test_update_returns_guidance():
    manager = IntelManager()
    info = manager.update("nvd")
    assert info["source"] == "nvd"
    assert "import" in info["guidance"]
