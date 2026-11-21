"""Tests for core configuration, enums, and path resolution."""

from __future__ import annotations

import os

from mijhar.core import config
from mijhar.core.config import (
    Platform,
    Severity,
    Status,
    detect_platform,
    get_config,
    get_data_dir,
    severity_rank,
)


def test_severity_ranking_order():
    ranks = [severity_rank(s) for s in Severity]
    # Enum order is most->least severe, so ranks must be strictly descending.
    assert ranks == sorted(ranks, reverse=True), "severity ranks must be ordered"
    assert severity_rank(Severity.CRITICAL) == 5
    assert severity_rank(Severity.INFORMATIONAL) == 1


def test_severity_values():
    assert {s.value for s in Severity} == {
        "critical",
        "high",
        "medium",
        "low",
        "informational",
    }


def test_status_values():
    assert {s.value for s in Status} == {
        "pass",
        "fail",
        "warning",
        "not_supported",
        "not_applicable",
        "error",
    }


def test_detect_platform():
    assert detect_platform("Darwin") is Platform.MACOS
    assert detect_platform("darwin") is Platform.MACOS
    assert detect_platform("Linux") is Platform.LINUX
    assert detect_platform("Windows") is Platform.WINDOWS
    assert detect_platform("Solaris") is Platform.UNKNOWN


def test_data_dir_override(monkeypatch, tmp_path):
    target = tmp_path / "custom-home"
    monkeypatch.setenv(config.ENV_HOME, str(target))
    assert get_data_dir() == target


def test_config_defaults_resolve_bundled_catalogs():
    cfg = get_config()
    assert cfg.db_path.name == "mijhar.db"
    assert (cfg.rules_dir / "linux" / "ssh.yaml").is_file()
    assert (cfg.frameworks_dir / "cis" / "cis_benchmarks.yaml").is_file()
    assert cfg.reports_dir.name == "reports"


def test_config_ensure_dirs(monkeypatch, tmp_path):
    target = tmp_path / "home"
    monkeypatch.setenv(config.ENV_HOME, str(target))
    cfg = get_config()
    cfg.ensure_dirs()
    assert (target / "reports").is_dir()


def test_version_is_defined():
    assert config.VERSION == "0.2.0"


def test_implemented_module_registry():
    from mijhar.core.config import (
        IMPLEMENTED_MODULES,
        PLANNED_MODULES,
        implemented_module_count,
        implemented_platform_count,
    )

    assert implemented_platform_count() == 2
    assert implemented_module_count() == 3
    assert {m.id for m in IMPLEMENTED_MODULES} == {"macos", "linux", "linux-ssh"}
    assert all(m.implemented for m in IMPLEMENTED_MODULES)
    assert all(not m.implemented for m in PLANNED_MODULES)
