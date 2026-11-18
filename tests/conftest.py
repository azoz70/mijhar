"""Shared pytest fixtures for the MIJHAR test suite."""

from __future__ import annotations

from typing import Dict, Iterable, List, Tuple

import pytest

from mijhar.collectors.base import CommandResult, FileResult
from mijhar.core.config import Severity, Status
from mijhar.core.models import Finding


class FakeRunner:
    """A deterministic command runner for collector tests.

    ``responses`` maps a command argument tuple to a :class:`CommandResult`.
    Unmapped commands fall back to ``default`` (or a generic failure).
    """

    def __init__(
        self,
        responses: Dict[Tuple[str, ...], CommandResult] | None = None,
        default: CommandResult | None = None,
    ) -> None:
        self.responses = dict(responses or {})
        self.default = default or CommandResult(args=[], returncode=1, stderr="no response")
        self.calls: List[List[str]] = []

    def run(self, args: Iterable[str]) -> CommandResult:
        key = tuple(args)
        self.calls.append(list(key))
        result = self.responses.get(key, self.default)
        result.args = list(key)
        return result

    def called(self, args: Iterable[str]) -> bool:
        return tuple(args) in {tuple(c) for c in self.calls}


def result(rc: int = 0, stdout: str = "", stderr: str = "") -> CommandResult:
    return CommandResult(args=[], returncode=rc, stdout=stdout, stderr=stderr)


class FakeFileReader:
    """A deterministic file reader for collector tests."""

    def __init__(self, texts=None, modes=None) -> None:
        self.texts = dict(texts or {})
        self.modes = dict(modes or {})
        self.reads: List[str] = []
        self.stats: List[str] = []

    def read_text(self, path: str) -> FileResult:
        self.reads.append(path)
        if path in self.texts:
            return FileResult(path=path, content=self.texts[path])
        return FileResult(path=path, error=f"no such file: {path}")

    def stat_mode(self, path: str) -> FileResult:
        self.stats.append(path)
        if path in self.modes:
            return FileResult(path=path, mode=self.modes[path])
        return FileResult(path=path, error=f"no such file: {path}")


@pytest.fixture()
def isolated_home(tmp_path, monkeypatch):
    """Point MIJHAR runtime data at a per-test temporary directory."""
    monkeypatch.setenv("MIJHAR_HOME", str(tmp_path / "mijhar"))
    return tmp_path / "mijhar"


def make_finding(
    rule_id: str = "T-1",
    severity=Severity.HIGH,
    status=Status.FAIL,
    asset_id: str = "local",
    **kwargs,
) -> Finding:
    defaults = dict(
        id=f"F-{rule_id}",
        rule_id=rule_id,
        asset_id=asset_id,
        title="Test finding",
        description="",
        severity=severity,
        status=status,
        fact_key="a.b",
        observed_value=False,
        evidence={"fact": "a.b", "value": False},
        technical_impact="",
        security_impact="",
        remediation="",
        framework_refs={},
        detected_at="2026-01-01T00:00:00+00:00",
    )
    defaults.update(kwargs)
    return Finding(**defaults)
