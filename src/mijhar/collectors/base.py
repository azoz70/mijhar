"""Collection engine base classes.

Collectors gather *raw system facts* in a read-only fashion. Facts are
evaluated later by the rules engine; collectors never mutate the target and
never decide PASS/FAIL themselves.
"""

from __future__ import annotations

import os
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar, List, Optional

from mijhar.core.config import Platform


@dataclass
class CommandResult:
    """Outcome of a single read-only command invocation."""

    args: List[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def output(self) -> str:
        """The command's stripped stdout, convenient for single-value probes."""
        return self.stdout.strip()

    @property
    def error(self) -> str:
        return self.stderr.strip()


class CommandRunner:
    """Run commands safely and read-only.

    Commands are always invoked as an argument list (no shell), with a
    timeout, and their output is captured. This avoids shell injection and
    keeps collection non-interactive.
    """

    def __init__(self, timeout: float = 15.0) -> None:
        self.timeout = timeout

    def run(self, args: List[str]) -> CommandResult:
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            return CommandResult(
                args=list(args),
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
            )
        except FileNotFoundError:
            return CommandResult(
                args=list(args),
                returncode=127,
                stderr=f"command not found: {args[0] if args else ''}",
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                args=list(args),
                returncode=-1,
                stdout=exc.stdout or "",
                stderr=(exc.stderr or "") or "command timed out",
                timed_out=True,
            )
        except OSError as exc:  # permission denied, etc.
            return CommandResult(
                args=list(args),
                returncode=-1,
                stderr=str(exc),
            )


@dataclass
class FileResult:
    """Outcome of a read-only file access."""

    path: str
    content: Optional[str] = None
    mode: Optional[int] = None
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None


class FileReader:
    """Read files and file metadata read-only.

    ``read_text`` returns the decoded content or an error; ``stat_mode``
    returns the POSIX permission bits (``st_mode``) without reading content.
    """

    def read_text(self, path: str) -> FileResult:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                return FileResult(path=path, content=handle.read())
        except OSError as exc:
            return FileResult(path=path, error=str(exc))

    def stat_mode(self, path: str) -> FileResult:
        try:
            return FileResult(path=path, mode=os.stat(path).st_mode)
        except OSError as exc:
            return FileResult(path=path, error=str(exc))


@dataclass
class Fact:
    """A single collected system fact.

    ``value`` is a normalized, typed interpretation when parsing succeeds;
    ``raw`` always preserves the original command output for evidence.
    ``error`` is set when the fact could not be collected (missing tool,
    insufficient privileges, etc.).
    """

    key: str
    value: Any = None
    source: str = ""
    raw: Optional[str] = None
    error: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "value": self.value,
            "source": self.source,
            "raw": self.raw,
            "error": self.error,
        }


@dataclass
class CollectionResult:
    """The full result of a collector run."""

    collector: str
    platform: Platform
    facts: List[Fact] = field(default_factory=list)

    @property
    def errors(self) -> List[Fact]:
        return [f for f in self.facts if f.error]

    def to_dict(self) -> dict:
        return {
            "collector": self.collector,
            "platform": self.platform.value,
            "facts": [f.as_dict() for f in self.facts],
        }


class BaseCollector(ABC):
    """Abstract base for all collectors."""

    platform: ClassVar[Platform] = Platform.UNKNOWN
    name: ClassVar[str] = "base"

    def __init__(
        self,
        runner: Optional[CommandRunner] = None,
        files: Optional[FileReader] = None,
    ) -> None:
        self.runner = runner or CommandRunner()
        self.files = files or FileReader()

    @abstractmethod
    def collect(self) -> CollectionResult:
        """Collect facts and return a :class:`CollectionResult`."""

    def run(self, args: List[str]) -> CommandResult:
        return self.runner.run(args)

    def _fact(
        self,
        key: str,
        result: CommandResult,
        value: Any = None,
        parse: Any = None,
    ) -> Fact:
        """Build a Fact from a command result, capturing errors and raw output."""
        error = None if result.ok else (result.error or f"exit code {result.returncode}")
        resolved = value
        if result.ok and parse is not None:
            try:
                resolved = parse(result.output)
            except Exception as exc:  # noqa: BLE001 - normalize parse failures
                error = f"parse error: {exc}"
                resolved = None
        return Fact(
            key=key,
            value=resolved,
            source=" ".join(result.args),
            raw=result.stdout.rstrip() if result.stdout else None,
            error=error,
        )

    def _file_fact(
        self,
        key: str,
        file_result: FileResult,
        value: Any = None,
        parse: Any = None,
    ) -> Fact:
        """Build a Fact from a :class:`FileResult`, capturing errors."""
        error = file_result.error
        resolved = value
        if file_result.ok and parse is not None:
            try:
                resolved = parse(file_result.content)
            except Exception as exc:  # noqa: BLE001 - normalize parse failures
                error = f"parse error: {exc}"
                resolved = None
        return Fact(
            key=key,
            value=resolved,
            source=f"file:{file_result.path}",
            raw=(file_result.content.rstrip() if file_result.content else None),
            error=error,
        )
