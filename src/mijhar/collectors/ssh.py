"""Remote SSH collection adapter.

Runs the Linux collector's read-only probes over an OpenSSH connection using
the user's existing key-based authentication. No credentials are stored or
prompted for: ``BatchMode`` disables interactive password prompts, and
``StrictHostKeyChecking`` requires the host to be already known/trusted.
"""

from __future__ import annotations

from typing import List, Optional

from mijhar.collectors.base import CommandResult, CommandRunner, FileReader, FileResult
from mijhar.collectors.linux import LinuxCollector
from mijhar.core.config import Platform


class SSHRunner(CommandRunner):
    """Wrap every command with ``ssh`` using non-interactive, key-based auth."""

    def __init__(
        self,
        host: str,
        user: Optional[str] = None,
        port: int = 22,
        timeout: float = 25.0,
        ssh_bin: str = "ssh",
    ) -> None:
        super().__init__(timeout=timeout)
        self.host = host
        self.user = user
        self.port = port
        self.ssh_bin = ssh_bin

    def build_args(self, args: List[str]) -> List[str]:
        target = f"{self.user}@{self.host}" if self.user else self.host
        return [
            self.ssh_bin,
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=10",
            "-p", str(self.port),
            target,
            *args,
        ]

    def run(self, args: List[str]) -> CommandResult:
        return super().run(self.build_args(args))


class SSHFileReader(FileReader):
    """Read remote files and metadata through an SSH runner."""

    def __init__(self, runner: SSHRunner) -> None:
        self.runner = runner

    def read_text(self, path: str) -> FileResult:
        result = self.runner.run(["cat", path])
        if result.ok:
            return FileResult(path=path, content=result.stdout)
        return FileResult(path=path, error=result.error or f"exit {result.returncode}")

    def stat_mode(self, path: str) -> FileResult:
        result = self.runner.run(["stat", "-c", "%a", path])
        if result.ok:
            try:
                return FileResult(path=path, mode=int(result.output, 8))
            except ValueError:
                return FileResult(path=path, error=f"bad stat output: {result.output!r}")
        return FileResult(path=path, error=result.error or f"exit {result.returncode}")


class SSHCollector(LinuxCollector):
    """Collect Linux security facts from a remote host over SSH."""

    platform = Platform.LINUX
    name = "linux-ssh"

    def __init__(
        self,
        host: str,
        user: Optional[str] = None,
        port: int = 22,
        timeout: float = 25.0,
        runner: Optional[SSHRunner] = None,
        files: Optional[SSHFileReader] = None,
    ) -> None:
        ssh_runner = runner or SSHRunner(host=host, user=user, port=port, timeout=timeout)
        ssh_files = files or SSHFileReader(ssh_runner)
        super().__init__(runner=ssh_runner, files=ssh_files)
        self.host = host
