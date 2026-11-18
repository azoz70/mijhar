"""MIJHAR CLI entry point."""

from __future__ import annotations

import sqlite3

from mijhar.cli.app import app
from mijhar.cli.console import stderr_console


def main() -> None:
    """Run the MIJHAR command-line application."""
    try:
        app()
    except (PermissionError, sqlite3.Error) as exc:
        stderr_console.print(f"[red]MIJHAR error:[/red] {exc}")
        stderr_console.print(
            "[mijhar.subtle]Tip: ensure the data directory is writable, or set "
            "MIJHAR_HOME to a writable path (e.g. export MIJHAR_HOME=/tmp/mijhar).[/mijhar.subtle]"
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
