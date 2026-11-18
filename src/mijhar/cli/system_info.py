"""``mijhar system-info`` — display host and MIJHAR environment information."""

from __future__ import annotations

import getpass
import platform as _platform
import socket
import sys

from rich import box
from rich.table import Table

from mijhar import __app_name__, __version__
from mijhar.cli.console import console
from mijhar.core.config import detect_platform, get_config


def _rows() -> list[tuple[str, str]]:
    cfg = get_config()
    return [
        ("Application", f"{__app_name__} v{__version__}"),
        ("Detected Platform", detect_platform().value),
        ("Operating System", f"{_platform.system()} {_platform.release()}"),
        ("OS Version", _platform.version()),
        ("Architecture", _platform.machine()),
        ("Hostname", socket.gethostname()),
        ("Username", getpass.getuser()),
        ("Python", f"{_platform.python_implementation()} {_platform.python_version()}"),
        ("Executable", sys.executable),
        ("Data Directory", str(cfg.data_dir)),
        ("Database", str(cfg.db_path)),
        ("Rules Directory", str(cfg.rules_dir)),
        ("Frameworks Directory", str(cfg.frameworks_dir)),
        ("Reports Directory", str(cfg.reports_dir)),
    ]


def system_info_command() -> None:
    """Print a summary of the host and the MIJHAR runtime environment."""
    table = Table(
        title=f"{__app_name__} — System Information",
        box=box.ROUNDED,
        title_style="mijhar.title",
        header_style="bold cyan",
        border_style="mijhar.subtle",
    )
    table.add_column("Property", style="mijhar.accent", no_wrap=True)
    table.add_column("Value", style="white")
    for key, value in _rows():
        table.add_row(key, value)
    console.print(table)
