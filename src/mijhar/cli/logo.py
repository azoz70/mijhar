"""MIJHAR terminal identity.

A clean, calm, single-color "Cool Arctic Cyan" startup screen: a large
``MIJHAR`` wordmark (pyfiglet, with a block-letter fallback), the slogan,
developer attribution with a clickable LinkedIn link, a short product
description, and a compact information panel whose numbers come from the actual
project configuration.

There is no microscope artwork and no rainbow/neon theming: MIJHAR itself is
the visual identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from rich.panel import Panel
from rich.table import Table
from rich import box

from mijhar import (
    __app_name__,
    __author__,
    __author_linkedin__,
    __author_linkedin_placeholder__,
    __slogan__,
    __tagline__,
    __version__,
)
from mijhar.cli.console import (
    PRIMARY,
    SECONDARY,
    SUPPORTING,
    TEXT,
    stderr_console,
)
from mijhar.core.config import implemented_module_count, implemented_platform_count

_FIGLET_FONT = "slant"

_PRODUCT_DESCRIPTION = (
    "MIJHAR is a modular Technical Security Assessment Framework designed to "
    "inspect system configurations, identify security weaknesses, collect "
    "technical evidence, and map findings to recognized cybersecurity "
    "frameworks such as NCA ECC, SAMA CSF, CIS Benchmarks, and ISO/IEC 27001."
)

PRODUCT_DESCRIPTION = _PRODUCT_DESCRIPTION

# Block-letter fallback if pyfiglet is unavailable.
_BLOCK_LETTERS = {
    "M": ["█   █", "██ ██", "█ █ █", "█   █", "█   █"],
    "I": ["█████", "  █  ", "  █  ", "  █  ", "█████"],
    "J": ["█████", "   █ ", "   █ ", "█  █ ", " ███ "],
    "H": ["█   █", "█   █", "█████", "█   █", "█   █"],
    "A": ["█████", "█   █", "█████", "█   █", "█   █"],
    "R": ["████ ", "█  █ ", "████ ", "█ █  ", "█  █ "],
}


@dataclass(frozen=True)
class Theme:
    id: str = "arctic-cyan"
    name: str = "Cool Arctic Cyan"
    primary: str = PRIMARY
    secondary: str = SECONDARY
    text: str = TEXT
    supporting: str = SUPPORTING


_THEME = Theme()


def get_theme(index: Optional[int] = None) -> Theme:
    """Return the single MIJHAR theme (the ``index`` argument is ignored)."""
    return _THEME


def theme_by_id(theme_id: str) -> Optional[Theme]:
    """Resolve a theme id; only ``arctic-cyan`` exists."""
    return _THEME if theme_id in (None, _THEME.id, _THEME.name.lower()) else None


def count_themes() -> int:
    return 1


def theme_ids() -> List[str]:
    return [_THEME.id]


def _block_rows(text: str) -> List[str]:
    rows = ["", "", "", "", ""]
    for ch in text:
        glyph = _BLOCK_LETTERS[ch]
        for i in range(5):
            rows[i] += glyph[i] + "  "
    return [r.rstrip() for r in rows]


def wordmark() -> str:
    """Return the large MIJHAR wordmark (pyfiglet, fallback to block letters)."""
    try:
        from pyfiglet import Figlet

        art = Figlet(font=_FIGLET_FONT, width=160).renderText(__app_name__)
        lines = [ln.rstrip() for ln in art.rstrip("\n").splitlines()]
        if lines:
            return "\n".join(lines)
    except Exception:  # noqa: BLE001 - any font/render issue falls back
        pass
    return "\n".join("  ".join(row) for row in _block_rows("MIJHAR"))


def _framework_count() -> int:
    """Number of supported compliance frameworks (from the actual catalog)."""
    from mijhar.compliance.registry import FrameworkRegistry
    from mijhar.core.config import get_config

    registry = FrameworkRegistry(get_config().frameworks_dir)
    registry.load()
    return len(registry.list())


def _linkedin_display() -> str:
    """Render the LinkedIn line as a clickable terminal hyperlink."""
    note = " (placeholder)" if __author_linkedin_placeholder__ else ""
    return f"[link={__author_linkedin__}]{__author_linkedin__}[/link]{note}"


def info_rows() -> List[tuple]:
    """Return the key/value rows for the terminal information panel."""
    return [
        ("Version", f"v{__version__}"),
        ("Assessment Engine", "Operational"),
        ("Supported Frameworks", str(_framework_count())),
        ("Implemented Platforms", str(implemented_platform_count())),
        ("Implemented Modules", str(implemented_module_count())),
    ]


def _info_table() -> Table:
    table = Table(
        box=box.SIMPLE_HEAVY,
        show_header=False,
        border_style=SECONDARY,
        padding=(0, 2),
        expand=False,
    )
    table.add_column("Key", style="bold " + PRIMARY, no_wrap=True)
    table.add_column("Value", style=TEXT)
    for key, value in info_rows():
        table.add_row(key, value)
    return table


def build_startup_body() -> str:
    """Compose the startup screen body (Rich markup string)."""
    linkedin = _linkedin_display()
    body = (
        f"[bold {PRIMARY}]{wordmark()}[/bold {PRIMARY}]\n"
        f"[{SECONDARY}]{__slogan__}[/{SECONDARY}]\n\n"
        f"[bold {TEXT}]Created by {__author__}[/bold {TEXT}]\n"
        f"[{SUPPORTING}]LinkedIn:[/{SUPPORTING}] {linkedin}\n\n"
        f"[{TEXT}]{_PRODUCT_DESCRIPTION}[/{TEXT}]\n"
    )
    return body


def print_startup(theme: Optional[Theme] = None, no_clear: bool = False) -> None:
    """Print the framed MIJHAR startup screen to stderr."""
    theme = theme or _THEME
    if stderr_console.is_terminal and not no_clear:
        stderr_console.clear()

    body = build_startup_body()
    panel = Panel(
        body,
        title=f"[bold {PRIMARY}]{__app_name__}[/bold {PRIMARY}]",
        subtitle=f"[{SUPPORTING}]{__tagline__}[/{SUPPORTING}]",
        border_style=PRIMARY,
        expand=False,
        padding=(1, 3),
    )
    stderr_console.print(panel)
    stderr_console.print(_info_table())
    stderr_console.print()


def print_random() -> None:
    """Print the startup screen (single theme; no randomization)."""
    print_startup(_THEME)
