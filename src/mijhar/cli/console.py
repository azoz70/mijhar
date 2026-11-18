"""Rich console helpers and the single MIJHAR "Cool Arctic Cyan" theme.

MIJHAR uses exactly one consistent color palette across every screen:

- primary   — soft icy cyan (wordmark, titles, borders)
- secondary — muted light blue (accents, highlights)
- text      — soft white
- supporting — cool gray
- background — black / very dark navy

Severity and result statuses use soft *pastel* accents so they stay readable
and distinguishable without being loud: a calm mint green for PASS, a muted
rose for FAIL, a pale amber for WARNING, and a light lavender for ERROR. All
are low-saturation light tones — no neon, no heavy backgrounds.
"""

from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

from mijhar.core.config import Severity, Status

# Cool Arctic Cyan palette (24-bit, but with ANSI fallbacks where possible).
PRIMARY = "#7fd7e8"      # soft icy cyan
SECONDARY = "#6fa8c9"    # muted light blue
TEXT = "#eaf4f8"         # soft white
SUPPORTING = "#7a8b99"   # cool gray
BACKGROUND = "#0b111a"   # very dark navy

# Soft, light pastel accent colors for severity (no neon, no harsh backgrounds).
SEVERITY_STYLE = {
    Severity.CRITICAL: "bold #e09a9a",   # soft rose-red
    Severity.HIGH: "bold #e8b0a0",       # soft coral
    Severity.MEDIUM: "#e8d1a0",          # soft amber
    Severity.LOW: "#a9c6e0",             # soft blue
    Severity.INFORMATIONAL: "dim #8a97a5",  # soft gray
}

# Soft, light pastel accent colors for result statuses.
STATUS_STYLE = {
    Status.PASS: "bold #9fd6a3",         # soft mint green
    Status.FAIL: "bold #e8a4a4",         # soft rose red
    Status.WARNING: "bold #e8d1a0",      # soft amber
    Status.NOT_SUPPORTED: "#9fb0c0",     # soft slate
    Status.NOT_APPLICABLE: "dim #8a97a5",  # soft gray
    Status.ERROR: "bold #c9aee8",        # soft lavender
}

STATUS_LABEL = {
    Status.PASS: "PASS",
    Status.FAIL: "FAIL",
    Status.WARNING: "WARNING",
    Status.NOT_SUPPORTED: "NOT SUPPORTED",
    Status.NOT_APPLICABLE: "N/A",
    Status.ERROR: "ERROR",
}

MIJHAR_THEME = Theme(
    {
        "mijhar.pass": STATUS_STYLE[Status.PASS],
        "mijhar.fail": STATUS_STYLE[Status.FAIL],
        "mijhar.warning": STATUS_STYLE[Status.WARNING],
        "mijhar.not_supported": STATUS_STYLE[Status.NOT_SUPPORTED],
        "mijhar.na": STATUS_STYLE[Status.NOT_APPLICABLE],
        "mijhar.error": STATUS_STYLE[Status.ERROR],
        "mijhar.critical": SEVERITY_STYLE[Severity.CRITICAL],
        "mijhar.high": SEVERITY_STYLE[Severity.HIGH],
        "mijhar.medium": SEVERITY_STYLE[Severity.MEDIUM],
        "mijhar.low": SEVERITY_STYLE[Severity.LOW],
        "mijhar.info": SEVERITY_STYLE[Severity.INFORMATIONAL],
        "mijhar.accent": "bold #6fa8c9",
        "mijhar.primary": "bold #7fd7e8",
        "mijhar.title": "bold #7fd7e8",
        "mijhar.text": "#eaf4f8",
        "mijhar.subtle": "dim #7a8b99",
    }
)

# Shared console used across the CLI for a consistent theme.
console = Console(theme=MIJHAR_THEME, highlight=False)

# Banner and diagnostics go to stderr so machine-readable report output
# (e.g. `mijhar report --format json`) stays clean on stdout.
stderr_console = Console(theme=MIJHAR_THEME, highlight=False, stderr=True)


def severity_label(severity: Severity | str) -> str:
    """Return the human-readable label for a severity."""
    return Severity(severity).value.upper()


def status_label(status: Status | str) -> str:
    """Return the human-readable label for a finding status."""
    return STATUS_LABEL[Status(status)]


def style_for_severity(severity: Severity | str) -> str:
    """Return the Rich style string for a severity."""
    return SEVERITY_STYLE[Severity(severity)]


def style_for_status(status: Status | str) -> str:
    """Return the Rich style string for a finding status."""
    return STATUS_STYLE[Status(status)]
