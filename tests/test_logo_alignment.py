"""Regression tests: the MIJHAR wordmark fits a standard terminal width."""

from __future__ import annotations

from mijhar.cli.logo import wordmark


def test_wordmark_fits_standard_terminal():
    lines = wordmark().splitlines()
    max_width = max(len(line) for line in lines)
    assert max_width <= 80, f"wordmark too wide: {max_width}"


def test_wordmark_is_readable_and_nonempty():
    lines = [ln for ln in wordmark().splitlines() if ln.strip()]
    assert lines
    assert all(len(ln) <= 80 for ln in lines)
