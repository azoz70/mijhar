"""Tests for the MIJHAR terminal identity: wordmark, theme, and startup body."""

from __future__ import annotations

from mijhar.cli import logo
from mijhar.cli.logo import build_startup_body, info_rows, wordmark


def test_single_theme():
    assert logo.count_themes() == 1
    theme = logo.get_theme(0)
    assert theme.id == "arctic-cyan"
    assert theme.name == "Cool Arctic Cyan"


def test_theme_by_id():
    assert logo.theme_by_id("arctic-cyan").id == "arctic-cyan"
    assert logo.theme_by_id("cool arctic cyan").id == "arctic-cyan"
    assert logo.theme_by_id("nonexistent") is None


def test_no_microscope_art():
    # The microscope artwork must be fully removed.
    assert not hasattr(logo, "_MICROSCOPE")


def test_wordmark_is_large_and_non_empty():
    art = wordmark()
    lines = art.splitlines()
    assert len(lines) >= 4
    assert all(line.strip() for line in lines)
    assert "MIJHAR" not in art.replace(" ", "").replace("\n", "") or len(lines) >= 4


def test_startup_body_contains_identity_and_attribution():
    body = build_startup_body()
    for text in (
        "SEE WHAT OTHERS MISS",
        "Created by Abdulaziz",
        "LinkedIn",
        "linkedin.com",
    ):
        assert text in body, f"startup body missing: {text}"


def test_startup_body_has_no_neon_themes():
    body = build_startup_body().lower()
    for banned in ("cyber green", "blood red", "golden", "phantom purple", "microscope"):
        assert banned not in body


def test_info_rows_come_from_real_config():
    rows = dict(info_rows())
    assert rows["Version"].startswith("v")
    assert rows["Assessment Engine"] == "Operational"
    assert int(rows["Supported Frameworks"]) == 4
    assert int(rows["Implemented Platforms"]) == 2
    assert int(rows["Implemented Modules"]) == 3


def test_linkedin_is_real_and_not_placeholder():
    from mijhar import __author_linkedin__, __author_linkedin_placeholder__

    assert __author_linkedin_placeholder__ is False
    assert __author_linkedin__ == "https://www.linkedin.com/in/abdulaziz-alshehri/"
    # The startup body shows the real URL and no "(placeholder)" note.
    body = build_startup_body()
    assert "abdulaziz-alshehri" in body
    assert "placeholder" not in body.lower()
