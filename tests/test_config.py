"""Unit tests for triage_web.config."""

from __future__ import annotations

import pytest

from triage_web.config import (
    DEFAULT_MNEMONIC_COLOR,
    MNEMONIC_COLORS,
    VULN_SEVERITY_COLORS,
    prot_color,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Enabled", "#3fb950"),
        ("Full RELRO", "#3fb950"),
        ("YES", "#ff7b72"),
        ("Disabled", "#d29922"),
        ("Partial", "#d29922"),
        ("None", "#d29922"),
        ("something else", "#8b949e"),  # the fallback
    ],
)
def test_prot_color(value: str, expected: str) -> None:
    assert prot_color(value) == expected


def test_palettes_are_hex_colours() -> None:
    assert DEFAULT_MNEMONIC_COLOR.startswith("#")
    assert all(c.startswith("#") for c in MNEMONIC_COLORS.values())
    assert all(c.startswith("#") for c in VULN_SEVERITY_COLORS.values())
