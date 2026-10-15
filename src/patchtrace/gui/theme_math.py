"""Colour maths for the theme tokens and the contrast gates (GUI plan 8.6). Pure: colours are '#rrggbb' strings.

`contrast_ratio` moved here from `ui_evidence` (which re-exports it): the numbers must not change.
"""
from __future__ import annotations

import re

TEXT_CONTRAST = 4.5       # WCAG 1.4.3: text against its background
NON_TEXT_CONTRAST = 3.0   # WCAG 1.4.11: borders, focus ring and chip outlines against their surroundings

_COLOR = re.compile(r'#[0-9a-fA-F]{6}')


def parse_color(color: str) -> tuple[int, int, int]:
    if not isinstance(color, str) or _COLOR.fullmatch(color) is None:
        raise ValueError(f'not a #rrggbb colour: {color!r:.40}')
    return int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)


def relative_luminance(color: str) -> float:
    channels = [value / 255 for value in parse_color(color)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast_ratio(first: str, second: str) -> float:
    """WCAG contrast ratio of two #rrggbb colours: 1.0 (identical) to 21.0 (black on white)."""
    high, low = sorted((relative_luminance(first), relative_luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def ensure_contrast(color: str, background: str, fallback: str, minimum: float = TEXT_CONTRAST) -> str:
    """The runtime guard: `color` when it reaches `minimum` against `background`, else `fallback` (the default text
    colour). A live palette can make a fixed accent unreadable, so painting code asks instead of assuming."""
    return color if contrast_ratio(color, background) >= minimum else fallback
