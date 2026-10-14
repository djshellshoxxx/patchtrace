"""`codetext/1` colours (WBQ S7): syntax roles, change-mark styles, WCAG contrast and the runtime guard. Pure.

`Palette('dark')` is bound to the app's dark theme: the pane base is the `QPlainTextEdit` background in
`ui.DARK_STYLE`, the two hunk colours are the full-width backgrounds `ui._highlight_hunks` paints, and the `text`
role is the stylesheet's default text colour (tests/test_codetext_palette.py reads ui.py to keep them equal).
Every text role reaches at least 4.5:1 against all three backgrounds (WCAG 1.4.3) and every mark colour at least
3:1 (WCAG 1.4.11). Colour never carries a class alone: bold, italic and underline style repeat it, because Qt's
Windows UI Automation provider does not expose character formatting to screen readers. There is no light theme in
the app yet, so none is defined; the plan's light values stay inactive until one exists.

Colour-vision-deficiency simulation is a test-time check (the Machado 2009 matrices live in the palette tests), not
a runtime feature.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import Literal, NamedTuple

MIN_TEXT_CONTRAST = 4.5  # WCAG 1.4.3 (AA)
MIN_MARK_CONTRAST = 3.0  # WCAG 1.4.11 (AA, non-text)
ROLES = ('text', 'keyword', 'number', 'string', 'comment', 'address', 'register', 'stack', 'symbol', 'size', 'temp',
         'mnemonic')
# Token kind to default role. A caller that knows an operand's class (address, stack, scalar, register) may choose
# the `address`, `stack`, `number` or `register` role instead; the role names are shared on purpose.
ROLE_BY_KIND: Mapping[str, str] = MappingProxyType({
    'ws': 'text', 'comment': 'comment', 'string': 'string', 'char': 'string', 'number': 'number',
    'keyword': 'keyword', 'type': 'keyword', 'auto_name': 'address', 'temp': 'temp', 'ident': 'text', 'op': 'text',
    'mnemonic': 'mnemonic', 'register': 'register', 'size': 'size', 'symbol': 'symbol', 'punct': 'text',
    'other': 'text'})
# Identical strings to `Mark.state` in the codetext/1 contract.
MARK_STATES = ('changed', 'address-only', 'rename-maybe')
Underline = Literal['single', 'dotted', 'dashed']
_HEX_COLOR = re.compile(r'#[0-9a-fA-F]{6}')


class Style(NamedTuple):
    color: str  # '#rrggbb'
    bold: bool = False
    italic: bool = False


class MarkStyle(NamedTuple):
    underline: Underline
    color: str  # underline colour, '#rrggbb'
    bold: bool = False
    italic: bool = False


class _Theme(NamedTuple):
    base: str
    hunk_replace: str
    hunk_edit: str
    roles: Mapping[str, Style]
    marks: Mapping[str, MarkStyle]


_DARK = _Theme(
    base='#10151c', hunk_replace='#263a43', hunk_edit='#33392b',
    roles=MappingProxyType({
        'text': Style('#d9e1ec'), 'keyword': Style('#56b4e9'), 'number': Style('#e9a93a'),
        'string': Style('#4fd1a5'), 'comment': Style('#93a7bd', italic=True), 'address': Style('#e08fbf'),
        'register': Style('#7cc4f0'), 'stack': Style('#6fd8b4'), 'symbol': Style('#f0e442'),
        'size': Style('#a9b8c9'), 'temp': Style('#c7d2e0'), 'mnemonic': Style('#d9e1ec', bold=True)}),
    marks=MappingProxyType({
        'changed': MarkStyle('single', '#f0e442', bold=True),
        'address-only': MarkStyle('dotted', '#93a7bd', italic=True),
        'rename-maybe': MarkStyle('dashed', '#93a7bd')}))
_THEMES = {'dark': _DARK}


class Palette:
    """The colours of one theme: `style(role)`, `mark(state)` and the three backgrounds text can sit on."""

    def __init__(self, theme: str = 'dark') -> None:
        try:
            self._theme = _THEMES[theme]
        except KeyError:
            raise ValueError(f'unknown theme {theme!r}; expected one of {sorted(_THEMES)}') from None
        self.theme = theme

    @property
    def base(self) -> str:
        return self._theme.base

    @property
    def hunk_replace(self) -> str:
        return self._theme.hunk_replace

    @property
    def hunk_edit(self) -> str:
        """The insert and delete hunk background."""
        return self._theme.hunk_edit

    @property
    def backgrounds(self) -> tuple[str, str, str]:
        return self.base, self.hunk_replace, self.hunk_edit

    def style(self, role: str) -> Style:
        return self._theme.roles[role]

    def mark(self, state: str) -> MarkStyle:
        return self._theme.marks[state]


def _luminance(color: str) -> float:
    if not _HEX_COLOR.fullmatch(color):
        raise ValueError(f'expected a #rrggbb colour, got {color!r}')
    channels = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast_ratio(first: str, second: str) -> float:
    """WCAG relative-luminance contrast ratio of two #rrggbb colours (same arithmetic as ui_evidence.contrast_ratio)."""
    high, low = sorted((_luminance(first), _luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def guard_color(color: str, backgrounds: Iterable[str], fallback: str, minimum: float = MIN_TEXT_CONTRAST) -> str:
    """`color` when it reaches `minimum` against every background, else `fallback` (the default text colour).

    The runtime guard: a pane whose live base or hunk colour differs from the theme's must not end up with an
    unreadable syntax colour."""
    return color if all(contrast_ratio(color, background) >= minimum for background in backgrounds) else fallback
