"""Pure side of the code-text controls (WBQ S9): the copy, the settings keys, the window arithmetic, the model of a
`PairText` and the resolved look of one `StyleKey`. Qt-free; `ui_codetext` turns these into formats and signals.

Colours come from `codetext.Palette` and pass the runtime guard here, so a pane whose live background differs from
the theme's never gets an unreadable syntax colour (it falls back to the default text colour, plan section 8).
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import NamedTuple

from .codetext import (
    MIN_MARK_CONTRAST,
    MIN_TEXT_CONTRAST,
    CodeTextModel,
    Language,
    MarkStyle,
    Palette,
    StyleKey,
    guard_color,
)
from .gui.pair_text import PairText
from .gui.text import sanitize_text
from .tooltips import TooltipEntry

SETTING_COLORS = 'desktop/code_colors'
SETTING_MARKS = 'desktop/token_marks'
WINDOW_MARGIN = 80  # blocks formatted above and below the visible ones
MAX_VIEW_CHARS = 200_000  # the same cap the panes apply (gui.qt.codediff.MAX_VIEW_CHARS); the model must see the same text
LANGUAGE_BY_MODE = {0: 'c', 1: 'asm'}  # the Workbench mode index; modes 2 to 5 are metadata and raw text: no language

DISABLED_AFTER_ERROR = 'Code colours were turned off for this session after an internal error; the text is unchanged.'
NEEDS_ASSEMBLY = 'Token marks need assembly text; this analysis stored only an instruction hash.'
NO_CHANGE_STOP = 'No more token changes in this direction.'
SCAN_LIMITED = 'Stopped looking for a token change at a safety limit; press the key again to continue.'
LABEL_NAME = 'Line changes'

TIPS = {
    'setup.code_colors': TooltipEntry(
        'Colour keywords, numbers, strings, addresses and registers in the code panes.',
        'Make long functions easier to scan; colour is never the only signal.',
        'Only changes how text is drawn; the text and the analysis are unchanged.',
        availability='Beta; off by default.'),
    'setup.token_marks': TooltipEntry(
        'Underline the tokens that differ between the two lines of a changed row.',
        'See which part of a line changed without reading both lines.',
        'Only changes how text is drawn. A mark is a hint about spelling, not a finding.',
        availability='Beta; off by default. Needs assembly or decompiled text.'),
    'action.next_token_change': TooltipEntry(
        'Go to the next line with a changed token.', 'Walk the token differences without hunting for them.',
        'Moves the caret in the code panes; changes no data.'),
    'action.previous_token_change': TooltipEntry(
        'Go to the previous line with a changed token.', 'Walk the token differences without hunting for them.',
        'Moves the caret in the code panes; changes no data.'),
    'viewer.line_changes': TooltipEntry(
        'What differs between the older and the newer text of the current line.',
        'A screen reader reads this sentence, since colour and underline are not announced.',
        'Read-only display; it is a hint about spelling, not evidence of a behaviour change.'),
}


def language_for_mode(mode: int) -> Language | None:
    return LANGUAGE_BY_MODE.get(mode)


def capped(text: str) -> str:
    """The text a pane shows: sanitized and cut like `CodeDiffView` does, so model rows equal block texts."""
    return sanitize_text(text[:MAX_VIEW_CHARS], MAX_VIEW_CHARS, multiline=True)


def model_for_pair(pair: PairText, language: Language, *, chrome: Iterable[int] = (), colors: bool = True,
                   marks: bool = True, **options) -> CodeTextModel:
    """The model of one displayed comparison. The paired rows are the rows of a `replace` hunk that hold a line on
    both sides; every other row is coloured but never marked. Offsets past the shown rows are dropped."""
    older, newer = capped(pair.older).split('\n'), capped(pair.newer).split('\n')
    rows = min(len(older), len(newer))
    on_both = set(pair.older_map) & set(pair.newer_map)
    paired = [row for hunk in pair.hunks if hunk.operation == 'replace'
              for row in range(hunk.start, min(hunk.start + hunk.length, rows)) if row in on_both]
    return CodeTextModel(older[:rows], newer[:rows], language, paired=paired,
                         chrome=[row for row in chrome if 0 <= row < rows], colors=colors, marks=marks, **options)


def window_bounds(first_visible: int, visible: int, rows: int, margin: int = WINDOW_MARGIN) -> tuple[int, int]:
    """The inclusive block range to format: the visible blocks plus `margin` on each side, clamped to the rows.
    (0, -1) when there are no rows."""
    if rows <= 0:
        return 0, -1
    first = max(0, min(first_visible, rows - 1) - margin)
    return first, min(rows - 1, max(first_visible, 0) + max(visible, 1) + margin)


class Look(NamedTuple):
    """The resolved look of a `StyleKey`: what `ui_codetext` writes into one `QTextCharFormat`."""

    color: str | None  # None keeps the pane's own text colour
    bold: bool
    italic: bool
    underline: str | None  # single | dotted | dashed
    underline_color: str | None


def look(key: StyleKey, palette: Palette, backgrounds: Iterable[str], *, colors: bool = True) -> Look:
    """Syntax role plus mark state, with both colours guarded against `backgrounds`. With `colors` off only the
    mark's own style remains."""
    grounds = tuple(backgrounds) or palette.backgrounds
    fallback = palette.style('text').color
    style = palette.style(key.role)
    color = guard_color(style.color, grounds, fallback, MIN_TEXT_CONTRAST) if colors and key.role != 'text' else None
    bold, italic = (style.bold, style.italic) if colors else (False, False)
    if key.mark is None:
        return Look(color, bold, italic, None, None)
    mark: MarkStyle = palette.mark(key.mark)
    line = guard_color(mark.color, grounds, fallback, MIN_MARK_CONTRAST)
    return Look(color, bold or mark.bold, italic or mark.italic, mark.underline, line)
