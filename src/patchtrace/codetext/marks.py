"""`codetext/1` mark records (WBQ S8): what a token mark is, and the spans a pane draws from it. Pure, stdlib only.

A mark is a lexical hint about two lines of text, never a finding. `changed` says the two spellings differ; it does not
say the behaviour does. `address-only` and `rename-maybe` say a difference is confined to names that move when code
moves (a Ghidra address-derived name, a decompiler temporary); they are drawn, never hidden, and never read as
"unchanged" or "cosmetic". Every mark names its side, `older` or `newer`, so a swapped orientation cannot be mistaken
for the original one: the two panes show the same row, and the older line is always the first argument of the
comparison.

Offsets are Python code points relative to the line (the tokenizer's unit). Only a `FormatSpan` is in UTF-16 code
units, because that is what `QSyntaxHighlighter.setFormat` counts (model.utf16_offset converts).
"""
from __future__ import annotations

from typing import Literal, NamedTuple

Side = Literal['older', 'newer']
MarkState = Literal['changed', 'address-only', 'rename-maybe']
SIDES = ('older', 'newer')
# The unified engine's `ChangeClass` values a token comparison can honestly claim, plus `token` for a lexical
# difference no class describes (tests/test_codetext_marks.py asserts the subset). `call-added` exists on the newer
# side only and `call-removed` on the older side only.
LABELS = ('constant', 'comparison', 'condition', 'callee', 'call-added', 'call-removed', 'data-ref', 'struct-offset',
          'cfg', 'string', 'address-only', 'register-only', 'name-only', 'frame', 'token')


class Mark(NamedTuple):
    side: Side
    start: int  # code points, relative to the line
    end: int
    state: MarkState
    label: str  # one of LABELS


class RowMarks(NamedTuple):
    """The comparison of one displayed row pair. `old` and `new` are the marks on the older and the newer line.

    A gated row (`gated`) carries no marks: `reason` says why (`similarity`, `long-line`, `tokens` or `size`) and
    `summary` is the sentence for the status line. `similarity` is the share of tokens the lines have in common once
    address-derived names and temporaries are masked, or None when it was not computed. `work` is the number of
    dynamic-programming cells the comparison evaluated, which a caller adds up to bound a refresh."""
    row: int
    old: tuple[Mark, ...]
    new: tuple[Mark, ...]
    similarity: float | None
    gated: bool
    summary: str
    reason: str = ''
    work: int = 0

    @property
    def has_change(self) -> bool:
        """True when a `changed` mark exists: the only state a token-change walk (F8) stops at."""
        return any(mark.state == 'changed' for mark in (*self.old, *self.new))


class StyleKey(NamedTuple):
    """Which merged character format to use: the syntax `role` (a palette role) and the mark state drawn over it."""
    role: str
    mark: MarkState | None


class FormatSpan(NamedTuple):
    start: int  # UTF-16 code units, relative to the block
    length: int
    style_key: StyleKey
