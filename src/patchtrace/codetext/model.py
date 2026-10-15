"""The pure model behind the windowed highlighter (WBQ S8, `codetext/1`): rows in, `FormatSpan`s out. Qt-free.

`CodeTextModel` holds the two panes' rows (the older and the newer line of each displayed row, `''` where one side has
none), says which rows are comparable pairs, and answers the three questions a highlighter has:

* `spans(side, row, text)`: the character formats of one block, in UTF-16 code units because that is what
  `QSyntaxHighlighter.setFormat` counts. It needs the block text Qt holds and fails closed (no spans) when that is not
  the text the model was built from, so a stale model can never colour the wrong line. It never computes a mark: its
  work is one tokenization of the block.
* `refresh(first, last)`: compute the marks of the paired rows in a window, at most `MAX_PAIRS_PER_REFRESH` new rows
  and `MAX_WORK_PER_REFRESH` alignment cells per call (`Refresh.pending` says how many were left), so scrolling does
  bounded work however many rows differ and however hostile they are. A caller that sees `pending` calls again.
* `summary(row)` and `find_change(row, step)`: the "Line changes" sentence of a row, and the next row with a `changed`
  mark (rename-maybe and address-only rows are never stops).

The model is built for one orientation and one text; a swapped orientation, another mode or another project builds a
new one (the highlighter drops the old model BEFORE the document text changes). Everything per row is memoised in
LRUs of `LRU_LINES` entries, so memory stays bounded on a 65,000-row pane. Chrome rows (a function header, the
truncation notice) get no spans: the caller styles them.

Offsets inside `RowMarks` are code points; only `FormatSpan` is in UTF-16 units (`utf16_offset` is the helper).
"""
from __future__ import annotations

import re
from collections import OrderedDict
from collections.abc import Iterable, Mapping, Sequence
from typing import NamedTuple

from .intraline import diff_row, long_line_sentence
from .marks import FormatSpan, Mark, RowMarks, Side, StyleKey
from .operands import Operand, OperandSource, TextOperandSource
from .oracle import NullOracle, NullRenameOracle, RenameOracle, TargetOracle
from .palette import ROLE_BY_KIND
from .tokens import MAX_LINE_CHARS, Language, Token, open_comment_lines, tokenize_line

MAX_PAIRS_PER_REFRESH = 200
MAX_WORK_PER_REFRESH = 250_000  # dynamic-programming cells; a pair may overshoot it once
LRU_LINES = 4_096
_ASTRAL = re.compile('[\U00010000-\U0010ffff]')  # a code point Qt stores as a surrogate pair
_LANGUAGES = ('c', 'asm')
_TEXT_SOURCE = TextOperandSource()


class Refresh(NamedTuple):
    computed: int  # rows whose marks were computed by this call
    pending: int  # rows of the window left without marks because of the per-call limit


class Found(NamedTuple):
    row: int | None  # the row with a `changed` mark, or None
    complete: bool  # False: the scan stopped at its limit before it could say there is none


def utf16_length(text: str) -> int:
    """Length of `text` in UTF-16 code units (what `QString.size()` and `QTextBlock.length()` count)."""
    return len(text) if text.isascii() else len(text) + len(_ASTRAL.findall(text))


def utf16_offset(text: str, index: int) -> int:
    """UTF-16 code units before code point `index` of `text` (clamped to the text): the unit conversion between a
    token offset and `setFormat`. A lone surrogate counts as one unit, like Qt."""
    index = max(0, min(index, len(text)))
    return index if text.isascii() else index + len(_ASTRAL.findall(text, 0, index))


def _utf16_prefix(text: str) -> list[int] | None:
    """UTF-16 units before every code point index, or None when every offset is unchanged (the common case)."""
    if text.isascii() or not _ASTRAL.search(text):
        return None
    prefix, total = [0], 0
    for character in text:
        total += 2 if character > '\U0000ffff' else 1
        prefix.append(total)
    return prefix


def _lower_bound(rows: Sequence[int], value: int) -> int:
    """Index of the first element >= value in an ascending sequence."""
    low, high = 0, len(rows)
    while low < high:
        middle = (low + high) // 2
        if rows[middle] < value:
            low = middle + 1
        else:
            high = middle
    return low


class _Lru:
    def __init__(self, capacity: int) -> None:
        self._items: OrderedDict = OrderedDict()
        self._capacity = capacity

    def __contains__(self, key: object) -> bool:
        return key in self._items

    def get(self, key):
        value = self._items.get(key)
        if value is not None:
            self._items.move_to_end(key)
        return value

    def put(self, key, value) -> None:
        self._items[key] = value
        self._items.move_to_end(key)
        if len(self._items) > self._capacity:
            self._items.popitem(last=False)


def _role(kind: str, operand: Operand | None) -> str:
    """The palette role of a token: the operand class decides for addresses and stack slots, the kind otherwise."""
    if operand is not None and operand.cls in ('address', 'stack'):
        return operand.cls
    return ROLE_BY_KIND[kind]


def _format_spans(text: str, tokens: Sequence[Token], operands: Mapping[int, Operand], marks: Sequence[Mark],
                  colors: bool) -> tuple[FormatSpan, ...]:
    """Merge syntax roles and mark states into the fewest spans. A token with the default role and no mark gets none."""
    spans: list[tuple[int, int, StyleKey]] = []
    upcoming = iter(marks)
    mark = next(upcoming, None)
    for index, token in enumerate(tokens):
        while mark is not None and mark.end <= token.start:
            mark = next(upcoming, None)
        state = mark.state if mark is not None and mark.start <= token.start else None
        role = _role(token.kind, operands.get(index)) if colors else 'text'
        if role == 'text' and state is None:
            continue
        key = StyleKey(role, state)
        if spans and spans[-1][1] == token.start and spans[-1][2] == key:
            spans[-1] = (spans[-1][0], token.end, key)
        else:
            spans.append((token.start, token.end, key))
    prefix = _utf16_prefix(text)
    if prefix is None:
        return tuple(FormatSpan(start, end - start, key) for start, end, key in spans)
    return tuple(FormatSpan(prefix[start], prefix[end] - prefix[start], key) for start, end, key in spans)


class CodeTextModel:
    """Syntax formats and token marks for the two panes of one comparison; see the module docstring.

    `older` and `newer` are the rows of the two panes (equal length). `paired` lists the rows whose two lines are a
    comparable pair: the rows of a replace hunk that hold a line on both sides. `chrome` rows get no spans. `colors`
    and `marks` switch the two features independently; with `colors` off only marked tokens get a format."""

    def __init__(self, older: Sequence[str], newer: Sequence[str], language: Language, *, paired: Iterable[int] = (),
                 chrome: Iterable[int] = (), colors: bool = True, marks: bool = True,
                 source: OperandSource | None = None, targets: TargetOracle | None = None,
                 renames: RenameOracle | None = None) -> None:
        if len(older) != len(newer):
            raise ValueError('the two panes need the same number of rows')
        if language not in _LANGUAGES:
            raise ValueError(f'unknown language {language!r}; expected one of {sorted(_LANGUAGES)}')
        self.language = language
        self.rows = len(older)
        self._lines: dict[Side, tuple[str, ...]] = {'older': tuple(older), 'newer': tuple(newer)}
        self._chrome = frozenset(self._checked(row) for row in chrome)
        self._paired = tuple(sorted({self._checked(row) for row in paired} - self._chrome))
        self._paired_set = frozenset(self._paired)
        self._colors, self._marks = colors, marks
        self._source = source or _TEXT_SOURCE
        self._targets = targets or NullOracle()
        self._renames = renames or NullRenameOracle()
        self._open_comments: dict[Side, frozenset[int]] = {}
        self._syntax = _Lru(LRU_LINES)
        self._pairs = _Lru(LRU_LINES)

    @classmethod
    def from_aligned(cls, aligned: Iterable[tuple[str | None, str | None, str]], language: Language,
                     **options) -> CodeTextModel:
        """A model from `alignment.align_lines` rows `(older|None, newer|None, operation)`: a missing line is the empty
        row, and the paired rows are the `replace` rows that have both lines."""
        rows = list(aligned)
        return cls([old or '' for old, _, _ in rows], [new or '' for _, new, _ in rows], language,
                   paired=[row for row, (old, new, operation) in enumerate(rows)
                           if operation == 'replace' and old is not None and new is not None], **options)

    @property
    def paired_rows(self) -> tuple[int, ...]:
        return self._paired

    def _checked(self, row: int) -> int:
        if not 0 <= row < self.rows:
            raise ValueError(f'row {row} is outside the {self.rows} rows of the panes')
        return row

    def _comment_rows(self, side: Side) -> frozenset[int]:
        if side not in self._open_comments:
            text = '\n'.join(self._lines[side])
            self._open_comments[side] = open_comment_lines(text) if self.language == 'c' else frozenset()
        return self._open_comments[side]

    def row_marks(self, row: int) -> RowMarks | None:
        """The marks of a paired row (computed once, then remembered), or None for any other row or when marks are off.
        Cost: one `diff_row`, which is bounded."""
        if not self._marks or row not in self._paired_set:
            return None
        found = self._pairs.get(row)
        if found is None:
            found = diff_row(
                self._lines['older'][row], self._lines['newer'][row], self.language, row=row, rows=self.rows,
                old_in_comment=row in self._comment_rows('older'), new_in_comment=row in self._comment_rows('newer'),
                source=self._source, targets=self._targets, renames=self._renames)
            self._pairs.put(row, found)
        return found

    def refresh(self, first: int, last: int) -> Refresh:
        """Compute the marks of the paired rows in `first..last` (inclusive) that have none yet, in row order, until
        `MAX_PAIRS_PER_REFRESH` rows or `MAX_WORK_PER_REFRESH` cells are spent; the rest are `pending`."""
        computed = pending = work = 0
        if not self._marks:
            return Refresh(0, 0)
        for index in range(_lower_bound(self._paired, first), len(self._paired)):
            row = self._paired[index]
            if row > last:
                break
            if row in self._pairs:
                continue
            if computed >= MAX_PAIRS_PER_REFRESH or work >= MAX_WORK_PER_REFRESH:
                pending += 1
                continue
            work += self.row_marks(row).work
            computed += 1
        return Refresh(computed, pending)

    def spans(self, side: Side, row: int, text: str) -> tuple[FormatSpan, ...]:
        """The formats of block `row` of a pane, whose current text is `text` (UTF-16 code units). Empty for a chrome
        row, a line over `MAX_LINE_CHARS`, and any text that is not the one this model holds for the row."""
        lines = self._lines[side]
        if not (self._colors or self._marks) or not 0 <= row < self.rows or row in self._chrome:
            return ()
        if text != lines[row] or len(text) > MAX_LINE_CHARS:
            return ()
        cached = self._syntax.get((side, row))
        if cached is None:
            tokens = tokenize_line(text, self.language, row in self._comment_rows(side)).tokens
            operands = self._source.operands(text, tokens, self.language) if self._colors else {}
            cached = (tokens, operands)
            self._syntax.put((side, row), cached)
        tokens, operands = cached
        computed = self._pairs.get(row)  # filled by `row_marks` only, so empty when marks are off
        marks = () if computed is None else (computed.old if side == 'older' else computed.new)
        return _format_spans(text, tokens, operands, marks, self._colors)

    def summary(self, row: int) -> str:
        """The "Line changes" sentence of a row: its marks, the reason it was skipped, or '' when there is nothing to
        say (not a paired row, a chrome row, marks off)."""
        if not 0 <= row < self.rows or row in self._chrome:
            return ''
        if any(len(lines[row]) > MAX_LINE_CHARS for lines in self._lines.values()):
            return long_line_sentence(row)
        found = self.row_marks(row)
        return found.summary if found is not None else ''

    def find_change(self, row: int, step: int, *, limit: int = MAX_PAIRS_PER_REFRESH) -> Found:
        """The nearest paired row after (`step` > 0) or before (`step` < 0) `row` that has a `changed` mark. Rows
        whose marks are not computed yet are computed on the way, at most `limit` of them and `MAX_WORK_PER_REFRESH`
        cells: `complete` is False when that stopped the scan, and a caller may continue from the last row it was
        given."""
        if not self._marks or step == 0:
            return Found(None, True)
        forward = step > 0
        index = _lower_bound(self._paired, row + 1) if forward else _lower_bound(self._paired, row) - 1
        fresh = work = 0
        while 0 <= index < len(self._paired):
            candidate = self._paired[index]
            computing = candidate not in self._pairs
            if computing:
                if fresh >= limit or work >= MAX_WORK_PER_REFRESH:
                    return Found(None, False)
                fresh += 1
            found = self.row_marks(candidate)
            if computing:
                work += found.work
            if found.has_change:
                return Found(candidate, True)
            index += 1 if forward else -1
        return Found(None, True)
