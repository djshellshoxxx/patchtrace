"""Aligned older/newer text for a two-pane code view (GUI plan 8.4, `CodeDiffView`). Pure: no Qt.

`PairText` is what a feature hands the view: both sides padded to the same number of rows, the changed regions
as aligned row ranges, and for each side a map from original line to aligned row (evidence navigation keeps
original line numbers). `align_pair` builds it from line lists and half-open opcodes, the shape
`alignment.diff_hunks` and `difflib` produce, without importing either.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

OPERATIONS = ('equal', 'replace', 'delete', 'insert')


@dataclass(frozen=True, slots=True)
class PairHunk:
    """A changed region as aligned rows (zero-based `start`, `length` >= 1) and its operation."""

    start: int
    length: int
    operation: str


@dataclass(frozen=True, slots=True)
class PairText:
    """Both sides as text with one line per aligned row; `older_map[i]` is the aligned row of original line `i`."""

    older: str = ''
    newer: str = ''
    hunks: tuple[PairHunk, ...] = ()
    older_map: tuple[int, ...] = ()
    newer_map: tuple[int, ...] = ()

    def line_map(self, side: str) -> tuple[int, ...]:
        if side not in ('older', 'newer'):
            raise ValueError(f'side must be older or newer, not {side!r}')
        return self.older_map if side == 'older' else self.newer_map


def align_pair(old_lines: Sequence[str], new_lines: Sequence[str],
               opcodes: Iterable[tuple[str, int, int, int, int]]) -> PairText:
    """Pad each opcode region to the longer side. A side with no line at a row gets an empty row, never invented
    code. Raises ValueError on an operation or range that does not fit the lines."""
    rows: dict[str, list[str]] = {'older': [], 'newer': []}
    maps: dict[str, list[int]] = {'older': [], 'newer': []}
    hunks: list[PairHunk] = []
    for operation, a, b, c, d in opcodes:
        if operation not in OPERATIONS:
            raise ValueError(f'unknown operation {operation!r}')
        if not (0 <= a <= b <= len(old_lines) and 0 <= c <= d <= len(new_lines)):
            raise ValueError('opcode range outside the lines')
        start, count = len(rows['older']), max(b - a, d - c)
        for offset in range(count):
            for side, lines, begin, end in (('older', old_lines, a, b), ('newer', new_lines, c, d)):
                if begin + offset < end:
                    maps[side].append(start + offset)
                    rows[side].append(lines[begin + offset])
                else:
                    rows[side].append('')
        if operation != 'equal' and count:
            hunks.append(PairHunk(start, count, operation))
    return PairText('\n'.join(rows['older']), '\n'.join(rows['newer']), tuple(hunks),
                    tuple(maps['older']), tuple(maps['newer']))
