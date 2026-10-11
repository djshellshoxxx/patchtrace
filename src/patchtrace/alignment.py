"""Bounded text alignment, independent of uncertain binary match scores."""
from __future__ import annotations

from difflib import SequenceMatcher

from .models import DiffHunk

EXACT_LINE_LIMIT = 2000
LINEAR_LINE_LIMIT = 10000


def alignment_strategy(older: str | None, newer: str | None) -> str:
    lines = max(len((older or '').splitlines()), len((newer or '').splitlines()))
    if lines > LINEAR_LINE_LIMIT:
        return 'coarse common-prefix/suffix alignment (large input)'
    if lines > EXACT_LINE_LIMIT:
        return 'SequenceMatcher with repeated-line popularity filtering'
    return 'exact SequenceMatcher'


def _opcodes(old_lines: list[str], new_lines: list[str]):
    """Coarse large regions bound runtime while retaining provably identical edges."""
    size = max(len(old_lines), len(new_lines))
    if size <= LINEAR_LINE_LIMIT:
        return SequenceMatcher(None, old_lines, new_lines,
                               autojunk=size > EXACT_LINE_LIMIT).get_opcodes()
    prefix = 0
    while prefix < min(len(old_lines), len(new_lines)) and old_lines[prefix] == new_lines[prefix]:
        prefix += 1
    old_end, new_end = len(old_lines), len(new_lines)
    while old_end > prefix and new_end > prefix and old_lines[old_end - 1] == new_lines[new_end - 1]:
        old_end -= 1
        new_end -= 1
    opcodes = []
    if prefix:
        opcodes.append(('equal', 0, prefix, 0, prefix))
    if old_end > prefix or new_end > prefix:
        operation = 'replace' if old_end > prefix and new_end > prefix else (
            'delete' if old_end > prefix else 'insert')
        opcodes.append((operation, prefix, old_end, prefix, new_end))
    if old_end < len(old_lines):
        opcodes.append(('equal', old_end, len(old_lines), new_end, len(new_lines)))
    return opcodes


def align_lines(older: str | None, newer: str | None) -> list[tuple[str | None, str | None, str]]:
    """Return aligned display rows; missing lines are None, never fabricated code."""
    old_lines, new_lines = (older or '').splitlines(), (newer or '').splitlines()
    rows = []
    for operation, i1, i2, j1, j2 in _opcodes(old_lines, new_lines):
        for offset in range(max(i2 - i1, j2 - j1)):
            rows.append((old_lines[i1 + offset] if i1 + offset < i2 else None,
                         new_lines[j1 + offset] if j1 + offset < j2 else None, operation))
    return rows


def diff_hunks(older: str | None, newer: str | None, match_id: str) -> list[DiffHunk]:
    """Half-open zero-based ranges over original text lines, including equality."""
    return [DiffHunk(match_id=match_id, old_start=i1, old_end=i2, new_start=j1, new_end=j2,
                     operation=operation)
            for operation, i1, i2, j1, j2 in _opcodes((older or '').splitlines(), (newer or '').splitlines())]


align_code = align_lines
