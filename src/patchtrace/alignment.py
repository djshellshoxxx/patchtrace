"""Text alignment, independent of uncertain binary match scores."""
from __future__ import annotations

from difflib import SequenceMatcher

from .models import DiffHunk


def align_lines(older: str | None, newer: str | None) -> list[tuple[str | None, str | None, str]]:
    """Return aligned display rows; missing lines are None, never fabricated code."""
    old_lines, new_lines = (older or '').splitlines(), (newer or '').splitlines()
    rows = []
    for operation, i1, i2, j1, j2 in SequenceMatcher(None, old_lines, new_lines, autojunk=False).get_opcodes():
        for offset in range(max(i2 - i1, j2 - j1)):
            rows.append((old_lines[i1 + offset] if i1 + offset < i2 else None,
                         new_lines[j1 + offset] if j1 + offset < j2 else None, operation))
    return rows


def diff_hunks(older: str | None, newer: str | None, match_id: str) -> list[DiffHunk]:
    """Half-open zero-based ranges over original text lines, including equality."""
    return [DiffHunk(match_id=match_id, old_start=i1, old_end=i2, new_start=j1, new_end=j2,
                     operation=operation)
            for operation, i1, i2, j1, j2 in SequenceMatcher(
                None, (older or '').splitlines(), (newer or '').splitlines(), autojunk=False).get_opcodes()]


# Explicit descriptive alias for consumers rendering the two sides.
align_code = align_lines
