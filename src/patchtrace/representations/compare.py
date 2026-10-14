"""Byte-level comparison for side-by-side raw views (equal logical offsets, no text hunks)."""
from __future__ import annotations

from .paging import MAX_PAGE_SIZE


def byte_diff_mask(older: bytes, newer: bytes) -> tuple[int, ...]:
    """Logical indices that differ; indices past the shorter input always differ."""
    if len(older) > MAX_PAGE_SIZE or len(newer) > MAX_PAGE_SIZE:
        raise ValueError(f'inputs are capped at {MAX_PAGE_SIZE} bytes (one page)')
    short = min(len(older), len(newer))
    diffs = [i for i in range(short) if older[i] != newer[i]]
    diffs.extend(range(short, max(len(older), len(newer))))
    return tuple(diffs)
