"""Chunked Shannon entropy and the standard PE checksum, both cancellable and bounded."""
from __future__ import annotations

import sys
from array import array
from collections import Counter
from math import log2

from ._common import Ctx

FILE_BUDGET_RANGES = 4  # one inspection measures at most this many `entropy_cap`-sized ranges in all


def entropy_of_range(ctx: Ctx, offset: int, length: int) -> tuple[float | None, int, bool]:
    """Return (entropy bits/byte or None, bytes measured, sampled).

    Measures at most ``limits.entropy_cap`` bytes from ``offset`` (clipped to the file) and at most
    ``FILE_BUDGET_RANGES * entropy_cap`` bytes over all the ranges of one inspection, so sections that overlap
    cannot multiply the work. ``sampled`` is true when the range was longer than what was measured; a measurement
    that the file budget shortened or denied is also reported once, as the warning ``entropy_budget_exhausted``.
    """
    size = ctx.reader.size
    if length <= 0 or offset < 0 or offset >= size:
        return None, 0, False
    length = min(length, size - offset)
    wanted = min(length, ctx.limits.entropy_cap)
    budget = FILE_BUDGET_RANGES * ctx.limits.entropy_cap
    measured = min(wanted, budget - ctx.entropy_spent)
    if measured < wanted:
        ctx.warn('entropy_budget_exhausted',
                 f'the {budget}-byte entropy budget of one file is spent; later sections and the overlay are '
                 'measured in part or not at all')
    counts: Counter[int] = Counter()
    done = 0
    while done < measured:
        ctx.check()
        chunk = ctx.read(offset + done, min(ctx.limits.chunk, measured - done))
        if not chunk:
            break
        counts.update(chunk)
        done += len(chunk)
    ctx.entropy_spent += done
    if done == 0:
        return None, 0, True
    ent = -sum((c / done) * log2(c / done) for c in counts.values())
    # `+ 0.0`: one repeated byte gives -0.0, which `max` keeps and which prints as -0.00
    return round(max(ent, 0.0) + 0.0, 4), done, done < length


def pe_checksum(ctx: Ctx, checksum_field_offset: int) -> int:
    """Standard PE checksum: 16-bit word sum (checksum DWORD zeroed), folded, plus file size."""
    size = ctx.reader.size
    total = 0
    pos = 0
    step = ctx.limits.chunk - (ctx.limits.chunk % 2)
    while pos < size:
        ctx.check()
        data = bytearray(ctx.reader.read(pos, min(step, size - pos)))
        lo = max(checksum_field_offset, pos)
        hi = min(checksum_field_offset + 4, pos + len(data))
        for i in range(lo, hi):
            data[i - pos] = 0
        if len(data) % 2:
            data.append(0)
        words = array('H', bytes(data))
        if sys.byteorder == 'big':
            words.byteswap()
        total += sum(words)
        pos += step
    while total >> 32:
        total = (total & 0xFFFFFFFF) + (total >> 32)
    total = (total & 0xFFFF) + (total >> 16)
    total += total >> 16
    total &= 0xFFFF
    return total + size
