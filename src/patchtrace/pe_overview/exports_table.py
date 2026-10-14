"""Export address table entries: ordinal, RVA, forwarder and name per exported slot (WBQ slice S4).

Complements ``parse_exports`` (names only), which it does not change. Tables are read in bulk through the
section map, every count is capped, and nothing is guessed: a slot whose name could not be read is left out
rather than reported as ordinal-only, and an unreadable address stays ``None``.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from ._common import Ctx
from .imports_exports import _name_at, _read_span, _readable
from .models import SectionMap

_BATCH = 4096  # table entries per read; keeps each read far below the 1 MiB struct-read clip
_POLL = 1024  # entries between cancel checks in the per-entry loops


@dataclass(frozen=True, slots=True)
class ExportEntry:
    """One exported name or ordinal.

    `name` is None only when the whole name table was read and no name points at the slot (ordinal-only).
    `ordinal` is Base plus the address-table index, so a hostile Base can push it past 0xFFFF.
    `rva` is the code or data address; None for a forwarder, an empty slot, or an address that was unreadable.
    `forwarder` is the ``DLL.Symbol`` text of a slot that lies inside the export directory's own range.
    """

    name: str | None
    ordinal: int
    rva: int | None
    forwarder: str | None


@dataclass(frozen=True, slots=True)
class ExportTable:
    """Entries sorted by (ordinal, name). When `truncated` is true the list is a verified subset: absence
    of an entry proves nothing."""

    entries: tuple[ExportEntry, ...]
    truncated: bool


def _read_table(ctx: Ctx, smap: SectionMap, rva: int, count: int, code: str) -> list[int]:
    """Up to `count` little-endian unsigned values at `rva`, stopping at the first entry not backed by file data.

    RVA 0 is the DOS header, never a table, so it reads as nothing instead of as header bytes.
    """
    width = struct.calcsize(f'<{code}')
    out: list[int] = []
    if not rva:
        return out
    while len(out) < count:
        ctx.check()
        want = min(_BATCH, count - len(out))
        at = rva + len(out) * width
        got = _readable(smap, at, want * width) // width
        raw = _read_span(ctx, smap, at, got * width) if got else b''
        n = len(raw) // width
        out.extend(struct.unpack(f'<{n}{code}', raw[:n * width]))
        if n < want:
            break
    return out


def _bind_names(ctx: Ctx, smap: SectionMap, pointers: list[int],
                indexes: list[int]) -> tuple[dict[int, list[str]], set[int], bool]:
    """Group the readable names by address-table index.

    Returns (names by index, every index the name table mentions, whether any binding was lost or cut).
    A repeated name pointer cannot occur in a well-formed table, so later repeats are skipped.
    """
    by_index: dict[int, list[str]] = {}
    mentioned: set[int] = set()
    seen: set[int] = set()
    lost = False
    for j, (pointer, index) in enumerate(zip(pointers, indexes, strict=False)):
        if j % _POLL == 0:
            ctx.check()
        mentioned.add(index)
        if pointer in seen:
            ctx.warn('export_name_table_loop', 'an export name pointer is repeated; later repeats were skipped')
            lost = True
            continue
        seen.add(pointer)
        found = _name_at(ctx, smap, pointer) if pointer else None
        if found is None:
            ctx.warn('export_rva_out_of_file', 'an export name RVA is null or not backed by file data')
            lost = True
            continue
        name, cut = found
        lost = lost or cut
        if name not in by_index.setdefault(index, []):
            by_index[index].append(name)
    return by_index, mentioned, lost


def _slot_target(ctx: Ctx, smap: SectionMap, value: int,
                 span: tuple[int, int]) -> tuple[int | None, str | None, bool]:
    """(rva, forwarder, lost) for one address-table value; a value inside `span` is a forwarder string."""
    if not value:
        return None, None, False
    if span[0] <= value < span[1]:
        found = _name_at(ctx, smap, value)
        if found is None:
            ctx.warn('export_rva_out_of_file', 'an export forwarder string is not backed by file data')
            return None, None, True
        return None, found[0], found[1]
    return value, None, False


def parse_export_entries(ctx: Ctx, smap: SectionMap, rva: int, size: int) -> ExportTable | None:
    """Entries of the export directory at `rva`; `rva` and `size` are the Export data directory's.

    The directory range [rva, rva + size) decides what is a forwarder, as in the Windows loader. Returns None
    when the 40-byte directory header is not backed by file data. Hostile counts, pointers and loops are
    bounded by ``Limits.max_export_names`` and ``Limits.max_name_length``; the function never raises for
    content (``Cancelled`` from ``ctx.check`` aside).
    """
    cap = ctx.limits.max_export_names
    header = _read_span(ctx, smap, rva, 40)
    if len(header) < 40:
        ctx.warn('export_rva_out_of_file', 'export directory is not backed by file data')
        return None
    base, nfuncs, nnames, eat_rva, names_rva, ords_rva = struct.unpack_from('<IIIIII', header, 16)
    if max(nfuncs, nnames) > max(cap, ctx.reader.size // 4):  # a table needs at least 4 bytes per entry
        ctx.warn('export_count_implausible', f'export counts ({nfuncs} functions, {nnames} names) are implausible')
    truncated = nfuncs > cap or nnames > cap
    if truncated:
        ctx.warn('export_table_over_cap', f'{nfuncs} export addresses and {nnames} names declared; reading {cap}')

    slots = _read_table(ctx, smap, eat_rva, min(nfuncs, cap), 'I')
    pointers = _read_table(ctx, smap, names_rva, min(nnames, cap), 'I')
    indexes = _read_table(ctx, smap, ords_rva, min(nnames, cap), 'H')
    bound = min(len(pointers), len(indexes))
    if len(slots) < min(nfuncs, cap) or bound < min(nnames, cap):
        ctx.warn('export_rva_out_of_file', 'an export table is not (fully) backed by file data')
        truncated = True
    by_index, mentioned, lost = _bind_names(ctx, smap, pointers, indexes)
    truncated = truncated or lost
    if any(index >= nfuncs for index in mentioned):
        ctx.warn('export_ordinal_out_of_range', 'an export name points past the end of the address table')

    # A slot is only called ordinal-only when the whole name table was seen and no name, even a lost one,
    # points at it.
    names_complete = bound == nnames
    entries: list[ExportEntry] = []
    for i, value in enumerate(slots):
        if i % _POLL == 0:
            ctx.check()
        names = sorted(by_index.get(i, ()))
        if not names and not (value and names_complete and i not in mentioned):
            continue
        target, forwarder, cut = _slot_target(ctx, smap, value, (rva, rva + size))
        truncated = truncated or cut
        entries.extend(ExportEntry(name, base + i, target, forwarder) for name in names or [None])
    for index in sorted(i for i in by_index if i >= len(slots)):  # named, but its slot was never examined
        entries.extend(ExportEntry(name, base + index, None, None) for name in sorted(by_index[index]))
    over = len(entries) > cap
    if over:
        ctx.warn('export_table_over_cap', f'more than {cap} export entries; the rest were not listed')
        del entries[cap:]
    return ExportTable(tuple(entries), truncated or over)
