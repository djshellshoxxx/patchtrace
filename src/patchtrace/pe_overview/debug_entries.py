"""Debug directory entry types (not only CodeView), bounded."""
from __future__ import annotations

import struct
from dataclasses import dataclass

from ._common import Ctx
from .debug_info import ENTRY_SIZE, MAX_ENTRIES
from .models import SectionMap

IMAGE_DEBUG_TYPE_REPRO = 16


@dataclass(frozen=True, slots=True)
class DebugEntries:
    types: tuple[int, ...]  # in directory order, at most MAX_ENTRIES
    repro: bool  # a REPRO entry is present (deterministic build)
    truncated: bool


def parse_debug_entry_types(ctx: Ctx, smap: SectionMap, rva: int, size: int) -> DebugEntries | None:
    declared = size // ENTRY_SIZE
    count = min(declared, MAX_ENTRIES)
    span = smap.backed_prefix(rva, count * ENTRY_SIZE) if count else None
    raw = ctx.read(*span) if span is not None else b''
    if len(raw) < ENTRY_SIZE:
        return None
    types = tuple(struct.unpack_from('<I', raw, i * ENTRY_SIZE + 12)[0] for i in range(len(raw) // ENTRY_SIZE))
    return DebugEntries(types, IMAGE_DEBUG_TYPE_REPRO in types, declared > MAX_ENTRIES)
