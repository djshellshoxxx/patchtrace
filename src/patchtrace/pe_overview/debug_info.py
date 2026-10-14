"""CodeView RSDS (PDB reference) extraction from the Debug directory."""
from __future__ import annotations

import struct
import uuid

from ._common import Ctx, clean_text
from .models import CodeViewInfo, SectionMap

IMAGE_DEBUG_TYPE_CODEVIEW = 2
ENTRY_SIZE = 28
MAX_ENTRIES = 16


def parse_codeview(ctx: Ctx, smap: SectionMap, rva: int, size: int) -> CodeViewInfo | None:
    count = min(size // ENTRY_SIZE, MAX_ENTRIES)
    off = smap.rva_to_offset(rva) if count else None
    raw = ctx.read(off, count * ENTRY_SIZE) if off is not None else b''
    if count and len(raw) < ENTRY_SIZE:
        ctx.warn('debug_unparseable', 'debug directory is not backed by file data')
        return None
    cap = ctx.limits.max_name_length
    for i in range(len(raw) // ENTRY_SIZE):
        ctx.check()
        dtype, data_size, _addr, ptr = struct.unpack_from('<IIII', raw, i * ENTRY_SIZE + 12)
        if dtype != IMAGE_DEBUG_TYPE_CODEVIEW:
            continue
        if data_size < 24 or ptr == 0 or ptr + 24 > ctx.reader.size:
            ctx.warn('debug_unparseable', 'CodeView debug entry is out of range')
            continue
        data = ctx.read(ptr, min(data_size, 24 + cap + 1))
        if data[:4] != b'RSDS' or len(data) < 24:
            continue
        guid = str(uuid.UUID(bytes_le=data[4:20]))
        age = struct.unpack_from('<I', data, 20)[0]
        path = data[24:]
        end = path.find(b'\0')
        if end < 0:
            ctx.warn('name_truncated', 'PDB path has no terminator within the allowed length; truncated')
            path = path[:cap]
        else:
            path = path[:end]
        return CodeViewInfo(clean_text(path), guid, age)
    return None
