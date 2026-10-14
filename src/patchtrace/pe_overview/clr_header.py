"""CLR (COR20) header basics: runtime version, flags and the metadata version string."""
from __future__ import annotations

import struct
from dataclasses import dataclass

from ._common import Ctx, clean_text
from .models import SectionMap

COR20_SIZE = 72
MAX_METADATA_VERSION = 64
FLAGS = {
    0x1: 'ILONLY', 0x2: '32BITREQUIRED', 0x4: 'IL_LIBRARY', 0x8: 'STRONGNAMESIGNED', 0x10: 'NATIVE_ENTRYPOINT',
    0x10000: 'TRACKDEBUGDATA', 0x20000: '32BITPREFERRED',
}


@dataclass(frozen=True, slots=True)
class ClrFacts:
    header_size: int
    runtime_major: int
    runtime_minor: int
    flags: tuple[str, ...]
    il_only: bool
    has_native_header: bool  # ManagedNativeHeader present: mixed mode or ReadyToRun
    metadata_version: str | None


def _metadata_version(ctx: Ctx, smap: SectionMap, rva: int, size: int) -> str | None:
    off = smap.rva_to_offset(rva) if rva and size >= 16 else None
    head = ctx.read(off, 16 + MAX_METADATA_VERSION) if off is not None else b''
    if len(head) < 16 or head[:4] != b'BSJB':
        return None
    length = min(struct.unpack_from('<I', head, 12)[0], MAX_METADATA_VERSION, len(head) - 16)
    return clean_text(head[16:16 + length].split(b'\0')[0])


def parse_clr_header(ctx: Ctx, smap: SectionMap, rva: int, size: int) -> ClrFacts | None:
    off = smap.rva_to_offset(rva) if size >= COR20_SIZE else None
    raw = ctx.read(off, COR20_SIZE) if off is not None else b''
    if len(raw) < COR20_SIZE:
        return None
    cb, major, minor, md_rva, md_size, flags = struct.unpack_from('<IHHIII', raw, 0)
    native_rva, native_size = struct.unpack_from('<II', raw, 64)
    names = tuple(name for bit, name in FLAGS.items() if flags & bit)
    return ClrFacts(cb, major, minor, names, bool(flags & 1), bool(native_rva and native_size),
                    _metadata_version(ctx, smap, md_rva, md_size))
