"""Rich header parser over the bytes between the DOS header and the PE header.

The format is undocumented by Microsoft (reverse-engineered), the header is optional and forgeable, so a missing
or failed parse means "unknown", never a negative fact. The walk goes backwards from the `Rich` marker to `DanS`
(it does not assume a fixed start offset) and every size is bounded.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

DANS = 0x536E6144
MAX_ENTRIES = 1024
MAX_REGION = 64 * 1024  # same bound as Limits.max_lfanew
DOS_HEADER_SIZE = 0x40
_LFANEW = range(0x3C, 0x40)


@dataclass(frozen=True, slots=True)
class RichEntry:
    product_id: int
    build: int
    count: int


@dataclass(frozen=True, slots=True)
class RichFacts:
    offset: int
    key: int
    checksum_ok: bool | None  # None when entries were truncated, so the checksum cannot be recomputed
    entries: tuple[RichEntry, ...]
    truncated: bool
    signature: str  # SHA-256 over the sorted unique (product_id, build) pairs; counts track code size and are excluded


def _rol32(value: int, count: int) -> int:
    count &= 31
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF if count else value


def _checksum(region: bytes, dans_offset: int, entries: tuple[RichEntry, ...]) -> int:
    total = dans_offset
    for index in range(dans_offset):
        if index not in _LFANEW:  # e_lfanew is excluded from the sum
            total += _rol32(region[index], index)
    for entry in entries:
        total += _rol32((entry.product_id << 16) | entry.build, entry.count)
    return total & 0xFFFFFFFF


def rich_signature(entries: tuple[RichEntry, ...]) -> str:
    pairs = sorted({(entry.product_id, entry.build) for entry in entries})
    return hashlib.sha256(b''.join(struct.pack('<HH', *pair) for pair in pairs)).hexdigest()


def _find_dans(region: bytes, rich_offset: int, key: int) -> int | None:
    pos = rich_offset - 4
    while pos >= DOS_HEADER_SIZE:
        if struct.unpack_from('<I', region, pos)[0] ^ key == DANS:
            return pos
        pos -= 4
    return None


def parse_rich_header(region: bytes) -> RichFacts | None:
    """Parse the Rich header from `region` (the file's first e_lfanew bytes); None when absent or malformed."""
    region = region[:MAX_REGION]
    marker = region.rfind(b'Rich')
    while marker >= 0 and marker % 4:  # the marker is dword aligned; a stray unaligned match is not it
        marker = region.rfind(b'Rich', 0, marker + 3)
    if marker < DOS_HEADER_SIZE or marker + 8 > len(region):
        return None
    key = struct.unpack_from('<I', region, marker + 4)[0]
    dans = _find_dans(region, marker, key)
    if dans is None:
        return None
    words = [word ^ key for word in struct.unpack_from(f'<{(marker - dans - 4) // 4}I', region, dans + 4)]
    while words and words[0] == 0:  # padding after DanS
        words.pop(0)
    if len(words) % 2:
        return None
    entries = [RichEntry(comp >> 16, comp & 0xFFFF, count)
               for comp, count in zip(words[0::2], words[1::2], strict=True) if comp or count]
    truncated = len(entries) > MAX_ENTRIES
    kept = tuple(entries[:MAX_ENTRIES])
    ok = None if truncated else _checksum(region, dans, kept) == key
    return RichFacts(dans, key, ok, kept, truncated, rich_signature(kept))
