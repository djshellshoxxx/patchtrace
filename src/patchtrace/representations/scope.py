"""Byte scopes: which on-disk bytes a raw view covers (whole file, file range, function RVA)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

MAX_INT = (1 << 63) - 1
DEFAULT_MAX_FUNCTION_LENGTH = 1024 * 1024
UNMAPPED_REASON = 'Function bytes unavailable: RVA range is unmapped, virtual-only or ambiguous'


class FileRangeLike(Protocol):
    file_offset: int
    length: int


class SectionMapLike(Protocol):
    def rva_to_file_ranges(self, rva: int, length: int) -> tuple[FileRangeLike, ...] | None: ...


@dataclass(frozen=True)
class Segment:
    file_offset: int
    length: int


@dataclass(frozen=True)
class ByteScope:
    kind: str
    segments: tuple[Segment, ...]
    total_length: int
    rva: int | None
    label: str
    available: bool = True
    unavailable_reason: str | None = None
    file_size: int | None = None
    clipped: bool = False


def _check_int(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f'{name} must be an integer')
    if value < 0:
        raise ValueError(f'{name} must be non-negative')
    if value > MAX_INT:
        raise ValueError(f'{name} is too large')
    return value


def whole_file(size: int) -> ByteScope:
    size = _check_int('size', size)
    segments = (Segment(0, size),) if size else ()
    return ByteScope('whole_file', segments, size, None, 'Whole file', file_size=size)


def file_range(size: int, offset: int, length: int) -> ByteScope:
    size = _check_int('size', size)
    offset = _check_int('offset', offset)
    length = _check_int('length', length)
    if offset > size:
        raise ValueError(f'offset 0x{offset:x} is past end of file (size 0x{size:x})')
    actual = min(length, size - offset)
    clipped = actual != length
    label = f'File range 0x{offset:x}..0x{offset + actual:x}'
    if clipped:
        label += f' (clipped to end of file, {length} bytes requested)'
    segments = (Segment(offset, actual),) if actual else ()
    return ByteScope('file_range', segments, actual, None, label, file_size=size, clipped=clipped)


def _unavailable(rva: int, length: int, reason: str) -> ByteScope:
    return ByteScope('function_rva', (), 0, rva, f'Function RVA 0x{rva:x} (+0x{length:x})',
                     available=False, unavailable_reason=reason)


def function_rva(section_map: SectionMapLike, rva: int, length: int, *,
                 max_length: int = DEFAULT_MAX_FUNCTION_LENGTH) -> ByteScope:
    rva = _check_int('rva', rva)
    length = _check_int('length', length)
    max_length = _check_int('max_length', max_length)
    if length == 0:
        raise ValueError('length must be positive')
    if length > max_length:
        return _unavailable(rva, length, f'Function bytes unavailable: length {length} exceeds the '
                                         f'{max_length} byte cap')
    ranges = section_map.rva_to_file_ranges(rva, length)
    if ranges is None:
        return _unavailable(rva, length, UNMAPPED_REASON)
    segments: list[Segment] = []
    total = 0
    for item in ranges:
        off, ln = item.file_offset, item.length
        bad = (isinstance(off, bool) or isinstance(ln, bool) or not isinstance(off, int)
               or not isinstance(ln, int) or off < 0 or ln <= 0 or off + ln > MAX_INT)
        if bad:
            return _unavailable(rva, length, UNMAPPED_REASON)
        segments.append(Segment(off, ln))
        total += ln
    if total != length or not segments:
        return _unavailable(rva, length, UNMAPPED_REASON)
    return ByteScope('function_rva', tuple(segments), total, rva, f'Function RVA 0x{rva:x} (+0x{length:x})')
