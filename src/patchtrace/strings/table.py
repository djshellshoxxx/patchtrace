"""`strings-table/1`: columnar per-side string table (spec WB3 s7). Pure: no Qt, no file I/O.

Rows are fixed-width columns (`array`) with deduplicated display values and fragments, about 65 bytes per row, so
200k strings per side stay small (the per-row pydantic route costs ~0.5 GiB and 8 s to reload, spec F15). The
sidecar is hostile input: `from_bytes` bounds every count against the data and validates each row by hand.
Identity is the value hash alone; offsets, RVAs and labels never take part in comparison.
"""
from __future__ import annotations

import json
import struct
import sys
from array import array
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import get_args

from .contracts import Encoding, StringBasis, StringsError, StringType
from .limits import MAX_FRAGMENTS, MAX_ROWS_PER_SIDE, MAX_TABLE_BYTES, NONE_U32

MAGIC = b'PTSTRT1\n'
TYPES: tuple[str, ...] = get_args(StringType)
ENCODINGS: tuple[str, ...] = get_args(Encoding)
CONFIDENCE: tuple[str, ...] = ('verified-bytes', 'tool-reported', 'unverified-location')
FLAG_SECRET, FLAG_DISPLAY_CUT, FLAG_NOISE = 1, 2, 4
FLAGS_MASK = FLAG_SECRET | FLAG_DISPLAY_CUT | FLAG_NOISE
_HEADER = struct.Struct('<8sIIII')  # magic, basis json bytes, rows, display values, fragments
_COUNT = struct.Struct('<I')
_U32_COLUMNS = ('length', 'offset', 'rva', 'fn_rva', 'site', 'disp', 'frag')
_BIG_ENDIAN = sys.byteorder == 'big'


@dataclass(frozen=True, slots=True)
class StringRow:
    value_sha256: bytes
    type: int
    encoding: int
    length: int
    offset: int = NONE_U32
    rva: int = NONE_U32
    fn_rva: int = NONE_U32
    site: int = NONE_U32
    confidence: int = 0
    flags: int = 0
    display: str = ''
    fragment: str | None = None


def _fail(message: str) -> StringsError:
    return StringsError('PT-STR-INPUT', message)


def _pool(values: Iterable[str]) -> tuple[list[str], dict[str, int]]:
    index: dict[str, int] = {}
    for value in values:
        index.setdefault(value, len(index))
    return list(index), index


def _encode_pool(values: list[str]) -> bytes:
    parts: list[bytes] = []
    for value in values:
        raw = value.encode('utf-8', 'surrogatepass')
        parts.append(_COUNT.pack(len(raw)))
        parts.append(raw)
    return b''.join(parts)


def _decode_pool(data: memoryview, pos: int, count: int) -> tuple[list[str], int]:
    out: list[str] = []
    for _ in range(count):
        if pos + 4 > len(data):
            raise _fail('truncated string pool')
        (size,) = _COUNT.unpack_from(data, pos)
        pos += 4
        if pos + size > len(data):
            raise _fail('truncated string pool')
        out.append(str(data[pos:pos + size], 'utf-8', 'surrogatepass'))
        pos += size
    return out, pos


def _column(code: str, data: memoryview, pos: int, rows: int) -> tuple[array, int]:
    column = array(code)
    end = pos + rows * column.itemsize
    if end > len(data):
        raise _fail('truncated column')
    column.frombytes(data[pos:end])
    if _BIG_ENDIAN and column.itemsize > 1:
        column.byteswap()
    return column, end


class StringTable:
    """Immutable after construction; build with `from_rows`, restore with `from_bytes`."""

    def __init__(self, basis: StringBasis, hashes: bytes, small: dict[str, array], wide: dict[str, array],
                 displays: list[str], fragments: list[str]):
        self.basis = basis
        self._hashes = hashes
        self._small = small
        self._wide = wide
        self.displays = displays
        self.fragments = fragments

    def __len__(self) -> int:
        return len(self._small['type'])

    @classmethod
    def from_rows(cls, basis: StringBasis, rows: Iterable[StringRow]) -> StringTable:
        rows = list(rows)
        if len(rows) > MAX_ROWS_PER_SIDE:
            raise StringsError('PT-STR-LIMIT', f'more than {MAX_ROWS_PER_SIDE} strings on one side')
        displays, display_index = _pool(row.display for row in rows)
        fragments, fragment_index = _pool(row.fragment for row in rows if row.fragment is not None)
        small = {'type': array('B'), 'enc': array('B'), 'conf': array('B'), 'flags': array('H')}
        wide = {name: array('I') for name in _U32_COLUMNS}
        digests = bytearray()
        for row in rows:
            _check_row(row)
            digests += row.value_sha256
            small['type'].append(row.type)
            small['enc'].append(row.encoding)
            small['conf'].append(row.confidence)
            small['flags'].append(row.flags)
            for name in ('length', 'offset', 'rva', 'fn_rva', 'site'):
                wide[name].append(getattr(row, name))
            wide['disp'].append(display_index[row.display])
            wide['frag'].append(NONE_U32 if row.fragment is None else fragment_index[row.fragment])
        return cls(basis, bytes(digests), small, wide, displays, fragments)

    def row(self, index: int) -> StringRow:
        if not 0 <= index < len(self):
            raise IndexError(index)
        frag = self._wide['frag'][index]
        return StringRow(
            value_sha256=self._hashes[index * 32:index * 32 + 32], type=self._small['type'][index],
            encoding=self._small['enc'][index], length=self._wide['length'][index],
            offset=self._wide['offset'][index], rva=self._wide['rva'][index], fn_rva=self._wide['fn_rva'][index],
            site=self._wide['site'][index], confidence=self._small['conf'][index], flags=self._small['flags'][index],
            display=self.displays[self._wide['disp'][index]], fragment=None if frag == NONE_U32 else self.fragments[frag])

    def __iter__(self) -> Iterator[StringRow]:
        return (self.row(i) for i in range(len(self)))

    def to_bytes(self) -> bytes:
        header = json.dumps(self.basis.model_dump(mode='json'), sort_keys=True, separators=(',', ':')).encode('ascii')
        out = [_HEADER.pack(MAGIC, len(header), len(self), len(self.displays), len(self.fragments)), header,
               _encode_pool(self.displays), _encode_pool(self.fragments), self._hashes]
        for column in (*self._small.values(), *self._wide.values()):
            out.append(_swapped(column).tobytes())
        return b''.join(out)

    @classmethod
    def from_bytes(cls, blob: bytes) -> StringTable:
        if len(blob) > MAX_TABLE_BYTES:
            raise StringsError('PT-STR-LIMIT', 'string table sidecar is too large')
        data = memoryview(blob)
        if len(data) < _HEADER.size:
            raise _fail('not a strings table')
        magic, header_size, rows, n_displays, n_fragments = _HEADER.unpack_from(data)
        if magic != MAGIC:
            raise _fail('not a strings table, or an unknown major version')
        if rows > MAX_ROWS_PER_SIDE or n_fragments > MAX_FRAGMENTS or n_displays > max(rows, 1):
            raise StringsError('PT-STR-LIMIT', 'string table counts exceed the limits')
        pos = _HEADER.size
        if pos + header_size > len(data):
            raise _fail('truncated header')
        try:
            basis = StringBasis.model_validate_json(bytes(data[pos:pos + header_size]))
        except ValueError as exc:
            raise _fail('invalid basis header') from exc
        pos += header_size
        displays, pos = _decode_pool(data, pos, n_displays)
        fragments, pos = _decode_pool(data, pos, n_fragments)
        if pos + rows * 32 > len(data):
            raise _fail('truncated hashes')
        hashes = bytes(data[pos:pos + rows * 32])
        pos += rows * 32
        small: dict[str, array] = {}
        for name, code in (('type', 'B'), ('enc', 'B'), ('conf', 'B'), ('flags', 'H')):
            small[name], pos = _column(code, data, pos, rows)
        wide: dict[str, array] = {}
        for name in _U32_COLUMNS:
            wide[name], pos = _column('I', data, pos, rows)
        if pos != len(data):
            raise _fail('trailing bytes')
        table = cls(basis, hashes, small, wide, displays, fragments)
        table._validate()
        return table

    def _validate(self) -> None:
        if len(self) != self.basis.rows_kept:
            raise _fail('row count disagrees with the basis')
        checks = ((self._small['type'], len(TYPES)), (self._small['enc'], len(ENCODINGS)),
                  (self._small['conf'], len(CONFIDENCE)))
        for column, limit in checks:
            if column and max(column) >= limit:
                raise _fail('code out of range')
        if any(flag & ~FLAGS_MASK for flag in self._small['flags']):
            raise _fail('unknown flag bits')
        if any(i >= len(self.displays) for i in self._wide['disp']):
            raise _fail('display index out of range')
        if any(i != NONE_U32 and i >= len(self.fragments) for i in self._wide['frag']):
            raise _fail('fragment index out of range')


def _swapped(column: array) -> array:
    if not _BIG_ENDIAN or column.itemsize == 1:
        return column
    copy = array(column.typecode, column)
    copy.byteswap()
    return copy


def _check_row(row: StringRow) -> None:
    if len(row.value_sha256) != 32:
        raise _fail('value hash must be 32 bytes')
    if not (0 <= row.type < len(TYPES) and 0 <= row.encoding < len(ENCODINGS)
            and 0 <= row.confidence < len(CONFIDENCE)):
        raise _fail('code out of range')
    if row.flags & ~FLAGS_MASK:
        raise _fail('unknown flag bits')
    for value in (row.length, row.offset, row.rva, row.fn_rva, row.site):
        if not 0 <= value <= NONE_U32:
            raise _fail('value does not fit 32 bits')
