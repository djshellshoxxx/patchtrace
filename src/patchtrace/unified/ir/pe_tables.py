"""PE tables for the IR (03 s7, s12.6): `.pdata` RUNTIME_FUNCTIONs with chained entries, the EH signature, DIR64
base relocations and the executable-section map. Stdlib only, bounded, read through `VerifiedArtifactReader`.

Malformed tables never fail the IR: the affected part is absent and a warning is kept (`pdata-unreadable`,
`reloc-unreadable`, `reloc-type-<n>`, `reloc-out-of-image`). Counts above the caps are `PT-UNIFIED-LIMIT`.
"""
from __future__ import annotations

import json
import struct
from array import array
from bisect import bisect_left, bisect_right
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from ...artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
from ...pe_overview import inspect_pe
from ..limits import UnifiedError

RUNTIME_FUNCTION_SIZE = 12
MAX_RUNTIME_FUNCTIONS = 1_000_000
MAX_RELOCATIONS = 4_000_000
MAX_EH_BYTES = 4096
MAX_SCOPES = 64
MAX_CHAIN_HOPS = 16
PAD_TOLERANCE = 15            # alignment padding between/after Ghidra's ranges that .pdata still covers
MAX_RELOC_DIRECTORY = 32 * 1024 * 1024
SCN_MEM_EXECUTE = 0x20000000
SCN_CNT_CODE = 0x20
UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER, UNW_FLAG_CHAININFO = 1, 2, 4
RELOC_ABSOLUTE, RELOC_DIR64 = 0, 10
EH_UNAVAILABLE = '{"trunc":true,"v":1}'


@dataclass(frozen=True)
class Section:
    name: str
    start: int
    end: int
    executable: bool


@dataclass
class Primary:
    begin: int
    end: int
    unwind: int
    chunks: list[tuple[int, int]] = field(default_factory=list)


def _coalesce(pairs: Sequence[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for begin, end in sorted(pairs):
        if out and begin <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((begin, end))
    return out


@dataclass
class PeTables:
    """Everything the ingest needs from the PE. Tests may build one directly (`eh` filled, no reader)."""
    image_base: int
    size_of_image: int
    sections: tuple[Section, ...] = ()
    primaries: dict[int, Primary] = field(default_factory=dict)
    relocs: array = field(default_factory=lambda: array('I'))
    warnings: list[str] = field(default_factory=list)
    eh: dict[int, str | None] = field(default_factory=dict)
    eh_loader: Callable[[Primary], str | None] | None = None
    _starts: list[int] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        self.sections = tuple(sorted(self.sections, key=lambda section: section.start))
        self._starts = [section.start for section in self.sections]

    def section_of(self, rva: int) -> Section | None:
        index = bisect_right(self._starts, rva) - 1
        if index >= 0 and rva < self.sections[index].end:
            return self.sections[index]
        return None

    def is_executable(self, rva: int) -> bool:
        section = self.section_of(rva)
        return bool(section and section.executable)

    def reloc_in(self, low: int, high: int) -> bool:
        index = bisect_left(self.relocs, low)
        return index < len(self.relocs) and self.relocs[index] < high

    def extent(self, entry: int, ranges: Sequence[Sequence[int]]) -> int:
        """`fn.extent_src`: 1 pdata-confirmed, 2 conflict, 0 unknown (03 s12.6).

        Confirmed = every Ghidra range lies inside the union of the primary and chained RUNTIME_FUNCTIONs, each
        pdata component starts exactly where a Ghidra range starts, and the bytes of a component that Ghidra does
        not cover form gaps of at most PAD_TOLERANCE (15) bytes: alignment padding inside or after a function
        (GCC/MinGW functions have such gaps; MSVC pads outside the entry). Anything else is a conflict."""
        primary = self.primaries.get(entry)
        if primary is None:
            return 0
        wanted = _coalesce([(primary.begin, primary.end), *primary.chunks])
        got = _coalesce([(start, start + length) for start, length in ranges])
        remaining = list(got)
        for begin, end in wanted:
            inside = [item for item in got if begin <= item[0] and item[1] <= end]
            if not inside or inside[0][0] != begin:
                return 2
            cursor = begin
            for start, stop in inside:
                if start - cursor > PAD_TOLERANCE:
                    return 2
                cursor = stop
                remaining.remove((start, stop))
            if end - cursor > PAD_TOLERANCE:
                return 2
        return 1 if not remaining else 2

    def eh_for(self, entry: int) -> str | None:
        if entry in self.eh:
            return self.eh[entry]
        primary = self.primaries.get(entry)
        value = None
        if primary is not None and self.eh_loader is not None:
            value = self.eh_loader(primary)
        self.eh[entry] = value
        return value


def _unsupported(message: str, reason: str) -> UnifiedError:
    return UnifiedError('PT-UNIFIED-UNSUPPORTED', message, reason=reason)


def _limit(message: str, reason: str) -> UnifiedError:
    return UnifiedError('PT-UNIFIED-LIMIT', message, reason=reason)


class _Rva:
    """RVA reads through the verified reader (None = not backed by file bytes)."""

    def __init__(self, reader: VerifiedArtifactReader, section_map) -> None:
        self.reader = reader
        self.map = section_map

    def read(self, rva: int, length: int) -> bytes | None:
        try:
            ranges = self.map.rva_to_file_ranges(rva, length)
            if ranges is None:
                return None
            data = b''.join(self.reader.read(item.file_offset, item.length, clip=False) for item in ranges)
        except ArtifactBytesError:
            return None
        return data if len(data) == length else None


def _parse_sections(overview) -> tuple[Section, ...]:
    out = []
    for item in overview.sections or ():
        size = item.virtual_size or item.raw_size
        if size > 0:
            out.append(Section(item.name, item.virtual_address, item.virtual_address + size,
                               bool(item.characteristics & (SCN_MEM_EXECUTE | SCN_CNT_CODE))))
    return tuple(sorted(out, key=lambda section: section.start))


def _in_section(sections: Sequence[Section], rva: int) -> bool:
    return any(section.start <= rva < section.end for section in sections)


def _read_runtime_functions(rva_reader: _Rva, directory, sections, tables: PeTables) -> list[tuple[int, int, int]] | None:
    if directory is None or not directory.present:
        return []
    count, remainder = divmod(directory.size, RUNTIME_FUNCTION_SIZE)
    if count > MAX_RUNTIME_FUNCTIONS:
        raise _limit('The exception directory holds more RUNTIME_FUNCTIONs than the cap', 'pdata-cap')
    entries: list[tuple[int, int, int]] = []
    chunk = 4096
    for first in range(0, count, chunk):
        take = min(chunk, count - first)
        data = rva_reader.read(directory.rva + first * RUNTIME_FUNCTION_SIZE, take * RUNTIME_FUNCTION_SIZE)
        if data is None:
            tables.warnings.append('pdata-unreadable')
            return None
        entries.extend(struct.iter_unpack('<III', data))
    previous_end = 0
    for begin, end, unwind in entries:
        if (remainder or begin >= end or begin < previous_end or not _in_section(sections, begin)
                or not _in_section(sections, end - 1) or unwind == 0):
            tables.warnings.append('pdata-unreadable')   # unsorted, overlapping, out-of-section or truncated table
            return None
        previous_end = end
    return entries


def _unwind_header(rva_reader: _Rva, unwind: int) -> tuple[int, int, int, int, int] | None:
    head = rva_reader.read(unwind, 4)
    if head is None:
        return None
    first, prolog, codes, frame = head
    return first & 7, first >> 3, prolog, codes, frame


def _resolve_chains(rva_reader: _Rva, entries: list[tuple[int, int, int]], tables: PeTables) -> None:
    by_begin = {begin: (begin, end, unwind) for begin, end, unwind in entries}
    parent_of: dict[int, int] = {}
    for begin, _end, unwind in entries:
        header = _unwind_header(rva_reader, unwind)
        if header is None:
            tables.warnings.append('pdata-unreadable')
            return
        _version, flags, _prolog, codes, _frame = header
        if flags & UNW_FLAG_CHAININFO:
            tail = rva_reader.read(unwind + 4 + ((codes + 1) & ~1) * 2, RUNTIME_FUNCTION_SIZE)
            if tail is None:
                tables.warnings.append('pdata-unreadable')
                return
            parent_of[begin] = struct.unpack('<III', tail)[0]
    for begin, end, unwind in entries:
        if begin in parent_of:
            continue
        tables.primaries[begin] = Primary(begin, end, unwind)
    for begin in parent_of:
        node, hops = begin, 0
        while node in parent_of and hops < MAX_CHAIN_HOPS:
            node, hops = parent_of[node], hops + 1
        primary = tables.primaries.get(node)
        if primary is None or node in parent_of or node not in by_begin:
            tables.warnings.append('pdata-unreadable')
            tables.primaries.clear()
            return
        primary.chunks.append((by_begin[begin][0], by_begin[begin][1]))


def _eh_signature(rva_reader: _Rva, primary: Primary) -> str | None:
    """Normalised UNWIND_INFO of a primary entry (03 s12.6); scope begin/end/target are function-relative."""
    header = _unwind_header(rva_reader, primary.unwind)
    if header is None:
        return EH_UNAVAILABLE
    version, flags, prolog, codes, frame = header
    codes_bytes = rva_reader.read(primary.unwind + 4, codes * 2) if codes else b''
    if codes_bytes is None:
        return EH_UNAVAILABLE
    document: dict = {'v': 1, 'ver': version, 'fl': flags, 'prolog': prolog, 'frame': [frame & 15, frame >> 4],
                      'codes': codes_bytes.hex(), 'handler': None, 'hlen': None, 'scopes': None}
    tail = primary.unwind + 4 + ((codes + 1) & ~1) * 2
    if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER):
        handler = rva_reader.read(tail, 4)
        if handler is None:
            return EH_UNAVAILABLE
        document['handler'] = struct.unpack('<I', handler)[0]
        count_bytes = rva_reader.read(tail + 4, 4)
        if count_bytes is not None:
            count = struct.unpack('<I', count_bytes)[0]
            if 0 < count <= MAX_SCOPES:
                table = rva_reader.read(tail + 8, count * 16)
                if table is not None and _plausible_scopes(table, count, primary):
                    document['hlen'] = 4 + 16 * count
                    document['scopes'] = [[begin - primary.begin, end - primary.begin, filt,
                                           target - primary.begin if target else 0]
                                          for begin, end, filt, target in struct.iter_unpack('<IIII', table)]
    text = json.dumps(document, sort_keys=True, separators=(',', ':'))
    return text if len(text) <= MAX_EH_BYTES else EH_UNAVAILABLE


def _plausible_scopes(table: bytes, count: int, primary: Primary) -> bool:
    """C scope-table shape: every record lies inside the function's extent (primary plus chunks)."""
    extent = _coalesce([(primary.begin, primary.end), *primary.chunks])
    for begin, end, _filter, target in struct.iter_unpack('<IIII', table):
        if not (begin < end and any(low <= begin and end <= high for low, high in extent)):
            return False
        if target and not any(low <= target < high for low, high in extent):
            return False
    return True


def _read_relocations(rva_reader: _Rva, directory, size_of_image: int, tables: PeTables) -> None:
    if directory is None or not directory.present:
        return
    if directory.size > MAX_RELOC_DIRECTORY:
        raise _limit('The base relocation directory is larger than the cap', 'reloc-cap')
    data = rva_reader.read(directory.rva, directory.size)
    if data is None:
        tables.warnings.append('reloc-unreadable')
        return
    found: list[int] = []
    seen_types: set[int] = set()
    position = 0
    while position + 8 <= len(data):
        page, size = struct.unpack_from('<II', data, position)
        if size == 0 and page == 0:
            break   # zero padding after the last block
        if size < 8 or size % 2 or position + size > len(data):
            tables.warnings.append('reloc-unreadable')
            break
        for (entry,) in struct.iter_unpack('<H', data[position + 8:position + size]):
            kind, offset = entry >> 12, entry & 0xFFF
            if kind == RELOC_ABSOLUTE:
                continue
            if kind != RELOC_DIR64:
                if kind not in seen_types:
                    seen_types.add(kind)
                    tables.warnings.append(f'reloc-type-{kind}')
                continue
            if page + offset >= size_of_image:
                if 'reloc-out-of-image' not in tables.warnings:
                    tables.warnings.append('reloc-out-of-image')
                continue
            found.append(page + offset)
            if len(found) > MAX_RELOCATIONS:
                raise _limit('The image holds more base relocations than the cap', 'reloc-cap')
        position += size
    tables.relocs = array('I', sorted(found))


def read_pe_tables(reader: VerifiedArtifactReader) -> PeTables:
    """Parse the tables of a verified PE32+ artifact (the same reader that verified its SHA-256)."""
    overview = inspect_pe(reader)
    if overview.status == 'not_pe' or overview.optional_magic != 'PE32+' or overview.image_base is None \
            or not overview.size_of_image:
        raise _unsupported('The artifact is not a readable PE32+ image', 'not-pe32plus')
    sections = _parse_sections(overview)
    tables = PeTables(image_base=overview.image_base, size_of_image=overview.size_of_image, sections=sections)
    rva_reader = _Rva(reader, overview.section_map())
    entries = _read_runtime_functions(rva_reader, overview.directory('Exception'), sections, tables)
    if entries:
        _resolve_chains(rva_reader, entries, tables)
        tables.eh_loader = lambda primary: _eh_signature(rva_reader, primary)
    _read_relocations(rva_reader, overview.directory('BaseReloc'), overview.size_of_image, tables)
    return tables
