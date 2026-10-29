"""Bounded PE tables for the rule workflow (YRX-integration-plan R4): `.pdata` function extents, base relocations, the import
address table and the executable sections' bytes. Read-only through a `VerifiedArtifactReader`; headers and sections come
from `inspect_pe`. Nothing is executed or loaded; a malformed table raises `PeTableError`.

The `.pdata` and `.reloc` readers are COPIED from the dev-only `tools/calibration/tier_w/pe_tables.py` (SPEC-33), with its
bounds and its error type; that module keeps serving Tier W and is not touched. Two readers are new: `import_slots` (the
RVA of the import address table slot of every imported name, which a `call [rip+disp]` goes through) and the accessors the
rule workflow needs (`read_backed`, `executable_sections`, `function_extent`).

A function's extent comes from `.pdata` only for a function that has an entry: a leaf function (no stack frame) has none,
and an entry that is only a chained fragment of another function is not the start of a function.
"""
from __future__ import annotations

import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from patchtrace.artifact_bytes import MAX_READ_BYTES, VerifiedArtifactReader

from .inspect import inspect_pe
from .models import PeOverview
from .sections import SCN_MEM_EXECUTE

MAX_TABLE = 64 * 1024 * 1024
MAX_RELOCS = 16_000_000
MAX_PDATA = 4_000_000
RELOC_WIDTH = {0: 0, 1: 2, 2: 2, 3: 4, 10: 8}
UNW_FLAG_CHAININFO = 0x4
MACHINE_AMD64 = 0x8664


class PeTableError(ValueError):
    pass


@dataclass(frozen=True)
class RuntimeFunction:
    begin: int
    end: int
    chained: bool


def _placeholder(text: str) -> bool:
    """`parse_imports` stands in `<unreadable ...>` or `<invalid thunk ...>` for entries it could not read."""
    return text.startswith('<') and text.endswith('>')


class PeTables:
    """A verified, read-only PE: its overview plus lazily parsed tables. The reader stays the caller's to close."""

    def __init__(self, reader: VerifiedArtifactReader, overview: PeOverview):
        self.reader = reader
        self.overview = overview
        self.smap = overview.section_map()
        self._regions = sorted(self.smap.regions, key=lambda r: r.start)
        self.warnings: list[str] = [w.code for w in overview.warnings]
        self._extents: dict[int, int] | None = None
        self._relocs: tuple[list[int], list[int]] | None = None

    @classmethod
    def open(cls, reader: VerifiedArtifactReader, cancel: Callable[[], bool] | None = None) -> PeTables:
        overview = inspect_pe(reader, cancel=cancel)
        if overview.status not in ('ok', 'partial') or not overview.sections:
            raise PeTableError(f'not a parsable PE image ({overview.status})')
        return cls(reader, overview)

    @property
    def sha256(self) -> str:
        return self.reader.sha256

    @property
    def size_of_image(self) -> int | None:
        return self.overview.size_of_image

    @property
    def is_x64(self) -> bool:
        return self.overview.machine is not None and self.overview.machine.code == MACHINE_AMD64

    # -- bytes -----------------------------------------------------------------------------------------------------
    def read_rva(self, rva: int, length: int) -> bytes:
        """Bytes at [rva, rva+length); RVA space the file does not back (BSS, gaps) reads as zero."""
        if length < 0 or rva < 0 or rva + length > 2**32:
            raise PeTableError('RVA range out of 32-bit space')
        out = bytearray()
        cursor, end = rva, rva + length
        regions = self._regions
        while cursor < end:
            region = next((r for r in regions if r.start <= cursor < r.start + r.extent), None)
            if region is None:
                nxt = min((r.start for r in regions if r.start > cursor), default=end)
                stop = min(end, nxt)
                out += bytes(stop - cursor)
                cursor = stop
                continue
            stop = min(end, region.start + region.extent)
            backed_end = region.start + region.backed
            if cursor < backed_end:
                take = min(stop, backed_end, cursor + MAX_READ_BYTES)   # the reader caps one read (#105 BUG-PE-1)
                data = self.reader.read(region.file_offset + cursor - region.start, take - cursor)
                out += data.ljust(take - cursor, b'\0')
                cursor = take
            if cursor < stop:
                out += bytes(stop - cursor)
                cursor = stop
        return bytes(out)

    def read_backed(self, rva: int, length: int) -> bytes | None:
        """The file's own bytes at [rva, rva+length), or `None` when any of it is not backed by file data in one section
        (code that is zero-filled is not code the file contains)."""
        ranges = self.smap.rva_to_file_ranges(rva, length)
        if not ranges or len(ranges) != 1 or ranges[0].length != length:
            return None
        start = ranges[0].file_offset
        return b''.join(self.reader.read(start + done, min(MAX_READ_BYTES, length - done), clip=False)
                        for done in range(0, length, MAX_READ_BYTES))

    def rva_to_offset(self, rva: int) -> int | None:
        return self.smap.rva_to_offset(rva)

    def executable_sections(self) -> Iterator[tuple[int, bytes]]:
        """(file offset, raw bytes) of every section marked executable, one at a time."""
        for section in self.overview.sections or ():
            if section.characteristics & SCN_MEM_EXECUTE and section.raw_size and section.raw_offset < self.reader.size:
                length = min(section.raw_size, self.reader.size - section.raw_offset)
                pieces = (self.reader.read(section.raw_offset + start, min(MAX_READ_BYTES, length - start))
                          for start in range(0, length, MAX_READ_BYTES))
                yield section.raw_offset, b''.join(pieces)

    # -- tables ----------------------------------------------------------------------------------------------------
    def _directory(self, name: str) -> tuple[int, int] | None:
        item = self.overview.directory(name)
        if item is None or not item.present:
            return None
        if item.size > MAX_TABLE:
            raise PeTableError(f'{name} directory larger than {MAX_TABLE} bytes')
        return item.rva, item.size

    def runtime_functions(self) -> list[RuntimeFunction]:
        """x64 `.pdata` entries; chained entries (UNW_FLAG_CHAININFO) are secondary fragments of a function."""
        found = self._directory('Exception')
        if found is None or not self.is_x64:
            return []
        rva, size = found
        count = size // 12
        if count > MAX_PDATA:
            raise PeTableError('too many .pdata entries')
        data = self.read_rva(rva, count * 12)
        limit = self.size_of_image or 2**32
        out = []
        for i in range(count):
            begin, end, unwind = struct.unpack_from('<III', data, i * 12)
            if begin == 0 and end == 0:
                continue
            if not begin < end <= limit:
                raise PeTableError('a .pdata entry is out of range')
            # Low bit set = indirect entry pointing at another RUNTIME_FUNCTION: a secondary fragment as well.
            flags = (self.read_rva(unwind, 1)[0] >> 3) if not unwind & 1 and unwind < limit else 0
            out.append(RuntimeFunction(begin, end, bool(unwind & 1) or bool(flags & UNW_FLAG_CHAININFO)))
        return out

    def function_extent(self, rva: int) -> int | None:
        """Size in bytes of the function that BEGINS at `rva` according to `.pdata`, else `None` (no entry: a leaf
        function, or an address that is not a function start or only a chained fragment)."""
        if self._extents is None:
            self._extents = {f.begin: f.end - f.begin for f in self.runtime_functions() if not f.chained}
        return self._extents.get(rva)

    def relocations(self) -> tuple[list[int], list[int]]:
        """Sorted base-relocation RVAs and their widths (bytes to mask). Unknown types mask 8 bytes."""
        if self._relocs is not None:
            return self._relocs
        found = self._directory('BaseReloc')
        if found is None:
            self._relocs = ([], [])
            return self._relocs
        rva, size = found
        data = self.read_rva(rva, size)
        pos, entries = 0, []
        while pos + 8 <= len(data):
            page, block = struct.unpack_from('<II', data, pos)
            if block == 0 and page == 0:
                break
            if block < 8 or pos + block > len(data) or block % 2:
                raise PeTableError('malformed base relocation block')
            for i in range((block - 8) // 2):
                (entry,) = struct.unpack_from('<H', data, pos + 8 + 2 * i)
                kind, offset = entry >> 12, entry & 0xFFF
                width = RELOC_WIDTH.get(kind, 8)
                if kind not in RELOC_WIDTH:
                    self.warnings.append(f'relocation type {kind} masked as 8 bytes')
                if width:
                    entries.append((page + offset, width))
                    if len(entries) > MAX_RELOCS:
                        raise PeTableError('too many base relocations')
            pos += block
        entries.sort()
        self._relocs = ([e[0] for e in entries], [e[1] for e in entries])
        return self._relocs

    def import_slots(self) -> dict[int, tuple[str, str]]:
        """Import address table slot RVA -> (DLL, name) for every imported name (`#N` for an ordinal), as `parse_imports`
        spelled them. The n-th descriptor owns the n-th DLL of the overview and its FirstThunk array is the table the
        loader fills, so the slot of the j-th import is `FirstThunk + j * entry size`. An import table that is missing, cut
        short or partly unreadable gives no slots (a wrong slot would pin a call to the wrong API)."""
        info = self.overview.imports
        found = self._directory('Import')
        if info is None or found is None or info.truncated or any(dll.truncated for dll in info.dlls):
            return {}
        entry = 8 if self.overview.optional_magic == 'PE32+' else 4
        raw = self.read_rva(found[0], 20 * len(info.dlls))
        slots: dict[int, tuple[str, str]] = {}
        for index, dll in enumerate(info.dlls):
            (first_thunk,) = struct.unpack_from('<I', raw, 20 * index + 16)
            if not first_thunk or _placeholder(dll.name):
                continue
            for position, name in enumerate(dll.functions):
                if not _placeholder(name):
                    slots[first_thunk + position * entry] = (dll.name, name)
        return slots
