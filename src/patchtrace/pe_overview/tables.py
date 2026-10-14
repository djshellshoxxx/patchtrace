"""Bounded PE tables for rule authoring: `.pdata` function extents, base relocations and IAT slot names.

The `.pdata` and `.reloc` readers are a copy of the Tier W calibration module (that module stays dev-only); the
unified IR keeps its own reader in `unified/ir/pe_tables.py` and is adapted later through a port, so names here are
deliberately distinct. Read-only through `VerifiedArtifactReader`; nothing is executed or loaded. Malformed tables
raise `PeTableError`.
"""
from __future__ import annotations

import bisect
import struct
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
from .inspect import inspect_pe
from .models import PeOverview

MAX_TABLE = 64 * 1024 * 1024
MAX_RELOCS = 16_000_000
MAX_PDATA = 4_000_000
MAX_IMPORT_SLOTS = 200_000
RELOC_WIDTH = {0: 0, 1: 2, 2: 2, 3: 4, 10: 8}
UNW_FLAG_CHAININFO = 0x4
MACHINES = {0x8664: 'x64', 0x14C: 'x86', 0xAA64: 'arm64'}
ORDINAL_FLAG_64 = 1 << 63


class PeTableError(ValueError):
    pass


@dataclass(frozen=True)
class RuntimeFunction:
    begin: int
    end: int
    chained: bool


class PeTableView:
    """A verified, read-only PE: overview plus lazily parsed tables. Use as a context manager."""

    def __init__(self, path: Path, expected_sha256: str | None = None, cancel: Callable[[], bool] | None = None):
        try:
            self.reader = VerifiedArtifactReader.open_path(Path(path), expected_sha256, cancel=cancel)
        except ArtifactBytesError as exc:
            raise PeTableError(f'cannot open {Path(path).name}: {exc}') from None
        self.overview: PeOverview = inspect_pe(self.reader, cancel=cancel)
        if self.overview.status not in ('ok', 'partial') or not self.overview.sections:
            self.reader.close()
            raise PeTableError(f'{Path(path).name} is not a parsable PE image ({self.overview.status})')
        self.smap = self.overview.section_map()
        self.warnings: list[str] = [w.code for w in self.overview.warnings]
        self._primaries: list[RuntimeFunction] | None = None

    def __enter__(self) -> PeTableView:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self.reader.close()

    @property
    def sha256(self) -> str:
        return self.reader.sha256

    @property
    def image_base(self) -> int:
        return self.overview.image_base or 0

    @property
    def size_of_image(self) -> int | None:
        return self.overview.size_of_image

    @property
    def machine(self) -> str:
        code = self.overview.machine.code if self.overview.machine else None
        return MACHINES.get(code, 'other')

    def read_rva(self, rva: int, length: int) -> bytes:
        """Bytes at [rva, rva+length); RVA space the file does not back (BSS, gaps) reads as zero."""
        if length < 0 or rva < 0 or rva + length > 2**32:
            raise PeTableError('RVA range out of 32-bit space')
        out = bytearray()
        cursor, end = rva, rva + length
        regions = sorted(self.smap.regions, key=lambda r: r.start)
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
                take = min(stop, backed_end)
                data = self.reader.read(region.file_offset + cursor - region.start, take - cursor)
                out += data.ljust(take - cursor, b'\0')
                cursor = take
            if cursor < stop:
                out += bytes(stop - cursor)
                cursor = stop
        return bytes(out)

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
        if found is None or self.machine != 'x64':
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

    def function_extent(self, rva: int) -> tuple[int, int] | None:
        """(begin, end) of the primary `.pdata` entry that starts exactly at `rva`; None for leaf code without one."""
        if self._primaries is None:
            self._primaries = sorted((f for f in self.runtime_functions() if not f.chained), key=lambda f: f.begin)
        index = bisect.bisect_left(self._primaries, rva, key=lambda f: f.begin)
        if index < len(self._primaries) and self._primaries[index].begin == rva:
            return rva, self._primaries[index].end
        return None

    def relocations(self) -> tuple[list[int], list[int]]:
        """Sorted base-relocation RVAs and their widths (bytes to mask). Unknown types mask 8 bytes."""
        found = self._directory('BaseReloc')
        if found is None:
            return [], []
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
        return [e[0] for e in entries], [e[1] for e in entries]

    def import_slots(self) -> dict[int, tuple[str, str]]:
        """IAT slot RVA -> (dll, function) for the PE32+ import directory. Ordinals read `#<n>`; a slot that is
        absent means unknown, never 'not an import'."""
        found = self._directory('Import')
        if found is None or self.machine != 'x64':
            return {}
        rva, size = found
        slots: dict[int, tuple[str, str]] = {}
        for index in range(size // 20):
            oft, _ts, _fwd, name_rva, ft = struct.unpack('<IIIII', self.read_rva(rva + 20 * index, 20))
            if not (oft or ft) or not name_rva:
                break
            dll = self._cstring(name_rva)
            lookup = oft or ft
            for slot in range(MAX_IMPORT_SLOTS):
                (thunk,) = struct.unpack('<Q', self.read_rva(lookup + 8 * slot, 8))
                if not thunk:
                    break
                label = f'#{thunk & 0xFFFF}' if thunk & ORDINAL_FLAG_64 else self._cstring((thunk & 0x7FFFFFFF) + 2)
                slots[ft + 8 * slot] = (dll, label)
                if len(slots) > MAX_IMPORT_SLOTS:
                    raise PeTableError('too many import slots')
        return slots

    def _cstring(self, rva: int, limit: int = 256) -> str:
        return self.read_rva(rva, limit).split(b'\0', 1)[0].decode('ascii', 'replace')
