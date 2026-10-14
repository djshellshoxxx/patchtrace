"""Bounded PE tables for Tier W (SPEC-33 s5.3, s6.3, s6.4): `.pdata` extents, base relocations, export RVAs and
relocation-masked function-body hashes. Read-only through `VerifiedArtifactReader`; headers come from
`pe_overview.inspect_pe`. Nothing is executed or loaded; malformed tables raise `PeTableError`."""
from __future__ import annotations

import bisect
import hashlib
import struct
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from patchtrace.artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
from patchtrace.pe_overview.inspect import inspect_pe
from patchtrace.pe_overview.models import PeOverview

from .msf import Section

MAX_TABLE = 64 * 1024 * 1024
MAX_RELOCS = 16_000_000
MAX_PDATA = 4_000_000
MAX_EXPORTS = 1_000_000
MAX_BODY = 16 * 1024 * 1024
RELOC_WIDTH = {0: 0, 1: 2, 2: 2, 3: 4, 10: 8}
UNW_FLAG_CHAININFO = 0x4
MACHINES = {0x8664: 'x64', 0x14C: 'x86', 0xAA64: 'arm64'}


class PeTableError(ValueError):
    pass


@dataclass(frozen=True)
class RuntimeFunction:
    begin: int
    end: int
    chained: bool


class PeView:
    """A verified, read-only PE: overview + lazily parsed tables. Use as a context manager."""

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

    def __enter__(self):
        return self

    def __exit__(self, *exc):
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

    def sections(self) -> tuple[Section, ...]:
        return tuple(Section(s.name, s.virtual_address, s.virtual_size) for s in self.overview.sections or ())

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

    def export_rvas(self) -> frozenset[int]:
        """RVAs in the export address table, forwarders (RVAs inside the export directory) excluded."""
        found = self._directory('Export')
        if found is None:
            return frozenset()
        rva, size = found
        head = self.read_rva(rva, 40)
        nfuncs, = struct.unpack_from('<I', head, 20)
        table, = struct.unpack_from('<I', head, 28)
        if nfuncs > MAX_EXPORTS:
            raise PeTableError('too many exports')
        data = self.read_rva(table, 4 * nfuncs)
        values = struct.unpack(f'<{nfuncs}I', data) if nfuncs else ()
        return frozenset(v for v in values if v and not rva <= v < rva + size)


def masked_body_sha256(view: PeView, ranges: Sequence[tuple[int, int]], relocs: tuple[list[int], list[int]]) -> str:
    """SHA-256 over the body bytes in range order, every byte covered by a base relocation zeroed (s6.3)."""
    starts, widths = relocs
    digest = hashlib.sha256()
    total = 0
    for start, end in ranges:
        total += end - start
        if total > MAX_BODY:
            raise PeTableError('function body larger than the hashing cap')
        data = bytearray(view.read_rva(start, end - start))
        i = bisect.bisect_left(starts, start - 8)
        while i < len(starts) and starts[i] < end:
            lo, hi = max(starts[i], start), min(starts[i] + widths[i], end)
            if lo < hi:
                data[lo - start:hi - start] = bytes(hi - lo)
            i += 1
        digest.update(data)
    return digest.hexdigest()
