"""Frozen, JSON-serializable records for the PE overview (see docs/specs/pe-overview.md)."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

SIGNATURE_NOT_VERIFIED = 'not_verified'


@dataclass(frozen=True, slots=True)
class Limits:
    max_lfanew: int = 64 * 1024
    max_sections: int = 96
    max_data_directories: int = 16
    max_import_dlls: int = 512
    max_functions_per_dll: int = 4096
    max_total_names: int = 20000
    max_name_length: int = 512
    max_export_names: int = 20000
    entropy_cap: int = 8 * 1024 * 1024
    checksum_max_file: int = 256 * 1024 * 1024
    max_certificates: int = 64
    chunk: int = 1024 * 1024


@dataclass(frozen=True, slots=True)
class PeWarning:
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class CodeLabel:
    code: int
    name: str


@dataclass(frozen=True, slots=True)
class PeKind:
    kind: str
    reason: str


@dataclass(frozen=True, slots=True)
class CoffTimestamp:
    raw: int
    iso_utc: str | None
    note: str = 'Untrusted: forgeable or randomized by the build; not a file creation or signing date.'


@dataclass(frozen=True, slots=True)
class ChecksumInfo:
    stored: int
    computed: int | None
    match: bool | None


@dataclass(frozen=True, slots=True)
class DataDirectory:
    index: int
    name: str
    rva: int
    size: int
    present: bool


@dataclass(frozen=True, slots=True)
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int
    flags: tuple[str, ...]
    entropy: float | None
    entropy_bytes: int
    sampled: bool


@dataclass(frozen=True, slots=True)
class ImportDll:
    name: str
    functions: tuple[str, ...]
    function_count: int
    truncated: bool


@dataclass(frozen=True, slots=True)
class ImportsInfo:
    dlls: tuple[ImportDll, ...]
    total_dlls: int
    total_functions: int
    truncated: bool


@dataclass(frozen=True, slots=True)
class ExportsInfo:
    dll_name: str | None
    count: int
    named_count: int
    names: tuple[str, ...]
    truncated: bool


@dataclass(frozen=True, slots=True)
class OverlayInfo:
    offset: int
    size: int
    entropy: float | None
    sampled: bool


@dataclass(frozen=True, slots=True)
class CertificateEntry:
    offset: int
    length: int
    revision: int
    cert_type: int


@dataclass(frozen=True, slots=True)
class CertificateTable:
    present: bool
    file_offset: int
    size: int
    entries: tuple[CertificateEntry, ...]
    signature_status: str = SIGNATURE_NOT_VERIFIED


@dataclass(frozen=True, slots=True)
class CodeViewInfo:
    pdb_path: str
    guid: str
    age: int


@dataclass(frozen=True, slots=True)
class PackerHint:
    name: str
    confidence: str
    evidence: str


@dataclass(frozen=True, slots=True)
class FileRange:
    file_offset: int
    length: int


@dataclass(frozen=True, slots=True)
class FieldComparison:
    field: str
    older: str
    newer: str
    status: str
    reason: str
    provenance: str


@dataclass(frozen=True, slots=True)
class PeOverview:
    size: int
    sha256: str
    status: str
    warnings: tuple[PeWarning, ...] = ()
    header_magic: str | None = None
    pe_kind: PeKind | None = None
    machine: CodeLabel | None = None
    coff_timestamp: CoffTimestamp | None = None
    characteristics: tuple[str, ...] | None = None
    optional_magic: str | None = None
    entrypoint_rva: int | None = None
    entrypoint_va: int | None = None
    image_base: int | None = None
    section_alignment: int | None = None
    file_alignment: int | None = None
    size_of_image: int | None = None
    size_of_headers: int | None = None
    subsystem: CodeLabel | None = None
    dll_characteristics: tuple[str, ...] | None = None
    checksum: ChecksumInfo | None = None
    data_directories: tuple[DataDirectory, ...] | None = None
    sections: tuple[SectionInfo, ...] | None = None
    imports: ImportsInfo | None = None
    exports: ExportsInfo | None = None
    overlay: OverlayInfo | None = None
    certificates: CertificateTable | None = None
    codeview: CodeViewInfo | None = None
    packer_hints: tuple[PackerHint, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def section_map(self) -> SectionMap:
        return SectionMap.from_overview(self)

    def directory(self, name: str) -> DataDirectory | None:
        for item in self.data_directories or ():
            if item.name == name:
                return item
        return None


_U32 = 0x1_0000_0000


@dataclass(frozen=True, slots=True)
class _Region:
    start: int
    extent: int
    file_offset: int
    backed: int


@dataclass(frozen=True, slots=True)
class SectionMap:
    """RVA to file-offset translation. Conservative: anything ambiguous or unbacked is None."""

    regions: tuple[_Region, ...]

    @classmethod
    def from_overview(cls, ov: PeOverview) -> SectionMap:
        regions: list[_Region] = []
        size = ov.size
        soh = ov.size_of_headers
        if soh:
            regions.append(_Region(0, soh, 0, max(0, min(soh, size))))
        for sec in ov.sections or ():
            extent = sec.virtual_size or sec.raw_size
            if extent <= 0:
                continue
            avail = max(0, min(sec.raw_size, size - sec.raw_offset)) if sec.raw_offset < size else 0
            regions.append(_Region(sec.virtual_address, extent, sec.raw_offset, min(extent, avail)))
        return cls(tuple(regions))

    def rva_to_file_ranges(self, rva: int, length: int) -> tuple[FileRange, ...] | None:
        if isinstance(rva, bool) or isinstance(length, bool) or not isinstance(rva, int) \
                or not isinstance(length, int):
            return None
        if rva < 0 or length < 0 or rva + length > _U32:
            return None
        if length == 0:
            return ()
        end = rva + length
        cursor = rva
        out: list[FileRange] = []
        while cursor < end:
            covering = [r for r in self.regions if r.start <= cursor < r.start + r.extent]
            if len(covering) != 1:
                return None
            reg = covering[0]
            backed_end = reg.start + reg.backed
            if cursor >= backed_end:
                return None
            seg_end = min(end, backed_end)
            for other in self.regions:
                if other is not reg and cursor < other.start < seg_end:
                    seg_end = other.start
            out.append(FileRange(reg.file_offset + cursor - reg.start, seg_end - cursor))
            cursor = seg_end
        return tuple(out)

    def rva_to_offset(self, rva: int) -> int | None:
        ranges = self.rva_to_file_ranges(rva, 1)
        return ranges[0].file_offset if ranges else None
