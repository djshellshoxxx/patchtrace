"""Hand-laid PE export directories for the WBQ S4 tests. Every table is placed explicitly so a test can patch
single header fields or table entries. Bytes only: nothing is executed, loaded or mapped."""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from pe_builder import RDATA, PeSpec, SectionSpec, build_pe_ex

TEXT_RVA = 0x1000   # `.text` (builder default, 64 bytes): code RVAs 0x1000..0x103F are mapped
EDATA_RVA = 0x2000  # `.edata` holds the whole export blob, which is also the data directory's range

# IMAGE_EXPORT_DIRECTORY field offsets
H_BASE, H_NFUNCS, H_NNAMES, H_AOF, H_AON, H_AOO = 16, 20, 24, 28, 32, 36


@dataclass
class ExportSpec:
    functions: list[int | str | None] = field(default_factory=list)  # code RVA, forwarder text, None = gap
    names: list[tuple[str, int]] = field(default_factory=list)  # (latin-1 name, address table index)
    base: int = 1
    pe32plus: bool = True


@dataclass(frozen=True)
class ExportLayout:
    header_rva: int
    eat_rva: int
    names_rva: int
    ords_rva: int
    size: int  # export data directory size: header, tables and every string
    file_offset: int  # file offset of RVA EDATA_RVA
    strings: dict[str, int]  # text -> RVA, for names and forwarders

    def off(self, rva: int) -> int:
        """File offset of an RVA inside the export blob."""
        return self.file_offset + rva - EDATA_RVA

    def header_field(self, offset: int) -> int:
        return self.off(self.header_rva) + offset


def build_exports(spec: ExportSpec) -> tuple[bytes, ExportLayout]:
    blob = bytearray()

    def alloc(data: bytes, alignment: int = 4) -> int:
        while len(blob) % alignment:
            blob.append(0)
        pos = len(blob)
        blob.extend(data)
        return pos

    header = alloc(b'\0' * 40)
    eat = alloc(b'\0' * (4 * len(spec.functions)))
    name_ptrs = alloc(b'\0' * (4 * len(spec.names)))
    ords = alloc(b''.join(struct.pack('<H', idx) for _name, idx in spec.names), 2)
    dll_name = alloc(b'lib.dll\0', 1)
    strings: dict[str, int] = {}
    wanted = [name for name, _idx in spec.names] + [fn for fn in spec.functions if isinstance(fn, str)]
    for text in wanted:
        if text not in strings:
            strings[text] = EDATA_RVA + alloc(text.encode('latin-1') + b'\0', 1)
    for i, fn in enumerate(spec.functions):
        struct.pack_into('<I', blob, eat + 4 * i, strings[fn] if isinstance(fn, str) else fn or 0)
    for i, (name, _idx) in enumerate(spec.names):
        struct.pack_into('<I', blob, name_ptrs + 4 * i, strings[name])
    struct.pack_into('<IIHHIIIIIII', blob, header, 0, 0x5F000000, 0, 0, EDATA_RVA + dll_name, spec.base,
                     len(spec.functions), len(spec.names), EDATA_RVA + eat, EDATA_RVA + name_ptrs,
                     EDATA_RVA + ords)
    data, info = build_pe_ex(PeSpec(
        pe32plus=spec.pe32plus, kind='dll', sections=[SectionSpec(), SectionSpec('.edata', bytes(blob), RDATA)],
        extra_directories={0: (EDATA_RVA + header, len(blob) - header)}))
    return data, ExportLayout(EDATA_RVA + header, EDATA_RVA + eat, EDATA_RVA + name_ptrs, EDATA_RVA + ords,
                              len(blob) - header, info['sections'][1][3], strings)


def patch(data: bytes, offset: int, fmt: str, *values: int) -> bytes:
    out = bytearray(data)
    struct.pack_into(fmt, out, offset, *values)
    return bytes(out)
