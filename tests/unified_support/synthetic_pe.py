"""Deterministic PE32+ fixture images, never executed or loaded as libraries.

Reuses tests/pe_builder.py for PE headers/import directories; adds function placement, accurate export RVAs
and .pdata leaf unwind extents. UNVERIFIED: loader compatibility and parser tests have not been run.
The bytes carry no Microsoft input, tool output, signatures, PDBs or downloaded data.
"""
from __future__ import annotations

import struct
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from pe_builder import CODE, RDATA, PeSpec, SectionSpec, align, build_pe_ex

FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
MAX_IMAGE_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class Function:
    name: str
    body: bytes


@dataclass(frozen=True)
class Section:
    name: str
    data: bytes
    characteristics: int = RDATA


@dataclass(frozen=True)
class Image:
    data: bytes
    functions: tuple[tuple[str, int], ...]
    sections: tuple[tuple[str, int, int, int, int], ...]

    def offset(self, rva: int) -> int:
        for _name, start, _vsize, offset, raw_size in self.sections:
            if start <= rva < start + raw_size:
                return offset + rva - start
        raise ValueError("RVA has no file backing")

    def write(self, path: Path) -> None:
        """Write a test artifact; callers must never execute it."""
        path.write_bytes(self.data)


def _name(text: str, what: str) -> None:
    if not text or not text.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in text):
        raise ValueError(f"invalid {what} name")


def build_image(
    functions: Sequence[Function],
    *,
    sections: Sequence[Section] = (),
    imports: Sequence[tuple[str, Sequence[str | int]]] = (),
    exports: Sequence[str] = (),
    prefix_padding: int = 0,
    function_alignment: int = 16,
    timestamp: int = 0,
    image_base: int = 0x180000000,
    unwind: bool = True,
) -> Image:
    """Build explicit older/newer image bytes, with no tool invocation.

    Functions are placed in input order. Bodies containing rel32/disp32 fixups must be assembled at their
    final RVAs by the caller. .pdata has a no-prologue UNWIND_INFO for every function; authors changing
    RSP or callee-saved state must supply a different fixture rather than claim these extents describe it.
    Imports are deterministic in supplied order; export names are sorted like the existing header builder.
    """
    if not 1 <= len(functions) <= 4096:
        raise ValueError("function count out of range")
    if type(prefix_padding) is not int or not 0 <= prefix_padding <= 65536:
        raise ValueError("prefix padding out of range")
    if function_alignment not in (1, 2, 4, 8, 16, 32, 64):
        raise ValueError("function alignment out of range")
    if type(timestamp) is not int or not 0 <= timestamp < 2**32:
        raise ValueError("timestamp out of range")
    if type(image_base) is not int or not 0 <= image_base < 2**64 or image_base % 65536:
        raise ValueError("image base out of range or unaligned")
    names = [f.name for f in functions]
    for name in names:
        _name(name, "function")
    if len(set(names)) != len(names):
        raise ValueError("duplicate function name")
    if len(set(exports)) != len(exports) or any(e not in names for e in exports):
        raise ValueError("duplicate or missing export")
    reserved = {".text", ".xdata", ".pdata", ".idata"}
    custom_names = [s.name for s in sections]
    if len(set(custom_names)) != len(custom_names) or reserved.intersection(custom_names):
        raise ValueError("duplicate or reserved section")
    for section in sections:
        _name(section.name, "section")
        if len(section.name) > 8 or not section.data:
            raise ValueError("section name too long or section empty")
    imported: dict[str, list[str | int]] = {}
    for dll, symbols in imports:
        _name(dll, "import DLL")
        if dll in imported or not symbols:
            raise ValueError("duplicate or empty import DLL")
        for symbol in symbols:
            if type(symbol) is int:
                if not 1 <= symbol <= 65535:
                    raise ValueError("import ordinal out of range")
            elif isinstance(symbol, str):
                _name(symbol, "import symbol")
            else:
                raise ValueError("invalid import symbol")
        imported[dll] = list(symbols)

    text = bytearray(b"\x90" * prefix_padding)
    placed: list[tuple[str, int]] = []
    ranges: list[tuple[int, int]] = []
    for function in functions:
        if not isinstance(function.body, bytes) or not function.body:
            raise ValueError("function body must be nonempty bytes")
        text.extend(b"\x90" * (align(len(text), function_alignment) - len(text)))
        start = 0x1000 + len(text)
        text.extend(function.body)
        placed.append((function.name, start))
        ranges.append((start, start + len(function.body)))
        if len(text) > MAX_IMAGE_BYTES:
            raise ValueError("image fixture cap exceeded")
    specs = [SectionSpec(".text", bytes(text), CODE)]
    specs.extend(SectionSpec(s.name, s.data, s.characteristics) for s in sections)
    directories: dict[int, tuple[int, int]] = {}
    if unwind:
        xdata_rva = 0x1000 + sum(align(max(len(s.data), 1), SECTION_ALIGNMENT) for s in specs)
        xdata = b"\x01\0\0\0" * len(ranges)
        pdata_rva = xdata_rva + align(len(xdata), SECTION_ALIGNMENT)
        pdata = b"".join(struct.pack("<III", start, end, xdata_rva + 4 * i)
                         for i, (start, end) in enumerate(ranges))
        specs.extend((SectionSpec(".xdata", xdata, RDATA), SectionSpec(".pdata", pdata, RDATA)))
        directories[3] = (pdata_rva, len(pdata))
    spec = PeSpec(pe32plus=True, kind="dll", sections=specs, imports=imported,
                  exports=("synthetic.dll", list(exports)) if exports else None,
                  timestamp=timestamp, entry_rva=0, image_base=image_base, extra_directories=directories)
    data, info = build_pe_ex(spec)
    image = Image(data, tuple(placed), tuple(info["sections"]))
    # The shared builder points every export at 0x1000; patch only this new byte buffer, never a repo fixture.
    if exports:
        buffer = bytearray(data)
        export_offset = info["export_dir_off"]
        eat_rva = struct.unpack_from("<I", buffer, export_offset + 28)[0]
        eat_offset = image.offset(eat_rva)
        addresses = dict(placed)
        for i, name in enumerate(sorted(exports)):
            struct.pack_into("<I", buffer, eat_offset + 4 * i, addresses[name])
        image = Image(bytes(buffer), image.functions, image.sections)
    if len(image.data) > MAX_IMAGE_BYTES:
        raise ValueError("image fixture cap exceeded")
    return image
