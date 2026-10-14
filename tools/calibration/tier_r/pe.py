"""Minimal, bounded PE32+ reader for the factory: headers, sections, RVA reads, base relocations, image comparison.

Pure stdlib; reads files only (images are never executed). Fails closed on anything malformed.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

MAX_IMAGE = 64 * 1024 * 1024
MAX_SECTIONS = 96
IMAGE_FILE_MACHINE_AMD64 = 0x8664


class PEError(ValueError):
    pass


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def is_code(self) -> bool:
        return bool(self.characteristics & 0x20000020)   # CNT_CODE | MEM_EXECUTE

    @property
    def is_discardable(self) -> bool:
        return bool(self.characteristics & 0x02000000)


@dataclass(frozen=True)
class PEImage:
    path: Path
    data: bytes
    machine: int
    timestamp: int
    image_base: int
    size_of_image: int
    sections: tuple[Section, ...]
    directories: tuple[tuple[int, int], ...]
    symtab_offset: int
    symbol_count: int

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    def section_for(self, rva: int) -> Section | None:
        for s in self.sections:
            if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
                return s
        return None

    def read(self, rva: int, size: int) -> bytes:
        """Bytes [rva, rva+size) from one section; uninitialised tail reads as zeros."""
        if size < 0 or size > MAX_IMAGE:
            raise PEError('bad read size')
        sec = self.section_for(rva)
        if sec is None or rva + size > sec.virtual_address + max(sec.virtual_size, sec.raw_size):
            raise PEError(f'rva {rva:#x}+{size} is outside every section')
        start = rva - sec.virtual_address
        chunk = self.data[sec.raw_offset + start:sec.raw_offset + min(start + size, sec.raw_size)]
        return chunk + b'\0' * (size - len(chunk))

    def base_relocations(self) -> frozenset[int]:
        """RVAs of IMAGE_REL_BASED_DIR64 (and HIGHLOW) fix-ups from the base relocation directory."""
        if len(self.directories) <= 5:
            return frozenset()
        rva, size = self.directories[5]
        if not rva or not size:
            return frozenset()
        blob = self.read(rva, size)
        out, pos = set(), 0
        while pos + 8 <= len(blob):
            page, block = struct.unpack_from('<II', blob, pos)
            if block < 8 or pos + block > len(blob):
                break
            for k in range(pos + 8, pos + block - 1, 2):
                (entry,) = struct.unpack_from('<H', blob, k)
                kind, offset = entry >> 12, entry & 0xFFF
                if kind in (3, 10):
                    out.add(page + offset)
            pos += block
        return frozenset(out)


def read_pe(path: Path | str) -> PEImage:
    path = Path(path)
    size = path.stat().st_size
    if size > MAX_IMAGE:
        raise PEError('image larger than 64 MiB')
    data = path.read_bytes()
    return parse_pe(data, path)


def parse_pe(data: bytes, path: Path = Path('<memory>')) -> PEImage:
    if len(data) < 0x40 or data[:2] != b'MZ':
        raise PEError('not an MZ image')
    (lfanew,) = struct.unpack_from('<I', data, 0x3C)
    if lfanew + 24 > len(data) or data[lfanew:lfanew + 4] != b'PE\0\0':
        raise PEError('missing PE signature')
    machine, nsec, timestamp, symptr, nsym, opt_size, _chars = struct.unpack_from('<HHIIIHH', data, lfanew + 4)
    if nsec > MAX_SECTIONS:
        raise PEError('too many sections')
    opt = lfanew + 24
    if opt + opt_size > len(data) or opt_size < 112:
        raise PEError('truncated optional header')
    (magic,) = struct.unpack_from('<H', data, opt)
    if magic != 0x20B:
        raise PEError('not PE32+ (x64)')
    (image_base,) = struct.unpack_from('<Q', data, opt + 24)
    (size_of_image,) = struct.unpack_from('<I', data, opt + 56)
    (ndirs,) = struct.unpack_from('<I', data, opt + 108)
    ndirs = min(ndirs, 16, max(0, (opt_size - 112) // 8))
    dirs = tuple(struct.unpack_from('<II', data, opt + 112 + 8 * k) for k in range(ndirs))
    table = opt + opt_size
    if table + 40 * nsec > len(data):
        raise PEError('truncated section table')
    strtab = symptr + 18 * nsym if symptr else 0
    sections = []
    for k in range(nsec):
        raw = data[table + 40 * k:table + 40 * (k + 1)]
        name = raw[:8].rstrip(b'\0').decode('latin-1')
        if name.startswith('/') and name[1:].isdigit() and strtab:   # long name in the COFF string table
            at = strtab + int(name[1:])
            end = data.find(b'\0', at)
            if 0 <= at < len(data) and end > at:
                name = data[at:end].decode('latin-1')
        vsize, va, rsize, roff = struct.unpack_from('<IIII', raw, 8)
        (chars,) = struct.unpack_from('<I', raw, 36)
        if roff + rsize > len(data) and rsize:
            raise PEError(f'section {name} raw data outside the file')
        sections.append(Section(name, va, vsize, roff, rsize, chars))
    return PEImage(path, data, machine, timestamp, image_base, size_of_image, tuple(sections), dirs, symptr, nsym)


def loaded_view(img: PEImage) -> dict[str, tuple[int, bytes]]:
    """Section name -> (rva, bytes) for every non-discardable section: what an engine sees at run time.

    The debug directory's PointerToRawData fields are FILE offsets that a strip legitimately rewrites when it re-lays
    out the file; they are zeroed so that only run-time-visible content is compared."""
    view = {}
    masks: list[int] = []
    if len(img.directories) > 6 and img.directories[6][0] and img.directories[6][1]:
        rva, size = img.directories[6]
        masks = [rva + 28 * k + 24 for k in range(size // 28)]
    for s in img.sections:
        if s.is_discardable or s.name.startswith('.debug'):
            continue
        data = bytearray(img.data[s.raw_offset:s.raw_offset + min(s.raw_size, s.virtual_size or s.raw_size)])
        for at in masks:
            off = at - s.virtual_address
            if 0 <= off <= len(data) - 4:
                data[off:off + 4] = b'\0\0\0\0'
        view[s.name] = (s.virtual_address, bytes(data))
    return view


def compare_images(a: PEImage, b: PEImage) -> tuple[bool, tuple[str, ...], int]:
    """(byte_identical, differing section names (+'headers'), differing byte count) for reproducibility reports."""
    if a.data == b.data:
        return True, (), 0
    names: list[str] = []
    total = 0
    head = min(len(a.data), len(b.data), 0x1000)
    diff = sum(1 for x, y in zip(a.data[:head], b.data[:head], strict=True) if x != y)
    if diff:
        names.append('headers')
        total += diff
    sa = {s.name: s for s in a.sections}
    sb = {s.name: s for s in b.sections}
    for name in sorted(set(sa) | set(sb)):
        if name not in sa or name not in sb:
            names.append(name)
            total += (sa.get(name) or sb[name]).raw_size
            continue
        x = a.data[sa[name].raw_offset:sa[name].raw_offset + sa[name].raw_size]
        y = b.data[sb[name].raw_offset:sb[name].raw_offset + sb[name].raw_size]
        if x != y or sa[name].virtual_address != sb[name].virtual_address:
            names.append(name)
            total += sum(1 for p, q in zip(x, y, strict=False) if p != q) + abs(len(x) - len(y))
    tail = len(a.data) != len(b.data)
    if tail and 'size' not in names:
        names.append('file-size')
    return False, tuple(names), total
