"""Synthetic PE image builder for tests (PE32+ AMD64 and PE32 i386). Never executed; bytes only."""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000
CODE = 0x60000020
DATA = 0xC0000040
RDATA = 0x40000040


def align(value: int, to: int) -> int:
    return (value + to - 1) // to * to


@dataclass
class SectionSpec:
    name: str = '.text'
    data: bytes = b'\x90' * 64
    characteristics: int = CODE
    virtual_size: int | None = None
    raw_size: int | None = None  # defaults to file-aligned len(data); 0 gives a virtual-only section


@dataclass
class PeSpec:
    pe32plus: bool = True
    kind: str = 'exe'  # exe | dll | sys
    sections: list[SectionSpec] = field(default_factory=lambda: [SectionSpec()])
    imports: dict[str, list[str | int]] = field(default_factory=dict)
    exports: tuple[str, list[str]] | None = None
    rsds: tuple[bytes, int, str] | None = None  # (16 byte guid, age, pdb path)
    overlay: bytes = b''
    cert_payloads: list[bytes] = field(default_factory=list)
    timestamp: int = 0x5F000000
    checksum: int = 0
    entry_rva: int | None = None
    image_base: int | None = None
    e_lfanew: int = 0x80
    extra_directories: dict[int, tuple[int, int]] = field(default_factory=dict)
    meta_name: str = '.idata'


def build_pe(spec: PeSpec | None = None, **kw) -> bytes:
    return build_pe_ex(spec or PeSpec(**kw))[0]


def _meta_blob(spec: PeSpec, base_rva: int, base_off: int):
    plus = spec.pe32plus
    esize = 8 if plus else 4
    blob = bytearray()

    def alloc(data: bytes, alignment: int = 4) -> int:
        while len(blob) % alignment:
            blob.append(0)
        pos = len(blob)
        blob.extend(data)
        return pos

    dirs: dict[int, tuple[int, int]] = {}
    info: dict[str, int] = {}
    desc_pos = None
    if spec.imports:
        desc_pos = alloc(b'\0' * ((len(spec.imports) + 1) * 20))
        dirs[1] = (base_rva + desc_pos, (len(spec.imports) + 1) * 20)
        info['import_desc_off'] = base_off + desc_pos
    if spec.exports:
        dll, names = spec.exports
        names = sorted(names)
        n = len(names)
        edir = alloc(b'\0' * 40)
        funcs = alloc(b''.join(struct.pack('<I', 0x1000) for _ in names))
        nameptrs = alloc(b'\0' * (4 * n))
        ords = alloc(b''.join(struct.pack('<H', i) for i in range(n)), 2)
        dll_pos = alloc(dll.encode() + b'\0', 1)
        for i, nm in enumerate(names):
            p = alloc(nm.encode() + b'\0', 1)
            struct.pack_into('<I', blob, nameptrs + 4 * i, base_rva + p)
        struct.pack_into('<IIHHIIIIIII', blob, edir, 0, spec.timestamp, 0, 0, base_rva + dll_pos, 1, n, n,
                         base_rva + funcs, base_rva + nameptrs, base_rva + ords)
        dirs[0] = (base_rva + edir, 40 + 4 * n * 2 + 2 * n)
        info['export_dir_off'] = base_off + edir
    for i, (dll, funcs) in enumerate(spec.imports.items()):
        thunk = alloc(b'\0' * (esize * (len(funcs) + 1)), 8)
        for j, f in enumerate(funcs):
            if isinstance(f, int):
                val = f | (1 << (63 if plus else 31))
            else:
                val = base_rva + alloc(b'\0\0' + f.encode() + b'\0', 2)
            struct.pack_into('<Q' if plus else '<I', blob, thunk + j * esize, val)
        name = alloc(dll.encode() + b'\0', 1)
        struct.pack_into('<IIIII', blob, desc_pos + i * 20, base_rva + thunk, 0, 0, base_rva + name,
                         base_rva + thunk)
        info.setdefault('first_thunk_off', base_off + thunk)
    if spec.rsds:
        guid, age, path = spec.rsds
        payload = b'RSDS' + guid + struct.pack('<I', age) + path.encode() + b'\0'
        entry = alloc(b'\0' * 28)
        data = alloc(payload)
        struct.pack_into('<IIHHIIII', blob, entry, 0, spec.timestamp, 0, 0, 2, len(payload),
                         base_rva + data, base_off + data)
        dirs[6] = (base_rva + entry, 28)
        info['rsds_off'] = base_off + data
    return bytes(blob), dirs, info


def build_pe_ex(spec: PeSpec) -> tuple[bytes, dict]:
    plus = spec.pe32plus
    opt_size = 240 if plus else 224
    sections = list(spec.sections)
    has_meta = bool(spec.imports or spec.exports or spec.rsds)
    if has_meta:
        sections.append(SectionSpec(spec.meta_name, b'', RDATA))
    nsec = len(sections)
    headers_end = spec.e_lfanew + 24 + opt_size + 40 * nsec
    size_of_headers = align(headers_end, FILE_ALIGN)

    # layout pass
    meta_len = len(_meta_blob(spec, 0, 0)[0]) if has_meta else 0
    placed = []
    rva = SECTION_ALIGN
    off = size_of_headers
    for i, s in enumerate(sections):
        data = s.data
        meta_index = has_meta and i == nsec - 1
        if meta_index:
            data = b'\0' * meta_len
        raw_size = s.raw_size if s.raw_size is not None else align(len(data), FILE_ALIGN)
        vsize = s.virtual_size if s.virtual_size is not None else len(data)
        placed.append((s, data, rva, vsize, off if raw_size else 0, raw_size))
        rva += align(max(vsize, 1), SECTION_ALIGN)
        off += raw_size
    size_of_image = rva
    dirs: dict[int, tuple[int, int]] = {}
    info: dict = {}
    if has_meta:
        s, _d, mrva, mvs, moff, mraw = placed[-1]
        blob, dirs, info = _meta_blob(spec, mrva, moff)
        placed[-1] = (s, blob.ljust(mraw, b'\0'), mrva, mvs, moff, mraw)
    body_end = off
    cert_off = 0
    cert_blob = b''
    overlay_off = body_end
    pos = body_end + len(spec.overlay)
    if spec.cert_payloads:
        cert_off = align(pos, 8)
        parts = []
        for payload in spec.cert_payloads:
            length = 8 + len(payload)
            parts.append(struct.pack('<IHH', length, 0x200, 2) + payload + b'\0' * (align(length, 8) - length))
        cert_blob = b''.join(parts)
        dirs[4] = (cert_off, len(cert_blob))
    dirs.update(spec.extra_directories)

    out = bytearray(b'\0' * size_of_headers)
    out[0:2] = b'MZ'
    struct.pack_into('<I', out, 0x3C, spec.e_lfanew)
    e = spec.e_lfanew
    out[e:e + 4] = b'PE\0\0'
    machine = 0x8664 if plus else 0x14C
    chars = 0x22 if plus else 0x102 | 0x2
    if spec.kind == 'dll':
        chars |= 0x2000
    struct.pack_into('<HHIIIHH', out, e + 4, machine, nsec, spec.timestamp, 0, 0, opt_size, chars)
    o = e + 24
    entry = spec.entry_rva if spec.entry_rva is not None else SECTION_ALIGN
    base = spec.image_base if spec.image_base is not None else (0x140000000 if plus else 0x400000)
    subsystem = {'exe': 3, 'dll': 2, 'sys': 1}[spec.kind]
    struct.pack_into('<HBBIII', out, o, 0x20B if plus else 0x10B, 14, 0, 0x200, 0, 0)
    struct.pack_into('<I', out, o + 16, entry)
    struct.pack_into('<I', out, o + 20, SECTION_ALIGN)
    if plus:
        struct.pack_into('<Q', out, o + 24, base)
    else:
        struct.pack_into('<I', out, o + 24, SECTION_ALIGN)
        struct.pack_into('<I', out, o + 28, base)
    struct.pack_into('<II', out, o + 32, SECTION_ALIGN, FILE_ALIGN)
    struct.pack_into('<IIII', out, o + 56 - 0, size_of_image, size_of_headers, spec.checksum,
                     subsystem | (0x8160 << 16))
    count_off = o + (108 if plus else 92)
    struct.pack_into('<I', out, count_off, 16)
    for idx, (r, sz) in dirs.items():
        struct.pack_into('<II', out, count_off + 4 + idx * 8, r, sz)
    sec_table = o + opt_size
    for i, (s, _data, srva, vsize, soff, rsize) in enumerate(placed):
        name = s.name.encode('latin-1')[:8].ljust(8, b'\0')
        struct.pack_into('<8sIIIIIIHHI', out, sec_table + i * 40, name, vsize, srva, rsize, soff, 0, 0, 0, 0,
                         s.characteristics)
    for _s, data, _r, _v, soff, rsize in placed:
        if rsize:
            out.extend(b'\0' * (soff - len(out)))
            out.extend(data[:rsize].ljust(rsize, b'\0'))
    out.extend(spec.overlay)
    if cert_blob:
        out.extend(b'\0' * (cert_off - len(out)))
        out.extend(cert_blob)
    info.update(
        e_lfanew=e, opt_off=o, checksum_off=o + 64, dir_off=count_off + 4, section_table_off=sec_table,
        size_of_headers=size_of_headers, size_of_image=size_of_image, overlay_off=overlay_off,
        cert_off=cert_off, cert_len=len(cert_blob), size=len(out),
        sections=[(s.name, srva, vsize, soff, rsize) for s, _d, srva, vsize, soff, rsize in placed],
    )
    return bytes(out), info
