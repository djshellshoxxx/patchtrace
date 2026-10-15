"""Synthetic PEs with controlled build-environment fields (Rich header, version fields, debug, LoadConfig, CLR).

Bytes only, never executed. Built on `pe_builder`, then patched in place so the layout stays the builder's.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from pe_builder import DATA, PeSpec, SectionSpec, build_pe_ex

RICH_AT = 0x80
E_LFANEW = 0x100
MSVC_RICH = [(0x0105, 33134, 12), (0x0104, 33134, 9), (0x0103, 33134, 3), (0x0001, 0, 41), (0x0101, 33134, 4)]
AUX_RVA = 0x2000
DEBUG_AT, CONFIG_AT, CLR_AT, META_AT = 0, 0x100, 0x300, 0x400


def _rol(value: int, count: int) -> int:
    count &= 31
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF if count else value


def rich_bytes(dos: bytes, entries: list[tuple[int, int, int]], *, key: int | None = None) -> bytes:
    """DanS + 3 padding words + entries + Rich + key; `key` overrides the checksum to forge a failed one."""
    checksum = len(dos)
    for index, byte in enumerate(dos):
        if not 0x3C <= index <= 0x3F:
            checksum = (checksum + _rol(byte, index)) & 0xFFFFFFFF
    for product, build, count in entries:
        checksum = (checksum + _rol((product << 16) | build, count)) & 0xFFFFFFFF
    key = checksum if key is None else key
    out = struct.pack('<4I', 0x536E6144 ^ key, key, key, key)
    for product, build, count in entries:
        out += struct.pack('<II', ((product << 16) | build) ^ key, count ^ key)
    return out + b'Rich' + struct.pack('<I', key)


@dataclass
class BuildSpec:
    rich: list[tuple[int, int, int]] | None = None
    rich_key: int | None = None
    linker: tuple[int, int] = (14, 36)
    os_version: tuple[int, int] = (6, 0)
    image_version: tuple[int, int] = (0, 0)
    subsystem_version: tuple[int, int] = (6, 0)
    pe32plus: bool = True
    imports: dict[str, list[str | int]] | None = None
    debug_types: tuple[int, ...] = ()
    load_config: tuple[int, int] | None = None  # (security cookie, guard flags)
    load_config_size: int | None = None
    clr_flags: int | None = None
    clr_native_header: bool = False
    clr_version: bytes = b'v4.0.30319\0\0'
    overlay: bytes = b''


def _debug_blob(types: tuple[int, ...]) -> bytes:
    return b''.join(struct.pack('<IIHHIIII', 0, 0, 0, 0, t, 0, 0, 0) for t in types)


def _config_blob(spec: BuildSpec) -> bytes:
    cookie, flags = spec.load_config or (0, 0)
    blob = bytearray(160)
    cookie_at, width, flags_at = (88, 8, 144) if spec.pe32plus else (60, 4, 88)
    struct.pack_into('<Q' if width == 8 else '<I', blob, cookie_at, cookie)
    struct.pack_into('<I', blob, flags_at, flags)
    size = spec.load_config_size if spec.load_config_size is not None else (0x94 if spec.pe32plus else 0x5C)
    struct.pack_into('<I', blob, 0, size)
    return bytes(blob)


def _clr_blob(spec: BuildSpec) -> tuple[bytes, bytes]:
    meta = b'BSJB' + struct.pack('<HHII', 1, 1, 0, len(spec.clr_version)) + spec.clr_version
    native = (0x2000, 8) if spec.clr_native_header else (0, 0)
    hdr = struct.pack('<IHHIIIIII', 72, 2, 5, AUX_RVA + META_AT, len(meta), spec.clr_flags or 0, 0, 0, 0)
    hdr += b'\0' * 32 + struct.pack('<II', *native)
    return hdr.ljust(72, b'\0'), meta


def build_with_facts(spec: BuildSpec | None = None) -> bytes:
    spec = spec or BuildSpec()
    aux = bytearray(0x600)
    dirs: dict[int, tuple[int, int]] = {}
    if spec.debug_types:
        aux[DEBUG_AT:DEBUG_AT + 28 * len(spec.debug_types)] = _debug_blob(spec.debug_types)
        dirs[6] = (AUX_RVA + DEBUG_AT, 28 * len(spec.debug_types))
    if spec.load_config is not None:
        aux[CONFIG_AT:CONFIG_AT + 160] = _config_blob(spec)
        dirs[10] = (AUX_RVA + CONFIG_AT, 160)
    if spec.clr_flags is not None:
        hdr, meta = _clr_blob(spec)
        aux[CLR_AT:CLR_AT + 72] = hdr
        aux[META_AT:META_AT + len(meta)] = meta
        dirs[14] = (AUX_RVA + CLR_AT, 72)
    e_lfanew = max(E_LFANEW, (RICH_AT + 24 + 8 * len(spec.rich or ()) + 7) // 8 * 8)
    pe = PeSpec(pe32plus=spec.pe32plus, e_lfanew=e_lfanew, extra_directories=dirs, overlay=spec.overlay,
                imports=spec.imports or {}, sections=[SectionSpec(), SectionSpec('.aux', bytes(aux), DATA)])
    data, info = build_pe_ex(pe)
    out = bytearray(data)
    o = info['opt_off']
    out[o + 2:o + 4] = bytes(spec.linker)
    struct.pack_into('<HHHHHH', out, o + 40, *spec.os_version, *spec.image_version, *spec.subsystem_version)
    if spec.rich is not None:
        blob = rich_bytes(bytes(out[:RICH_AT]), spec.rich, key=spec.rich_key)
        out[RICH_AT:RICH_AT + len(blob)] = blob
    return bytes(out)
