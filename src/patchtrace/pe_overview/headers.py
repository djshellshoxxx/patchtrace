"""DOS/COFF/optional header parsing with explicit truncation handling."""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ._common import Ctx
from .directories import parse_directories
from .models import ChecksumInfo, CodeLabel, CoffTimestamp, PeKind

MACHINES = {
    0x0: 'UNKNOWN', 0x14C: 'I386', 0x166: 'R4000', 0x1C0: 'ARM', 0x1C4: 'ARMNT', 0x200: 'IA64',
    0x266: 'MIPS16', 0x366: 'MIPSFPU', 0x5032: 'RISCV32', 0x5064: 'RISCV64', 0x6232: 'LOONGARCH32',
    0x6264: 'LOONGARCH64', 0x8664: 'AMD64', 0xAA64: 'ARM64', 0xA641: 'ARM64EC', 0xEBC: 'EBC',
}
SUBSYSTEMS = {
    0: 'UNKNOWN', 1: 'NATIVE', 2: 'WINDOWS_GUI', 3: 'WINDOWS_CUI', 5: 'OS2_CUI', 7: 'POSIX_CUI',
    8: 'NATIVE_WINDOWS', 9: 'WINDOWS_CE_GUI', 10: 'EFI_APPLICATION', 11: 'EFI_BOOT_SERVICE_DRIVER',
    12: 'EFI_RUNTIME_DRIVER', 13: 'EFI_ROM', 14: 'XBOX', 16: 'WINDOWS_BOOT_APPLICATION',
}
CHARACTERISTICS = {
    0x1: 'RELOCS_STRIPPED', 0x2: 'EXECUTABLE_IMAGE', 0x4: 'LINE_NUMS_STRIPPED',
    0x8: 'LOCAL_SYMS_STRIPPED', 0x10: 'AGGRESSIVE_WS_TRIM', 0x20: 'LARGE_ADDRESS_AWARE',
    0x80: 'BYTES_REVERSED_LO', 0x100: '32BIT_MACHINE', 0x200: 'DEBUG_STRIPPED',
    0x400: 'REMOVABLE_RUN_FROM_SWAP', 0x800: 'NET_RUN_FROM_SWAP', 0x1000: 'SYSTEM', 0x2000: 'DLL',
    0x4000: 'UP_SYSTEM_ONLY', 0x8000: 'BYTES_REVERSED_HI',
}
DLL_CHARACTERISTICS = {
    0x20: 'HIGH_ENTROPY_VA', 0x40: 'DYNAMIC_BASE', 0x80: 'FORCE_INTEGRITY', 0x100: 'NX_COMPAT',
    0x200: 'NO_ISOLATION', 0x400: 'NO_SEH', 0x800: 'NO_BIND', 0x1000: 'APPCONTAINER',
    0x2000: 'WDM_DRIVER', 0x4000: 'GUARD_CF', 0x8000: 'TERMINAL_SERVER_AWARE',
}
IMAGE_FILE_DLL = 0x2000
IMAGE_FILE_EXECUTABLE_IMAGE = 0x2
SUBSYSTEM_NATIVE = 1


def flag_names(value: int, table: dict[int, str]) -> tuple[str, ...]:
    return tuple(name for bit, name in table.items() if value & bit)


@dataclass(slots=True)
class HeaderState:
    """Parsed header results plus the offsets later stages need."""

    fields: dict[str, Any] = field(default_factory=dict)
    status: str = 'ok'  # ok | partial | not_pe
    e_lfanew: int = 0
    opt_offset: int = 0
    checksum_offset: int | None = None
    stored_checksum: int | None = None
    section_table_offset: int = 0
    section_count: int = 0
    directories: tuple = ()
    opt_present: bool = False


def classify_kind(characteristics: int, subsystem: int | None) -> PeKind:
    if characteristics & IMAGE_FILE_DLL:
        extra = ' with NATIVE subsystem' if subsystem == SUBSYSTEM_NATIVE else ''
        return PeKind('DLL', f'IMAGE_FILE_DLL characteristic set{extra}')
    if subsystem == SUBSYSTEM_NATIVE:
        return PeKind('SYS', 'NATIVE subsystem without IMAGE_FILE_DLL (typical of kernel drivers; heuristic)')
    if characteristics & IMAGE_FILE_EXECUTABLE_IMAGE:
        return PeKind('EXE', 'IMAGE_FILE_EXECUTABLE_IMAGE set without IMAGE_FILE_DLL')
    return PeKind('unknown', 'no DLL flag, no NATIVE subsystem and EXECUTABLE_IMAGE not set')


def _iso(ts: int) -> str | None:
    if ts == 0:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=UTC).strftime('%Y-%m-%dT%H:%M:%SZ')
    except (OverflowError, OSError, ValueError):
        return None


def parse_headers(ctx: Ctx) -> HeaderState:
    st = HeaderState()
    size = ctx.reader.size
    lim = ctx.limits
    head = ctx.read(0, 64)
    st.fields['header_magic'] = head[:16].hex() if head else None
    if len(head) < 2 or head[:2] != b'MZ':
        st.status = 'not_pe'
        ctx.warn('not_mz', 'file does not start with the MZ signature')
        return st
    if len(head) < 64:
        st.status = 'partial'
        ctx.warn('too_short', 'file is shorter than the 64-byte DOS header')
        return st
    e_lfanew = struct.unpack_from('<I', head, 0x3C)[0]
    st.e_lfanew = e_lfanew
    if e_lfanew > lim.max_lfanew:
        st.status = 'partial'
        ctx.warn('lfanew_over_cap', f'e_lfanew {e_lfanew:#x} exceeds the {lim.max_lfanew:#x} cap')
        return st
    if e_lfanew + 4 > size:
        st.status = 'partial'
        ctx.warn('lfanew_out_of_range', f'e_lfanew {e_lfanew:#x} points beyond the end of the file')
        return st
    sig = ctx.read(e_lfanew, 4)
    if sig != b'PE\0\0':
        st.status = 'not_pe'
        ctx.warn('pe_signature_missing', 'PE\\0\\0 signature not found at e_lfanew')
        return st
    ctx.check()
    coff = ctx.read(e_lfanew + 4, 20)
    if len(coff) < 20:
        st.status = 'partial'
        ctx.warn('coff_truncated', 'COFF file header is truncated')
        return st
    machine, nsec, ts, _symptr, _nsyms, opt_size, chars = struct.unpack('<HHIIIHH', coff)
    f = st.fields
    f['machine'] = CodeLabel(machine, MACHINES.get(machine, f'UNKNOWN_{machine:#06x}'))
    f['coff_timestamp'] = CoffTimestamp(ts, _iso(ts))
    f['characteristics'] = flag_names(chars, CHARACTERISTICS)
    st.section_count = nsec
    st.opt_offset = e_lfanew + 24
    st.section_table_offset = st.opt_offset + opt_size
    subsystem: int | None = None
    if opt_size == 0:
        st.status = 'partial'
        ctx.warn('optional_header_truncated', 'optional header is absent (SizeOfOptionalHeader is 0)')
    else:
        subsystem = _parse_optional(ctx, st, opt_size)
    f['pe_kind'] = classify_kind(chars, subsystem)
    return st


def _parse_optional(ctx: Ctx, st: HeaderState, opt_size: int) -> int | None:
    lim = ctx.limits
    f = st.fields
    opt = ctx.read(st.opt_offset, min(opt_size, 1024))
    avail = len(opt)

    def get(fmt: str, off: int) -> int | None:
        n = struct.calcsize(fmt)
        return struct.unpack_from(fmt, opt, off)[0] if off + n <= avail else None

    magic = get('<H', 0)
    if magic not in (0x10B, 0x20B):
        st.status = 'partial'
        if magic is None:
            ctx.warn('optional_header_truncated', 'optional header could not be read')
        else:
            ctx.warn('optional_magic_unknown', f'unsupported optional header magic {magic:#06x}')
        return None
    st.opt_present = True
    plus = magic == 0x20B
    f['optional_magic'] = 'PE32+' if plus else 'PE32'
    rva = get('<I', 16)
    base = get('<Q', 24) if plus else get('<I', 28)
    f['entrypoint_rva'] = rva
    f['image_base'] = base
    f['entrypoint_va'] = base + rva if rva is not None and base is not None else None
    f['section_alignment'] = get('<I', 32)
    f['file_alignment'] = get('<I', 36)
    f['size_of_image'] = get('<I', 56)
    f['size_of_headers'] = get('<I', 60)
    stored = get('<I', 64)
    subsystem = get('<H', 68)
    dllc = get('<H', 70)
    if subsystem is not None:
        f['subsystem'] = CodeLabel(subsystem, SUBSYSTEMS.get(subsystem, f'UNKNOWN_{subsystem}'))
    if dllc is not None:
        f['dll_characteristics'] = flag_names(dllc, DLL_CHARACTERISTICS)
    if stored is not None:
        st.stored_checksum = stored
        st.checksum_offset = st.opt_offset + 64
    count_off = 108 if plus else 92
    ndirs = get('<I', count_off)
    if ndirs is None:
        st.status = 'partial'
        ctx.warn('optional_header_truncated', 'optional header ends before the data directory count')
    else:
        dir_off = count_off + 4
        if ndirs > lim.max_data_directories:
            ctx.warn('directories_over_cap', f'{ndirs} data directories declared; reading {lim.max_data_directories}')
            st.status = 'partial'
        usable = max(0, min(ndirs, lim.max_data_directories, (min(opt_size, avail) - dir_off) // 8))
        if usable < min(ndirs, lim.max_data_directories):
            st.status = 'partial'
            ctx.warn('optional_header_truncated', 'optional header ends inside the data directories')
        raw = []
        for i in range(usable):
            raw.append(struct.unpack_from('<II', opt, dir_off + i * 8))
        st.directories = tuple(raw)
        f['data_directories'] = parse_directories(raw)
    if stored is None or any(f.get(k) is None for k in ('size_of_headers', 'subsystem')):
        st.status = 'partial'
        ctx.warn('optional_header_truncated', 'optional header ends before the standard windows fields')
    return subsystem


def build_checksum(stored: int | None, computed: int | None) -> ChecksumInfo | None:
    if stored is None:
        return None
    return ChecksumInfo(stored, computed, None if computed is None else stored == computed)
