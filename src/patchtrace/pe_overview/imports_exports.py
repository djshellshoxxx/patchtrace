"""Bounded import and export directory parsing driven by the section map."""
from __future__ import annotations

import struct

from ._common import Ctx
from .models import ExportsInfo, ImportDll, ImportsInfo, SectionMap


def _span(smap: SectionMap, rva: int, length: int) -> int | None:
    """File offset of `length` bytes at `rva`, only if the whole span is one contiguous backed range."""
    ranges = smap.rva_to_file_ranges(rva, length)
    if ranges and len(ranges) == 1 and ranges[0].length == length:
        return ranges[0].file_offset
    return None


def _readable(smap: SectionMap, rva: int, want: int) -> int:
    """Largest n <= want such that [rva, rva+n) is contiguously backed (0 if none)."""
    if _span(smap, rva, want) is not None:
        return want
    low, high = 0, want - 1
    while low < high:
        mid = (low + high + 1) // 2
        if _span(smap, rva, mid) is not None:
            low = mid
        else:
            high = mid - 1
    return low


def _name_at(ctx: Ctx, smap: SectionMap, rva: int) -> tuple[str, bool] | None:
    if rva == 0:                                    # RVA 0 is the DOS header, never a name (issue #105 BUG-PE-2)
        return None
    available = _readable(smap, rva, ctx.limits.max_name_length + 1)
    if not available:
        return None
    return ctx.cstring(_span(smap, rva, available), available)


def _read_span(ctx: Ctx, smap: SectionMap, rva: int, length: int) -> bytes:
    off = _span(smap, rva, length)
    return ctx.read(off, length) if off is not None else b''


def parse_imports(ctx: Ctx, smap: SectionMap, rva: int, plus: bool) -> ImportsInfo | None:
    lim = ctx.limits
    entry = 8 if plus else 4
    ordinal_flag = 1 << (63 if plus else 31)
    dlls: list[ImportDll] = []
    total_funcs = 0
    total_dlls = 0
    truncated = False
    seen_desc: set[tuple[int, int, int]] = set()
    index = 0
    while True:
        ctx.check()
        if index >= lim.max_import_dlls:
            ctx.warn('import_dlls_over_cap', f'more than {lim.max_import_dlls} import descriptors; stopped')
            truncated = True
            break
        raw = _read_span(ctx, smap, rva + index * 20, 20)
        if len(raw) < 20:
            ctx.warn('import_rva_out_of_file', 'import descriptor table is not (fully) backed by file data')
            if index == 0:
                return None
            truncated = True
            break
        oft, _ts, _fwd, name_rva, ft = struct.unpack('<IIIII', raw)
        if raw == b'\0' * 20:
            break
        key = (oft, name_rva, ft)
        if key in seen_desc:
            ctx.warn('import_descriptor_loop', 'repeated import descriptor; stopped to avoid a loop')
            truncated = True
            break
        seen_desc.add(key)
        index += 1
        total_dlls += 1
        named = _name_at(ctx, smap, name_rva)
        if named is None:
            ctx.warn('import_rva_out_of_file', 'an import DLL name RVA is not backed by file data')
            dll_name = f'<unreadable name @ {name_rva:#x}>'
        else:
            dll_name = named[0]
        funcs: list[str] = []
        count = 0
        dll_trunc = False
        thunk_rva = oft or ft
        seen_names: set[int] = set()
        while thunk_rva:
            ctx.check()
            if count >= lim.max_functions_per_dll:
                ctx.warn('import_functions_over_cap', f'more than {lim.max_functions_per_dll} imports from one DLL')
                dll_trunc = True
                break
            if total_funcs >= lim.max_total_names:
                ctx.warn('import_names_over_cap', f'more than {lim.max_total_names} imported names in total')
                dll_trunc = truncated = True
                break
            traw = _read_span(ctx, smap, thunk_rva + count * entry, entry)
            if len(traw) < entry:
                ctx.warn('import_rva_out_of_file', 'an import thunk table is not backed by file data')
                dll_trunc = True
                break
            value = struct.unpack('<Q' if plus else '<I', traw)[0]
            if value == 0:
                break
            if value & ordinal_flag:
                funcs.append(f'#{value & 0xFFFF}')
            elif value >> 31:
                # PE32+ requires bits 62..31 of a by-name thunk to be zero; masking would show another RVA's name.
                ctx.warn('import_thunk_reserved_bits', f'import thunk {value:#x} has reserved high bits set')
                funcs.append(f'<invalid thunk {value:#x}>')
                dll_trunc = True
                break
            else:
                name_ptr = value
                if name_ptr in seen_names:
                    ctx.warn('import_name_pointer_loop', 'repeated import name pointer; stopped')
                    dll_trunc = True
                    break
                seen_names.add(name_ptr)
                fname = _name_at(ctx, smap, name_ptr + 2)
                funcs.append(fname[0] if fname else f'<unreadable @ {name_ptr:#x}>')
                if fname is None:
                    ctx.warn('import_rva_out_of_file', 'an import name RVA is not backed by file data')
            count += 1
            total_funcs += 1
        dlls.append(ImportDll(dll_name, tuple(funcs), count, dll_trunc))
        if total_funcs >= lim.max_total_names and dll_trunc:
            break
    return ImportsInfo(tuple(dlls), total_dlls, total_funcs, truncated or any(d.truncated for d in dlls))


def parse_exports(ctx: Ctx, smap: SectionMap, rva: int) -> ExportsInfo | None:
    lim = ctx.limits
    raw = _read_span(ctx, smap, rva, 40)
    if len(raw) < 40:
        ctx.warn('export_rva_out_of_file', 'export directory is not backed by file data')
        return None
    name_rva, _base, nfuncs, nnames, _aof, aon, _aoo = struct.unpack_from('<IIIIIII', raw, 12)
    dll_name = None
    named = _name_at(ctx, smap, name_rva) if name_rva else None
    if named:
        dll_name = named[0]
    if nfuncs > max(lim.max_export_names, ctx.reader.size // 4) or nnames > nfuncs and nfuncs:
        ctx.warn('export_count_implausible', f'export counts ({nfuncs} functions, {nnames} names) are implausible')
    to_read = min(nnames, lim.max_export_names)
    truncated = nnames > to_read
    if truncated:
        ctx.warn('export_names_over_cap', f'{nnames} export names declared; reading {to_read}')
    names: list[str] = []
    i = 0
    while i < to_read:
        ctx.check()
        batch = min(1024, to_read - i)
        traw = _read_span(ctx, smap, aon + i * 4, _readable(smap, aon + i * 4, batch * 4) // 4 * 4)
        if len(traw) < 4:
            ctx.warn('export_rva_out_of_file', 'export name pointer table is not backed by file data')
            truncated = True
            break
        got = len(traw) // 4
        for ptr in struct.unpack(f'<{got}I', traw[:got * 4]):
            fname = _name_at(ctx, smap, ptr)
            if fname is None:
                ctx.warn('export_rva_out_of_file', 'an export name RVA is not backed by file data')
                truncated = True
            else:
                names.append(fname[0])
        i += got
        if got < batch:
            truncated = True
            ctx.warn('export_rva_out_of_file', 'export name pointer table ends early')
            break
    return ExportsInfo(dll_name, nfuncs, nnames, tuple(names), truncated)
