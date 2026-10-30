"""Build-environment facts of one PE: header version fields, Rich header, debug entry types, LoadConfig, CLR.

Every field is read from the file and carries no brand claim: the linker version field is forgeable (lld-link
writes 14.0) and the Rich header is optional, so absence means unknown. Never raises for malformed content.
"""
from __future__ import annotations

import importlib
import re
import struct
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from patchtrace.artifact_bytes import ArtifactBytesError, VerifiedArtifactReader

from ._common import Cancelled, Ctx
from .clr_header import ClrFacts, parse_clr_header
from .debug_entries import parse_debug_entry_types
from .headers import flag_names
from .models import Limits, PeOverview
from .rich_header import MAX_REGION, RichFacts, parse_rich_header

FACTS_VERSION = 'pe-build-facts/1'
DEFAULT_LIMITS = Limits()
MAX_ANOMALIES = 16
MAX_FAMILIES = 8
SCN_MEM_EXECUTE = 0x20000000
GUARD_FLAGS = {
    0x100: 'CF_INSTRUMENTED', 0x200: 'CFW_INSTRUMENTED', 0x400: 'CF_FUNCTION_TABLE_PRESENT',
    0x800: 'SECURITY_COOKIE_UNUSED', 0x1000: 'PROTECT_DELAYLOAD_IAT', 0x2000: 'DELAYLOAD_IAT_IN_ITS_OWN_SECTION',
    0x4000: 'CF_EXPORT_SUPPRESSION_INFO_PRESENT', 0x8000: 'CF_ENABLE_EXPORT_SUPPRESSION',
    0x10000: 'CF_LONGJUMP_TABLE_PRESENT', 0x100000: 'RETPOLINE_PRESENT', 0x400000: 'EH_CONTINUATION_TABLE_PRESENT',
    0x800000: 'XFG_ENABLED',
}
# (security cookie offset, width, guard flags offset) per optional-header magic
_LOAD_CONFIG = {'PE32+': (88, 8, 144), 'PE32': (60, 4, 88)}
# Closed table by DLL name; a family says which runtime the image links, never a version claim.
_FAMILIES = (
    ('msvc-crt-14', re.compile(r'(vcruntime|msvcp|concrt|vcomp)140(_\d+)?(d)?\.dll')),
    ('ucrt', re.compile(r'(ucrtbased?|api-ms-win-crt-[a-z0-9-]+-l\d+-\d+-\d+)\.dll')),
    ('msvcrt-legacy', re.compile(r'(msvcrt(d)?|msvc[pr](?!140)\d{2,3}d?)\.dll')),
    ('mingw', re.compile(r'(libgcc_s_[a-z0-9]+-\d+|libstdc\+\+-\d+|libwinpthread-\d+|libssp-\d+)\.dll')),
)


@dataclass(frozen=True, slots=True)
class PeBuildFacts:
    facts_version: str
    linker_field: tuple[int, int] | None
    os_field: tuple[int, int] | None
    image_field: tuple[int, int] | None
    subsystem_field: tuple[int, int] | None
    subsystem: str | None
    dll_characteristics: tuple[str, ...]
    guard_flags: tuple[str, ...] | None
    security_cookie_set: bool | None
    debug_entry_types: tuple[int, ...]
    repro: bool
    rich: RichFacts | None
    clr: ClrFacts | None
    runtime_families: tuple[str, ...]
    entropy_exec_max: float | None
    overlay_size: int
    overlay_entropy: float | None
    sampled: bool
    anomalies: tuple[str, ...]


def runtime_families(dll_names: list[str]) -> tuple[str, ...]:
    found = {family for name in dll_names for family, pattern in _FAMILIES if pattern.fullmatch(name.lower())}
    return tuple(sorted(found))[:MAX_FAMILIES]


def _version_pairs(ctx: Ctx, opt_offset: int) -> dict[str, tuple[int, int] | None]:
    raw = ctx.read(opt_offset, 52)
    if len(raw) < 52:
        return {'linker': None, 'os': None, 'image': None, 'subsystem': None}
    return {'linker': (raw[2], raw[3]), 'os': struct.unpack_from('<HH', raw, 40),
            'image': struct.unpack_from('<HH', raw, 44), 'subsystem': struct.unpack_from('<HH', raw, 48)}


def _load_config(ctx: Ctx, ov: PeOverview, span: tuple[int, int] | None,
                 size: int) -> tuple[tuple[str, ...] | None, bool | None]:
    layout = _LOAD_CONFIG.get(ov.optional_magic or '')
    raw = ctx.read(*span) if layout is not None and span is not None else b''
    if layout is None or len(raw) < 4:
        return None, None
    cookie_at, width, flags_at = layout
    usable = min(struct.unpack_from('<I', raw, 0)[0], len(raw))  # the structure's own Size field bounds its fields
    cookie = struct.unpack_from('<Q' if width == 8 else '<I', raw, cookie_at)[0] if cookie_at + width <= usable else None
    flags = struct.unpack_from('<I', raw, flags_at)[0] if flags_at + 4 <= usable else None
    return (None if flags is None else flag_names(flags, GUARD_FLAGS)), (None if cookie is None else cookie != 0)


def _rich_region(ctx: Ctx, e_lfanew: int) -> bytes:
    return ctx.read(0, min(e_lfanew, MAX_REGION)) if 0x40 < e_lfanew else b''


def _pefile_mismatch(ctx: Ctx, rich: RichFacts | None) -> bool:
    """Optional cross-check on the same header bytes; pefile is dev-only so it is usually not importable."""
    try:
        pefile = importlib.import_module('pefile')  # dynamic on purpose: pefile is dev-only and never a static dependency here
    except ImportError:
        return False
    try:
        pe = pefile.PE(data=ctx.read(0, MAX_REGION + 4096), fast_load=True)
        parsed = pe.parse_rich_header()
    except Exception:  # pefile raises many types on hostile bytes; a failed cross-check proves nothing
        return False
    values = [] if rich is None else [word for e in rich.entries for word in ((e.product_id << 16) | e.build, e.count)]
    return bool(parsed and parsed.get('values') != values) or (parsed is None and bool(values))


def _guarded(ctx: Ctx, name: str, fn: Callable[[], Any], anomalies: list[str]) -> Any:
    ctx.check()
    try:
        return fn()
    except (Cancelled, ArtifactBytesError):
        raise
    except Exception:  # defensive fault boundary: hostile input must not escape
        anomalies.append(f'{name}-failed')
        return None


def collect_build_facts(reader: VerifiedArtifactReader, ov: PeOverview, *, cancel: Callable[[], bool] | None = None,
                        limits: Limits = DEFAULT_LIMITS) -> PeBuildFacts:
    ctx = Ctx(reader, cancel, limits)
    anomalies: list[str] = []
    out: dict[str, Any] = {}
    try:
        _collect(ctx, ov, out, anomalies)
    except Cancelled:
        anomalies.append('cancelled')
    except ArtifactBytesError:
        anomalies.append('read-failed')
    return _assemble(ov, out, anomalies)


def _collect(ctx: Ctx, ov: PeOverview, out: dict[str, Any], anomalies: list[str]) -> None:
    head = ctx.read(0, 64)
    if len(head) < 64 or head[:2] != b'MZ' or ov.optional_magic is None:
        return
    e_lfanew = struct.unpack_from('<I', head, 0x3C)[0]
    out['pairs'] = _guarded(ctx, 'header-fields', lambda: _version_pairs(ctx, e_lfanew + 24), anomalies)
    if e_lfanew <= ctx.limits.max_lfanew:
        out['rich'] = _guarded(ctx, 'rich', lambda: parse_rich_header(_rich_region(ctx, e_lfanew)), anomalies)
        rich = out['rich']
        if rich is not None and rich.checksum_ok is False:
            anomalies.append('rich-checksum-failed')
        if rich is not None and rich.truncated:
            anomalies.append('rich-truncated')
        if _guarded(ctx, 'rich-crosscheck', lambda: _pefile_mismatch(ctx, rich), anomalies):
            anomalies.append('rich-pefile-mismatch')
    smap = ov.section_map()
    dbg, clr, cfg = ov.directory('Debug'), ov.directory('CLR'), ov.directory('LoadConfig')
    if dbg is not None and dbg.present:
        out['debug'] = _guarded(ctx, 'debug-entries', lambda: parse_debug_entry_types(ctx, smap, dbg.rva, dbg.size),
                                anomalies)
    if clr is not None and clr.present:
        out['clr'] = _guarded(ctx, 'clr-header', lambda: parse_clr_header(ctx, smap, clr.rva, clr.size), anomalies)
        if out['clr'] is None:
            anomalies.append('clr-header-unreadable')
    if cfg is not None and cfg.present:
        out['load_config'] = _guarded(
            ctx, 'load-config', lambda: _load_config(ctx, ov, smap.backed_prefix(cfg.rva, min(cfg.size, 160)),
                                                     cfg.size), anomalies)


def _assemble(ov: PeOverview, out: dict[str, Any], anomalies: list[str]) -> PeBuildFacts:
    pairs = out.get('pairs') or {}
    debug = out.get('debug')
    guard, cookie = out.get('load_config') or (None, None)
    if debug is not None and debug.truncated:
        anomalies.append('debug-entries-truncated')
    sections = ov.sections or ()
    exec_entropy = [s.entropy for s in sections if s.characteristics & SCN_MEM_EXECUTE and s.entropy is not None]
    overlay = ov.overlay
    return PeBuildFacts(
        FACTS_VERSION, pairs.get('linker'), pairs.get('os'), pairs.get('image'), pairs.get('subsystem'),
        ov.subsystem.name if ov.subsystem else None, ov.dll_characteristics or (), guard, cookie,
        debug.types if debug else (), bool(debug and debug.repro), out.get('rich'), out.get('clr'),
        runtime_families([d.name for d in ov.imports.dlls]) if ov.imports else (),
        max(exec_entropy, default=None), overlay.size if overlay else 0, overlay.entropy if overlay else None,
        any(s.sampled for s in sections) or bool(overlay and overlay.sampled), tuple(anomalies[:MAX_ANOMALIES]))
