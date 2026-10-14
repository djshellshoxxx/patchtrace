"""Orchestration: ``inspect_pe`` never raises for malformed content (see docs/specs/pe-overview.md)."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from patchtrace.artifact_bytes import ArtifactBytesError, VerifiedArtifactReader

from ._common import Cancelled, Ctx
from .certificates import parse_certificate_table
from .debug_info import parse_codeview
from .entropy import entropy_of_range, pe_checksum
from .headers import HeaderState, build_checksum, parse_headers
from .imports_exports import parse_exports, parse_imports
from .models import Limits, OverlayInfo, PeOverview, SectionMap
from .sections import last_raw_end, packer_hints, parse_sections

DEFAULT_LIMITS = Limits()
INFORMATIONAL = frozenset({'data_after_certificate_table'})


def inspect_pe(reader: VerifiedArtifactReader, *, cancel: Callable[[], bool] | None = None,
               limits: Limits = DEFAULT_LIMITS) -> PeOverview:
    ctx = Ctx(reader, cancel, limits)
    fields: dict[str, Any] = {}
    status = 'ok'
    try:
        status = _run(ctx, fields)
    except Cancelled:
        status = 'cancelled'
    return PeOverview(size=reader.size, sha256=reader.sha256, status=status,
                      warnings=tuple(ctx.warnings), **fields)


def _stage(ctx: Ctx, name: str, fn: Callable[[], Any]) -> Any:
    ctx.check()
    try:
        return fn()
    except (Cancelled, ArtifactBytesError):
        raise
    except Exception as exc:  # defensive fault boundary: hostile input must not escape
        ctx.warn(f'internal_error_{name}', f'{name} stage failed: {type(exc).__name__}')
        return None


def _run(ctx: Ctx, fields: dict[str, Any]) -> str:
    st: HeaderState | None = _stage(ctx, 'headers', lambda: parse_headers(ctx))
    if st is None:
        return 'partial'
    fields.update(st.fields)
    if st.status == 'not_pe':
        return 'not_pe'
    if st.opt_present or st.section_count:
        _inspect_body(ctx, st, fields)
    partial = st.status == 'partial' or any(w.code not in INFORMATIONAL for w in ctx.warnings)
    return 'partial' if partial else 'ok'


def _inspect_body(ctx: Ctx, st: HeaderState, fields: dict[str, Any]) -> None:
    size = ctx.reader.size
    sections = _stage(ctx, 'sections', lambda: parse_sections(ctx, st.section_table_offset, st.section_count))
    if sections is None:
        return
    fields['sections'] = sections
    fields['packer_hints'] = _stage(ctx, 'packer', lambda: packer_hints(sections)) or ()
    pre = PeOverview(size=size, sha256=ctx.reader.sha256, status='ok', **fields)
    smap = SectionMap.from_overview(pre)
    dirs = {d.name: d for d in fields.get('data_directories') or ()}

    if st.checksum_offset is not None and st.stored_checksum is not None:
        computed = None
        if size > ctx.limits.checksum_max_file:
            ctx.warn('checksum_skipped_large',
                     f'PE checksum not computed for files over {ctx.limits.checksum_max_file} bytes')
        else:
            computed = _stage(ctx, 'checksum', lambda: pe_checksum(ctx, st.checksum_offset))
        fields['checksum'] = build_checksum(st.stored_checksum, computed)

    sec = dirs.get('Security')
    if sec is not None:
        fields['certificates'] = _stage(
            ctx, 'certificates', lambda: parse_certificate_table(ctx, sec.rva, sec.size))
    fields['overlay'] = _stage(ctx, 'overlay', lambda: _overlay(ctx, fields, sections))

    plus = fields.get('optional_magic') == 'PE32+'
    imp = dirs.get('Import')
    if imp is not None and imp.present:
        fields['imports'] = _stage(ctx, 'imports', lambda: parse_imports(ctx, smap, imp.rva, plus))
    exp = dirs.get('Export')
    if exp is not None and exp.present:
        fields['exports'] = _stage(ctx, 'exports', lambda: parse_exports(ctx, smap, exp.rva))
    dbg = dirs.get('Debug')
    if dbg is not None and dbg.present:
        fields['codeview'] = _stage(ctx, 'debug', lambda: parse_codeview(ctx, smap, dbg.rva, dbg.size))
    ctx.check()


def _overlay(ctx: Ctx, fields: dict[str, Any], sections: tuple) -> OverlayInfo | None:
    size = ctx.reader.size
    start = last_raw_end(sections) or (fields.get('size_of_headers') or 0)
    if start <= 0 or start >= size:
        return None
    end = size
    cert = fields.get('certificates')
    if cert is not None and cert.present and cert.file_offset < size:
        if start <= cert.file_offset:
            end = cert.file_offset
            if cert.file_offset + cert.size < size:
                ctx.warn('data_after_certificate_table', 'data follows the certificate table')
    if end <= start:
        return None
    ent, _measured, sampled = entropy_of_range(ctx, start, end - start)
    return OverlayInfo(start, end - start, ent, sampled)


__all__ = ['inspect_pe']
