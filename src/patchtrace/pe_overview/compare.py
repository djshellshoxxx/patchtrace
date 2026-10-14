"""Field-by-field comparison of two PE overviews with reason and provenance."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .models import FieldComparison, PeOverview

IDENTITY = 'recorded file identity'
COFF = 'COFF file header'
OPT = 'PE optional header'
SECT = 'section table'
DIRS = 'data directories'
IMPORT = 'import directory'
EXPORT = 'export directory'
SCAN = 'file scan'
DEBUG = 'debug directory'


def _hex(v: int | None) -> str | None:
    return None if v is None else f'0x{v:X}'


def _label(v: Any) -> str | None:
    return None if v is None else f'{v.name} ({v.code:#x})'


def _join(v: tuple[str, ...] | None) -> str | None:
    return None if v is None else (', '.join(v) if v else '(none)')


def _dir_present(ov: PeOverview, name: str) -> str | None:
    d = ov.directory(name)
    return None if d is None else ('present' if d.present else 'absent')


def _dll_names(ov: PeOverview) -> list[str] | None:
    return None if ov.imports is None else sorted({d.name.lower() for d in ov.imports.dlls})


def _imports_absent(ov: PeOverview) -> bool:
    d = ov.directory('Import')
    return d is not None and not d.present


def _rows() -> list[tuple[str, str, Callable[[PeOverview], str | None]]]:
    return [
        ('File size (bytes)', IDENTITY, lambda o: str(o.size)),
        ('SHA-256', IDENTITY, lambda o: o.sha256),
        ('Header magic', 'file header', lambda o: o.header_magic),
        ('PE type', 'COFF characteristics and subsystem (heuristic)', lambda o: o.pe_kind and o.pe_kind.kind),
        ('Machine', COFF, lambda o: _label(o.machine)),
        ('COFF timestamp (untrusted)', COFF, lambda o: o.coff_timestamp and (
            f'{o.coff_timestamp.raw} ({o.coff_timestamp.iso_utc or "n/a"})')),
        ('Characteristics', COFF, lambda o: _join(o.characteristics)),
        ('Optional header format', OPT, lambda o: o.optional_magic),
        ('Entrypoint RVA', OPT, lambda o: _hex(o.entrypoint_rva)),
        ('Entrypoint VA', OPT, lambda o: _hex(o.entrypoint_va)),
        ('Image base', OPT, lambda o: _hex(o.image_base)),
        ('Section alignment', OPT, lambda o: _hex(o.section_alignment)),
        ('File alignment', OPT, lambda o: _hex(o.file_alignment)),
        ('Size of image', OPT, lambda o: _hex(o.size_of_image)),
        ('Size of headers', OPT, lambda o: _hex(o.size_of_headers)),
        ('Subsystem', OPT, lambda o: _label(o.subsystem)),
        ('DLL characteristics', OPT, lambda o: _join(o.dll_characteristics)),
        ('Stored checksum', OPT, lambda o: o.checksum and _hex(o.checksum.stored)),
        ('Computed checksum', SCAN, lambda o: o.checksum and _hex(o.checksum.computed)),
        ('Section count', SECT, lambda o: None if o.sections is None else str(len(o.sections))),
        ('Section names', SECT, lambda o: None if o.sections is None else _join(tuple(s.name for s in o.sections))),
        ('Section sizes (virtual/raw)', SECT, lambda o: None if o.sections is None else _join(tuple(
            f'{s.name}:{s.virtual_size:#x}/{s.raw_size:#x}' for s in o.sections))),
        ('Imported DLLs', IMPORT, lambda o: _join(tuple(_dll_names(o))) if _dll_names(o) is not None else (
            '(none)' if _imports_absent(o) else None)),
        ('Imported function count', IMPORT, lambda o: None if o.imports is None else str(o.imports.total_functions)),
        ('Export count', EXPORT, lambda o: None if o.exports is None else str(o.exports.count)),
        ('Overlay present', SCAN, lambda o: None if o.sections is None else (
            'yes' if o.overlay else 'no')),
        ('Overlay size', SCAN, lambda o: None if o.sections is None else str(o.overlay.size if o.overlay else 0)),
        ('Certificate table present (signature not verified)', DIRS, lambda o: (
            None if o.certificates is None else ('yes' if o.certificates.present else 'no'))),
        ('TLS directory', DIRS, lambda o: _dir_present(o, 'TLS')),
        ('Relocation directory', DIRS, lambda o: _dir_present(o, 'BaseReloc')),
        ('Exception directory', DIRS, lambda o: _dir_present(o, 'Exception')),
        ('Resource directory', DIRS, lambda o: _dir_present(o, 'Resource')),
        ('Debug directory', DIRS, lambda o: _dir_present(o, 'Debug')),
        ('PDB path', DEBUG, lambda o: o.codeview and o.codeview.pdb_path),
        ('PDB GUID/age', DEBUG, lambda o: o.codeview and f'{o.codeview.guid}/{o.codeview.age}'),
        ('Packer hints', SECT, lambda o: _join(tuple(f'{h.name} ({h.confidence})' for h in o.packer_hints))),
    ]


def _import_reason(old: PeOverview, new: PeOverview) -> str:
    a, b = set(_dll_names(old) or ()), set(_dll_names(new) or ())
    parts = []
    if b - a:
        parts.append('added: ' + ', '.join(sorted(b - a)))
    if a - b:
        parts.append('removed: ' + ', '.join(sorted(a - b)))
    return '; '.join(parts) or 'same DLL set'


def compare_overviews(older: PeOverview, newer: PeOverview) -> tuple[FieldComparison, ...]:
    out = []
    for name, provenance, get in _rows():
        a, b = get(older), get(newer)
        sa = '' if a is None else str(a)
        sb = '' if b is None else str(b)
        if a is None or b is None:
            missing = [side for side, v in (('older', a), ('newer', b)) if v is None]
            out.append(FieldComparison(name, sa, sb, 'unavailable',
                                       f'not available in {" and ".join(missing)} file '
                                       f'(status: older {older.status}, newer {newer.status})', provenance))
        elif sa == sb:
            out.append(FieldComparison(name, sa, sb, 'unchanged', 'identical values', provenance))
        else:
            reason = _import_reason(older, newer) if name == 'Imported DLLs' else 'values differ'
            out.append(FieldComparison(name, sa, sb, 'changed', reason, provenance))
    return tuple(out)
