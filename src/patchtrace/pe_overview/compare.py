"""Field-by-field comparison of two PE overviews with reason and provenance."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .labels import embedded_label
from .metadata import PeMetadata
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


# --- version, manifest and signature (SPEC-51 D2-5) --------------------------------------------------------------

VERSION_SRC = 'RT_VERSION resource (VS_VERSIONINFO), verified bytes'
MANIFEST_SRC = 'RT_MANIFEST resource, verified bytes, parsed without DTDs or entities'
SIGNATURE_SRC = 'WIN_CERTIFICATE PKCS#7 container: structure and digest only, chain not evaluated'
NONE = '(none)'
NOT_APPLICABLE = 'not applicable'
LEAD_FIELD = 'Combined lead (not a verdict)'
LEAD_TEXT = 'newer build requests administrator rights and is not signed (a lead, not a verdict)'
_STRENGTH = {'md5': 0, 'sha1': 1, 'sha256': 2, 'sha384': 3, 'sha512': 4}
Getter = Callable[[PeMetadata, 'str | None'], str]


def _primary_block(meta: PeMetadata):
    if meta.version is None or meta.version.primary_index is None:
        return None
    return meta.version.blocks[meta.version.primary_index]


def _quad(attr: str) -> Getter:
    def get(meta: PeMetadata, _trust: str | None) -> str:
        block = _primary_block(meta)
        if block is None or block.fixed is None:
            return NONE
        return '.'.join(str(part) for part in getattr(block.fixed, attr))
    return get


def _string(key: str) -> Getter:
    def get(meta: PeMetadata, _trust: str | None) -> str:
        block = _primary_block(meta)
        return next((s.value for s in block.strings if s.key == key), NONE) if block else NONE
    return get


def _manifest_value(read: Callable[[Any], Any]) -> Getter:
    def get(meta: PeMetadata, _trust: str | None) -> str:
        value = read(meta.manifests[0]) if meta.manifests else None
        if value is None or value == ():
            return NONE
        if isinstance(value, bool):
            return 'yes' if value else 'no'
        return ', '.join(value) if isinstance(value, tuple) else str(value)
    return get


def _dependencies(found) -> tuple[str, ...]:
    return tuple(f'{d.name} {d.version}'.strip() for d in found.dependencies if d.name or d.version)


def _signers(attr: str, fallback: str) -> Getter:
    def get(meta: PeMetadata, _trust: str | None) -> str:
        if not meta.signatures:
            return '(not signed)'
        names = [getattr(s, attr) or getattr(s, fallback) or '(unnamed)' for sig in meta.signatures
                 for s in sig.signers]
        return '; '.join(dict.fromkeys(names)) or '(no signer)'
    return get


def _digest_algorithms(meta: PeMetadata, _trust: str | None) -> str:
    return '; '.join(dict.fromkeys(s.digest_algorithm for s in meta.signatures)) or '(not signed)'


def _digest_state(meta: PeMetadata, _trust: str | None) -> str:
    if not meta.signatures:
        return NOT_APPLICABLE
    states = {s.digest_match for s in meta.signatures}
    if False in states:
        return 'does NOT match'
    return 'matches' if states == {True} else 'not computed'


def _claims(meta: PeMetadata, _trust: str | None) -> str:
    claims = [f'{t.kind} {t.claimed_time_utc}' for s in meta.signatures for t in s.timestamps if t.claimed_time_utc]
    return '; '.join(dict.fromkeys(claims)) or NONE


def _embedded(meta: PeMetadata, trust: str | None) -> str:
    return embedded_label(meta.signatures, trust)


_METADATA_ROWS: tuple[tuple[str, str, Getter], ...] = (
    ('File version (fixed)', VERSION_SRC, _quad('file_version')),
    ('Product version (fixed)', VERSION_SRC, _quad('product_version')),
    ('FileVersion string', VERSION_SRC, _string('FileVersion')),
    ('ProductVersion string', VERSION_SRC, _string('ProductVersion')),
    ('OriginalFilename', VERSION_SRC, _string('OriginalFilename')),
    ('InternalName', VERSION_SRC, _string('InternalName')),
    ('CompanyName', VERSION_SRC, _string('CompanyName')),
    ('FileDescription', VERSION_SRC, _string('FileDescription')),
    ('ProductName', VERSION_SRC, _string('ProductName')),
    ('Requested execution level', MANIFEST_SRC, _manifest_value(lambda o: o.execution_level)),
    ('UI access', MANIFEST_SRC, _manifest_value(lambda o: o.ui_access)),
    ('Supported OS', MANIFEST_SRC, _manifest_value(lambda o: o.supported_os)),
    ('Dependent assemblies', MANIFEST_SRC, _manifest_value(_dependencies)),
    ('Long path aware', MANIFEST_SRC, _manifest_value(lambda o: o.long_path_aware)),
    ('DPI awareness', MANIFEST_SRC, _manifest_value(lambda o: o.dpi_awareness)),
    ('Signature (embedded)', SIGNATURE_SRC, _embedded),
    ('Signer subject', SIGNATURE_SRC, _signers('subject_cn', 'subject_dn')),
    ('Signer issuer', SIGNATURE_SRC, _signers('issuer_cn', 'issuer_dn')),
    ('Signature digest algorithm', SIGNATURE_SRC, _digest_algorithms),
    ('Signature digest vs file', SIGNATURE_SRC, _digest_state),
    ('Claimed signing time (not verified)', SIGNATURE_SRC, _claims),
)


def describe_metadata(meta: PeMetadata, trust: str | None = None) -> tuple[tuple[str, str, str], ...]:
    """(field, value, provenance) of one side with the same wording as the comparison rows."""
    return tuple((name, get(meta, trust), provenance) for name, provenance, get in _METADATA_ROWS)


def _weakest(meta: PeMetadata) -> int:
    return min((_STRENGTH.get(s.digest_algorithm, -1) for s in meta.signatures), default=-1)


def _metadata_reason(name: str, older: PeMetadata, newer: PeMetadata) -> str:
    if name == 'Requested execution level':
        return 'privilege request changed'
    if name == 'Signature (embedded)' and bool(older.signatures) != bool(newer.signatures):
        return 'signature removed' if older.signatures else 'signature added'
    if name in ('Signer subject', 'Signer issuer'):
        return 'signer changed'
    if name == 'Signature digest algorithm' and _weakest(newer) < _weakest(older):
        return 'digest algorithm weaker'
    return 'values differ'


def compare_metadata(older: PeMetadata | None, newer: PeMetadata | None, *,
                     trust: tuple[str | None, str | None] = (None, None)) -> tuple[FieldComparison, ...]:
    """Old/new rows for version, manifest and signature facts, changed rows first, order otherwise stable.

    `trust` carries the Windows `TrustResult.status` of each side when the platform probe ran.
    """
    if older is None or newer is None:
        missing = ' and '.join(side for side, meta in (('older', older), ('newer', newer)) if meta is None)
        return (FieldComparison('Version and signing', '', '', 'unavailable',
                                f'not available in {missing} file', VERSION_SRC),)
    out = []
    for name, provenance, get in _METADATA_ROWS:
        a, b = get(older, trust[0]), get(newer, trust[1])
        if a == b:
            out.append(FieldComparison(name, a, b, 'unchanged', 'identical values', provenance))
        else:
            out.append(FieldComparison(name, a, b, 'changed', _metadata_reason(name, older, newer), provenance))
    lead = _lead(older, newer)
    if lead is not None:
        out.append(lead)
    return tuple(sorted(out, key=lambda r: r.status != 'changed'))


def _lead(older: PeMetadata, newer: PeMetadata) -> FieldComparison | None:
    """Both deltas together: a neutral field diff each, a triage lead jointly (never a verdict)."""
    level = _manifest_value(lambda o: o.execution_level)
    old_level, new_level = level(older, None), level(newer, None)
    if new_level != 'requireAdministrator' or old_level == new_level or newer.signatures or not older.signatures:
        return None
    return FieldComparison(LEAD_FIELD, f'{old_level}; signature present', f'{new_level}; not signed', 'changed',
                           LEAD_TEXT, f'{MANIFEST_SRC}; {SIGNATURE_SRC}')
