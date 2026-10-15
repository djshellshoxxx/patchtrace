"""Pure view-model of the PE build-facts tab (WBQ S6, `pe-meta/1`): what the Files panel says about the version
resource, the manifest and the imported-API delta of the older and the newer file. Qt-free; `ui_pemeta` draws it.

The inputs are the parsed records of `pe_overview` (S1, S2, S4). Everything is text about bytes that were verified
and parsed, never evidence of a vulnerability: unknown is `unavailable`, never "removed", and a limit that cut a fact
says so in words (plan section 8 copy). Cell text is untrusted and passes `sanitize_text` in `prepare_table`.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from .gui.state import StateModel, state_model
from .gui.table_spec import ColumnSpec, PreparedTable, TableSpec, prepare_table
from .gui.text import sanitize_text
from .pe_overview.api_delta import ApiChange, ApiDelta
from .pe_overview.manifest import ManifestObservation
from .pe_overview.version_info import VersionBlock, VersionInfoSet, version_text

CONTRACT = 'pe-meta/1'
TITLE = 'Build facts'
LOADING = 'Reading version, manifest and build records from verified file bytes...'
NO_VERSION = 'No version resource in this file. This is normal for some drivers and tools; it is not an error.'
UNREADABLE = 'Could not read this record ({code}). The other side is still shown.'
LIMIT = 'Stopped at a safety limit ({what}). The values shown are partial; nothing below the limit was guessed.'
DTD_BLOCKED = ('Manifest not parsed: it declares a document type definition (DTD), which PatchTrace refuses to '
               'process.')
DECODER_MISSING = ('Readable names unavailable: the optional name decoder is not installed. The original decorated '
                   'names are shown.')
DECODER_STOPPED = ('The name decoder stopped on a name it could not process safely; the original name is shown.')
VERSION_PROVENANCE = 'RT_VERSION resource (VS_VERSIONINFO), verified bytes'
MANIFEST_PROVENANCE = 'RT_MANIFEST resource, verified bytes, parsed without DTDs or entities'
ABSENT = '(not present)'
UNKNOWN = '(unavailable)'
SIDES = ('older', 'newer')
CHANGES = ('added', 'removed')
SHOWN_STRING_KEYS = ('CompanyName', 'FileDescription', 'FileVersion', 'InternalName', 'OriginalFilename',
                     'ProductName', 'ProductVersion')
_LIMIT_WHAT = {'resource_nodes_over_cap': '20,000 resource entries', 'resource_depth_over_cap': 'the resource depth',
               'version_over_cap': 'the version resource size', 'manifest_over_cap': 'the manifest size',
               'metadata_time_budget': 'the time budget'}
_DECODER_STATES = ('ok', 'off', 'unavailable', 'stopped')


@dataclass(frozen=True, slots=True)
class SideMeta:
    """What one file gave. `error` is a stable code (for example `artifact_changed`) when its bytes could not be
    read or verified; `version` is None when that was not parsed, and has no blocks when the file has none."""

    version: VersionInfoSet | None = None
    manifests: tuple[ManifestObservation, ...] = ()
    warnings: tuple[str, ...] = ()
    error: str = ''


@dataclass(frozen=True, slots=True)
class PeMetaSnapshot:
    older: SideMeta
    newer: SideMeta
    api_delta: ApiDelta | None = None
    decoder: str = 'off'  # off | ok | unavailable | stopped

    def __post_init__(self) -> None:
        if self.decoder not in _DECODER_STATES:
            raise ValueError(f'decoder must be one of {_DECODER_STATES}, not {self.decoder!r:.20}')

    def side(self, name: str) -> SideMeta:
        if name not in SIDES:
            raise ValueError(f'side must be older or newer, not {name!r:.20}')
        return self.older if name == 'older' else self.newer


@dataclass(frozen=True, slots=True)
class FactRow:
    key: str
    label: str
    older: str
    newer: str
    status: str  # changed | unchanged | unavailable
    provenance: str


def _primary(version: VersionInfoSet | None) -> VersionBlock | None:
    if version is None or version.primary_index is None:
        return None
    return version.blocks[version.primary_index]


def _first_manifest(side: SideMeta) -> ManifestObservation | None:
    return side.manifests[0] if side.manifests else None


def _version_value(side: SideMeta, pick: Callable[[VersionBlock], str | None]) -> str | None:
    """The value, ABSENT for a verified absence, None (unknown) when the side was not parsed."""
    if side.error or side.version is None:
        return None
    block = _primary(side.version)
    if block is None:
        return ABSENT
    return pick(block) or ABSENT


def _fixed(attribute: str) -> Callable[[VersionBlock], str | None]:
    return lambda block: version_text(getattr(block.fixed, attribute)) if block.fixed is not None else None


def _string(key: str) -> Callable[[VersionBlock], str | None]:
    return lambda block: next((item.value for item in block.strings if item.key == key), None)


def _manifest_value(side: SideMeta, pick: Callable[[ManifestObservation], object]) -> str | None:
    if side.error or side.version is None:  # the manifest and the version come from one resource walk
        return None
    if 'manifest_dtd_rejected' in side.warnings:
        return None
    manifest = _first_manifest(side)
    if manifest is None:
        return ABSENT
    value = pick(manifest)
    if value is None or value == '':
        return ABSENT
    return 'yes' if value is True else 'no' if value is False else str(value)


def _row(key: str, label: str, older: str | None, newer: str | None, provenance: str) -> FactRow:
    if older is None or newer is None:
        status = 'unavailable'
    else:
        status = 'unchanged' if older == newer else 'changed'
    return FactRow(key, label, older if older is not None else UNKNOWN, newer if newer is not None else UNKNOWN,
                   status, provenance)


def _strings_keys(snapshot: PeMetaSnapshot) -> list[str]:
    """The documented string keys either side carries, in a stable order; other keys are not listed here."""
    present = {item.key for name in SIDES for item in getattr(_primary(snapshot.side(name).version), 'strings', ())}
    return [key for key in SHOWN_STRING_KEYS if key in present]


def fact_rows(snapshot: PeMetaSnapshot) -> tuple[FactRow, ...]:
    """Short facts, one row each, in a fixed order (version first, then its strings, then the manifest)."""
    rows = [_row('file_version', 'Version: file version', *(_version_value(snapshot.side(n), _fixed('file_version'))
                                                            for n in SIDES), VERSION_PROVENANCE),
            _row('product_version', 'Version: product version',
                 *(_version_value(snapshot.side(n), _fixed('product_version')) for n in SIDES), VERSION_PROVENANCE)]
    rows += [_row(f'string:{key}', f'Version string: {key}',
                  *(_version_value(snapshot.side(n), _string(key)) for n in SIDES), VERSION_PROVENANCE)
             for key in _strings_keys(snapshot)]
    manifest_facts: tuple[tuple[str, str, Callable[[ManifestObservation], object]], ...] = (
        ('execution_level', 'Manifest: requested execution level', lambda m: m.execution_level),
        ('ui_access', 'Manifest: UI access', lambda m: m.ui_access),
        ('dpi_awareness', 'Manifest: DPI awareness', lambda m: m.dpi_awareness),
        ('long_path_aware', 'Manifest: long paths', lambda m: m.long_path_aware),
        ('assembly_version', 'Manifest: assembly version', lambda m: m.identity.version if m.identity else None))
    rows += [_row(f'manifest:{key}', label, *(_manifest_value(snapshot.side(n), pick) for n in SIDES),
                  MANIFEST_PROVENANCE) for key, label, pick in manifest_facts]
    if snapshot.api_delta is not None:
        delta = snapshot.api_delta
        counts = tuple('' if count is None else str(count) for count in (delta.older_count, delta.newer_count))
        rows.append(FactRow('imports', f'Imports: APIs added or removed ({len(delta.changes)})',
                            counts[0] or UNKNOWN, counts[1] or UNKNOWN, delta.status, delta.provenance))
    return tuple(rows)


def _notes(snapshot: PeMetaSnapshot) -> list[tuple[str, bool]]:
    """(sentence, makes the result partial) per explained fact, per side."""
    out: list[tuple[str, bool]] = []
    for name in SIDES:
        side, prefix = snapshot.side(name), f'{name.upper()}: '
        if side.error:
            out.append((prefix + UNREADABLE.format(code=sanitize_text(side.error, 40)), True))
            continue
        if side.version is not None and not side.version.blocks:
            out.append((prefix + NO_VERSION, False))  # a verified absence is normal
        if 'manifest_dtd_rejected' in side.warnings:
            out.append((prefix + DTD_BLOCKED, True))
        out.extend((prefix + LIMIT.format(what=_LIMIT_WHAT[code]), True) for code in side.warnings
                   if code in _LIMIT_WHAT)
    if snapshot.decoder == 'unavailable':
        out.append((DECODER_MISSING, False))
    elif snapshot.decoder == 'stopped':
        out.append((DECODER_STOPPED, True))
    delta = snapshot.api_delta
    if delta is not None and delta.status == 'unavailable' and delta.reason:
        out.append((f'Imported API changes: {sanitize_text(delta.reason, 200)}', True))
    return out


def notes(snapshot: PeMetaSnapshot) -> tuple[str, ...]:
    """The sentences that explain an empty, partial or blocked fact, per side; none for a clean result."""
    return tuple(text for text, _ in _notes(snapshot))


def panel_state(snapshot: PeMetaSnapshot | None, *, loading: bool = False, has_project: bool = True) -> StateModel:
    """The strip above the tab: no project, loading, partial (a limit, an unreadable side or a refused manifest), or
    ready. A partial result keeps its rows; the reasons are the notes."""
    if not has_project:
        return state_model('no-project', TITLE)
    if snapshot is None:
        return StateModel('loading', LOADING) if loading else state_model(
            'idle', TITLE, hint='Open the Files panel after a project is loaded.')
    partial = sum(1 for _, is_partial in _notes(snapshot) if is_partial)
    if partial:
        return state_model('partial', TITLE, reasons=f'{partial} note(s) below')
    return StateModel('ready', '')


# ---- the API-delta table ----------------------------------------------------------------------------------------

API_COLUMNS = (
    ColumnSpec('change', 'Change', lambda c: c.change, width_em=9),
    ColumnSpec('dll', 'DLL', lambda c: c.dll, width_em=22),
    ColumnSpec('name', 'Name', lambda c: c.name, width_em=40),
    ColumnSpec('kind', 'Kind', lambda c: c.kind, width_em=8),
)
API_SPEC = TableSpec(row_key=lambda c: f'{c.change}|{c.dll}|{c.name}', search_text=lambda c: f'{c.dll} {c.name}',
                     default_order=lambda c: (CHANGES.index(c.change), c.dll, c.name))


def api_changes(snapshot: PeMetaSnapshot | None) -> tuple[ApiChange, ...]:
    return () if snapshot is None or snapshot.api_delta is None else tuple(snapshot.api_delta.changes)


# ---- the facts table ---------------------------------------------------------------------------------------------

FACT_COLUMNS = (
    ColumnSpec('label', 'Fact', lambda r: r.label, width_em=34),
    ColumnSpec('older', 'OLDER', lambda r: r.older, width_em=26),
    ColumnSpec('newer', 'NEWER', lambda r: r.newer, width_em=26),
    ColumnSpec('status', 'Status', lambda r: r.status, width_em=11),
    ColumnSpec('provenance', 'Provenance', lambda r: r.provenance, width_em=40),
)
FACT_SPEC = TableSpec(row_key=lambda r: r.key, search_text=lambda r: f'{r.label} {r.older} {r.newer}')


def unique_changes(changes: Iterable[ApiChange]) -> tuple[ApiChange, ...]:
    """Row keys must be unique: a delta never lists a pair twice, but a hostile caller could."""
    seen: dict[str, ApiChange] = {}
    for change in changes:
        seen.setdefault(API_SPEC.row_key(change), change)
    return tuple(seen.values())


@dataclass(frozen=True, slots=True)
class PreparedMeta:
    """Everything the widget needs, built off the GUI thread (`prepare_meta`); the GUI thread only swaps pointers."""

    snapshot: PeMetaSnapshot
    facts: PreparedTable
    api: PreparedTable
    state: StateModel
    notes: tuple[str, ...]


def prepare_meta(snapshot: PeMetaSnapshot, token: object = None) -> PreparedMeta:
    """Worker-side preparation; `token` is a `CancelToken` (a set token raises `table_spec.Cancelled`)."""
    api = prepare_table(API_SPEC, API_COLUMNS, unique_changes(api_changes(snapshot)), token)
    return PreparedMeta(snapshot, prepare_table(FACT_SPEC, FACT_COLUMNS, fact_rows(snapshot), token), api,
                        panel_state(snapshot), notes(snapshot))
