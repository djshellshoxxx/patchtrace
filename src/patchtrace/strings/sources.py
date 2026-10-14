"""String sources (WB3-S1): turn one extraction run into compact, table-ready rows plus the facts that decide
comparability (`StringBasis` parts and stage states). Pure; no Qt, no process.

Two FLOSS adapters share one row shape: `FlossEvidenceSource` over the already-validated `ToolEvidenceSet`
(file offsets verified against the artifact bytes) and `RawFlossSource` over the raw 3.1.1 JSON (the parsed level
can then be rebuilt without re-running FLOSS). Rows hold the SHA-256 and the escaped display text only, never the
raw string, so a hostile value cannot reach a renderer through this layer.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal, NamedTuple, Protocol, runtime_checkable

from pydantic import ValidationError

from ..intelligence.tools import floss
from ..intelligence.tools.common import (
    DEFAULT_LIMITS,
    ToolError,
    ToolEvidenceSet,
    display_text,
    load_json_strict,
    secret_kind,
)

# Static-class strings of FLOSS 3.1.1 (documented character class, minimum length, ASCII and UTF-16LE of the
# ASCII range) and of the built-in scan share one semantics id, so their tables are comparable (WB3 7.1).
STATIC_SEMANTICS_ID = 'ascii+utf16le-ascii/v1'
STRING_TYPES = ('static', 'language', 'stack', 'tight', 'decoded')
EMULATION_TYPES = ('stack', 'tight', 'decoded')
DEFAULT_MAX_ROWS = 200_000

StageStateName = Literal['complete', 'heuristic', 'not-run', 'failed', 'truncated']
SourceName = Literal['builtin-scan', 'floss']


class StageState(NamedTuple):
    state: StageStateName
    detail: str = ''


class SourceRow(NamedTuple):
    """One string occurrence. `None` = absent (the columnar table stores 0xFFFFFFFF)."""
    value_sha256: bytes
    display: str
    length: int
    type: str
    encoding: str
    offset: int | None          # file offset (static and language strings only)
    rva: int | None             # RVA of the string bytes (static and language strings only)
    fn_rva: int | None          # emulation strings: stack frame function or decoding routine
    site_rva: int | None        # decoded strings: instruction where the string was decoded
    data_rva: int | None        # decoded strings: RVA of the string's own address (GLOBAL only)
    secret_kind: str | None
    confidence: str


@dataclass(frozen=True)
class StringPart:
    source: SourceName
    semantics_id: str
    source_version: str | None
    types: tuple[str, ...]
    config_digest: str
    executable_sha256: str | None = None
    run_id: str | None = None
    raw_sha256: str | None = None
    consent_sha256: str | None = None


@dataclass(frozen=True)
class SourceResult:
    side: str
    artifact_sha256: str
    min_length: int | None
    language: str | None
    rows: tuple[SourceRow, ...]
    rows_seen: int
    stages: dict[str, StageState]
    part: StringPart
    anomalies: tuple[str, ...] = field(default=())


@runtime_checkable
class StringSource(Protocol):
    def load(self) -> SourceResult: ...


def stage_states(run_types: set[str], totals: dict[str, int], truncated: set[str]) -> dict[str, StageState]:
    """Per-type completeness. A type that did not run is `not-run`, never "found nothing" (WB3 section 6)."""
    stages: dict[str, StageState] = {}
    for kind in STRING_TYPES:
        # Language strings come from the static stage (FLOSS 3.1.1 main.py), not from emulation.
        ran = kind in run_types or (kind == 'language' and 'static' in run_types)
        if not ran:
            stages[kind] = StageState('not-run')
        elif kind in truncated:
            stages[kind] = StageState('truncated', 'cut at the per-type row quota')
        elif kind in EMULATION_TYPES:
            stages[kind] = StageState('heuristic', 'emulation can miss strings; absence is not evidence')
        else:
            stages[kind] = StageState('complete', '' if totals.get(kind) else 'none-found')
    return stages


def _hash(value: str) -> bytes:
    return hashlib.sha256(value.encode('utf-8', 'surrogatepass')).digest()


class FlossEvidenceSource:
    def __init__(self, evidence: ToolEvidenceSet, *, executable_sha256: str | None = None,
                 source_version: str | None = None, consent_sha256: str | None = None,
                 raw_sha256: str | None = None) -> None:
        self._evidence = evidence
        self._part = dict(executable_sha256=executable_sha256, source_version=source_version,
                          consent_sha256=consent_sha256, raw_sha256=raw_sha256)

    def load(self) -> SourceResult:
        ev = self._evidence
        rows = tuple(self._row(item) for item in ev.strings)
        totals = {kind: ev.counts.get(f'total_{kind}', 0) for kind in STRING_TYPES}
        if 'empty_output' not in ev.analysis:
            totals = {kind: totals[kind] or sum(1 for r in rows if r.type == kind) for kind in STRING_TYPES}
        run_types = set(str(ev.analysis.get('types', 'static')).split(','))
        truncated = set(ev.truncated_types) or (run_types if ev.truncated else set())
        min_length = ev.analysis.get('min_length')
        language = ev.analysis.get('language')
        part = StringPart(
            source='floss', semantics_id=STATIC_SEMANTICS_ID, run_id=ev.run_id, config_digest=ev.config_digest,
            types=tuple(kind for kind in STRING_TYPES if kind in run_types), **{
                **self._part, 'source_version': self._part['source_version'] or _text(ev.analysis.get('version'))})
        return SourceResult(
            side=ev.side, artifact_sha256=ev.artifact_sha256, min_length=min_length if isinstance(
                min_length, int) else None, language=language if isinstance(language, str) else None,
            rows=rows, rows_seen=ev.counts.get('strings_total', len(rows)),
            stages=stage_states(run_types, totals, truncated), part=part, anomalies=ev.anomalies)

    @staticmethod
    def _row(item) -> SourceRow:
        loc = item.source_location
        located = item.type in ('static', 'language')
        return SourceRow(
            bytes.fromhex(item.value_hash), item.display_value, item.length, item.type, item.encoding,
            loc.file_offset if located else None, loc.rva if located else None,
            None if located or loc.function_id is None else loc.rva, loc.site_rva, loc.data_rva, item.secret_kind,
            item.confidence_class)


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


class RawFlossSource:
    """Parses the raw FLOSS 3.1.1 document with the strict adapter models. No PE verification: rows are
    `unverified-location` unless the caller supplies an offset-to-RVA mapping from the verified image."""

    def __init__(self, raw: bytes, *, artifact_sha256: str, side: str, run_id: str, config_digest: str,
                 max_rows: int = DEFAULT_MAX_ROWS, image_base: int | None = None,
                 offset_to_rva: Callable[[int], int | None] | None = None,
                 executable_sha256: str | None = None, consent_sha256: str | None = None) -> None:
        self._raw, self._max_rows = raw, max_rows
        self._ids = (artifact_sha256, side, run_id, config_digest)
        self._image_base, self._offset_to_rva = image_base, offset_to_rva
        self._executable_sha256, self._consent_sha256 = executable_sha256, consent_sha256

    def load(self) -> SourceResult:
        artifact_sha256, side, run_id, config_digest = self._ids
        raw_sha = hashlib.sha256(self._raw).hexdigest()
        if not self._raw.strip():   # FLOSS 3.1.1 prints nothing when the file holds no static string
            return self._result(None, (), {}, set(), {'static'}, raw_sha)
        doc = self._document()
        enabled = {'static': doc.analysis.enable_static_strings, 'stack': doc.analysis.enable_stack_strings,
                   'tight': doc.analysis.enable_tight_strings, 'decoded': doc.analysis.enable_decoded_strings}
        run_types = {kind for kind, on in enabled.items() if on}
        by_type = self._candidates(doc)
        totals = {kind: len(items) for kind, items in by_type.items()}
        take = _quota(totals, self._max_rows)
        rows = [row for kind in STRING_TYPES for _key, row in sorted(by_type[kind], key=lambda c: c[0])[:take[kind]]]
        rows.sort(key=_order)
        truncated = {kind for kind in STRING_TYPES if take[kind] < totals[kind]}
        return self._result(doc.metadata, tuple(rows), totals, truncated, run_types, raw_sha)

    def _document(self) -> floss.ResultDocument:
        data = load_json_strict(self._raw, max_bytes=DEFAULT_LIMITS['floss'].stdout_bytes,
                                max_depth=DEFAULT_LIMITS['floss'].json_depth)
        if not isinstance(data, dict) or set(data) != {'analysis', 'metadata', 'strings'}:
            raise ToolError('PT-TOOL-OUTPUT', 'FLOSS output is not a result document (wrong parser contract)')
        try:
            doc = floss.ResultDocument.model_validate(data)
        except ValidationError:
            raise ToolError('PT-TOOL-OUTPUT', 'FLOSS output violates the 3.x contract') from None
        if not doc.metadata.version.lstrip('v').startswith(f'{floss.SUPPORTED_MAJOR}.'):
            raise ToolError('PT-TOOL-OUTPUT', 'FLOSS output version is not 3.x')
        return doc

    def _rva(self, va: int | None, base: int) -> int | None:
        """A tool address becomes an RVA only against the image base the caller verified."""
        if va is None or not base or base != self._image_base or not 0 <= va - base < 2**32:
            return None
        return va - base

    def _candidates(self, doc: floss.ResultDocument) -> dict[str, list]:
        base = doc.metadata.imagebase
        by_type: dict[str, list] = {kind: [] for kind in STRING_TYPES}

        def make(value: str, kind: str, encoding: str, *, offset=None, rva=None, fn=None, site=None, data=None,
                 confidence: str) -> SourceRow:
            return SourceRow(_hash(value), display_text(value), len(value), kind, encoding, offset, rva, fn, site,
                             data, secret_kind(value), confidence)
        for kind, items in (('static', doc.strings.static_strings), ('language', doc.strings.language_strings)):
            for index, item in enumerate(items):
                rva = self._offset_to_rva(item.offset) if self._offset_to_rva else None
                by_type[kind].append(((item.offset, item.string, item.encoding, index), make(
                    item.string, kind, item.encoding, offset=item.offset, rva=rva, confidence=(
                        'unverified-location'))))
        for kind, items in (('stack', doc.strings.stack_strings), ('tight', doc.strings.tight_strings)):
            for index, item in enumerate(items):
                by_type[kind].append(((item.function, item.string, item.encoding, index), make(
                    item.string, kind, item.encoding, fn=self._rva(item.function, base), confidence='tool-reported')))
        for index, item in enumerate(doc.strings.decoded_strings):
            by_type['decoded'].append(((item.decoding_routine, item.address, item.string, index), make(
                item.string, 'decoded', item.encoding, fn=self._rva(item.decoding_routine, base),
                site=self._rva(item.decoded_at, base),
                data=self._rva(item.address, base) if item.address_type == 'GLOBAL' else None,
                confidence='tool-reported')))
        return by_type

    def _result(self, meta: floss.Metadata | None, rows: tuple[SourceRow, ...], totals: dict[str, int],
                truncated: set[str], run_types: set[str], raw_sha: str) -> SourceResult:
        artifact_sha256, side, run_id, config_digest = self._ids
        part = StringPart(
            source='floss', semantics_id=STATIC_SEMANTICS_ID, source_version=meta.version[:32] if meta else None,
            types=tuple(kind for kind in STRING_TYPES if kind in run_types), config_digest=config_digest,
            executable_sha256=self._executable_sha256, run_id=run_id, raw_sha256=raw_sha,
            consent_sha256=self._consent_sha256)
        return SourceResult(
            side=side, artifact_sha256=artifact_sha256, min_length=meta.min_length if meta else None,
            language=meta.language if meta else None, rows=rows, rows_seen=sum(totals.values()),
            stages=stage_states(run_types, totals, truncated), part=part)


def _order(row: SourceRow) -> tuple:
    """Same order as the adapter: type, file offset, then the located RVA (function RVA for emulation types)."""
    located = row.rva if row.rva is not None else row.fn_rva
    return row.type, -1 if row.offset is None else row.offset, -1 if located is None else located, row.value_sha256


def _quota(totals: dict[str, int], max_rows: int) -> dict[str, int]:
    """Per-type share of the row cap, spare capacity handed out in a fixed order (same rule as the adapter)."""
    take = {kind: min(totals[kind], int(max_rows * floss.TYPE_SHARE[kind])) for kind in STRING_TYPES}
    spare = max_rows - sum(take.values())
    for kind in floss.SPARE_ORDER:
        extra = min(spare, totals[kind] - take[kind])
        take[kind] += extra
        spare -= extra
    return take
