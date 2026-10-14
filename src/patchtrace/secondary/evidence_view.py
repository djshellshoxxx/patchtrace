"""Pure view-model for the multi-engine evidence panel (C6, docs/specs/multi-engine-evidence-panel.md §3).

No Qt and no I/O. Every engine's native value stays in its own cell, in that engine's own units: values
are never summed, averaged, ranked across engines or merged into one figure. Every string that came
from a tool, a file or a function name passes through :func:`sanitize_text` and is plain text.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Literal

from ..enrichment.identity import parse_address
from ..models import FunctionMatch
from .contracts import SecondaryMatch, SecondaryMatchSet
from .evidence import EvidenceAssessment, assess_reports
from .reconcile import Reconciliation, ReconciliationReport, reconcile

EngineId = Literal['ghidriff', 'bindiff', 'rz-diff']
SecondaryId = Literal['bindiff', 'rz-diff']
ENGINE_COLUMNS: tuple[EngineId, ...] = ('ghidriff', 'bindiff', 'rz-diff')  # fixed display order
SECONDARY_ENGINES: tuple[SecondaryId, ...] = ('bindiff', 'rz-diff')
ENGINE_NAMES: dict[str, str] = {'ghidriff': 'Ghidriff', 'bindiff': 'BinDiff', 'rz-diff': 'rz-diff'}
# Units are in the header AND in the cell prefix so a screenshot of one cell is self-describing.
# BinDiff confidence is algorithm-dependent and not documented as a probability (research flag F1),
# so the cell shows similarity plus the producing algorithm; confidence stays in the detail text.
# Ghidriff exposes no match score: the cell shows its raw match types (flag F3). PatchTrace's `quality`
# label (which carries Ghidriff's difflib text diff ratio when present) is shown raw in the details only.
ENGINE_UNITS: dict[str, str] = {'ghidriff': 'match type (raw)',
                                'bindiff': 'similarity / algorithm',
                                'rz-diff': 'byte similarity (raw bytes)'}
UiVerdict = Literal['agree', 'contested', 'single-engine', 'unknown']
RowVerdict = Literal['agree', 'contested', 'single-engine', 'unknown', 'engine-only']
CellKind = Literal['value', 'no-record', 'not-comparable', 'pairs-elsewhere', 'not-run', 'failed']
VERDICTS: tuple[UiVerdict, ...] = ('contested', 'unknown', 'single-engine', 'agree')
VERDICT_PRIORITY: dict[str, int] = {'contested': 0, 'unknown': 1, 'single-engine': 2, 'agree': 3,
                                    'engine-only': 4}
VERDICT_FROM_CODE: dict[str, UiVerdict] = {'corroborated': 'agree', 'contested': 'contested',
                                           'single-engine': 'single-engine', 'insufficient': 'unknown'}
VERDICT_LABELS: dict[str, str] = {'agree': 'Agree', 'contested': 'Contested', 'single-engine': 'Single engine',
                                  'unknown': 'Unknown', 'engine-only': 'Engine-only record'}
VERDICT_GLYPHS: dict[str, str] = {'agree': '=', 'contested': '!', 'single-engine': '1', 'unknown': '?',
                                  'engine-only': '+'}
VERDICT_MEANING: dict[str, str] = {
    'agree': 'Every engine with an address-comparable record pairs the same endpoints as Ghidriff. '
             'Not proof; engines can share disassembly artifacts.',
    'contested': 'At least one engine pairs an endpoint differently. Review identities manually. '
                 'This is about function pairing only.',
    'single-engine': 'Only Ghidriff has a comparable record; absence elsewhere is not contradiction.',
    'unknown': 'No engine output could be compared to this match. Not a negative vote.',
    'engine-only': 'A secondary engine record that no Ghidriff match covers; listed separately.',
}
ViewState = Literal['no-project', 'no-engines', 'ready', 'partial', 'failed', 'stale', 'unsupported', 'too-large']
EngineState = Literal['baseline', 'ready', 'not-run', 'failed', 'cancelled', 'unsupported', 'stale']

FOOTER = ('Scores are engine-native, uncalibrated and not comparable across engines. This panel assesses '
          'function pairing only, not vulnerabilities or patch validity.')
PROVENANCE_HEADER = 'PatchTrace engine evidence (function pairing only; not a vulnerability assessment)'
PROVENANCE_FOOTER = 'Scores are engine-native, uncalibrated and not comparable across engines.'
STATE_TEXT: dict[str, str] = {
    'no-project': 'Open a project to see engine evidence.',
    'no-engines': ('No secondary engine results for this project. Ghidriff is the only engine. Import a '
                   '.BinDiff file or run rz-diff on the Engines tab. No cross-engine comparison is available, '
                   'which is not a disagreement.'),
    'loading': 'Loading engine evidence...',
    'refreshing': 'Refreshing engine evidence...',
    'partial': ("{n} engine(s) did not produce results (see Engines tab). Their columns read 'not run'. "
                'Missing results are unknown, not disagreement.'),
    'failed': 'Engine evidence could not be assembled: {error}. The stored Ghidriff results are unchanged.',
    'stale': ('Engine evidence is stale: {reason}. It describes a different run/artifact pair than the one on '
              'screen. Values are kept for reference only.'),
    'too-large': 'Too many rows to display ({n}). Narrow the filter.',
    'ready': 'Engine evidence ready.',
}
STALE_PAIR = 'secondary results were produced for a different older/newer artifact pair'
STALE_RUN = 'the Ghidriff run changed after these results were computed'
STALE_REVISION = 'the project changed after these results were loaded'
ENGINE_STATE_TEXT: dict[str, str] = {'baseline': 'baseline', 'ready': 'ready (stored)', 'not-run': 'not run',
                                     'failed': 'failed', 'cancelled': 'cancelled', 'unsupported': 'unsupported',
                                     'stale': 'stale'}
CALIBRATION_FALLBACK = 'ordinal'

# Hard caps (spec §9.3).
DISPLAY_ROW_CAP = 100_000
ALTERNATIVES_CAP = 20
ENGINE_ONLY_CAP = 10_000
DETAIL_CAP = 2_000
LOG_LINES = 200
CLIPBOARD_CAP = 16 * 1024
CLIPBOARD_ROWS = 200
SEARCH_KEY_CAP = 512
TEXT_LIMIT = 200
VALUE_LIMIT = 32

# Words that must never appear in user-visible text produced here (spec §0.3). The sanctioned
# disclaimers below negate them ("not a vulnerability assessment") and are removed before checking.
BANNED = ('probab', 'likelihood', 'confidence %', 'vulnerab', 'exploit', 'safe', 'secure', 'fixed',
          'verified', 'proven', 'certain')

_UNSAFE = re.compile('[\x00-\x08\x0b-\x1f\x7f-\x9f‎‏‪-‮⁦-⁩  ]')


def sanitize_text(value: object, limit: int = TEXT_LIMIT) -> str:
    """Untrusted text for plain-text display: controls/bidi/line separators removed, length capped.

    Never HTML-escapes: Qt text roles and setPlainText do not interpret markup.
    """
    text = _UNSAFE.sub('', '' if value is None else str(value))
    return text if len(text) <= limit else text[:max(0, limit - 3)] + '...'


def _line(value: object, limit: int = TEXT_LIMIT) -> str:
    """Single-line sanitized text (newlines/tabs become spaces)."""
    return sanitize_text(str('' if value is None else value).replace('\n', ' ').replace('\t', ' '), limit)


def hex_address(value: int | None) -> str:
    return '-' if value is None else f'0x{value:X}'


def calibration_display_level() -> str:
    """C9 policy level when that package is importable, else the conservative 'ordinal' constant."""
    try:
        from ..calibration.policy import display_level  # type: ignore[import-not-found]
    except Exception:  # noqa: BLE001 - C9 may be absent or broken; never fail the panel on it
        return CALIBRATION_FALLBACK
    try:
        level = display_level()
    except Exception:  # noqa: BLE001
        return CALIBRATION_FALLBACK
    return _line(level, 32) if isinstance(level, str) and level else CALIBRATION_FALLBACK


def format_triage_index(index: int | None) -> str:
    """Opt-in only (decision D1). Raw number, no denominator, never a percent (research flag F2)."""
    if index is None:
        return 'Triage index: not assessed (uncalibrated, ordering aid only)'
    return f'Triage index {int(index)} (uncalibrated, ordering aid only)'


# ---- typed records ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EngineCell:
    engine: EngineId
    kind: CellKind
    text: str                       # display text, unit-prefixed, sanitized
    sort_key: int | None            # this engine's OWN native milli; never compared across engines
    accessible: str                 # spoken form with units
    raw: tuple[SecondaryMatch, ...] = ()  # formatted lazily by format_cell_detail
    note: str = ''


@dataclass(frozen=True, slots=True)
class Alternative:
    engine: str
    older_address: int | None
    newer_address: int | None
    older_name: str | None
    newer_name: str | None
    similarity_text: str
    confidence_text: str | None
    algorithm: str
    note: str
    rank: int | None = None


@dataclass(frozen=True, slots=True)
class EvidenceRow:
    match_id: str
    function_label: str
    address_label: str
    category: str
    manual: bool
    verdict: RowVerdict
    verdict_text: str
    reason: str
    cells: tuple[EngineCell, ...]
    alternatives: tuple[Alternative, ...]
    supporting: tuple[str, ...]
    contradicting: tuple[str, ...]
    missing: tuple[str, ...]
    limitations: tuple[str, ...]
    triage_index: int | None
    search_key: str
    order: int = 0                  # Ghidriff order, the stable tie-break
    older_address: int | None = None
    newer_address: int | None = None
    older_name: str = ''
    newer_name: str = ''
    ghidriff_types: str = ''
    ghidriff_quality: str = ''
    alternatives_more: int = 0


@dataclass(frozen=True, slots=True)
class EngineInfo:
    engine: EngineId
    label: str
    state: EngineState
    detail: str
    file_sha256: str | None = None
    older_sha256: str | None = None
    newer_sha256: str | None = None
    limitations: tuple[str, ...] = ()
    version: str | None = None


@dataclass(frozen=True, slots=True)
class EngineOutcomeView:
    """What the panel needs from one SPEC-28 `EngineOutcome` or capability probe (adapter seam)."""
    engine: SecondaryId
    status: Literal['ok', 'cached', 'failed', 'cancelled', 'unsupported', 'timeout']
    version: str | None = None
    error_code: str | None = None
    message: str = ''
    stderr_tail: str = ''
    duration_ms: int = 0
    run_id: str | None = None
    started_utc: str = ''
    match_set: SecondaryMatchSet | None = None
    run: object | None = None       # the EngineRun record, persisted on the GUI thread only


@dataclass(frozen=True)
class EvidenceViewModel:
    project_id: str
    ghidriff_run_id: str | None
    revision: int
    state: ViewState
    engines: tuple[EngineInfo, ...]
    rows: tuple[EvidenceRow, ...]
    engine_only: tuple[EvidenceRow, ...]
    counts: dict[str, int]
    warnings: tuple[str, ...]
    stale_reason: str | None
    error: str | None
    older_sha256: str
    newer_sha256: str
    calibration_level: str = CALIBRATION_FALLBACK
    engine_only_more: int = 0
    failed_engines: int = 0
    generation: int = 0
    total_rows: int = field(default=0)

    def engine(self, engine: str) -> EngineInfo | None:
        return next((info for info in self.engines if info.engine == engine), None)

    @property
    def status_text(self) -> str:
        return state_text(self)


def state_text(vm: EvidenceViewModel) -> str:
    if vm.state == 'failed':
        return STATE_TEXT['failed'].format(error=vm.error or 'unknown error')
    if vm.state == 'stale':
        return STATE_TEXT['stale'].format(reason=vm.stale_reason or 'unknown reason')
    if vm.state == 'partial':
        return STATE_TEXT['partial'].format(n=vm.failed_engines)
    if vm.state == 'too-large':
        return STATE_TEXT['too-large'].format(n=f'{vm.total_rows:,}')
    if vm.state == 'unsupported':
        reasons = [f'{info.label}: {info.detail}' for info in vm.engines if info.state == 'unsupported']
        return '\n'.join([STATE_TEXT['no-engines'], *reasons])
    if vm.state == 'ready':
        c = vm.counts
        return (f'{len(vm.rows):,} matches - {c.get("agree", 0):,} agree - {c.get("contested", 0):,} contested'
                f' - {c.get("single-engine", 0):,} single-engine - {c.get("unknown", 0):,} unknown')
    return STATE_TEXT[vm.state]


def resolve_state(*, project: bool, failed: bool = False, stale: bool = False, partial: bool = False,
                  has_sets: bool = True, all_unsupported: bool = False, too_large: bool = False) -> ViewState:
    """Precedence E0 > E5 > E8 > E6 > E1/E7 > E4 > E3 (spec §1.6)."""
    if not project:
        return 'no-project'
    if failed:
        return 'failed'
    if too_large:
        return 'too-large'
    if stale:
        return 'stale'
    if not has_sets:
        return 'unsupported' if all_unsupported else 'no-engines'
    return 'partial' if partial else 'ready'


# ---- cell formatting ---------------------------------------------------------------------------


def _candidate_order(c: SecondaryMatch):
    return (c.older_address if c.older_address is not None else -1,
            c.newer_address if c.newer_address is not None else -1, -c.similarity_milli)


GHIDRIFF_QUALITY_NOTE = ('Quality label (raw, recorded by PatchTrace): {quality}. When it shows a number, that is '
                         "Ghidriff's difflib text diff ratio over the decompiled code of the already paired "
                         'functions: a measure of how much they differ, not a match score.')


def format_ghidriff_cell(match: FunctionMatch) -> EngineCell:
    types = ', '.join(_line(t, VALUE_LIMIT) for t in match.match_types[:3]) or 'unknown'
    if len(match.match_types) > 3:
        types += f' (+{len(match.match_types) - 3})'
    note = GHIDRIFF_QUALITY_NOTE.format(quality=_line(match.quality, VALUE_LIMIT) or 'unknown')
    if match.manual:
        note += '\nmanual correction (not engine output)'
    return EngineCell('ghidriff', 'value', types, None, f'Ghidriff match type {types}', note=note)


def _value_text(engine: str, c: SecondaryMatch) -> tuple[str, str]:
    sim = _line(c.similarity_text, VALUE_LIMIT)
    if engine == 'bindiff':
        algo = _line(c.algorithm, VALUE_LIMIT)
        return f'sim {sim}  algo {algo}', f'BinDiff similarity {sim}, algorithm {algo}'
    return f'byte sim {sim}', f'rz-diff byte similarity {sim}'


def format_bindiff_cell(rec: Reconciliation) -> EngineCell:
    return secondary_cell('bindiff', rec)


def format_rzdiff_cell(rec: Reconciliation) -> EngineCell:
    return secondary_cell('rz-diff', rec)


def secondary_cell(engine: str, rec: Reconciliation) -> EngineCell:
    name = ENGINE_NAMES[engine]
    candidates = tuple(sorted(rec.secondary, key=_candidate_order))
    note = _line(rec.note)
    if rec.status == 'agreement' and candidates:
        text, spoken = _value_text(engine, candidates[0])
        return EngineCell(engine, 'value', text, candidates[0].similarity_milli, spoken, candidates, note)
    if rec.status == 'disagreement':
        key = candidates[0].similarity_milli if candidates else None
        return EngineCell(engine, 'pairs-elsewhere', 'pairs elsewhere', key,
                          f'{name} pairs elsewhere', candidates, note)
    if rec.status == 'not-comparable':
        return EngineCell(engine, 'not-comparable', 'n/c', None, f'{name} not comparable', (), note)
    return EngineCell(engine, 'no-record', 'no record', None, f'{name} no record', (), note)


def state_cell(engine: str, state: str) -> EngineCell:
    name = ENGINE_NAMES[engine]
    if state in ('failed', 'cancelled', 'unsupported'):
        return EngineCell(engine, 'failed', state, None, f'{name} {state}, not a vote')
    return EngineCell(engine, 'not-run', 'not run', None, f'{name} not run')


def format_candidate(c: SecondaryMatch) -> str:
    parts = [f'older {hex_address(c.older_address)} {_line(c.older_name or "", 80)}'.rstrip(),
             f'-> newer {hex_address(c.newer_address)} {_line(c.newer_name or "", 80)}'.rstrip(),
             f' similarity {_line(c.similarity_text, VALUE_LIMIT)} (milli {c.similarity_milli})']
    if c.confidence_text is not None:
        parts.append(f' confidence value {_line(c.confidence_text, VALUE_LIMIT)} (milli {c.confidence_milli}; '
                     'algorithm-dependent, not a probability)')
    parts.append(f' algorithm "{_line(c.algorithm, 80)}"')
    if c.flags:
        parts.append(' flags ' + ''.join(c.flags))
    return ' '.join(parts)


def format_cell_detail(cell: EngineCell) -> str:
    """Multi-line plain detail for tooltips and the detail pane; built on demand (lazy), capped."""
    name = ENGINE_NAMES[cell.engine]
    lines = [f'{name} ({ENGINE_UNITS[cell.engine]}): {cell.text}']
    if cell.kind == 'not-comparable':
        lines.append('many-to-many or unparsable address')
    if cell.engine == 'rz-diff':
        lines.append('raw-byte Levenshtein, not semantic')
    for candidate in cell.raw[:ALTERNATIVES_CAP]:
        lines.append('  ' + format_candidate(candidate))
    if len(cell.raw) > ALTERNATIVES_CAP:
        lines.append(f'  +{len(cell.raw) - ALTERNATIVES_CAP} more')
    if cell.note:
        lines.append(cell.note)
    text = '\n'.join(lines)
    return text if len(text) <= DETAIL_CAP else text[:DETAIL_CAP - 3] + '...'


def format_alternative(alt: Alternative) -> str:
    label = 'Ghidriff (baseline)' if alt.engine == 'ghidriff' else ENGINE_NAMES.get(alt.engine, alt.engine)
    text = (f'{label}: older {hex_address(alt.older_address)} {alt.older_name or ""}'.rstrip()
            + f' -> newer {hex_address(alt.newer_address)} {alt.newer_name or ""}'.rstrip())
    if alt.similarity_text:
        text += f'  similarity {alt.similarity_text}'
    if alt.confidence_text:
        text += f'  confidence value {alt.confidence_text}'
    if alt.algorithm:
        text += f'  algorithm "{alt.algorithm}"'
    if alt.note:
        text += f'  ({alt.note})'
    return text


def _alternative(engine: str, c: SecondaryMatch, note: str, rank: int | None = None) -> Alternative:
    return Alternative(engine, c.older_address, c.newer_address,
                       _line(c.older_name, 80) if c.older_name else None,
                       _line(c.newer_name, 80) if c.newer_name else None,
                       _line(c.similarity_text, VALUE_LIMIT),
                       _line(c.confidence_text, VALUE_LIMIT) if c.confidence_text is not None else None,
                       _line(c.algorithm, 80), note, rank)


def _alternatives(engine: str, rec: Reconciliation) -> list[Alternative]:
    pair = (rec.older_address, rec.newer_address)
    out = [_alternative(engine, c, 'pairs elsewhere') for c in sorted(rec.secondary, key=_candidate_order)
           if (c.older_address, c.newer_address) != pair]
    out += [_alternative(engine, a.candidate, f'alternative rank {a.rank}', a.rank)
            for a in sorted(rec.alternatives, key=lambda a: (a.rank, a.anchor_side, a.anchor_address))]
    return out


# ---- filtering ---------------------------------------------------------------------------------


def normalize_search(search: str) -> str:
    query = search.strip().lower()
    return query[2:] if query.startswith('0x') else query


def filter_rows(rows: Sequence[EvidenceRow], verdicts: Iterable[str], search: str = '',
                hide_agree: bool = False) -> list[int]:
    """Indices (not copies) of rows passing the verdict set, the search and 'Hide agreed'."""
    allowed = frozenset(verdicts) - ({'agree'} if hide_agree else set())
    query = normalize_search(search)
    if not query:
        return [i for i, row in enumerate(rows) if row.verdict in allowed]
    return [i for i, row in enumerate(rows) if row.verdict in allowed and query in row.search_key]


# ---- view-model construction ------------------------------------------------------------------


def _side(records) -> tuple[str, str | None, str]:
    if not records:
        return '', None, '-'
    first = records[0]
    name = _line(first.name, 120)
    address = _line(first.address or '', 40) or '?'
    more = f' (+{len(records) - 1})' if len(records) > 1 else ''
    return name, first.address, address + more


def _search_key(older_name: str, newer_name: str, raws: Iterable[str | None], ints: Iterable[int | None]) -> str:
    parts = [older_name, newer_name]
    for raw in raws:
        if raw:
            parts.append(normalize_search(raw))
    for value in ints:
        if value is not None:
            parts.append(f'{value:x}')
    return ' '.join(parts).lower()[:SEARCH_KEY_CAP]


def engine_infos(sets: Sequence[SecondaryMatchSet], outcomes: Sequence[EngineOutcomeView],
                 older_sha256: str, newer_sha256: str, ghidriff_version: str | None = None) -> tuple[EngineInfo, ...]:
    by_engine = {s.engine: s for s in sets}
    last = {o.engine: o for o in outcomes}
    infos = [EngineInfo('ghidriff', 'Ghidriff (baseline)', 'baseline', 'Primary result in the project',
                        version=_line(ghidriff_version, 40) if ghidriff_version else None,
                        older_sha256=older_sha256, newer_sha256=newer_sha256)]
    for engine in SECONDARY_ENGINES:
        name = ENGINE_NAMES[engine]
        outcome = last.get(engine)
        match_set = by_engine.get(engine)
        failed = outcome is not None and outcome.status in ('failed', 'cancelled', 'unsupported', 'timeout')
        if match_set is not None:
            version = _line(match_set.engine_version, 40)
            pair_ok = (match_set.older_sha256, match_set.newer_sha256) == (older_sha256, newer_sha256)
            detail = f'stored set {match_set.file_sha256[:12]}'
            if failed:
                detail += f'; latest run {outcome.status}: {_line(outcome.error_code or "", 40)}'.rstrip(': ')
            infos.append(EngineInfo(engine, f'{name} {version}', 'ready' if pair_ok else 'stale', detail,
                                    match_set.file_sha256, match_set.older_sha256, match_set.newer_sha256,
                                    tuple(_line(x) for x in match_set.limitations), version))
            continue
        if failed:
            state: EngineState = 'failed' if outcome.status in ('failed', 'timeout') else outcome.status
            first = (outcome.message or '').splitlines()[0] if outcome.message else ''
            detail = _line(f'{outcome.error_code or outcome.status}: {first}'.rstrip(': '))
            label = f'{name} {_line(outcome.version, 40)}' if outcome.version else name
            infos.append(EngineInfo(engine, label, state, detail, version=outcome.version))
            continue
        infos.append(EngineInfo(engine, name, 'not-run', 'No stored result for this project'))
    return tuple(infos)


def empty_model(state: ViewState, *, project_id: str = '', run_id: str | None = None, revision: int = 0,
                engines: tuple[EngineInfo, ...] = (), warnings: tuple[str, ...] = (),
                older_sha256: str = '', newer_sha256: str = '', error: str | None = None,
                stale_reason: str | None = None, calibration_level: str = CALIBRATION_FALLBACK,
                generation: int = 0) -> EvidenceViewModel:
    return EvidenceViewModel(project_id, run_id, revision, state, engines, (), (), dict.fromkeys(VERDICTS, 0),
                             warnings, stale_reason, error, older_sha256, newer_sha256, calibration_level,
                             generation=generation)


def failed_model(message: str, **kw) -> EvidenceViewModel:
    return empty_model('failed', error=_line(message, 400), **kw)


class Cancelled(Exception):
    """The load was cancelled; the caller drops the result."""


def build_view_model(*, project_id: str, run_id: str | None, revision: int, older_sha256: str,
                     newer_sha256: str, matches: Sequence[FunctionMatch], sets: Sequence[SecondaryMatchSet],
                     outcomes: Sequence[EngineOutcomeView] = (), warnings: Sequence[str] = (),
                     stale_reason: str | None = None, calibration_level: str = CALIBRATION_FALLBACK,
                     generation: int = 0, ghidriff_version: str | None = None,
                     cancel: Callable[[], bool] = lambda: False) -> EvidenceViewModel:
    """Map stored sets + Ghidriff matches to rows. Sets must be one per engine (the service selects)."""
    infos = engine_infos(sets, outcomes, older_sha256, newer_sha256, ghidriff_version)
    common = dict(project_id=project_id, run_id=run_id, revision=revision, engines=infos,
                  older_sha256=older_sha256, newer_sha256=newer_sha256, calibration_level=calibration_level,
                  generation=generation)
    secondary = [i for i in infos if i.engine != 'ghidriff']
    failed_engines = sum(1 for i in secondary if i.state in ('failed', 'cancelled', 'unsupported'))
    if not sets:
        all_unsupported = bool(secondary) and all(i.state == 'unsupported' for i in secondary)
        state = resolve_state(project=True, has_sets=False, all_unsupported=all_unsupported)
        return empty_model(state, warnings=tuple(warnings), **common)
    reports: tuple[ReconciliationReport, ...] = tuple(reconcile(matches, s) for s in sets)
    if cancel():
        raise Cancelled()
    try:
        assessment: EvidenceAssessment = assess_reports(reports)
    except ValueError as exc:
        return failed_model(f'PT-EVIDENCE-ASSEMBLY: {exc}', warnings=tuple(warnings), **common)
    by_engine = {r.engine: r for r in reports}
    # Index every report once (spec §9.3): no per-match linear scans.
    rec_index = {engine: {row.match_id: row for row in report.rows} for engine, report in by_engine.items()}
    report_limits = {engine: tuple(_line(x) for x in report.limitations) for engine, report in by_engine.items()}
    order = {m.id: i for i, m in enumerate(matches)}
    match_by_id = {m.id: m for m in matches}
    states = {i.engine: i.state for i in infos}
    rows: list[EvidenceRow] = []
    counts = dict.fromkeys(VERDICTS, 0)
    for n, ev in enumerate(assessment.rows):
        if n % 2048 == 0 and cancel():
            raise Cancelled()
        m = match_by_id[ev.match_id]
        verdict = VERDICT_FROM_CODE[ev.verdict]  # total; a KeyError is a bug and surfaces as E5
        counts[verdict] += 1
        cells = []
        alternatives: list[Alternative] = []
        older_addr = newer_addr = None
        for engine in ENGINE_COLUMNS:
            if engine == 'ghidriff':
                cells.append(format_ghidriff_cell(m))
                continue
            rec = rec_index.get(engine, {}).get(ev.match_id)
            if rec is None:
                cells.append(state_cell(engine, states.get(engine, 'not-run')))
                continue
            older_addr, newer_addr = rec.older_address, rec.newer_address
            cells.append(secondary_cell(engine, rec))
            if rec.status == 'disagreement':
                alternatives += _alternatives(engine, rec)
        older_name, older_raw, older_text = _side(m.older)
        newer_name, newer_raw, newer_text = _side(m.newer)
        if older_addr is None and newer_addr is None:
            older_addr, newer_addr = parse_address(older_raw), parse_address(newer_raw)
        label = newer_name or older_name or f'sub_{(newer_addr or older_addr or 0):x}'
        limitations: dict[str, None] = {}
        for item in ev.limitations:
            limitations[_line(item)] = None
        for engine in by_engine:
            for item in report_limits[engine]:
                limitations[f'{ENGINE_NAMES.get(engine, engine)}: {item}'] = None
        if alternatives:
            alternatives.append(Alternative('ghidriff', older_addr, newer_addr, older_name or None,
                                            newer_name or None, '', None, '', 'baseline pairing'))
        types = ', '.join(_line(t, VALUE_LIMIT) for t in m.match_types) or 'unknown'
        rows.append(EvidenceRow(
            m.id, label, f'{older_text} > {newer_text}', _line(m.category, 32), m.manual, verdict,
            VERDICT_LABELS[verdict], _line(ev.explanation, 400), tuple(cells),
            tuple(alternatives[:ALTERNATIVES_CAP]), ev.supporting_engines, ev.contradicting_engines,
            ev.missing_engines, tuple(limitations), ev.evidence_index,
            _search_key(older_name.lower(), newer_name.lower(), (older_raw, newer_raw), (older_addr, newer_addr)),
            order.get(m.id, 0), older_addr, newer_addr, older_name, newer_name, _line(types, 400),
            _line(m.quality, VALUE_LIMIT), max(0, len(alternatives) - ALTERNATIVES_CAP)))
    rows.sort(key=lambda r: (VERDICT_PRIORITY[r.verdict], r.order))
    engine_only, more = _engine_only_rows(reports, len(rows))
    stale = stale_reason is not None or any(i.state == 'stale' for i in infos)
    reason = stale_reason or (STALE_PAIR if any(i.state == 'stale' for i in infos) else None)
    state = resolve_state(project=True, stale=stale, partial=failed_engines > 0,
                          too_large=len(rows) > DISPLAY_ROW_CAP)
    return EvidenceViewModel(project_id, run_id, revision, state, infos,
                             tuple(rows) if state != 'too-large' else (), engine_only, counts,
                             tuple(_line(w, 400) for w in warnings), reason, None, older_sha256, newer_sha256,
                             calibration_level, more, failed_engines, generation, len(rows))


def _engine_only_rows(reports: Sequence[ReconciliationReport], start: int) -> tuple[tuple[EvidenceRow, ...], int]:
    out: list[EvidenceRow] = []
    total = 0
    for report in reports:
        engine = report.engine
        for c in sorted(report.secondary_only, key=_candidate_order):
            total += 1
            if len(out) >= ENGINE_ONLY_CAP:
                continue
            cells = []
            for column in ENGINE_COLUMNS:
                if column == 'ghidriff':
                    cells.append(EngineCell('ghidriff', 'no-record', 'no record', None, 'Ghidriff no record'))
                elif column == engine:
                    text, spoken = _value_text(engine, c)
                    cells.append(EngineCell(column, 'value', text, c.similarity_milli, spoken, (c,),
                                            'engine-only record'))
                else:
                    cells.append(EngineCell(column, 'not-comparable', 'n/c', None,
                                            f'{ENGINE_NAMES[column]} not comparable'))
            older_name = _line(c.older_name or '', 120)
            newer_name = _line(c.newer_name or '', 120)
            label = newer_name or older_name or f'sub_{(c.newer_address or c.older_address or 0):x}'
            ident = f'{engine}:{hex_address(c.older_address)}>{hex_address(c.newer_address)}'
            out.append(EvidenceRow(
                ident, label, f'{hex_address(c.older_address)} > {hex_address(c.newer_address)}', 'engine-only',
                False, 'engine-only', VERDICT_LABELS['engine-only'], VERDICT_MEANING['engine-only'], tuple(cells),
                (), (), (), (), (f'{ENGINE_NAMES[engine]} record not covered by any Ghidriff match',), None,
                _search_key(older_name.lower(), newer_name.lower(), (), (c.older_address, c.newer_address)),
                start + len(out), c.older_address, c.newer_address, older_name, newer_name))
    return tuple(out), max(0, total - ENGINE_ONLY_CAP)


# ---- detail and provenance text ---------------------------------------------------------------


def _engine_line(vm: EvidenceViewModel, row: EvidenceRow, cell: EngineCell) -> str:
    info = vm.engine(cell.engine)
    label = info.label if info else ENGINE_NAMES[cell.engine]
    if cell.engine == 'ghidriff':
        return f'Ghidriff: types={row.ghidriff_types or "unknown"} quality={row.ghidriff_quality or "unknown"}'
    if cell.kind in ('value', 'pairs-elsewhere') and cell.raw:
        text = f'{label}: {format_candidate(cell.raw[0])}'
        if len(cell.raw) > 1:
            text += f' (+{len(cell.raw) - 1} more candidate(s))'
        if cell.kind == 'pairs-elsewhere':
            text += ' [pairs elsewhere]'
        if info and info.file_sha256:
            text += f'  [set sha256 {info.file_sha256}]'
        return text
    return f'{label}: {cell.text}'


def format_row_detail(vm: EvidenceViewModel, row: EvidenceRow, show_index: bool = False) -> str:
    """Detail pane text: plain, sectioned, deterministic."""
    lines = [f'Match: {row.function_label}   {row.address_label}',
             f'Verdict: {row.verdict_text} - {VERDICT_MEANING[row.verdict]}',
             f'Reason: {row.reason}']
    if row.manual:
        lines.append('Ghidriff side: manual correction (not engine output)')
    if show_index and row.verdict != 'engine-only':
        lines.append(format_triage_index(row.triage_index))
    lines += ['', 'Per-engine native values (separate units, never combined):']
    for cell in row.cells:
        lines.append('  ' + format_cell_detail(cell).replace('\n', '\n    '))
    lines += ['', 'Alternatives (engine pairs this endpoint with a different counterpart):']
    lines += ['  ' + format_alternative(a) for a in row.alternatives] or ['  none']
    if row.alternatives_more:
        lines.append(f'  +{row.alternatives_more} more')
    lines += ['', 'Limitations:'] + [f'- {x}' for x in row.limitations] + ['', 'Provenance:']
    for info in vm.engines:
        sha = f' | file sha256 {info.file_sha256[:12]}..' if info.file_sha256 else ''
        lines.append(f'  {info.label} | {ENGINE_STATE_TEXT[info.state]}{sha}')
    lines += [f'  Older SHA-256: {vm.older_sha256}', f'  Newer SHA-256: {vm.newer_sha256}',
              f'  Calibration display level: {vm.calibration_level} (no calibrated values are shown)',
              '', FOOTER]
    return '\n'.join(lines)


def format_provenance_block(vm: EvidenceViewModel, row: EvidenceRow, show_index: bool = False) -> str:
    """Deterministic LF-only plain text for the clipboard (spec §1.9), capped at 16 KiB."""
    stale = 'yes' if vm.state == 'stale' else 'no'
    index = ('hidden by default' if not show_index else
             format_triage_index(row.triage_index).removeprefix('Triage index').strip(': '))
    lines = [PROVENANCE_HEADER,
             f'Project: {vm.project_id} | Ghidriff run: {vm.ghidriff_run_id or "none"} | STALE: {stale}'
             + (f' ({vm.stale_reason})' if vm.state == 'stale' and vm.stale_reason else ''),
             f'Match: {row.match_id} | older {hex_address(row.older_address)} {row.older_name}'.rstrip()
             + f' -> newer {hex_address(row.newer_address)} {row.newer_name}'.rstrip(),
             f'Verdict: {row.verdict_text} (code: {row.verdict}) | Triage index: {index}']
    lines += [_engine_line(vm, row, cell) for cell in row.cells]
    lines += [f'Older SHA-256: {vm.older_sha256}', f'Newer SHA-256: {vm.newer_sha256}', 'Limitations:']
    lines += [f'- {x}' for x in row.limitations] or ['- none recorded']
    lines.append(PROVENANCE_FOOTER)
    text = '\n'.join(sanitize_text(line, CLIPBOARD_CAP) for line in lines)
    return text if len(text) <= CLIPBOARD_CAP else text[:CLIPBOARD_CAP - 12] + '\n(truncated)'


def format_provenance_blocks(vm: EvidenceViewModel, rows: Sequence[EvidenceRow], show_index: bool = False) -> str:
    chosen = rows[:CLIPBOARD_ROWS]
    blocks = [format_provenance_block(vm, row, show_index) for row in chosen]
    text = '\n\n'.join(blocks)
    if len(rows) > CLIPBOARD_ROWS:
        text += f'\n({len(rows) - CLIPBOARD_ROWS} more omitted)'
    if len(text) > CLIPBOARD_CAP:
        cut = text[:CLIPBOARD_CAP - 40]
        text = cut + f'\n({len(rows) - cut.count(PROVENANCE_HEADER)} more omitted)'
    return text

