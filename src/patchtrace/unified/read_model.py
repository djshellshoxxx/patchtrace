"""SPEC-31 read model (07 s4): the Qt-free view of a published unified result. Pure: no Qt, no process, no network.

`load_unified` turns a verified result directory into an immutable `UnifiedViewModel` (any thread; a damaged or
newer result is state U5, never an exception). Rows are built once from the strict row and fact records and kept
light (about 1 KiB each, so the display cap L-33 of 100,000 rows fits); the verbose text of a row is read lazily from
the sidecar (`read_text.SidecarRecords`). The Qt table model owns filter and order over an index list: `filter_rows`
and `sort_rows` return indices and `cell_text` is O(1), so nothing is re-sorted or re-formatted at paint time.

Rules inherited from the C6 evidence panel (07 s0): native values live only in their own source cell and are never
combined, a missing record is unknown (never a vote), a contested row is never hidden or demoted by a default,
display level stays `ordinal`, every string a person can read passes `sanitize_text`, and there is no probability
wording (the tests sweep everything this module can produce).

Default order (07 s7): contested, material, review, cosmetic (COS-PSEUDO/1), unconfirmed pairings, one-sided rows,
matched rows without a change signal, cosmetic (structural proof), unchanged. Inside a group: library rows after
first-party rows (F16), trace-argument constants last (F17), then severity (05 s2.6), attention order and RVA.
`unchanged` and structurally proven `cosmetic` rows are collapsed by default and counted (U-03).
"""
from __future__ import annotations

import functools
import re
from collections import Counter
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal, NamedTuple

from ..secondary.evidence_view import (
    CLIPBOARD_CAP,
    CLIPBOARD_ROWS,
    SEARCH_KEY_CAP,
    calibration_display_level,
    normalize_search,
)
from . import read_text, store
from .contracts import (
    DECISIONS,
    MATERIALITIES,
    SEMANTIC_CLASSES,
    STRUCTURAL_PROOFS,
    Atom,
    ChangeFacts,
    UnifiedMatch,
    UnifiedResultManifest,
)
from .limits import DEFAULT_LIMITS, UnifiedError, UnifiedLimits
from .read_text import (
    CLASS_NAMES,
    DECISION_GLYPHS,
    DECISION_LABELS,
    MATERIALITY_LABELS,
    TIER_NAMES,
    ContextFragment,
    RecordSource,
    SidecarRecords,
    clean,
    on_pair,
)
from .registry import REGISTRY, TIER_RANK, Registry

if TYPE_CHECKING:
    from ..service import ProjectService

UState = Literal['U0', 'U1', 'U2', 'U3', 'U4', 'U5', 'U6', 'U7', 'U8']
CellKind = Literal['value', 'pairs-elsewhere', 'no-record', 'not-run']
DISPLAY_ROW_CAP = DEFAULT_LIMITS.l33_displayed_rows
EDIT_GROUP_MIN = 3
ATTENTION_NONE = 2**31
CELL_LIMIT = 80
LABEL_LIMIT = 120

STATE_TEXT: dict[str, str] = {
    'U0': 'Open a project to see the unified comparison.',
    'U1': ('No unified result yet. The primary Ghidriff view is unchanged. Run unified analysis to add derived '
           'evidence from all stored engines.'),
    'U2': 'Unified analysis: {stage} {done}/{total}',
    'U2-indeterminate': 'Unified analysis: {stage} (no counts available)',
    'U4': 'Partial unified result: {reasons}. Missing evidence is unknown, not disagreement.',
    'U5': ('The unified result could not be produced: {error}. Earlier results and the primary Ghidriff results are '
           'unchanged.'),
    'U6': 'The unified result is stale: {reason}. It is shown for reference only.',
    'U7': ('Ghidra extraction is not configured; the unified result uses stored engine outputs only (no '
           'instruction-level change facts).'),
    'U8': 'Too many rows to display ({n}). Narrow the filter.',
}
STALE_REASONS: dict[str, str] = {
    'older_sha256': 'the older artifact changed', 'newer_sha256': 'the newer artifact changed',
    'orientation': 'the comparison direction changed', 'ghidriff_raw_sha256': 'the Ghidriff run changed',
    'ir_older_digest': 'the older ProgramIR changed', 'ir_newer_digest': 'the newer ProgramIR changed',
    'sources': 'the stored engine results changed', 'manual_digest': 'a manual correction changed the inputs',
    'config_digest': 'the engine configuration changed'}
STALE_FALLBACK = 'the project changed after this result was computed'


# --- chips: verdict and tier vocabulary as data (the Qt side maps `tone` to theme tokens) ------------------------------


@dataclass(frozen=True, slots=True)
class Chip:
    glyph: str      # ASCII and unique inside its table: colour is never the only carrier
    text: str
    tone: str       # theme token: ok | caution | info | muted | alt | plain; never an error colour for a conflict
    spoken: str


_DECISION_TONES = {'matched': 'ok', 'tentative': 'info', 'candidate': 'muted', 'contested': 'caution',
                   'ambiguous': 'alt', 'older-only': 'muted', 'newer-only': 'info', 'unknown': 'muted'}
_MATERIALITY_GLYPHS = {'unchanged': '=', 'cosmetic': '~', 'material': '*', 'review': '?', 'unknown': '.',
                       'not-applicable': '-'}
_MATERIALITY_TONES = {'unchanged': 'muted', 'cosmetic': 'muted', 'material': 'alt', 'review': 'info',
                      'unknown': 'muted', 'not-applicable': 'muted'}
_TIER_TONES = {'M': 'alt', 'A': 'ok', 'B': 'info', 'C': 'muted', 'W': 'plain'}
DECISION_CHIPS: dict[str, Chip] = {d: Chip(DECISION_GLYPHS[d], DECISION_LABELS[d], _DECISION_TONES[d],
                                           f'Decision: {DECISION_LABELS[d]}') for d in DECISIONS}
MATERIALITY_CHIPS: dict[str, Chip] = {m: Chip(_MATERIALITY_GLYPHS[m], MATERIALITY_LABELS[m], _MATERIALITY_TONES[m],
                                              f'Change: {MATERIALITY_LABELS[m]}') for m in MATERIALITIES}
TIER_CHIPS: dict[str, Chip] = {t: Chip(t, f'Tier {t}', _TIER_TONES[t], f'Evidence tier {t}: {TIER_NAMES[t]}')
                               for t in TIER_NAMES}
BADGES: dict[str, str] = {d: f'[{c.glyph}] {c.text}' for d, c in DECISION_CHIPS.items()}

# --- ordering (07 s7, 05 s2.6, F16, F17) -------------------------------------------------------------------------------

_SEVERITY_LEVELS: tuple[tuple[str, ...], ...] = (
    ('callee', 'call-added', 'call-removed'), ('condition', 'comparison'), ('constant@test',), ('struct-offset',),
    ('data-ref',), ('block-added', 'block-removed'), ('eh',), ('constant',), ('cfg',), ('string',), ('unknown',),
    ('frame',), ('size-only',), ('refcount-only',), ('address-only',), ('register-only',), ('name-only',),
    ('layout-only',))
SEVERITY: dict[str, int] = {name: rank for rank, names in enumerate(_SEVERITY_LEVELS) for name in names}
SEVERITY_NONE = len(_SEVERITY_LEVELS)
TEST_MNEMONICS = frozenset({'cmp', 'test', 'and', 'or', 'shl', 'shr', 'sal', 'sar', 'rol', 'ror', 'bt', 'bts', 'btr',
                            'btc'})  # a constant here is a compare, test, mask or shift operand (05 s2.6)
KEY_GROUP, KEY_LIBRARY, KEY_TRACE, KEY_SEVERITY, KEY_ATTENTION, KEY_RVA = range(6)
DECISION_PRIORITY = {d: i for i, d in enumerate(('contested', 'matched', 'tentative', 'candidate', 'ambiguous',
                                                 'older-only', 'newer-only', 'unknown'))}
MATERIALITY_PRIORITY = {m: i for i, m in enumerate(('material', 'review', 'unknown', 'not-applicable', 'cosmetic',
                                                    'unchanged'))}
GROUP_NAMES = ('contested', 'material', 'review', 'cosmetic (decompiler-relative)', 'unconfirmed pairing',
               'one-sided', 'no change signal', 'cosmetic (structural proof)', 'unchanged')


def group_rank(decision: str, materiality: str, proof: str | None) -> int:
    """Index into `GROUP_NAMES`; the first matching group wins, so a contested row never leaves group 0."""
    if decision == 'contested':
        return 0
    if materiality == 'material':
        return 1
    if materiality == 'review':
        return 2
    if materiality == 'cosmetic' and proof not in STRUCTURAL_PROOFS:
        return 3
    if decision in ('tentative', 'candidate', 'ambiguous'):
        return 4
    if decision in ('older-only', 'newer-only'):
        return 5
    if materiality == 'unchanged':
        return 8
    return 7 if materiality == 'cosmetic' else 6


def is_collapsed(decision: str, materiality: str, proof: str | None) -> bool:
    """U-03: only a pairing that is at least proposed AND whose change is `unchanged` or structurally proven
    `cosmetic` is collapsed. A contested, ambiguous or one-sided row and COS-PSEUDO/1 (decompiler-relative) stay."""
    if decision not in ('matched', 'tentative', 'candidate'):
        return False
    return materiality == 'unchanged' or (materiality == 'cosmetic' and proof in STRUCTURAL_PROOFS)


# --- types ----------------------------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SourceCell:
    source: str
    kind: CellKind
    text: str                  # that source's own native text with its unit words, sanitised
    sort_key: int | None       # this source's OWN native milli; never compared across sources
    spoken: str = ''           # AccessibleTextRole with units, for example "BinDiff similarity 0.97, algorithm ..."


@dataclass(frozen=True, slots=True)
class SourceInfo:
    source: str
    display: str
    unit_caption: str
    tooltip_id: str
    version: str
    known: bool                # False: an id this build has no registry row for (rendered generically)


@dataclass(frozen=True, slots=True)
class UnifiedRowView:
    row_id: str
    function_label: str
    address_label: str
    decision: str
    decision_text: str
    glyph: str
    materiality: str
    materiality_text: str
    change_text: str
    classes: tuple[str, ...]            # change classes, most severe first
    proof: str | None                   # the named proof behind a cosmetic or unchanged verdict
    tier: str                           # strongest supporting tier, '' when none
    flags: tuple[str, ...]
    cells: tuple[SourceCell, ...]       # one per `UnifiedViewModel.sources`, in that order
    source_ids: frozenset[str]          # sources with a record on this row (a value or "pairs elsewhere")
    ghidriff_match_id: str | None
    edit_group: int                     # F10 view-level group id; 0 = none
    collapsed: bool
    sort_keys: tuple[int, ...]          # KEY_* order: group, library, trace, severity, attention, rva
    search_key: str                     # lower-case names and hex RVAs, at most SEARCH_KEY_CAP characters


@dataclass(frozen=True, slots=True)
class EditGroup:
    group_id: int
    size: int
    summary: str


@dataclass(frozen=True)
class UnifiedViewModel:
    project_id: str
    run_id: str | None
    revision: int
    state: UState
    state_text: str                     # the status line: the summary when ready, else the notice of the state
    sources: tuple[SourceInfo, ...]
    rows: tuple[UnifiedRowView, ...]
    counts: Mapping[str, int]           # rows, hidden, decision/<d>, change/<m>
    warnings: tuple[str, ...]           # the result's limitations
    stale_reason: str | None
    display_level: str
    result_id: str | None = None
    manifest: UnifiedResultManifest | None = None
    banners: tuple[str, ...] = ()       # every notice to show above the table, highest precedence first
    absent_sources: tuple[str, ...] = ()
    evidence_classes: Mapping[str, int] = field(default_factory=lambda: MappingProxyType({}))   # rows per class
    edit_groups: tuple[EditGroup, ...] = ()
    records: RecordSource | None = None
    error: str | None = None


@dataclass(frozen=True)
class UnifiedLoadRequest:
    """Immutable, built on the owner (GUI) thread: everything `load_unified` needs, so a worker thread never touches
    the project database. `loaded` is the owner-thread read of the pointer row (`pipeline.load_current`)."""
    project_id: str | None
    run_id: str | None = None
    revision: int = 0
    loaded: store.LoadedResult | None = None
    changed_inputs: tuple[str, ...] = ()        # result_key inputs that differ from the current plan (stale reason)
    error: str | None = None                    # an owner-side failure, already "<code>: <message>"
    extraction_configured: bool = False         # drives the U7 notice
    attention: Mapping[str, int] = field(default_factory=dict)   # Ghidriff match id -> attention/1 order (read-only)
    registry: Registry = REGISTRY
    limits: UnifiedLimits = DEFAULT_LIMITS


class Cancelled(Exception):
    """The load was cancelled; the caller drops the result (not a data problem)."""


def _never() -> bool:
    return False


# --- states ------------------------------------------------------------------------------------------------------------------


def progress_text(stage: str, done: int, total: int | None) -> str:
    """U2 status text while a run or load is in progress."""
    if total:
        return STATE_TEXT['U2'].format(stage=clean(stage, 48), done=done, total=total)
    return STATE_TEXT['U2-indeterminate'].format(stage=clean(stage, 48))


def stale_reason_text(changed_inputs: Sequence[str]) -> str:
    known = [STALE_REASONS[name] for name in changed_inputs if name in STALE_REASONS]
    return '; '.join(known) if known else STALE_FALLBACK


def display_state(vm: UnifiedViewModel, shown: int) -> tuple[UState, str]:
    """The state after filtering: U8 when more than L-33 rows would be listed, else the model's own."""
    if shown > DISPLAY_ROW_CAP:
        return 'U8', STATE_TEXT['U8'].format(n=f'{shown:,}')
    return vm.state, vm.state_text


def _empty(req: UnifiedLoadRequest, state: UState, text: str, *, error: str | None = None) -> UnifiedViewModel:
    return UnifiedViewModel(
        project_id=req.project_id or '', run_id=req.run_id, revision=req.revision, state=state, state_text=text,
        sources=(), rows=(), counts=MappingProxyType({'rows': 0, 'hidden': 0}), warnings=(), stale_reason=None,
        display_level=calibration_display_level(), error=error)


def progress_model(req: UnifiedLoadRequest, stage: str, done: int, total: int | None) -> UnifiedViewModel:
    return _empty(req, 'U2', progress_text(stage, done, total))


def error_text(error: UnifiedError) -> str:
    return clean(f'{error.code}: {error.message}' + (f' [{error.reason}]' if error.reason else ''), 400)


def _failed(req: UnifiedLoadRequest, error: str) -> UnifiedViewModel:
    text = clean(error, 400)
    return _empty(req, 'U5', STATE_TEXT['U5'].format(error=text), error=text)


# --- cells ---------------------------------------------------------------------------------------------------------------------


@functools.lru_cache(maxsize=4096)
def _milli(text: str) -> int | None:
    """A source's own similarity text as integer milli units, used to order inside that source's column only."""
    try:
        value = Decimal(text)
    except InvalidOperation:
        return None
    return int(value * 1000) if value.is_finite() and 0 <= value <= 1000 else None


def _pass_words(step: str) -> tuple[str, str]:
    head, _, tail = step.partition('-')
    return (head, tail) if head[:1] == 'P' and head[1:].isdigit() and tail else ('', step)


_CELL_NATIVE = {'ghidriff': ('match types',), 'bindiff': ('similarity',), 'rz-diff': ('similarity',),
                'diaphora': ('category', 'ratio')}   # the native values of an atom that its cell text depends on


def _value_cell(display: str, atom: Atom) -> tuple[str, str, int | None]:
    """(text, spoken, sort_key) of the strongest atom of one source on a row, in that source's own words."""
    native = {k: clean(v, 120) for k, v in atom.native}
    step, source, similarity = clean(atom.step, 64), atom.source, native.get('similarity', '')[:32]
    if source == 'ghidriff':
        more = len(set(native.get('match types', '').split(', ')) - {step, ''})
        text = step + (f' (+{more})' if more else '')
        return text, f'{display} match type {text}', None
    if source == 'bindiff':
        text = (f'sim {similarity}  ' if similarity else '') + f'algo {step}'
        return text, f'{display} similarity {similarity or "unknown"}, algorithm {step}', _milli(similarity)
    if source == 'rz-diff':
        text = f'byte sim {similarity or "unknown"}'
        return text, f'{display} byte similarity {similarity or "unknown"}', _milli(similarity)
    if source == 'diaphora':
        text = f'{native.get("category") or step} {native.get("ratio", "")}'.strip()
        return text, f'{display} {text}', _milli(native.get('ratio', ''))
    if source in ('pt-ladder', 'pt-bytes'):
        pass_id, name = _pass_words(step)
        label = f'{pass_id} {name}' if pass_id else step
        return f'{label} ({atom.tier})', f'{display} pass {label}, tier {atom.tier}', None
    if source == 'manual':
        return 'correction', 'Analyst correction', None
    return f'{step} ({atom.tier})', f'{display} {step}, tier {atom.tier}', None


class _Fact(NamedTuple):
    proof: str | None
    compare_context: bool          # a `constant` delta sits in a compare, test, mask or shift instruction
    edit_key: tuple | None         # canonical semantic deltas, for the F10 edit groups


def _opens_with_test(text: str | None) -> bool:
    words = (text or '').split(None, 1)
    return bool(words) and words[0].lower() in TEST_MNEMONICS


def _fact_summary(fact: ChangeFacts) -> _Fact:
    compare = any(d.cls == 'constant' and (_opens_with_test(d.old) or _opens_with_test(d.new)) for d in fact.deltas)
    semantic = {(d.cls, d.old or '', d.new or '') for d in fact.deltas if d.cls in SEMANTIC_CLASSES}
    edit = tuple(sorted(semantic)) if fact.verdict in ('material', 'review') and semantic else None
    return _Fact(fact.proof, compare, edit)


@dataclass(slots=True)
class _Draft:
    """A row before the global column list is known (the columns come from every row's atoms)."""
    row_id: str
    label: str
    address: str
    search: str
    decision: str
    materiality: str
    proof: str | None
    classes: tuple[str, ...]
    flags: tuple[str, ...]
    cells: dict[str, SourceCell]
    evidence: frozenset[str]
    match_id: str | None
    tier: str
    group: int
    library: int
    trace: int
    severity: int
    attention: int
    rva: int
    edit_key: tuple | None


def _strongest(tiers) -> str:
    return max(tiers, key=TIER_RANK.__getitem__, default='')


def _side_label(side: Sequence) -> str:
    if not side:
        return '-'
    return f'0x{side[0].rva:X}' + (f' (+{len(side) - 1})' if len(side) > 1 else '')


def _labels(m: UnifiedMatch) -> tuple[str, str, str]:
    old = clean(m.older[0].name, LABEL_LIMIT) if m.older and m.older[0].name else ''
    new = clean(m.newer[0].name, LABEL_LIMIT) if m.newer and m.newer[0].name else ''
    unnamed = f'sub_{(m.newer or m.older)[0].rva:x}'
    label = f'{new} (was {old})' if old and new and old != new else new or old or unnamed
    names = ' '.join(clean(s.name, LABEL_LIMIT) for s in (*m.older, *m.newer) if s.name)
    hexes = ' '.join(f'{s.rva:x}' for s in (*m.older, *m.newer))
    return label, f'{_side_label(m.older)} > {_side_label(m.newer)}', f'{names} {hexes}'.lower()[:SEARCH_KEY_CAP]


class _Builder:
    """Per-load state: the flyweights (identical cells, texts and sets are shared between rows) and the draft step."""

    def __init__(self, req: UnifiedLoadRequest):
        self.req = req
        self.cells: dict[tuple, SourceCell] = {}
        self.values: dict[tuple, SourceCell] = {}   # (source, step, tier, ...the native values the cell shows)
        self.classes: dict[tuple, tuple[str, ...]] = {}
        self.changes: dict[tuple, tuple[str, str]] = {}
        self.sets: dict[frozenset, frozenset] = {}
        self.seen: set[str] = set()

    def display(self, source: str) -> str:
        spec = self.req.registry.source(source)
        return spec.display if spec else f'{source} (unknown source)'

    def cell(self, source: str, kind: CellKind, text: str, key: int | None, spoken: str) -> SourceCell:
        ident = (source, kind, text, key, spoken)
        found = self.cells.get(ident)
        if found is None:
            found = self.cells[ident] = SourceCell(*ident)
        return found

    def value_cell(self, source: str, atom: Atom, also_elsewhere: bool) -> SourceCell:
        native = dict(atom.native)
        ident = (source, atom.step, atom.tier, also_elsewhere, *(native.get(k) for k in _CELL_NATIVE.get(source, ())))
        found = self.values.get(ident)
        if found is None:
            text, spoken, key = _value_cell(self.display(source), atom)
            if also_elsewhere:
                text, spoken = f'{text} (also pairs elsewhere)', f'{spoken}; also pairs elsewhere'
            found = self.values[ident] = self.cell(source, 'value', clean(text, CELL_LIMIT), key, clean(spoken, 160))
        return found

    def elsewhere_cell(self, source: str) -> SourceCell:
        spoken = f'{self.display(source)} pairs elsewhere'
        return self.cell(source, 'pairs-elsewhere', 'pairs elsewhere', None, spoken)

    def shared(self, values: frozenset) -> frozenset:
        return self.sets.setdefault(values, values)

    def sorted_classes(self, classes: tuple[str, ...]) -> tuple[str, ...]:
        found = self.classes.get(classes)
        if found is None:
            found = self.classes[classes] = tuple(sorted(classes, key=SEVERITY.__getitem__))
        return found

    def change(self, materiality: str, proof: str | None, classes: tuple[str, ...]) -> tuple[str, str]:
        """(materiality_text, change_text), for example ("Cosmetic (proof COS-ADDR/1)", "...: address-only")."""
        ident = (materiality, proof, classes)
        found = self.changes.get(ident)
        if found is None:
            word = MATERIALITY_LABELS[materiality]
            word += f' (proof {proof})' if proof and materiality == 'cosmetic' else ''
            found = self.changes[ident] = (word, word + (f': {classes[0]}' if classes else ''))
        return found

    def draft(self, m: UnifiedMatch, fact: _Fact | None) -> _Draft:
        older, newer = tuple(s.rva for s in m.older), tuple(s.rva for s in m.newer)
        best: dict[str, Atom] = {}
        elsewhere: set[str] = set()
        evidence: set[str] = set()
        for atom in m.atoms:
            if not on_pair(atom, older, newer):
                elsewhere.add(atom.source)
                continue
            held = best.get(atom.source)
            if held is None or TIER_RANK[atom.tier] > TIER_RANK[held.tier]:
                best[atom.source] = atom
            evidence.add(atom.cls)
        cells = {source: self.value_cell(source, atom, source in elsewhere) for source, atom in best.items()}
        cells.update({source: self.elsewhere_cell(source) for source in elsewhere - best.keys()})
        self.seen.update(cells)
        proof = fact.proof if fact else None
        classes = self.sorted_classes(m.change_classes)
        compare = fact is not None and fact.compare_context
        severity = min((SEVERITY['constant@test' if c == 'constant' and compare else c] for c in classes),
                       default=SEVERITY_NONE)
        label, address, search = _labels(m)
        return _Draft(
            row_id=m.row_id, label=label, address=address, search=search, decision=m.decision,
            materiality=m.materiality, proof=proof, classes=classes, flags=m.flags, cells=cells,
            evidence=self.shared(frozenset(evidence)), match_id=m.ghidriff_match_id,
            tier=_strongest(s.tier for s in m.support) or _strongest(a.tier for a in best.values()),
            group=group_rank(m.decision, m.materiality, proof), library=int('library' in m.flags),
            trace=int('trace-arg' in m.hints), severity=severity,
            attention=self.req.attention.get(m.ghidriff_match_id or '', ATTENTION_NONE),
            rva=m.older[0].rva if m.older else 2**32 + m.newer[0].rva, edit_key=fact.edit_key if fact else None)


# --- loading -------------------------------------------------------------------------------------------------------------------


def _source_infos(ids: Sequence[str], manifest: UnifiedResultManifest, registry: Registry) -> tuple[SourceInfo, ...]:
    versions: dict[str, set[str]] = {}
    for ref in manifest.sources:
        versions.setdefault(ref.source, set()).add(clean(ref.version, 64))
    infos = []
    for source in ids:
        spec = registry.source(source)
        infos.append(SourceInfo(source, spec.display if spec else f'{source} (unknown source)',
                                spec.unit_caption if spec else 'step / tier',
                                spec.tooltip_id if spec else 'unified.source.unknown',
                                ', '.join(sorted(versions.get(source, ()))), spec is not None))
    return tuple(infos)


def _column_ids(seen: set[str], manifest: UnifiedResultManifest, registry: Registry) -> tuple[str, ...]:
    """Registry display order (D-08) for the sources present in the result, then unknown ids sorted."""
    present = seen | {ref.source for ref in manifest.sources}
    known = [s.id for s in registry.sources if s.id in present]
    return tuple(known + sorted(present - set(known)))


def _partial_reasons(manifest: UnifiedResultManifest) -> str:
    from .compute import is_degrading  # lazy: only the compute layer knows which limitations degrade a result
    reasons = [clean(x, 80) for x in manifest.limitations if is_degrading(x)] or [
        clean(x, 80) for x in manifest.limitations]
    return ', '.join(reasons[:6]) + (f' (+{len(reasons) - 6} more)' if len(reasons) > 6 else '')


def _read_facts(manifest: UnifiedResultManifest, directory: Path, limits: UnifiedLimits,
                cancel: Callable[[], bool]) -> dict[str, _Fact]:
    out: dict[str, _Fact] = {}
    for n, fact in enumerate(store.read_facts(directory, manifest, limits)):
        if n % 2048 == 0 and cancel():
            raise Cancelled()
        out[fact.row_id] = _fact_summary(fact)
    return out


def load_unified(req: UnifiedLoadRequest, cancel: Callable[[], bool] = _never) -> UnifiedViewModel:
    """The view model of the current (or stale) stored result. Any thread; reads only the verified sidecar parts.
    A damaged, unreadable or newer result is state U5 with the typed reason; only `cancel()` raises (`Cancelled`)."""
    if not req.project_id:
        return _empty(req, 'U0', STATE_TEXT['U0'])
    if req.error:
        return _failed(req, req.error)
    loaded = req.loaded
    if loaded is None or loaded.state == 'none':
        return _empty(req, 'U1', STATE_TEXT['U1'])
    if loaded.manifest is None or loaded.directory is None:
        return _failed(req, f'PT-UNIFIED-STORE: The stored unified result is unusable [{loaded.reason or "invalid"}]')
    try:
        return _assemble(req, loaded.manifest, loaded.directory, loaded.state == 'stale', cancel)
    except UnifiedError as error:
        return _failed(req, error_text(error))


def _assemble(req: UnifiedLoadRequest, manifest: UnifiedResultManifest, directory: Path, stale: bool,
              cancel: Callable[[], bool]) -> UnifiedViewModel:
    builder = _Builder(req)
    facts = _read_facts(manifest, directory, req.limits, cancel)
    drafts: list[_Draft] = []
    for n, match in enumerate(store.read_rows(directory, manifest, req.limits)):
        if n % 2048 == 0 and cancel():
            raise Cancelled()
        drafts.append(builder.draft(match, facts.get(match.row_id)))
    ids = _column_ids(builder.seen, manifest, req.registry)
    rows, groups, evidence = _finish(drafts, ids, builder)
    reason = stale_reason_text(req.changed_inputs) if stale else None
    banners = []
    if stale:
        banners.append(STATE_TEXT['U6'].format(reason=reason))
    if manifest.status == 'partial':
        banners.append(STATE_TEXT['U4'].format(reasons=_partial_reasons(manifest)))
    if not req.extraction_configured and manifest.ir_older is None:
        banners.append(STATE_TEXT['U7'])
    counts = _counts(rows)
    state: UState = 'U6' if stale else 'U4' if manifest.status == 'partial' else 'U3'
    return UnifiedViewModel(
        project_id=req.project_id or '', run_id=req.run_id or manifest.ghidriff_run_id, revision=req.revision,
        state=state, state_text=banners[0] if state != 'U3' else _summary(counts, show_collapsed=False),
        sources=_source_infos(ids, manifest, req.registry), rows=rows, counts=MappingProxyType(counts),
        warnings=tuple(clean(x, 400) for x in manifest.limitations), stale_reason=reason,
        display_level=calibration_display_level(), result_id=manifest.result_id, manifest=manifest,
        banners=tuple(banners), absent_sources=tuple(s.display for s in req.registry.sources if s.id not in ids),
        evidence_classes=MappingProxyType(dict(evidence)), edit_groups=groups,
        records=SidecarRecords(directory, manifest, req.limits))


def _counts(rows: Sequence[UnifiedRowView]) -> dict[str, int]:
    decisions = Counter(r.decision for r in rows)
    changes = Counter(r.materiality for r in rows)
    counts = {'rows': len(rows), 'hidden': sum(1 for r in rows if r.collapsed)}
    counts.update({f'decision/{d}': decisions.get(d, 0) for d in DECISIONS})
    counts.update({f'change/{m}': changes.get(m, 0) for m in MATERIALITIES})
    return counts


def _edit_groups(drafts: Sequence[_Draft]) -> tuple[dict[tuple, int], tuple[EditGroup, ...]]:
    """F10: identical canonical semantic deltas in at least EDIT_GROUP_MIN rows form one group, numbered in display
    order. A group is a view: no row is merged, hidden or re-ranked."""
    sizes = Counter(d.edit_key for d in drafts if d.edit_key)
    ids: dict[tuple, int] = {}
    groups = []
    for d in drafts:
        if d.edit_key and sizes[d.edit_key] >= EDIT_GROUP_MIN and d.edit_key not in ids:
            ids[d.edit_key] = len(ids) + 1
            cls, old, new = d.edit_key[0]
            groups.append(EditGroup(len(ids), sizes[d.edit_key], clean(f'{cls}: {old or "-"} -> {new or "-"}', 160)))
    return ids, tuple(groups)


def _finish(drafts: list[_Draft], ids: Sequence[str], b: _Builder
            ) -> tuple[tuple[UnifiedRowView, ...], tuple[EditGroup, ...], Counter]:
    """Order once, form the edit groups, align the cells to the columns and build the immutable rows."""
    drafts.sort(key=lambda d: ((d.group, d.library, d.trace, d.severity, d.attention, d.rva), d.row_id))
    group_ids, groups = _edit_groups(drafts)
    blank = {s: b.cell(s, 'no-record', 'no record', None, f'{b.display(s)} no record') for s in ids}
    evidence: Counter = Counter()
    rows = []
    for d in drafts:
        materiality_text, change_text = b.change(d.materiality, d.proof, d.classes)
        evidence.update(d.evidence)
        rows.append(UnifiedRowView(
            d.row_id, d.label, d.address, d.decision, DECISION_LABELS[d.decision], DECISION_GLYPHS[d.decision],
            d.materiality, materiality_text, change_text, d.classes, d.proof, d.tier, d.flags,
            tuple(d.cells.get(s) or blank[s] for s in ids), b.shared(frozenset(d.cells)), d.match_id,
            group_ids.get(d.edit_key, 0), is_collapsed(d.decision, d.materiality, d.proof),
            (d.group, d.library, d.trace, d.severity, d.attention, d.rva), d.search))
    return tuple(rows), groups, evidence


# --- header, summary, columns ----------------------------------------------------------------------------------------------------


def _summary(counts: Mapping[str, int], *, show_collapsed: bool) -> str:
    parts = [f'{counts.get("rows", 0):,} rows', f'{counts.get("change/material", 0):,} material',
             f'{counts.get("change/review", 0):,} review', f'{counts.get("decision/contested", 0):,} contested',
             f'{counts.get("decision/older-only", 0):,} older-only',
             f'{counts.get("decision/newer-only", 0):,} newer-only']
    if counts.get('hidden') and not show_collapsed:
        parts.append(f'{counts["hidden"]:,} cosmetic/unchanged hidden')
    return ' - '.join(parts)


def summary_text(vm: UnifiedViewModel, *, show_collapsed: bool = False) -> str:
    """The summary line of the wireframe: counts only, each next to its own word, nothing combined."""
    return _summary(vm.counts, show_collapsed=show_collapsed)


def evidence_summary(vm: UnifiedViewModel) -> str:
    """Rows per evidence class (05 s1.1), each count next to its own words: a count of rows, never a score."""
    parts = [f'{cls} ({CLASS_NAMES[cls]}) {vm.evidence_classes[cls]:,}' for cls in CLASS_NAMES
             if vm.evidence_classes.get(cls)]
    return 'Rows by evidence class: ' + (' - '.join(parts) or 'none')


def header_text(vm: UnifiedViewModel) -> str:
    """`Unified: ude/1, run <time> UTC, stale: no | Sources: ...`; absent sources are named here, not as columns."""
    manifest = vm.manifest
    if manifest is None:
        return ''
    present = ', '.join(f'{s.display} {s.version}'.strip() for s in vm.sources) or 'none'
    line = (f'Unified: {manifest.engine_version}, run {manifest.created_utc.replace("T", " ")[:16]} UTC, '
            f'stale: {"yes" if vm.stale_reason else "no"} | Sources: {present}')
    return line + (f' | Not present: {", ".join(vm.absent_sources)}' if vm.absent_sources else '')


@dataclass(frozen=True, slots=True)
class ColumnSpec:
    key: str
    title: str
    unit: str
    width_em: int
    tip_id: str
    source: str | None = None


FIXED_COLUMNS = (ColumnSpec('function', 'Function', '', 30, 'unified.table'),
                 ColumnSpec('decision', 'Decision', '', 14, 'unified.table'),
                 ColumnSpec('change', 'Change', '', 24, 'unified.table'))


def columns(vm: UnifiedViewModel) -> tuple[ColumnSpec, ...]:
    """Function, Decision, Change, then one column per present source in registry order. The unit of a source's
    native values is in its header (`unit`) as well as in the words of its cells."""
    return FIXED_COLUMNS + tuple(
        ColumnSpec(f'source:{s.source}', s.display, s.unit_caption, 22, s.tooltip_id, s.source) for s in vm.sources)


COLUMN_WIDTH_RANGE = (24, 4000)     # pixels a remembered width may have; anything else is the default (U5)
MAX_SAVED_COLUMNS = 32              # the settings list limit of the panel host
_COLUMN_KEY = re.compile(r'(?:function|decision|change|source:[a-z0-9][a-z0-9_.-]{0,63})')


def parse_column_widths(items: Sequence[str]) -> dict[str, int]:
    """`key:pixels` items of the `unified/columns` setting. Untrusted: keys that are no column key, non-decimal numbers,
    widths outside COLUMN_WIDTH_RANGE and repeats are ignored (the first valid item of a key wins). Keys of sources
    that this result does not show stay in the dict and are simply not applied."""
    out: dict[str, int] = {}
    low, high = COLUMN_WIDTH_RANGE
    for item in items:
        key, _, number = item.rpartition(':')
        if _COLUMN_KEY.fullmatch(key) and key not in out and number.isdecimal() and low <= int(number) <= high:
            out[key] = int(number)
    return out


def format_column_widths(widths: Mapping[str, int]) -> tuple[str, ...]:
    """The setting value: valid keys only, sorted, at most MAX_SAVED_COLUMNS items."""
    return tuple(f'{key}:{widths[key]}' for key in sorted(widths) if _COLUMN_KEY.fullmatch(key))[:MAX_SAVED_COLUMNS]


def cell_text(row: UnifiedRowView, column: int) -> str:
    """Display text of one cell, O(1): only the function cell joins two stored labels."""
    if column == 0:
        return f'{row.function_label}  {row.address_label}'
    if column == 1:
        return BADGES[row.decision]
    if column == 2:
        return row.change_text
    return row.cells[column - 3].text


def cell_spoken(row: UnifiedRowView, column: int) -> str:
    if column == 0:
        return f'Function {row.function_label}, addresses {row.address_label}'
    if column == 1:
        return DECISION_CHIPS[row.decision].spoken
    if column == 2:
        return f'Change: {row.change_text}'
    return row.cells[column - 3].spoken


def rows_tsv(vm: UnifiedViewModel, rows: Sequence[UnifiedRowView]) -> str:
    """Tab-separated copy of rows, header first, at most 16 KiB; cell text never holds a tab or a newline."""
    spec = columns(vm)
    lines = ['\t'.join(c.title for c in spec)]
    lines += ['\t'.join(cell_text(row, i) for i in range(len(spec))) for row in rows]
    text = '\n'.join(lines)
    return text if len(text) <= CLIPBOARD_CAP else text[:CLIPBOARD_CAP - 12] + '\n(truncated)'


# --- filter and order (indices, like evidence_view.filter_rows) ------------------------------------------------------------------


def filter_rows(rows: Sequence[UnifiedRowView], *, decisions: Collection[str] | None = None,
                materialities: Collection[str] | None = None, classes: Collection[str] | None = None,
                sources: Collection[str] | None = None, search: str = '', show_collapsed: bool = False,
                edit_group: int | None = None) -> list[int]:
    """Indices of the rows that pass every given filter (`None` = no restriction, an empty collection = nothing).
    Without an explicit `materialities` the default view applies: collapsed rows are left out unless
    `show_collapsed` (U-03). Asking for a materiality always lists it."""
    want_decisions = None if decisions is None else frozenset(decisions)
    want_changes = None if materialities is None else frozenset(materialities)
    want_classes = None if classes is None else frozenset(classes)
    want_sources = None if sources is None else frozenset(sources)
    query = normalize_search(search)
    hide = materialities is None and not show_collapsed
    out = []
    for index, row in enumerate(rows):
        if want_decisions is not None and row.decision not in want_decisions:
            continue
        if want_changes is not None and row.materiality not in want_changes:
            continue
        if hide and row.collapsed:
            continue
        if want_classes is not None and want_classes.isdisjoint(row.classes):
            continue
        if want_sources is not None and want_sources.isdisjoint(row.source_ids):
            continue
        if edit_group is not None and row.edit_group != edit_group:
            continue
        if query and query not in row.search_key:
            continue
        out.append(index)
    return out


def _default_key(row: UnifiedRowView) -> object:
    return row.sort_keys


def column_sort_key(vm: UnifiedViewModel, column: str) -> Callable[[UnifiedRowView], object]:
    """Sort key of a column key (`default`, `function`, `decision`, `change`, `source:<id>`); None sorts last."""
    if column == 'function':
        return lambda r: r.function_label.casefold()
    if column == 'decision':
        return lambda r: DECISION_PRIORITY[r.decision]
    if column == 'change':
        return lambda r: (MATERIALITY_PRIORITY[r.materiality], r.sort_keys[KEY_SEVERITY])
    if column.startswith('source:'):
        at = next((i for i, s in enumerate(vm.sources) if s.source == column[len('source:'):]), None)
        return (lambda r: None) if at is None else (lambda r: r.cells[at].sort_key)
    return _default_key


def sort_rows(rows: Sequence[UnifiedRowView], indices: Sequence[int],
              key: Callable[[UnifiedRowView], object] = _default_key, *, descending: bool = False) -> list[int]:
    """Stable order of `indices` by `key`; rows whose key is None stay last in either direction, and ties keep the
    given order (the default review order when `indices` came from `filter_rows`)."""
    keyed = [(i, key(rows[i])) for i in indices]
    present = sorted(((i, k) for i, k in keyed if k is not None), key=lambda pair: pair[1], reverse=descending)
    return [i for i, _ in present] + [i for i, k in keyed if k is None]


# --- verbose text (lazy) ---------------------------------------------------------------------------------------------------------------


def records_for(vm: UnifiedViewModel, rows: Sequence[UnifiedRowView]) -> dict[str, read_text.RowRecord]:
    """The full records of `rows` by row id, read lazily in one pass over the sidecar (`UnifiedError` on damage)."""
    return {} if vm.records is None or not rows else vm.records.get([r.row_id for r in rows])


def row_detail(vm: UnifiedViewModel, row: UnifiedRowView) -> str:
    """Plain text of the Unified tab for one row (fixed section headers, `read_text.SECTIONS`). It reads the
    sidecar lazily, so call it off the GUI thread for a large result; it never raises for data problems."""
    if vm.manifest is None or vm.records is None:
        return 'Details are not available for this result.'
    notes = []
    if vm.stale_reason:
        notes.append(read_text.STALE_NOTE.format(reason=vm.stale_reason))
    if row.edit_group:
        notes.append(f'The same change appears in {vm.edit_groups[row.edit_group - 1].size} rows (edit group '
                     f'{row.edit_group}); they may all be induced by one edit. Every row stays listed.')
    try:
        record = records_for(vm, [row]).get(row.row_id)
    except UnifiedError as error:
        return f'Details could not be read: {error_text(error)}'
    if record is None:
        return 'Details are not available for this row.'
    return read_text.detail_text(vm.manifest, record, notes=notes)


def provenance_block(vm: UnifiedViewModel, rows: Sequence[UnifiedRowView]) -> str:
    """Deterministic clipboard text for the selected rows (at most 200 rows and 16 KiB)."""
    if vm.manifest is None:
        return ''
    chosen = rows[:CLIPBOARD_ROWS]
    try:
        found = records_for(vm, chosen)
    except UnifiedError as error:
        return f'Provenance could not be read: {error_text(error)}'
    return read_text.provenance_block(vm.manifest, [found[r.row_id] for r in chosen if r.row_id in found],
                                      project_id=vm.project_id, run_id=vm.run_id, stale_reason=vm.stale_reason,
                                      total=len(rows))


def explain_context(vm: UnifiedViewModel, row: UnifiedRowView) -> ContextFragment | None:
    """The bounded plain text the EXISTING context preview may include for this row (D-30), or None when the records
    cannot be read. Nothing is transmitted from here."""
    try:
        record = records_for(vm, [row]).get(row.row_id)
    except UnifiedError:
        return None
    return read_text.context_fragment(record) if record else None


# --- the owner-thread side ---------------------------------------------------------------------------------------------------------------


def changed_inputs(loaded: store.LoadedResult, plan) -> list[str]:
    """Names of the result_key inputs that differ between the stored result and the current plan ([] when equal)."""
    from . import keys
    if plan is None or loaded.manifest is None or loaded.manifest.result_id == plan.result_id:
        return []
    return list(keys.changed_inputs(keys.result_key_inputs(loaded.manifest), plan.identity.key_inputs))


def request_from_service(service: ProjectService, *, extraction_configured: bool = False,
                         attention: Mapping[str, int] | None = None) -> UnifiedLoadRequest:
    """OWNER thread only (it reads the project database): the plan, the stored pointer row and what changed since.
    A failure becomes the request's `error` (state U5), never an exception."""
    from . import pipeline
    project = service.project
    try:
        plan = pipeline.make_plan(service)
    except UnifiedError:
        plan = None  # nothing to compare with: a stored result is then reported as stale
    run_id = plan.run_id if plan else None
    try:
        loaded = pipeline.load_current(service, plan)
    except UnifiedError as error:
        return UnifiedLoadRequest(project.id, run_id, project.revision, error=error_text(error))
    return UnifiedLoadRequest(project.id, run_id, project.revision, loaded, tuple(changed_inputs(loaded, plan)), None,
                              extraction_configured, dict(attention or {}))


# --- data the Qt side registers (07 s8; this module registers nothing) ------------------------------------------------------------------------


TOOLTIP_IDS: tuple[str, ...] = (
    'unified.view_switch', 'unified.run', 'unified.cancel', 'unified.filter_decision', 'unified.filter_change',
    'unified.filter_class', 'unified.filter_source', 'unified.search', 'unified.show_hidden', 'unified.table',
    'unified.tab', 'unified.detail', 'unified.goto', 'unified.correct', 'unified.copy', 'unified.explain',
    'unified.retry', 'unified.copy_error', 'unified.stale_banner', 'unified.source.unknown')
TOOLTIP_TEMPLATE_IDS: tuple[str, ...] = ('unified.row', 'unified.cell', 'unified.badge', 'unified.delta')


def source_tooltip_ids(registry: Registry = REGISTRY) -> tuple[str, ...]:
    """`unified.source.<id>` of every registry source, in registry order."""
    return tuple(s.tooltip_id for s in registry.sources)
