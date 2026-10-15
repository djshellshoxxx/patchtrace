"""capa capability changes on matched function pairs (CAP-2, contract `capa-pairs/1`). Pure: no Qt, no I/O.

Derived, never persisted. The inventory delta in `delta.py` compares whole files; this module compares the
behaviours capa recognises in the two functions of each matched pair, and keeps what capa did not look at apart from
what it did not find:

- `gained`/`lost` only when capa evaluated both sides (or one side has no function at all). A function capa skipped
  as library code, did not recover, or whose evidence was cut is `not-evaluated`; the pair row is `not-compared`.
- The same rule gained in one pair and lost in another is `moved` (capa does not follow calls, so wrappers, inlining
  and outlining relocate behaviour): a candidate, never counted as gain or loss.
- A gain or loss in a pair the analysis calls unchanged is `detection-difference` noise, not new code.
- Matches that name no function (file and instruction scope) are listed apart; no function is guessed for them.

No score, rank or confidence is produced; the value gate stays `unvalidated`. Rows are ordered by namespace and rule
name, never by importance.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from typing import Annotated, Literal

from pydantic import Field, model_validator

from ...enrichment.identity import domain_id
from .common import (
    LOCALIZED,
    MAX_FEATURES,
    MAX_LABELS,
    CapabilityEvidence,
    EvidenceLink,
    FeatureRef,
    TaxonomyLabel,
    ToolError,
    ToolEvidenceSet,
    ToolRun,
    _Strict,
    display_text,
)
from .delta import QualityFlag
from .normalize import _record_rva, comparability, parse_address

CONTRACT = 'capa-pairs/1'
MAX_ROWS = 100_000
MAX_GROUPS = 200_000
MAX_CELL_LINKS = 4
MAX_GROUP_FUNCTIONS = 4096
GroupCategory = Literal['modified', 'added', 'removed', 'unchanged', 'ambiguous', 'split', 'merged', 'unmatched']
NO_ROWS = frozenset({'ambiguous', 'unmatched'})
CellState = Literal['present', 'absent', 'not-evaluated', 'no-function']
NotEvaluated = Literal['library-function', 'function-not-recovered', 'evidence-truncated']
Change = Literal['gained', 'lost', 'moved', 'unchanged', 'not-compared']
UnattributedReason = Literal['file-scope', 'instruction-scope', 'basic-block-without-layout', 'address-rejected',
                             'function-not-paired']
_Rva = Annotated[int, Field(ge=0, lt=2**32)]


class PairGroup(_Strict):
    """One matched function pair (or n:m set) in canonical module-relative terms."""
    group_id: str = Field(min_length=1, max_length=160)   # 'm:<match id>' or 'u:<older rva>:<newer rva>'
    match_id: str | None = Field(default=None, max_length=128)
    category: GroupCategory
    older_rvas: tuple[_Rva, ...] = Field(default=(), max_length=MAX_GROUP_FUNCTIONS)
    newer_rvas: tuple[_Rva, ...] = Field(default=(), max_length=MAX_GROUP_FUNCTIONS)
    older_names: tuple[Annotated[str, Field(max_length=256)], ...] = Field(default=(), max_length=64)
    newer_names: tuple[Annotated[str, Field(max_length=256)], ...] = Field(default=(), max_length=64)
    # A side holds project functions whose address could not be placed in the image: no row is claimed for it.
    unresolved: bool = False


class PairCell(_Strict):
    state: CellState
    reason: NotEvaluated | None = None
    matches: int = Field(default=0, ge=0)
    links: tuple[EvidenceLink, ...] = Field(default=(), max_length=MAX_CELL_LINKS)
    features: tuple[FeatureRef, ...] = Field(default=(), max_length=MAX_FEATURES)

    @model_validator(mode='after')
    def _consistent(self):
        if (self.state == 'not-evaluated') != (self.reason is not None):
            raise ValueError('only a not-evaluated cell carries a reason')
        if (self.state == 'present') != (self.matches > 0):
            raise ValueError('a cell is present exactly when it holds matches')
        return self


class PairChange(_Strict):
    change_id: str = Field(max_length=64)
    group_id: str = Field(max_length=160)
    match_id: str | None = Field(default=None, max_length=128)
    category: GroupCategory
    rule_id: str = Field(max_length=256)
    namespace: str | None = Field(default=None, max_length=256)
    scope: str = Field(max_length=16)
    kind: Literal['capability', 'library']
    change: Change
    noise: Literal['none', 'detection-difference'] = 'none'
    relocation: Literal['none', 'candidate'] = 'none'
    older: PairCell
    newer: PairCell
    labels: tuple[TaxonomyLabel, ...] = Field(default=(), max_length=MAX_LABELS)
    observation_key: str = Field(max_length=64)   # `capobs/1`: lets later evidence dedupe shared-origin observations


class Unattributed(_Strict):
    rule_id: str = Field(max_length=256)
    scope: str = Field(max_length=16)
    namespace: str | None = Field(default=None, max_length=256)
    change: Literal['gained', 'lost', 'unchanged']
    older_matches: int = Field(ge=0)
    newer_matches: int = Field(ge=0)
    reason: UnattributedReason


class CoverageSummary(_Strict):
    matched_groups: int = Field(ge=0)
    both_evaluated: int = Field(ge=0)
    older_library: int = Field(ge=0)
    newer_library: int = Field(ge=0)
    older_not_recovered: int = Field(ge=0)
    newer_not_recovered: int = Field(ge=0)
    ambiguous_groups: int = Field(ge=0)
    attributed_matches: int = Field(ge=0)
    total_matches: int = Field(ge=0)


class PairCapabilityDelta(_Strict):
    contract: Literal['capa-pairs/1'] = CONTRACT
    comparable: bool
    reasons: tuple[str, ...] = ()
    engine: Literal['capa'] = 'capa'
    older_run_id: str | None
    newer_run_id: str | None
    pairing: Literal['available', 'unavailable'] = 'unavailable'
    changes: tuple[PairChange, ...] = ()
    unattributed: tuple[Unattributed, ...] = ()
    coverage: CoverageSummary | None = None
    flags: tuple[QualityFlag, ...] = ()
    counts: dict[str, int] = Field(default_factory=dict)
    notes: tuple[str, ...] = ()
    truncated: bool = False
    value_gate: Literal['unvalidated'] = 'unvalidated'


# ---- groups from the project's matches ---------------------------------------------------------------------------

def _names(records: Iterable) -> tuple[str, ...]:
    return tuple(sorted({display_text(record.name, 256) for record in records}))[:64]


def groups_from_project(matches: Sequence, raw_matches: Mapping | None, bases: tuple[int, int],
                        sizes: tuple[int | None, int | None] = (None, None)) -> tuple[PairGroup, ...]:
    """Pair groups from the normalised `FunctionMatch` rows plus the raw Ghidriff `address_matches` for unchanged
    pairs the rows omit. `bases` and `sizes` are (older, newer) and apply the RVA rules of `FunctionPairing`."""
    groups: list[PairGroup] = []
    seen: tuple[set[int], set[int]] = (set(), set())
    for match in matches:
        sides = []
        for index, side in enumerate(('older', 'newer')):
            records = getattr(match, side)
            rvas = sorted({rva for rva in (_record_rva(r, bases[index], sizes[index]) for r in records)
                           if rva is not None})
            seen[index].update(rvas)
            sides.append((records, tuple(rvas)))
        (old_records, old_rvas), (new_records, new_rvas) = sides
        groups.append(PairGroup(
            group_id=f'm:{match.id}', match_id=match.id, category=match.category, older_rvas=old_rvas,
            newer_rvas=new_rvas, older_names=_names(old_records), newer_names=_names(new_records),
            unresolved=bool(old_records and not old_rvas) or bool(new_records and not new_rvas)))
    table = raw_matches.get('address_matches') if isinstance(raw_matches, Mapping) else None
    if isinstance(table, Mapping):
        groups.extend(_raw_groups(table, bases, seen))
    if len(groups) > MAX_GROUPS:
        raise ToolError('PT-TOOL-LIMIT', f'more than {MAX_GROUPS} function pairs')
    return tuple(sorted(groups, key=lambda group: group.group_id))


def _raw_groups(table: Mapping, bases: tuple[int, int], seen: tuple[set[int], set[int]]) -> Iterable[PairGroup]:
    for old_text, targets in table.items():
        old = parse_address(old_text) if isinstance(old_text, str) else None
        if old is None or old < bases[0] or not isinstance(targets, list):
            continue   # EXTERNAL:<hex> import locations and unparsable keys are not image functions
        news = sorted({parse_address(t[0]) - bases[1] for t in targets
                       if isinstance(t, list) and t and isinstance(t[0], str)
                       and (parse_address(t[0]) or -1) >= bases[1]})
        old_rva = old - bases[0]
        if old_rva in seen[0] or any(new in seen[1] for new in news) or not news:
            continue   # normalised and manual matches win over raw engine relations
        category = 'unchanged' if len(news) == 1 and len(targets) == 1 else 'ambiguous'
        yield PairGroup(group_id=f'u:{old_rva}:{news[0]}', category=category, older_rvas=(old_rva,),
                        newer_rvas=tuple(news))


# ---- computation -------------------------------------------------------------------------------------------------

def _reasons(older_run: ToolRun | None, older: ToolEvidenceSet | None, newer_run: ToolRun | None,
             newer: ToolEvidenceSet | None) -> list[str]:
    if older_run is None or newer_run is None:
        missing = [side for side, run in (('older', older_run), ('newer', newer_run)) if run is None]
        return ['no stored run for the ' + ' and '.join(missing) + ' artifact']
    reasons = comparability(older_run, newer_run)
    if older_run.engine != 'capa':
        reasons.append('capability pairs need capa evidence')
    for side, run, evidence in (('older', older_run, older), ('newer', newer_run, newer)):
        if evidence is None:
            if not reasons:
                reasons.append(f'{side} evidence is missing')
        elif evidence.cache_key != run.cache_key or evidence.artifact_sha256 != run.input_artifact_hash:
            reasons.append(f'{side} evidence does not belong to the {side} run')
        elif evidence.coverage is None:
            reasons.append(f'{side} evidence has no function coverage (refresh from the stored capa output)')
    return reasons


def _function_rva(link: EvidenceLink) -> int | None:
    return int(link.function_id[6:], 16) if link.function_id and link.attribution in LOCALIZED else None


def _unattributed_reason(item: CapabilityEvidence) -> UnattributedReason:
    if item.scope == 'file':
        return 'file-scope'
    if item.scope == 'instruction':
        return 'instruction-scope'
    if item.scope == 'basic block' and item.location.rva is not None:
        return 'basic-block-without-layout'
    return 'address-rejected'


class _SideState:
    """What capa did with the functions of one group side."""

    def __init__(self, rvas: tuple[int, ...], evaluated: frozenset[int], library: frozenset[int], truncated: bool):
        self.empty = not rvas
        skipped = [rva for rva in rvas if rva not in evaluated]
        self.evaluated = not self.empty and not skipped
        self.library = bool(skipped) and all(rva in library for rva in skipped)
        self.reason: NotEvaluated = 'library-function' if self.library else 'function-not-recovered'
        self.truncated = truncated


def _cell(state: _SideState, items: Sequence[CapabilityEvidence]) -> PairCell:
    if items:
        links = sorted((i.location for i in items), key=lambda link: (-1 if link.rva is None else link.rva,
                                                                         link.source_fragment or ''))
        features = sorted({f for i in items for f in i.features},
                          key=lambda f: (f.kind, f.value, -1 if f.rva is None else f.rva))
        return PairCell(state='present', matches=len(items), links=tuple(links[:MAX_CELL_LINKS]),
                        features=tuple(features[:MAX_FEATURES]))
    if state.empty:
        return PairCell(state='no-function')
    if not state.evaluated:
        return PairCell(state='not-evaluated', reason=state.reason)
    if state.truncated:
        return PairCell(state='not-evaluated', reason='evidence-truncated')
    return PairCell(state='absent')


def _classify(older: PairCell, newer: PairCell) -> Change:
    if older.state == newer.state == 'present':
        return 'unchanged'
    if 'not-evaluated' in (older.state, newer.state):
        return 'not-compared'
    return 'lost' if older.state == 'present' else 'gained'


def _labels(items: Iterable[CapabilityEvidence]) -> tuple[TaxonomyLabel, ...]:
    found = {label for item in items for label in item.labels}
    return tuple(sorted(found, key=lambda x: (x.scheme, x.group, x.name, x.ident)))[:MAX_LABELS]


def _group_index(groups: Sequence[PairGroup]) -> tuple[dict[int, list[PairGroup]], dict[int, list[PairGroup]]]:
    older: dict[int, list[PairGroup]] = defaultdict(list)
    newer: dict[int, list[PairGroup]] = defaultdict(list)
    for group in groups:
        for rva in group.older_rvas:
            older[rva].append(group)
        for rva in group.newer_rvas:
            newer[rva].append(group)
    return older, newer


def compute_pairs(older_run: ToolRun | None, older: ToolEvidenceSet | None, newer_run: ToolRun | None,
                  newer: ToolEvidenceSet | None, groups: Sequence[PairGroup] | None, *,
                  flags: Iterable[QualityFlag] = (), include_unchanged: bool = False) -> PairCapabilityDelta:
    """Capability changes per matched pair. `groups=None` means no completed analysis: pairing is unavailable and
    only per-side totals are reported. Unchanged rows are materialised only on request; their counts are not."""
    base = dict(older_run_id=older_run.run_id if older_run else None,
                newer_run_id=newer_run.run_id if newer_run else None, flags=tuple(flags))
    reasons = _reasons(older_run, older, newer_run, newer)
    if reasons:
        return PairCapabilityDelta(comparable=False, reasons=tuple(reasons), **base)
    if groups is None:
        totals = {f'{side}_capabilities': sum(c.kind == 'capability' for c in evidence.capabilities)
                  for side, evidence in (('older', older), ('newer', newer))}
        return PairCapabilityDelta(comparable=True, counts=totals, truncated=older.truncated or newer.truncated,
                                   notes=('no completed analysis run: function pairs are unavailable',), **base)
    if len(groups) > MAX_GROUPS:
        raise ToolError('PT-TOOL-LIMIT', f'more than {MAX_GROUPS} function pairs')
    return _compute(older, newer, groups, include_unchanged, base)


def _compute(older: ToolEvidenceSet, newer: ToolEvidenceSet, groups: Sequence[PairGroup], include_unchanged: bool,
             base: dict) -> PairCapabilityDelta:
    sides = {'older': older, 'newer': newer}
    index = dict(zip(('older', 'newer'), _group_index(groups), strict=True))
    states: dict[str, dict[str, _SideState]] = {}
    for group in groups:
        states[group.group_id] = {
            side: _SideState(getattr(group, f'{side}_rvas'), frozenset(sides[side].coverage.evaluated),
                             frozenset(sides[side].coverage.library), sides[side].truncated)
            for side in sides}
    cells: dict[tuple[str, str, str, str], dict[str, list[CapabilityEvidence]]] = defaultdict(
        lambda: {'older': [], 'newer': []})
    loose: dict[tuple[str, str, UnattributedReason], dict] = {}
    total = attributed = 0
    for side, evidence in sides.items():
        for item in evidence.capabilities:
            if item.kind == 'limitation':
                continue
            if item.kind == 'capability':
                total += 1
            rva = _function_rva(item.location)
            owners = index[side].get(rva, []) if rva is not None else []
            if owners:
                attributed += item.kind == 'capability'
                for group in owners:
                    cells[(group.group_id, item.rule_id, item.scope, item.kind)][side].append(item)
            elif item.kind == 'capability':
                reason = _unattributed_reason(item) if rva is None else 'function-not-paired'
                entry = loose.setdefault((item.rule_id, item.scope, reason),
                                         {'namespace': item.namespace, 'older': 0, 'newer': 0})
                entry[side] += 1
    by_group = {group.group_id: group for group in groups}
    rows: list[PairChange] = []
    for (group_id, rule_id, scope, kind), found in cells.items():
        group = by_group[group_id]
        if group.category in NO_ROWS or group.unresolved:
            continue
        old_cell, new_cell = (_cell(states[group_id][side], found[side]) for side in ('older', 'newer'))
        change = _classify(old_cell, new_cell)
        noise = 'detection-difference' if group.category == 'unchanged' and change in ('gained', 'lost') else 'none'
        items = [*found['older'], *found['newer']]
        rows.append(PairChange(
            change_id=domain_id('capa-pair-change', 1, {'group': group_id, 'rule': rule_id, 'scope': scope})[:32],
            group_id=group_id, match_id=group.match_id, category=group.category, rule_id=rule_id,
            namespace=items[0].namespace, scope=scope, kind=kind, change=change, noise=noise, older=old_cell,
            newer=new_cell, labels=_labels(items),
            observation_key=domain_id('capobs', 1, {'kind': kind, 'rule_id': rule_id, 'scope': scope,
                                                    'pair': group_id})))
    rows = _mark_moved(rows)
    counts = _counts(rows)
    shown = [r for r in rows if include_unchanged or r.change != 'unchanged']
    shown.sort(key=lambda r: (r.namespace or '', r.rule_id, r.scope, r.group_id))
    truncated = len(shown) > MAX_ROWS
    notes = _notes(groups, older, newer)
    return PairCapabilityDelta(
        comparable=True, pairing='available', changes=tuple(shown[:MAX_ROWS]),
        unattributed=_unattributed(loose), coverage=_coverage(groups, states, attributed, total), counts=counts,
        notes=notes, truncated=truncated or older.truncated or newer.truncated, **base)


def _mark_moved(rows: list[PairChange]) -> list[PairChange]:
    """The same (rule, scope) gained and lost in different pairs: every involved row is a relocation candidate."""
    seen: dict[tuple[str, str, str], dict[str, list[int]]] = defaultdict(lambda: {'gained': [], 'lost': []})
    for position, row in enumerate(rows):
        if row.change in ('gained', 'lost') and row.noise == 'none':
            seen[(row.kind, row.rule_id, row.scope)][row.change].append(position)
    for sides in seen.values():
        if sides['gained'] and sides['lost']:
            for position in (*sides['gained'], *sides['lost']):
                rows[position] = rows[position].model_copy(update={'change': 'moved', 'relocation': 'candidate'})
    return rows


def _counts(rows: Sequence[PairChange]) -> dict[str, int]:
    counts = {'gained': 0, 'lost': 0, 'moved': 0, 'unchanged': 0, 'not-compared': 0, 'detection-difference': 0}
    for row in rows:
        if row.kind != 'capability':
            continue
        if row.noise == 'detection-difference':
            counts['detection-difference'] += 1
        elif row.change != 'moved':
            counts[row.change] += 1
    counts['moved'] = len({(row.rule_id, row.scope) for row in rows
                           if row.change == 'moved' and row.kind == 'capability'})
    return counts


def _unattributed(loose: dict) -> tuple[Unattributed, ...]:
    out = []
    for (rule_id, scope, reason), entry in loose.items():
        change = 'unchanged' if entry['older'] and entry['newer'] else ('lost' if entry['older'] else 'gained')
        out.append(Unattributed(rule_id=rule_id, scope=scope, namespace=entry['namespace'], change=change,
                                older_matches=entry['older'], newer_matches=entry['newer'], reason=reason))
    return tuple(sorted(out, key=lambda u: (u.namespace or '', u.rule_id, u.scope, u.reason)))


def _coverage(groups: Sequence[PairGroup], states: dict[str, dict[str, _SideState]], attributed: int,
              total: int) -> CoverageSummary:
    matched = [g for g in groups if g.older_rvas and g.newer_rvas and g.category not in NO_ROWS
               and not g.unresolved]
    def skipped(side: str, library: bool) -> int:
        return sum(1 for g in matched if not states[g.group_id][side].evaluated
                   and states[g.group_id][side].library is library)
    return CoverageSummary(
        matched_groups=len(matched),
        both_evaluated=sum(1 for g in matched if all(s.evaluated for s in states[g.group_id].values())),
        older_library=skipped('older', True), newer_library=skipped('newer', True),
        older_not_recovered=skipped('older', False), newer_not_recovered=skipped('newer', False),
        ambiguous_groups=sum(1 for g in groups if g.category == 'ambiguous'),
        attributed_matches=attributed, total_matches=total)


def _notes(groups: Sequence[PairGroup], older: ToolEvidenceSet, newer: ToolEvidenceSet) -> tuple[str, ...]:
    notes = set()
    skipped = sum(1 for g in groups if g.category == 'unmatched' or g.unresolved)
    if skipped:
        notes.add(f'{skipped} function pairs have no usable counterpart: no capability rows are claimed for them')
    for side, evidence in (('older', older), ('newer', newer)):
        if evidence.coverage.truncated:
            notes.add(f'{side} coverage list is truncated: later functions count as not recovered')
        if evidence.truncated:
            notes.add(f'{side} evidence is truncated: missing matches are not-evaluated, not absent')
    return tuple(sorted(notes))
