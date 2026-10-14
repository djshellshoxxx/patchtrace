"""A current unified result (SPEC-31) as pilot candidates and typed ChangeFacts observations (PIL-integration-plan.md
s4, s7, s9 PIL-A3).

PIL reads unified rows and facts only through `unified.store` (`LoadedResult`, `read_rows`, `read_facts`) and never
writes them. Only a `current` result is used; a stale, missing or invalid one is `PT-PILOT-STALE` and the caller falls
back to Ghidriff rows with secondary verdicts (`code.GhidriffPairing`): the two identity sources are never combined, they
share their origin. A result of another pair, or of the reversed orientation, is refused.

Rows are candidates (`candidate_key` is the row id) and the s7 identity map applies: matched is corroborated, contested
and ambiguous are contested, everything else is unassessed. ChangeFacts become observations on the `code` channel:

* `cf:cosmetic` / `cf:unchanged` (role `conflict`): the named proof is kept visible next to any B1 guard it contradicts,
  and the deltas of a proven row are part of the proof, not shape evidence;
* `cf:<ChangeClass>` per delta of a `material` or `review` row: semantic classes are `shape`, everything else (strings,
  noise classes such as `register-only`, structural classes) is `context`. A `review` row has no second channel that
  observed the change, which each of its shape observations records as the unmet obligation `second-channel`; a
  `material` row has at least one anchored delta (ChangeFacts do not say which), so none is marked;
* row-level noise classes that no delta carries (`address-only` and kin, from Ghidriff diff types) are `context`;
* row flags become `pair:<flag>` context: nuisance (`NUISANCE_FLAGS`, a function that is a likely false lead) and data
  quality (`QUALITY_FLAGS`, evidence that is cut or missing for this function).

Without ProgramIR (`ir_older` is None, S0 mode) the facts are decompiler- and name-relative, so the code channel is
`partial` and says so; evidence classes record what each delta read (`E-BODY` operand level, `E-DECOMP` decompiler text).
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from ...unified.contracts import ChangeFacts, Delta, SideRef, UnifiedMatch, UnifiedResultManifest
from ...unified.limits import UnifiedError
from ...unified.store import LoadedResult, read_facts, read_rows
from ..contracts import (
    MAX_SIDE_FUNCTIONS,
    Candidate,
    ChannelStatus,
    FunctionRef,
    Nav,
    Observation,
    clean_line,
)
from ..limits import DEFAULT_LIMITS, Budget, PilotError, PilotLimits
from ..ports import OriginRegistry
from .code import DEFAULT_REGISTRY, MAX_PER_CANDIDATE, build_observation, channel_status, lookup, settle

# s7 identity map, unified half (the secondary half is `code.IDENTITY_OF_VERDICT`).
IDENTITY_OF_DECISION: Mapping[str, str] = MappingProxyType({
    'matched': 'corroborated', 'contested': 'contested', 'ambiguous': 'contested', 'tentative': 'unassessed',
    'candidate': 'unassessed', 'older-only': 'unassessed', 'newer-only': 'unassessed', 'unknown': 'unassessed'})
NUISANCE_FLAGS = ('hub', 'icf', 'import', 'library', 'thunk', 'tiny')
QUALITY_FLAGS = ('ir-missing', 'mask-missing', 'mask-unlocated', 'oversize', 'truncated')
FLAG_TEXT = {
    'hub': 'called from very many places', 'icf': 'identical code folded with another function',
    'import': 'import stub', 'library': 'matches library code', 'thunk': 'thunk: a jump to another function',
    'tiny': 'very small function', 'ir-missing': 'no ProgramIR for this function',
    'mask-missing': 'no address mask for this function', 'mask-unlocated': 'the address mask could not be placed',
    'oversize': 'too large to analyze in full', 'truncated': 'code was cut at the scan limit'}
SHAPE_CLASSES = frozenset({'block-added', 'block-removed', 'callee', 'call-added', 'call-removed', 'comparison',
                           'condition', 'constant', 'data-ref', 'struct-offset'})
NUISANCE_CLASSES = ('address-only', 'frame', 'layout-only', 'name-only', 'refcount-only', 'register-only',
                    'size-only')
# What a delta (by channel) or a proof read: operand level, CFG, callee lists, constants, decompiler text.
EVIDENCE_CLASS_OF_CHANNEL = {'C0': 'E-BODY', 'C1': 'E-BODY', 'C2': 'E-BODY', 'C3': 'E-CFG', 'C4': 'E-CALL',
                             'C5': 'E-DATA', 'C6': 'E-DECOMP', 'C7': 'E-DECOMP', 'C8': 'E-BODY'}
EVIDENCE_CLASS_OF_PROOF = {'UNCH/1': 'E-BODY', 'COS-ADDR/1': 'E-BODY', 'COS-LAYOUT/1': 'E-LAYOUT',
                           'COS-PSEUDO/1': 'E-DECOMP'}


def _refs(sides: tuple[SideRef, ...]) -> tuple[FunctionRef, ...]:
    return tuple(FunctionRef(rva=s.rva, name=clean_line(s.name, 256) or None) for s in sides[:MAX_SIDE_FUNCTIONS])


def _stream(read: Callable, directory: Path, manifest: UnifiedResultManifest) -> Iterator:
    """The store's reader, with its failures reported as a storage error of this feature."""
    try:
        yield from read(directory, manifest)
    except UnifiedError as exc:
        raise PilotError('PT-PILOT-STORAGE', 'The unified result could not be read', reason='unified-read') from exc


def _delta_text(delta: Delta) -> str:
    if delta.old is not None and delta.new is not None:
        return f'{delta.cls}: {delta.old} -> {delta.new}'
    if delta.new is not None:
        return f'{delta.cls}: {delta.new}'
    return delta.cls if delta.old is None else f'{delta.cls}: was {delta.old}'


def _delta_nav(delta: Delta) -> Nav:
    """The newer address when there is one; a removed thing is located on the older side."""
    if delta.newer_rva is not None:
        return Nav(side='newer', rva=delta.newer_rva)
    return Nav(side='older', rva=delta.older_rva)


def _row_nav(spot: tuple[int | None, int | None]) -> Nav | None:
    older, newer = spot
    if newer is not None:
        return Nav(side='newer', rva=newer)
    return None if older is None else Nav(side='older', rva=older)


def _proof_observation(fact: ChangeFacts, spot, registry: OriginRegistry) -> Observation:
    if fact.verdict == 'unchanged':
        detail = 'proof UNCH/1 holds: the code is unchanged'
    else:
        relative = ' (decompiler-relative)' if fact.proof == 'COS-PSEUDO/1' else ''
        detail = f'proof {fact.proof} holds: the change is cosmetic{relative}'
    return build_observation(
        registry, source='change-facts', channel='code', kind=f'cf:{fact.verdict}', role='conflict',
        verification='tool-reported', evidence_class=EVIDENCE_CLASS_OF_PROOF[fact.proof or ''],
        ref_kind='change-facts', ref_id=fact.row_id, detail=detail, nav=_row_nav(spot))


def _fact_observations(fact: ChangeFacts, spot, registry: OriginRegistry) -> list[Observation]:
    if fact.verdict in ('unchanged', 'cosmetic'):
        return [_proof_observation(fact, spot, registry)]
    if fact.verdict not in ('material', 'review'):
        return []  # unknown and not-applicable: nothing was observed
    out = []
    for index, delta in enumerate(fact.deltas):
        shape = delta.cls in SHAPE_CLASSES
        out.append(build_observation(
            registry, source='change-facts', channel='code', kind=f'cf:{delta.cls}',
            role='shape' if shape else 'context', verification='tool-reported',
            evidence_class=EVIDENCE_CLASS_OF_CHANNEL[delta.channel], ref_kind='change-facts', ref_id=fact.row_id,
            ref_pointer=f'/deltas/{index}', detail=_delta_text(delta), nav=_delta_nav(delta),
            obligations=('second-channel',) if shape and fact.verdict == 'review' else ()))
    return out


def _row_observations(row: UnifiedMatch, spot, registry: OriginRegistry) -> list[Observation]:
    return [build_observation(
        registry, source='change-facts', channel='pairing', kind=f'pair:{flag}', role='context',
        verification='tool-reported', evidence_class='E-BODY', ref_kind='unified-row', ref_id=row.row_id,
        detail=FLAG_TEXT[flag], nav=_row_nav(spot)) for flag in (*NUISANCE_FLAGS, *QUALITY_FLAGS)
        if flag in row.flags]


def _class_observations(row_id: str, classes: Iterable[str], spot, registry: OriginRegistry) -> list[Observation]:
    return [build_observation(
        registry, source='change-facts', channel='code', kind=f'cf:{name}', role='context',
        verification='tool-reported', evidence_class='E-NAME' if name == 'name-only' else 'E-BODY',
        ref_kind='unified-row', ref_id=row_id, detail=f'row class {name}: no code change was listed',
        nav=_row_nav(spot)) for name in classes]


class _Reading:
    """What one pass over the rows and facts of a result collects (candidates, locations, observations)."""

    def __init__(self, registry: OriginRegistry, limits: PilotLimits, budget: Budget | None):
        self.registry, self.limits, self.budget = registry, limits, budget
        self.candidates: list[Candidate] = []
        self.where: dict[str, tuple[int | None, int | None]] = {}
        self.noise: dict[str, tuple[str, ...]] = {}  # row-level noise classes no delta has carried (yet)
        self.found: dict[str, list[Observation]] = {}
        self.cut_rows = 0

    def row(self, row: UnifiedMatch) -> None:
        if self.budget is not None:
            self.budget.tick()
        if len(self.candidates) >= self.limits.p01_candidates:
            raise PilotError('PT-PILOT-LIMIT', 'The candidate universe exceeds the limit', reason='candidates')
        self.cut_rows += len(row.older) > MAX_SIDE_FUNCTIONS or len(row.newer) > MAX_SIDE_FUNCTIONS
        self.candidates.append(Candidate(
            candidate_key=row.row_id, older=_refs(row.older), newer=_refs(row.newer),
            identity=IDENTITY_OF_DECISION[row.decision]))  # type: ignore[arg-type]
        spot = (row.older[0].rva if row.older else None, row.newer[0].rva if row.newer else None)
        self.where[row.row_id] = spot
        noise = tuple(name for name in row.change_classes if name in NUISANCE_CLASSES)
        if noise:
            self.noise[row.row_id] = noise
        if any(flag in row.flags for flag in (*NUISANCE_FLAGS, *QUALITY_FLAGS)):
            self.found.setdefault(row.row_id, []).extend(_row_observations(row, spot, self.registry))

    def fact(self, fact: ChangeFacts) -> None:
        if self.budget is not None:
            self.budget.tick()
        spot = self.where.get(fact.row_id)
        if spot is None:
            return
        self.found.setdefault(fact.row_id, []).extend(_fact_observations(fact, spot, self.registry))
        if fact.row_id in self.noise:
            carried = {d.cls for d in fact.deltas} if fact.verdict in ('material', 'review') else set()
            self.noise[fact.row_id] = tuple(name for name in self.noise[fact.row_id] if name not in carried)

    def observations(self) -> tuple[dict[str, tuple[Observation, ...]], int]:
        """The per-candidate table (row-level noise classes added) and how many observations the cap cut."""
        for row_id, classes in self.noise.items():
            self.found.setdefault(row_id, []).extend(
                _class_observations(row_id, classes, self.where[row_id], self.registry))
        table, cut = {}, 0
        for key, items in self.found.items():
            kept, dropped = settle(items)
            cut += dropped
            if kept:
                table[key] = kept
        return table, cut


def _current(loaded: LoadedResult, older_sha256: str, newer_sha256: str) -> tuple[UnifiedResultManifest, Path]:
    """The manifest and directory of a current result of exactly this pair in this orientation."""
    manifest, directory = loaded.manifest, loaded.directory
    if loaded.state != 'current' or manifest is None or directory is None:
        raise PilotError('PT-PILOT-STALE', 'The unified result is not current', reason=f'unified-{loaded.state}')
    pair = (manifest.older_sha256, manifest.newer_sha256)
    if older_sha256 != newer_sha256 and pair == (newer_sha256, older_sha256):
        raise PilotError('PT-PILOT-ORIENTATION', 'The unified result describes the reversed pair',
                         reason='unified-orientation')
    if pair != (older_sha256, newer_sha256):
        raise PilotError('PT-PILOT-MISMATCH', 'The unified result describes another pair', reason='unified-pair')
    return manifest, directory


@dataclass(frozen=True)
class UnifiedView:
    """One current unified result read once: its candidates and the observations of its facts and rows."""
    result_id: str
    status: str
    limitations: tuple[str, ...]
    typed: bool  # ProgramIR on both sides; without it (S0 mode) the facts are decompiler- and name-relative
    candidates: tuple[Candidate, ...]
    observations: Mapping[str, tuple[Observation, ...]]
    cut_rows: int
    cut_observations: int

    @classmethod
    def read(cls, loaded: LoadedResult, *, older_sha256: str, newer_sha256: str,
             registry: OriginRegistry = DEFAULT_REGISTRY, limits: PilotLimits = DEFAULT_LIMITS,
             budget: Budget | None = None) -> UnifiedView:
        manifest, directory = _current(loaded, older_sha256, newer_sha256)
        reading = _Reading(registry, limits, budget)
        for row in _stream(read_rows, directory, manifest):
            reading.row(row)
        for fact in _stream(read_facts, directory, manifest):
            reading.fact(fact)
        table, cut = reading.observations()
        return cls(result_id=manifest.result_id, status=manifest.status, limitations=manifest.limitations,
                   typed=manifest.ir_older is not None,
                   candidates=tuple(sorted(reading.candidates, key=lambda c: c.candidate_key)),
                   observations=MappingProxyType(table), cut_rows=reading.cut_rows, cut_observations=cut)


class UnifiedPairing:
    """`PairingSource` over a current unified result: its rows are the candidates, its decisions the identities."""

    def __init__(self, view: UnifiedView):
        self._view = view

    def status(self) -> ChannelStatus:
        view = self._view
        notes = []
        if view.status == 'partial':
            notes.append('the unified result is partial: ' + '; '.join(view.limitations[:3]))
        if view.cut_rows:
            notes.append(f'{view.cut_rows} row(s) with more than {MAX_SIDE_FUNCTIONS} functions on a side are listed '
                         'in part')
        return channel_status('pairing', 'partial' if notes else 'available', '; '.join(notes))

    def candidates(self) -> Iterator[Candidate]:
        return iter(self._view.candidates)

    def unified_result_id(self) -> str:
        return self._view.result_id

    def secondary_set_ids(self) -> tuple[str, ...]:
        return ()  # a unified result already fuses the secondary engines; counting them again would double their weight


class UnifiedFacts:
    """`ChangeEvidenceSource` over the ChangeFacts and row flags of a current unified result (the typed source of
    `code.CodeEvidence`)."""

    def __init__(self, view: UnifiedView):
        self._view = view

    def status(self) -> ChannelStatus:
        view = self._view
        notes = []
        if not view.typed:
            notes.append('unified S0 result: facts come from Ghidriff text and names, no ProgramIR')
        if view.status == 'partial':
            notes.append('the unified result is partial: ' + '; '.join(view.limitations[:3]))
        if view.cut_observations:
            notes.append(f'{view.cut_observations} observation(s) beyond the cap of {MAX_PER_CANDIDATE} per candidate '
                         'not listed')
        return channel_status('code', 'partial' if notes else 'available', '; '.join(notes))

    def observations(self, candidate_keys: Iterable[str]) -> Iterator[tuple[str, Observation]]:
        return lookup(self._view.observations, candidate_keys)
