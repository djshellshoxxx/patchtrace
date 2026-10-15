"""Fusion: the observations of one candidate read against the hypotheses of one CVE (PIL-integration-plan.md s7 tier
steps 2 and 3, s6 "Averaging or summing channels" and "Shared origin counted twice").

For every hypothesis of the advisory (a K rule revision found in the PIL rule table) the expected changes are
evaluated three-valued by `rules.evaluate`: a change is met by shape evidence, contradicted by a named proof, not
observed only by a complete channel and otherwise unknown. Independence is counted over the origins of the evidence
that meets a change plus the advisory text: observations that share an origin (B1, ChangeFacts and call labels are all
`D_ghidra`; every repetition of the advisory is `D_vendor_text`) form one component, and the number of components is
the number of independent witnesses. Locality (a function name that matches the advisory's component phrase) is never
a witness; it only separates the CVEs of a confounded window. Nothing here adds, weights or averages anything.

A hypothesis is `eligible` for a moderate tier when every required change is met (`ready`), each of them by at least
one observation that is not a bare call label ("label-only calls support at most tentative", s4), and two components
agree. A rule without a B1 detector (14 of 22) rests on thinner machine evidence, so it also needs two independent
components among the code observations alone, the advisory excluded (s7: "stay tentative unless two components
agree").

Speed: the states of the expected changes depend only on the pattern of the evidence (kind, role, B1 level, and
whether a call names one of the rule's API hints), not on which observations they are. A pattern is evaluated once per
rule and then shared by every candidate that shows it, as positions into that candidate's own observations; the
`ExpectedChange` records are built only for the leads that are kept (`Fit.changes`).
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from types import MappingProxyType
from typing import NamedTuple

from ..enrichment.cve import name_terms
from ..intelligence.contracts import Anchor, PatchHypothesis
from .contracts import (
    Candidate,
    ChannelState,
    CveContext,
    ExpectedChange,
    HypothesisFit,
    Nav,
    Observation,
    ObsRef,
    PilotConfig,
    clean_line,
)
from .keys import make_observation
from .ports import OriginRegistry
from .quality import category, is_change, is_material, is_placeholder, is_toolchain, is_typed
from .ranking import BASIS_INDEX, NO_BASIS, Key, advisory_key, code_key, severity
from .rules.contracts import PilotRule
from .rules.data import find_rule
from .rules.evaluate import Evidence, api_key, evaluate_rule
from .tiers import Tier, TierFacts, derive, lead_class

# B1 reports a signal at its detector's default confidence unless a finding says otherwise. `INT` reports `moderate` for a
# strictness flip on identical operands; the observation does not repeat the confidence, so `INT` is read at `weak`, the
# confidence every INT signal has. Tests pin this table to `enrichment.signals.DETECTORS`.
B1_LEVEL = MappingProxyType({'BND': 'moderate', 'ERR': 'weak', 'INT': 'weak', 'OVF': 'moderate', 'SCRUB': 'moderate',
                             'SIZE': 'moderate', 'VAL': 'weak'})
RULE_CHANNELS = ('code', 'calls', 'capa')  # the channels a rule leaf can read
# The code channels compare one function with one function. Against a one-sided or group candidate they say nothing, so
# every change they would have observed is unknown, never "not seen".
BLIND = MappingProxyType(dict.fromkeys(RULE_CHANNELS, 'unsupported'))
ADVISORY_TEXT = 'advisory-text'  # the origin source of every repetition of an advisory statement
NAME_SOURCE = 'names'
_SHAPE_ROLES = ('shape', 'local')
Components = tuple[tuple[str, ...], ...]
Base = tuple[tuple[str, str, str], ...]  # (kind, role, B1 level or '') per observation of the evidence


class Change(NamedTuple):
    """One expected change as a pattern evaluation left it: `positions` index the pattern's observations."""
    id: str
    state: str
    required: bool
    positions: tuple[int, ...]
    teach_id: str


class Shape(NamedTuple):
    """The three-valued evaluation of one rule against one evidence pattern."""
    changes: tuple[Change, ...]
    conflicts: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class Held:
    """What PIL holds about one candidate, whatever the CVE: its observations (deduplicated, ordered by id) and the
    counts the order key reads."""
    candidate: Candidate
    observations: tuple[Observation, ...]
    base: Base  # the shape and conflict observations as the rule table reads them, in a fixed order ...
    ids: tuple[str, ...]  # ... their ids in that order ...
    calls: tuple[tuple[int, str], ...]  # ... and the (position, API key) of those that are calls
    comparable: bool  # one function on each side: the only candidate the code channels can compare
    change: bool
    nuisance: int
    toolchain: bool
    severity: int
    shape_kinds: int
    anchored: bool
    tokens: frozenset[str]


@dataclass(frozen=True, slots=True)
class View:
    """What PIL holds about one CVE: its context, rule hypotheses (with their rows), the advisory's own ledger entries
    and the component phrases the function names are compared with."""
    context: CveContext
    hypotheses: tuple[PatchHypothesis, ...]
    rules: tuple[PilotRule | None, ...]  # parallel to `hypotheses`; None = no expected changes, fails closed
    observations: tuple[Observation, ...]
    origin_sets: tuple[tuple[str, ...], ...]
    phrases: tuple[frozenset[str], ...]
    confounded: bool


@dataclass(slots=True)
class Run:
    """State shared by one localization run: the channel states the rules read, the configuration, every observation by
    id, and the caches."""
    states: Mapping[str, ChannelState]
    config: PilotConfig
    registry: OriginRegistry
    pool: Mapping[str, Observation]
    components: dict[frozenset, Components] = field(default_factory=dict)
    shapes: dict[tuple, Shape] = field(default_factory=dict)
    hints: dict[tuple[str, ...], frozenset[str]] = field(default_factory=dict)
    bare: dict[tuple[str, bool], Fused] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Fit:
    """One hypothesis evaluated for one candidate."""
    index: int  # position in the advisory's hypothesis list (its own order is the last tie-break)
    hypothesis: PatchHypothesis
    shape: Shape
    ids: tuple[str, ...]  # the candidate's observation ids by pattern position
    support: tuple[str, ...]  # the shape observations that meet a change, by id
    components: Components  # independent witnesses: that evidence plus the advisory
    met: int
    ready: bool
    eligible: bool
    conflicted: bool  # a named proof argues against any change

    def changes(self) -> tuple[ExpectedChange, ...]:
        return tuple(ExpectedChange(id=c.id, state=c.state, required=c.required, teach_id=c.teach_id,
                                    observation_ids=tuple(sorted(self.ids[p] for p in c.positions)))
                     for c in self.shape.changes)


@dataclass(frozen=True, slots=True)
class Fused:
    """The fusion result for one candidate in one context (no advisory: `fits` is empty and `support` is all shape
    evidence)."""
    fits: tuple[Fit, ...]  # best first
    best: Fit | None
    support: tuple[str, ...]
    components: Components
    typed: bool
    material: bool
    conflict: bool  # a named proof argues against the met required change


@dataclass(frozen=True, slots=True)
class Assessed:
    fused: Fused
    tier: Tier
    lead_class: str
    key: Key
    local_hits: int
    local_tokens: tuple[str, ...]


# --- candidates -------------------------------------------------------------------------------------------------------

def evidence_of(observation: Observation) -> Evidence | None:
    """The rule table's view of an observation; only shape and conflict observations are read. The call API is the
    reference id; capa leaves are unused in v1, so no capability namespace is carried."""
    if observation.role not in ('shape', 'conflict'):
        return None
    prefix, _, name = observation.kind.partition(':')
    level = B1_LEVEL.get(name) if prefix == 'b1' else None
    return Evidence(observation.obs_id, observation.kind, observation.role, level,
                    observation.ref.id if prefix == 'call' else None)


@lru_cache(maxsize=1 << 16)
def _name_tokens(name: str) -> frozenset[str]:
    return frozenset() if is_placeholder(name) else frozenset(name_terms(name))


def candidate_tokens(candidate: Candidate) -> frozenset[str]:
    names = {ref.name for side in (candidate.older, candidate.newer) for ref in side if ref.name}
    return frozenset().union(*map(_name_tokens, names))


def hold(candidate: Candidate, observations: Iterable[Observation]) -> Held:
    unique = tuple(sorted({o.obs_id: o for o in observations}.values(), key=lambda o: o.obs_id))
    evidence = sorted((e for e in map(evidence_of, unique) if e is not None),
                      key=lambda e: (e.kind, e.role, e.level or '', e.subject or '', e.obs_id))
    return Held(
        candidate=candidate, observations=unique, base=tuple((e.kind, e.role, e.level or '') for e in evidence),
        ids=tuple(e.obs_id for e in evidence),
        calls=tuple((i, api_key(e.subject)) for i, e in enumerate(evidence) if e.subject),
        comparable=len(candidate.older) == len(candidate.newer) == 1, change=any(map(is_change, unique)),
        nuisance=sum(category(o) == 'alternative' for o in unique), toolchain=any(map(is_toolchain, unique)),
        severity=severity(unique), shape_kinds=len({o.kind for o in unique if o.role == 'shape'}),
        anchored=any(o.role == 'shape' and is_material(o) for o in unique), tokens=candidate_tokens(candidate))


# --- the advisory -----------------------------------------------------------------------------------------------------

def _phrases(anchors: Iterable[Anchor]) -> tuple[frozenset[str], ...]:
    """Token sets of the advisory's component phrases, without the tokens of its module and feature names (they name
    the whole product, not one function)."""
    anchors = tuple(anchors)
    skip = frozenset().union(*(name_terms(a.value) for a in anchors if a.kind in ('module', 'feature')))
    found = {frozenset(name_terms(a.value)) - skip for a in anchors if a.kind == 'component'}
    return tuple(sorted((p for p in found if p), key=sorted))


def view_of(context: CveContext, hypotheses: Iterable[PatchHypothesis], anchors: Iterable[Anchor],
            observations: Iterable[Observation], config: PilotConfig, registry: OriginRegistry) -> View:
    hypotheses = tuple(hypotheses)
    ledger = tuple(sorted({o.obs_id: o for o in observations}.values(), key=lambda o: o.obs_id))
    origin_sets = tuple(sorted({o.origins for o in ledger}))
    if not origin_sets and hypotheses:  # a hypothesis exists because of the advisory text, ledger entry or not
        origin_sets = (registry.tags_for(ADVISORY_TEXT),)
    window = context.confounding
    return View(
        context=context, hypotheses=hypotheses, rules=tuple(find_rule(h.rule_id, h.rule_revision) for h in hypotheses),
        observations=ledger, origin_sets=origin_sets, phrases=_phrases(anchors),
        confounded=window.state == 'yes' and len(window.cves) >= config.confounded_min_cves)


def locality(held: Held, view: View, minimum: int) -> tuple[int, tuple[str, ...]]:
    """The most name tokens one component phrase shares with the function; below `minimum` there is no locality."""
    hits, tokens = 0, ()
    for phrase in view.phrases:
        shared = held.tokens & phrase
        if len(shared) > hits:
            hits, tokens = len(shared), tuple(sorted(shared))
    return (hits, tokens) if hits >= minimum else (0, ())


def locality_observation(candidate: Candidate, cve: str, tokens: tuple[str, ...], registry: OriginRegistry) -> Observation:
    """The ledger entry of a locality, role `local`: the tokens a function name shares with the advisory's component."""
    side, ref = ('newer', candidate.newer[0]) if candidate.newer else ('older', candidate.older[0])
    return make_observation(
        channel='pairing', kind='loc:names', role='local', verification='label-only',
        origins=registry.tags_for(NAME_SOURCE), evidence_class='E-NAME', ref=ObsRef(kind='name-tokens', id=cve),
        nav=Nav(side=side, rva=ref.rva),
        detail=clean_line(f'function name shares {", ".join(tokens)} with the advisory component'))


# --- hypotheses against a candidate ---------------------------------------------------------------------------------------

def _components(run: Run, origin_sets: Iterable[tuple[str, ...]]) -> Components:
    key = frozenset(origin_sets)
    found = run.components.get(key)
    if found is None:
        found = run.components[key] = run.registry.components(tuple(sorted(key)))
    return found


def _hint_keys(run: Run, api_hints: tuple[str, ...]) -> frozenset[str]:
    if api_hints not in run.hints:
        run.hints[api_hints] = frozenset(map(api_key, api_hints))
    return run.hints[api_hints]


def _shape(rule: PilotRule, hypothesis: PatchHypothesis, hinted: tuple[int, ...], held: Held, run: Run) -> Shape:
    """`rules.evaluate` on an evidence pattern (synthetic ids are the positions), once per rule and pattern; `hinted`
    are the positions of the calls that name one of the hypothesis's API hints."""
    key = (rule.rule_id, rule.revision, hypothesis.api_hints, held.comparable, held.base, hinted)
    found = run.shapes.get(key)
    if found is None:
        evidence = [Evidence(f'{i:064x}', kind, role, level or None, hypothesis.api_hints[0] if i in hinted else None)
                    for i, (kind, role, level) in enumerate(held.base)]
        evaluation = evaluate_rule(rule, evidence, run.states if held.comparable else BLIND, hypothesis.api_hints)
        found = run.shapes[key] = Shape(
            tuple(Change(c.id, c.state, c.required, tuple(int(i, 16) for i in c.observation_ids), c.teach_id)
                  for c in evaluation.changes), tuple(int(i, 16) for i in evaluation.conflict_ids))
    return found


def _firm(shape: Shape, ids: tuple[str, ...], run: Run) -> bool:
    """Every required change is met by an observation that is more than a call label."""
    return all(any(run.pool[ids[p]].verification != 'label-only' for p in change.positions)
               for change in shape.changes if change.required)


def _fit(index: int, hypothesis: PatchHypothesis, rule: PilotRule, held: Held, view: View, run: Run) -> Fit:
    hints = _hint_keys(run, hypothesis.api_hints)
    shape = _shape(rule, hypothesis, tuple(i for i, key in held.calls if key in hints), held, run)
    ids = held.ids
    met = sum(change.state == 'met' for change in shape.changes)
    ready = met >= 1 and all(change.state == 'met' for change in shape.changes if change.required)
    support = tuple(sorted({ids[p] for change in shape.changes if change.state == 'met' for p in change.positions}))
    code = {run.pool[i].origins for i in support}
    components = _components(run, (*code, *view.origin_sets)) if support else ()
    eligible = (ready and _firm(shape, ids, run) and len(components) >= 2
                and (bool(rule.detectors) or len(_components(run, code)) >= 2))
    return Fit(index, hypothesis, shape, ids, support, components, met, ready, eligible, bool(shape.conflicts))


def _fit_order(fit: Fit) -> tuple[bool, bool, int, int, int]:
    return not fit.eligible, not fit.ready, -fit.met, BASIS_INDEX[fit.hypothesis.basis], fit.index


def _fused(fits: tuple[Fit, ...], run: Run) -> Fused:
    best = fits[0] if fits else None
    support = best.support if best else ()
    observations = [run.pool[i] for i in support]
    return Fused(fits=fits, best=best, support=support, components=best.components if best else (),
                 typed=any(map(is_typed, observations)), material=any(map(is_material, observations)),
                 conflict=bool(best and best.ready and best.conflicted))


def fuse(held: Held, view: View, run: Run) -> Fused:
    """Every hypothesis with a rule row evaluated against the candidate, the best first; a hypothesis without a row
    fails closed (it is left out, never guessed). Candidates with no evidence share one result per CVE."""
    bare = (view.context.cve, held.comparable)
    if not held.ids and bare in run.bare:
        return run.bare[bare]
    fits = tuple(sorted((_fit(i, h, r, held, view, run)
                         for i, (h, r) in enumerate(zip(view.hypotheses, view.rules, strict=True)) if r is not None),
                        key=_fit_order))
    fused = _fused(fits, run)
    if not held.ids:
        run.bare[bare] = fused
    return fused


def fuse_code(held: Held, run: Run) -> Fused:
    """No advisory: the shape evidence of the candidate itself, nothing to fit it to."""
    shape = [o for o in held.observations if o.role in _SHAPE_ROLES]
    return Fused(fits=(), best=None, support=tuple(o.obs_id for o in shape),
                 components=_components(run, (o.origins for o in shape)), typed=any(map(is_typed, shape)),
                 material=any(map(is_material, shape)), conflict=False)


# --- the verdict ------------------------------------------------------------------------------------------------------

def assess(held: Held, view: View, run: Run) -> Assessed:
    """The tier, class and order key of one candidate for one CVE."""
    fused = fuse(held, view, run)
    best = fused.best
    hits, tokens = locality(held, view, run.config.locality_min_tokens)
    identity = held.candidate.identity
    tier = derive(TierFacts(
        gate=view.context.gate, identity=identity, eligible=bool(best and best.eligible),
        met_any=bool(best and best.met), change=held.change, local=hits > 0, typed=fused.typed,
        material=fused.material, conflict=fused.conflict, confounded=view.confounded, toolchain=held.toolchain,
        lexical_moderate=run.config.lexical_moderate))
    cls = lead_class(tier.mechanism, view.context.gate, held.change)
    key = advisory_key(
        lead_class=cls, mechanism=tier.mechanism, contested=identity == 'contested', met=best.met if best else 0,
        components=len(fused.components), basis=BASIS_INDEX[best.hypothesis.basis] if best else NO_BASIS,
        local_hits=hits, anchored=held.anchored, severity=held.severity, nuisance=held.nuisance)
    return Assessed(fused, tier, cls, key, hits, tokens)


def assess_code(held: Held, run: Run) -> Assessed:
    """The class and order key of one candidate with code evidence only: changed or not, and in what order to look."""
    fused = fuse_code(held, run)
    tier = derive(TierFacts(
        gate='none', identity=held.candidate.identity, eligible=False, met_any=False, change=held.change, local=False,
        typed=fused.typed, material=fused.material, conflict=False, confounded=False, toolchain=held.toolchain,
        lexical_moderate=run.config.lexical_moderate))
    cls = lead_class(tier.mechanism, 'none', held.change)
    key = code_key(lead_class=cls, severity=held.severity, shape_kinds=held.shape_kinds, anchored=held.anchored,
                   nuisance=held.nuisance)
    return Assessed(fused, tier, cls, key, 0, ())


def hypothesis_fit(fit: Fit) -> HypothesisFit:
    h = fit.hypothesis
    return HypothesisFit(hypothesis_id=h.hypothesis_id, rule_id=h.rule_id, rule_revision=h.rule_revision,
                         cwe_id=h.cwe_id, basis=h.basis, expected_changes=fit.changes(), met=fit.met,
                         total=len(fit.shape.changes))
