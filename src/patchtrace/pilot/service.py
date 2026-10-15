"""The localization service: `localize(inputs, config, cancel) -> PilotAssessment` (PIL-integration-plan.md s7, s9 PIL-B2).

It reads the six ports (and the per-CVE contexts the advisory adapters report) and ranks every candidate function pair,
for the code evidence alone and for every CVE whose gate lets it:

1. the candidate universe, once, with its pairing verdicts;
2. the observations of each candidate from the code, call and tool channels (an observation of a channel that did not
   run, failed or is stale is not read: missing evidence is unknown, never a negative vote);
3. per context, `fusion.assess` gives each candidate its mechanism, class and integer order key and `ranking.place`
   orders them with explicit tie groups; only the leads P-04 allows are built, the rest are counted.

Nothing is sent, executed or written. The deadline (P-08) and the caller's cancel event are honoured throughout
(`PT-PILOT-CANCEL`, `PT-PILOT-LIMIT`). The result identifies itself: `result_id` hashes every input digest, and the
contract validators reject a lead that breaks a rule of s7. The assessment holds no float.

Contexts: a lead belongs to one context. The code-only context (`cve` None, gate `none`) is always present, so the Leads
dock can show the changed functions whether or not an advisory is loaded; each CVE context follows, sorted by id. A CVE
whose gate is `not-applicable` has a context and no leads. `queue_count` is the number of queue rows (changed or not,
no fit) that P-04 left out of `leads`, over all contexts; a context's `counts` hold the true totals.
"""
from __future__ import annotations

import threading
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from pydantic import ValidationError

from ..intelligence.hypotheses import rules_digest
from ..intelligence.lexicon import lexicon_digest
from .contracts import (
    CHANNELS,
    CLASS_RANK,
    LEAD_CLASSES,
    Candidate,
    ChannelStatus,
    CveContext,
    Lead,
    LeadComponents,
    LeadCounts,
    Observation,
    PilotAssessment,
    PilotConfig,
    PilotInputs,
    Tie,
    clean_line,
)
from .fusion import (
    RULE_CHANNELS,
    Assessed,
    Fused,
    Held,
    Run,
    View,
    assess,
    assess_code,
    hold,
    hypothesis_fit,
    locality_observation,
    view_of,
)
from .keys import config_digest, limits_digest, result_id
from .limits import DEFAULT_LIMITS, Budget, PilotError
from .origins import DefaultOriginRegistry
from .ports import (
    AdvisorySource,
    CallDeltaSource,
    ChangeEvidenceSource,
    KevSource,
    OriginRegistry,
    PairingSource,
    ToolEvidenceSource,
)
from .quality import category
from .ranking import Place, place
from .rules.data import pilot_rules_digest
from .tiers import TIERS_VERSION
from .why import CHANNEL_LABELS

DEFAULT_REGISTRY = DefaultOriginRegistry()
_LIMITS = DEFAULT_LIMITS
_USABLE = ('available', 'partial')  # a channel in any other state yields no evidence: unknown, not a negative vote
_CHECK_EVERY = 64  # work units between two looks at the clock and the cancel event
_GROUPS = ('support', 'counter', 'unknown', 'alternative')
_NO_REPORT = 'No advisory report is stored for this CVE, so no expected change applies to it.'
_NO_COMPONENT = 'The advisory names no component, so function names could not separate the CVEs fixed in this build.'


class LocalizeInputs(Protocol):
    """Everything `localize` reads: a frozen dataclass, or any object with these attributes.

    The ports are the A1 Protocols. `contexts` are the per-CVE contexts as the advisory adapters report them (gate, CWE
    summary, KEV state, window; their counts are zero, localization fills them) and `advisory_observations` the `adv:*`
    ledger entries of every source that repeats the CWE. `advisory` may also offer `status() -> ChannelStatus` (the
    stored-advisory adapter does); without it the advisory channel is `available` when contexts exist, else `not-run`."""
    project_id: str
    revision: int
    older_sha256: str
    newer_sha256: str
    ghidriff_run_id: str
    raw_sha256: str
    advisory: AdvisorySource
    changes: ChangeEvidenceSource
    tools: ToolEvidenceSource
    kev: KevSource
    calls: CallDeltaSource
    pairing: PairingSource
    contexts: Sequence[CveContext]
    advisory_observations: Mapping[str, Sequence[Observation]]


@dataclass(slots=True)
class _Outcome:
    """The leads of one context and what P-04 left out of them."""
    leads: list[Lead]
    counts: dict[str, int]
    leads_cut: int = 0
    queue_cut: int = 0
    trimmed: bool = False  # a lead was cut to P-02


@dataclass(slots=True)
class _Work:
    """What every context of one run reads: the candidates, the shared state and the budget."""
    items: list[Held]
    run: Run
    budget: Budget
    by_key: dict[str, Held] = field(init=False)
    extra: dict[str, Observation] = field(default_factory=dict)  # advisory and locality entries, not in `run.pool`

    def __post_init__(self) -> None:
        self.by_key = {h.candidate.candidate_key: h for h in self.items}


@dataclass(slots=True)
class _Ranking:
    leads: list[Lead] = field(default_factory=list)
    cves: list[CveContext] = field(default_factory=list)
    outcomes: list[_Outcome] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)  # evidence a CVE could not use because a source was missing


# --- reading the sources ----------------------------------------------------------------------------------------------

def _invalid(message: str, reason: str) -> PilotError:
    return PilotError('PT-PILOT-INPUT', message, reason=reason)


def _check_config(config: PilotConfig) -> None:
    if config.limits_digest != limits_digest(_LIMITS):
        raise _invalid('The configuration was made for other limits than these', 'limits-digest')


def _advisory_status(inputs: LocalizeInputs) -> ChannelStatus:
    offered = getattr(inputs.advisory, 'status', None)
    if callable(offered):
        return offered()
    if inputs.contexts:
        return ChannelStatus(channel='advisory', state='available')
    return ChannelStatus(channel='advisory', state='not-run', reason='no advisory is loaded')


def _channels(inputs: LocalizeInputs) -> dict[str, ChannelStatus]:
    """The seven channel states in canonical order; a channel no source reported was not run."""
    found: dict[str, ChannelStatus] = {}

    def put(status: ChannelStatus, owned: tuple[str, ...]) -> None:
        if status.channel not in owned or status.channel in found:
            raise _invalid('A source reported a channel it does not own, or a channel twice', 'channel-mismatch')
        found[status.channel] = status

    put(inputs.changes.status(), ('code',))
    put(inputs.calls.status(), ('calls',))
    put(inputs.pairing.status(), ('pairing',))
    put(_advisory_status(inputs), ('advisory',))
    for status in inputs.tools.statuses():
        put(status, ('strings', 'capa', 'build'))
    return {name: found.get(name) or ChannelStatus(channel=name, state='not-run', reason='no source reported it')
            for name in CHANNELS}


def _contexts(inputs: LocalizeInputs) -> tuple[CveContext, ...]:
    contexts = tuple(sorted(inputs.contexts, key=lambda c: c.cve))
    if len(contexts) > _LIMITS.p03_cves:
        raise PilotError('PT-PILOT-LIMIT', f'A run covers at most {_LIMITS.p03_cves} CVEs', reason='cves')
    if len({c.cve for c in contexts}) != len(contexts):
        raise _invalid('Two contexts describe one CVE', 'duplicate-context')
    return contexts


def _candidates(pairing: PairingSource, budget: Budget) -> list[Candidate]:
    found: dict[str, Candidate] = {}
    for candidate in pairing.candidates():
        budget.tick()
        if candidate.candidate_key in found:
            raise _invalid('The candidate universe lists a candidate twice', 'duplicate-candidate')
        if len(found) >= _LIMITS.p01_candidates:
            raise PilotError('PT-PILOT-LIMIT', 'The candidate universe exceeds the limit', reason='candidates')
        found[candidate.candidate_key] = candidate
    return list(found.values())


def _gather(inputs: LocalizeInputs, candidates: list[Candidate], channels: Mapping[str, ChannelStatus],
            budget: Budget) -> list[Held]:
    """Every candidate with the observations of the channels that ran, plus the binary-level ones that apply to all."""
    usable = {name for name, status in channels.items() if status.state in _USABLE}
    keys = [c.candidate_key for c in candidates]
    wanted = set(keys)
    attached: dict[str, list[Observation]] = defaultdict(list)
    for source in (inputs.changes, inputs.calls, inputs.tools):
        for key, observation in source.observations(keys):
            budget.tick()
            if key not in wanted:
                raise _invalid('A source reported evidence for a candidate that is not in the universe',
                               'unknown-candidate')
            if observation.channel in usable:
                attached[key].append(observation)
    budget.check()
    binary = [o for o in inputs.tools.pair_observations() if o.channel in usable]
    held = []
    for candidate in sorted(candidates, key=lambda c: c.candidate_key):
        budget.tick()
        held.append(hold(candidate, [*attached.get(candidate.candidate_key, ()), *binary]))
    return held


# --- ranking one context ------------------------------------------------------------------------------------------------

def _select(placed: Sequence[Place]) -> tuple[list[Place], int, int]:
    """The rows P-04 persists, in order, and how many leads and queue rows it leaves out."""
    queue = CLASS_RANK['queue']
    kept: list[Place] = []
    leads = rows = leads_cut = queue_cut = 0
    for row in placed:
        if row.key[0] == queue:
            if rows < _LIMITS.p04_queue_rows_per_context:
                kept.append(row)
                rows += 1
            else:
                queue_cut += 1
        elif leads < _LIMITS.p04_leads_per_context:
            kept.append(row)
            leads += 1
        else:
            leads_cut += 1
    return kept, leads_cut, queue_cut


def _depth(fused: Fused) -> str:
    return 'none' if not fused.support else 'typed' if fused.typed else 'lexical'


def _kind(assessed: Assessed) -> str:
    """`rule-hypothesis` when a rule's expected change is met or the lead was held back from a fit, else `unknown`."""
    best = assessed.fused.best
    if assessed.tier.mechanism in ('moderate', 'contested'):
        return 'rule-hypothesis'
    return 'rule-hypothesis' if assessed.tier.mechanism == 'tentative' and best is not None and best.met else 'unknown'


def _groups(held: Held, assessed: Assessed, view: View | None, work: _Work) -> dict[str, tuple[str, ...]]:
    """The four observation lists of a lead. The advisory's own entries back a lead only when code evidence meets an
    expected change (otherwise the advisory says nothing about this function); a locality is its own entry."""
    groups: dict[str, list[str]] = {name: [] for name in _GROUPS}
    for observation in held.observations:
        groups[category(observation)].append(observation.obs_id)
    if view is not None:
        if assessed.local_hits:
            local = locality_observation(held.candidate, view.context.cve, assessed.local_tokens, work.run.registry)
            work.extra[local.obs_id] = local
            groups['support'].append(local.obs_id)
        if assessed.fused.support:
            for observation in view.observations:
                work.extra[observation.obs_id] = observation
                groups['support'].append(observation.obs_id)
    return {name: tuple(sorted(set(ids))) for name, ids in groups.items()}


def _bound(groups: dict[str, tuple[str, ...]], pinned: set[str]) -> tuple[dict[str, tuple[str, ...]], bool]:
    """At most P-02 observations per lead: alternatives go first, then unknowns, then support context; `pinned` ids (the
    evidence behind an expected change, the advisory's entries and the locality) and every counter stay."""
    excess = len({i for ids in groups.values() for i in ids}) - _LIMITS.p02_observations_per_lead
    if excess <= 0:
        return groups, False
    droppable = [i for name in ('alternative', 'unknown', 'support') for i in groups[name] if i not in pinned]
    if len(droppable) < excess:
        raise PilotError('PT-PILOT-LIMIT', 'A lead references more observations than P-02 allows',
                         reason='lead-observations')
    gone = set(droppable[:excess])
    return {name: tuple(i for i in ids if i not in gone) for name, ids in groups.items()}, True


def _lead(held: Held, assessed: Assessed, where: Place, view: View | None, work: _Work) -> tuple[Lead, bool]:
    fused, tier = assessed.fused, assessed.tier
    fits = tuple(map(hypothesis_fit, fused.fits))
    groups = _groups(held, assessed, view, work)
    pinned = {i for fit in fits for change in fit.expected_changes for i in change.observation_ids}
    pinned |= {i for i in groups['support'] if i in work.extra}  # the advisory's entries and the locality
    groups, cut = _bound(groups, pinned)
    lead = Lead(
        candidate_key=held.candidate.candidate_key, cve=None if view is None else view.context.cve,
        lead_class=assessed.lead_class, mechanism=tier.mechanism, identity=held.candidate.identity,
        gate='none' if view is None else view.context.gate, depth=_depth(fused), fits=fits,
        components=LeadComponents(count=len(fused.components), tags=tuple(c[0] for c in fused.components)),
        local_hits=assessed.local_hits, caps=tier.caps, support_ids=groups['support'], counter_ids=groups['counter'],
        unknown_ids=groups['unknown'], alternative_ids=groups['alternative'], rank=where.rank,
        tie=Tie(size=where.last - where.first + 1, first=where.first, last=where.last), assessment=_kind(assessed),
        older=held.candidate.older, newer=held.candidate.newer)
    return lead, cut


def _rank_context(work: _Work, assess_one: Callable[[Held], Assessed], view: View | None) -> _Outcome:
    """Assess every candidate of one context, order them and build the leads P-04 keeps. The kept leads are assessed a
    second time to build them: the first pass keeps only the key, so memory stays flat at 250,000 candidates."""
    rows = []
    counts = dict.fromkeys(LEAD_CLASSES, 0)
    for item in work.items:
        work.budget.tick()
        assessed = assess_one(item)
        rows.append((assessed.key, item.candidate.candidate_key))
        counts[assessed.lead_class] += 1
    kept, leads_cut, queue_cut = _select(place(rows))
    outcome = _Outcome([], counts, leads_cut, queue_cut)
    for where in kept:
        work.budget.tick()
        item = work.by_key[where.candidate_key]
        lead, cut = _lead(item, assess_one(item), where, view, work)
        outcome.leads.append(lead)
        outcome.trimmed = outcome.trimmed or cut
    return outcome


# --- the context of each CVE ----------------------------------------------------------------------------------------------

def _view(inputs: LocalizeInputs, context: CveContext, config: PilotConfig, registry: OriginRegistry
          ) -> tuple[View, list[str]]:
    """The view of one CVE and the gaps in it: what its leads could not use because a source was missing."""
    report = inputs.advisory.report(context.cve)
    hypotheses = () if report is None else report.hypotheses.hypotheses[:_LIMITS.p07_rules]
    anchors = () if report is None else report.anchors.anchors
    view = view_of(context, hypotheses, anchors, inputs.advisory_observations.get(context.cve, ()), config, registry)
    gaps = [_NO_REPORT] if report is None else []
    gaps += [f'No expected changes are defined for rule {h.rule_id} revision {h.rule_revision}, so its leads stay '
             'unexplained.' for h, rule in zip(view.hypotheses, view.rules, strict=True) if rule is None]
    return view, gaps


def _counted(context: CveContext, outcome: _Outcome | None, notes: Iterable[str]) -> CveContext:
    """The context with its true lead counts (all zero when it has no leads) and the notes about its evidence."""
    counts = LeadCounts(**(outcome.counts if outcome else dict.fromkeys(LEAD_CLASSES, 0)))
    limitations = tuple(dict.fromkeys((*context.limitations, *map(clean_line, notes))))
    return context.model_copy(update={'counts': counts, 'limitations': limitations[:64]})


def _rank_cve(work: _Work, inputs: LocalizeInputs, context: CveContext, config: PilotConfig,
              ranking: _Ranking) -> None:
    work.budget.check()
    if context.gate == 'not-applicable':  # the advisory says these builds do not fix it: no leads, nothing to explain
        ranking.cves.append(_counted(context, None, ()))
        return
    view, gaps = _view(inputs, context, config, work.run.registry)
    outcome = _rank_context(work, lambda item: assess(item, view, work.run), view)
    notes = [*gaps, *([_NO_COMPONENT] if view.confounded and not view.phrases else [])]
    ranking.gaps += gaps
    ranking.outcomes.append(outcome)
    ranking.leads += outcome.leads
    ranking.cves.append(_counted(context, outcome, notes))


# --- the assessment --------------------------------------------------------------------------------------------------------

def _inputs_record(inputs: LocalizeInputs, config: PilotConfig, contexts: Sequence[CveContext],
                   registry: OriginRegistry) -> PilotInputs:
    try:
        return PilotInputs(
            older_sha256=inputs.older_sha256, newer_sha256=inputs.newer_sha256, ghidriff_run_id=inputs.ghidriff_run_id,
            raw_sha256=inputs.raw_sha256, unified_result_id=inputs.pairing.unified_result_id(),
            secondary_set_ids=tuple(sorted(set(inputs.pairing.secondary_set_ids()))),
            tool_keys=tuple(sorted(inputs.tools.cache_keys(), key=lambda k: (k.engine, k.side))),
            advisory_facts_ids=tuple(sorted(set(inputs.advisory.facts_ids()))),
            kev_snapshot_id=inputs.kev.snapshot_id(),
            asserted_gates=tuple(sorted(c.cve for c in contexts if c.gate == 'asserted')),
            lexicon_digest=lexicon_digest(), rules_digest=rules_digest(), pilot_rules_digest=pilot_rules_digest(),
            origins_digest=registry.digest(), tiers_version=TIERS_VERSION, config_digest=config_digest(config))
    except ValidationError as exc:
        raise _invalid('The identity inputs of the sources are malformed', 'inputs-invalid') from exc


def _limitations(channels: Mapping[str, ChannelStatus], outcomes: Iterable[_Outcome], gaps: Iterable[str]) -> list[str]:
    """One plain line for everything that makes a result partial: an unusable channel, a source that was missing for a
    CVE, and whatever a limit cut. No line means a complete result."""
    outcomes = tuple(outcomes)
    lines = [f'The {CHANNEL_LABELS[s.channel]} channel is {s.state}' + (f': {s.reason}' if s.reason else '')
             for s in channels.values() if s.state in ('failed', 'stale')]
    if leads_cut := sum(o.leads_cut for o in outcomes):
        lines.append(f'{leads_cut} further leads beyond the first {_LIMITS.p04_leads_per_context} of a context are '
                     'counted but not listed.')
    if queue_cut := sum(o.queue_cut for o in outcomes):
        lines.append(f'{queue_cut} changed functions with no fit beyond the first {_LIMITS.p04_queue_rows_per_context} '
                     'of a context are counted but not listed.')
    if any(o.trimmed for o in outcomes):
        lines.append(f'A lead lists at most {_LIMITS.p02_observations_per_lead} observations; the least relevant context '
                     'of some leads was left out.')
    return [clean_line(line) for line in dict.fromkeys((*lines, *gaps))]


def _utc(clock: Callable[[], datetime] | None) -> str:
    return (clock() if clock else datetime.now(UTC)).astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')


def _assessment(inputs: LocalizeInputs, record: PilotInputs, channels: Mapping[str, ChannelStatus],
                ranking: _Ranking, pool: Mapping[str, Observation], lines: Sequence[str], limits_hit: Iterable[str],
                status: str, created: str) -> PilotAssessment:
    leads = ranking.leads
    referenced = {i for lead in leads for ids in (lead.support_ids, lead.counter_ids, lead.unknown_ids,
                                                  lead.alternative_ids) for i in ids}
    referenced |= {i for lead in leads for fit in lead.fits for c in fit.expected_changes for i in c.observation_ids}
    try:
        return PilotAssessment(
            result_id=result_id(record), project_id=inputs.project_id, revision=inputs.revision,
            older_sha256=inputs.older_sha256, newer_sha256=inputs.newer_sha256, inputs=record,
            channels=tuple(channels.values()), cves=tuple(ranking.cves), leads=tuple(leads),
            queue_count=sum(o.queue_cut for o in ranking.outcomes), observations=tuple(pool[i] for i in sorted(referenced)),
            status=status, limitations=tuple(lines[:64]), limits_hit=tuple(sorted(set(limits_hit))),
            created_utc=created)
    except ValidationError as exc:
        raise PilotError('PT-PILOT-INTEGRITY', 'The assessment failed its own contract', reason='assessment-invalid') \
            from exc


def _abstained(inputs: LocalizeInputs, record: PilotInputs, channels: Mapping[str, ChannelStatus],
               contexts: Sequence[CveContext], created: str) -> PilotAssessment:
    pairing = channels['pairing']
    reason = (f'The pairing channel is {pairing.state}, so there is no candidate function pair.'
              if pairing.state not in _USABLE else 'There is no candidate function pair.')
    ranking = _Ranking(cves=[_counted(c, None, ()) for c in contexts])
    return _assessment(inputs, record, channels, ranking, {}, [reason], (), 'abstained', created)


def _localize(inputs: LocalizeInputs, config: PilotConfig, cancel: threading.Event, registry: OriginRegistry,
              clock: Callable[[], datetime] | None) -> PilotAssessment:
    budget = Budget.after(_LIMITS.p08_deadline_s, cancel, check_every=_CHECK_EVERY)
    budget.check()
    _check_config(config)
    channels = _channels(inputs)
    contexts = _contexts(inputs)
    record = _inputs_record(inputs, config, contexts, registry)
    created = _utc(clock)
    candidates = _candidates(inputs.pairing, budget) if channels['pairing'].state in _USABLE else []
    if not candidates:
        return _abstained(inputs, record, channels, contexts, created)
    items = _gather(inputs, candidates, channels, budget)
    run = Run(states={name: channels[name].state for name in RULE_CHANNELS}, config=config, registry=registry,
              pool={o.obs_id: o for item in items for o in item.observations})
    work = _Work(items, run, budget)
    ranking = _Ranking()
    code = _rank_context(work, lambda item: assess_code(item, run), None)
    ranking.leads += code.leads
    ranking.outcomes.append(code)
    for context in contexts:
        _rank_cve(work, inputs, context, config, ranking)
    limits_hit = [slug for slug, hit in (('leads-cut', any(o.leads_cut for o in ranking.outcomes)),
                                         ('queue-cut', any(o.queue_cut for o in ranking.outcomes)),
                                         ('observations-cut', any(o.trimmed for o in ranking.outcomes))) if hit]
    lines = _limitations(channels, ranking.outcomes, ranking.gaps)
    return _assessment(inputs, record, channels, ranking, {**run.pool, **work.extra}, lines, limits_hit,
                       'partial' if lines else 'complete', created)


def localize(inputs: LocalizeInputs, config: PilotConfig, cancel: threading.Event, *,
             registry: OriginRegistry = DEFAULT_REGISTRY, clock: Callable[[], datetime] | None = None
             ) -> PilotAssessment:
    """Rank every candidate function pair for the code evidence alone and for each CVE; see the module docstring.

    Raises `PilotError`: `PT-PILOT-CANCEL` when `cancel` is set, `PT-PILOT-LIMIT` past the deadline or a P-xx limit,
    `PT-PILOT-INPUT` for a malformed source or configuration, `PT-PILOT-INTEGRITY` if the result would break its own
    contract. A pair that cannot be listed at all (no usable pairing channel, no candidate) gives an `abstained`
    assessment instead: no lead, and the reason named."""
    try:
        return _localize(inputs, config, cancel, registry, clock)
    except ValidationError as exc:
        raise PilotError('PT-PILOT-INTEGRITY', 'A lead failed its own contract', reason='lead-invalid') from exc
