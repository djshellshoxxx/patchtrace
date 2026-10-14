"""Enrichment stage orchestration (SPEC-07 §2, §9, §10). No Qt, no network, no project writes.

`run` is worker-thread safe: it reads an immutable project snapshot and returns an
immutable result. `publish` must run on the thread owning the ProjectStore and is the
only step that writes. Stage order: views → signals (B1) → wil (B2) → ranking → contextual (B3).
An optional later stage failing never discards earlier completed stages; the overall
status degrades to `partial`. Missing evidence is `unavailable`, never an empty success.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from ..models import ComparisonProject
from . import identity, ranking, signals, wil
from .contracts import (
    ChangeSignal,
    ContextualRanking,
    CveSnapshot,
    DetectorOutcome,
    EnrichmentError,
    FeatureTransition,
    PipelineStatus,
    RankingConfig,
    RankingResult,
    SignalSet,
    StageResult,
    Status,
)
from .storage import ORPHAN_GRACE, EnrichmentStore, Entry, Guard
from .views import MatchView, RunView, build_views

STAGE_VERSIONS = {'signals': 2, 'wil': 2, 'ranking': 2, 'contextual': 2}
CANCEL_EVERY = 256


@dataclass(frozen=True)
class PipelineOptions:
    config: RankingConfig = field(default_factory=RankingConfig)
    run_id: str | None = None
    feature_ids: frozenset[int] | None = None
    snapshots: tuple[CveSnapshot, ...] = ()
    max_age_days: int | None = 30
    cache: object | None = None  # enrichment.cache.DerivedCache; optional


@dataclass(frozen=True)
class PipelineResult:
    views: RunView
    guard: Guard
    signal_sets: tuple[SignalSet, ...]
    transitions: tuple[FeatureTransition, ...]
    ranking: RankingResult | None
    contextual: ContextualRanking | None
    status: PipelineStatus
    stage_ids: dict[str, str]
    config_digest: str = ''
    default_profile: bool = False


def _filter_text(feature_ids) -> str:
    """'' means no filter; '-' means an explicit empty filter (they must never share a cache key)."""
    if feature_ids is None:
        return ''
    return ','.join(str(i) for i in sorted(feature_ids)) or '-'


def input_digest(views: RunView) -> str:
    """Everything derived stages depend on from the project: diff identity, pairings, code."""
    pairings = [{'pairing_id': m.pairing_id, 'match_id': m.match_id, 'quality': m.quality,
                 'code': [identity.excerpt_sha256(f.code) if f.code is not None else None
                          for f in m.older + m.newer]} for m in views.matches]
    pairings.sort(key=lambda item: (item['pairing_id'], item['match_id']))
    return identity.domain_id('enrichment-input', 1, {'diff_id': views.diff_id, 'pairings': pairings})


def guard_for(project: ComparisonProject, run_id: str | None = None) -> Guard:
    views = build_views(project, run_id)
    return Guard(views.project_id, views.run_id, views.raw_sha256, input_digest(views))


def _check(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise EnrichmentError('PT-ENRICH-CANCEL', 'enrichment cancelled; completed stages were kept')


def _locations_owned(views: RunView, items, model) -> bool:
    """A cache entry is only trusted if every record belongs to a current pairing and every
    location re-derives to the same excerpt hash from the live views. The manifest hash only
    proves the file is self-consistent, not that it was produced from these inputs."""
    matches = {m.pairing_id: m for m in views.matches}
    for item in items:
        match = matches.get(item.pairing_id)
        if match is None or item.match_id != match.match_id:
            return False
        sites = []
        if isinstance(item, SignalSet):
            sites = [loc for sig in item.signals for loc in sig.locations]
            if any(sig.pairing_id != item.pairing_id or sig.match_id != item.match_id for sig in item.signals):
                return False
        elif isinstance(item, FeatureTransition):
            sites = [site.location for site in item.older_sites + item.newer_sites]
        functions = {f.id: f for f in match.older + match.newer}
        for loc in sites:
            function = functions.get(loc.function_id)
            if function is None or function.side != loc.side or function.artifact_id != loc.artifact_id \
                    or function.run_id != loc.run_id:
                return False
            try:
                if function.location(loc.start_line, loc.end_line, loc.representation).excerpt_sha256 \
                        != loc.excerpt_sha256:
                    return False
            except EnrichmentError:
                return False
    # Signal sets cover every pairing; transitions are legitimately sparse (often empty).
    if model is SignalSet and {i.pairing_id for i in items} != set(matches):
        return False
    return True


def _cached(cache, stage: str, key: str, model, compute: Callable[[], tuple], views: RunView):
    """Return (value_tuple, from_cache). Cache admission failure never fails the stage.
    Only fully completed values are admitted, so a cancelled or failed computation can
    never be replayed as if it were a real empty result."""
    if cache is not None:
        try:
            payload = cache.get(stage, key)
        except EnrichmentError:
            payload = None
        if payload is not None:
            import json
            try:
                from pydantic import TypeAdapter
                value = tuple(TypeAdapter(list[model]).validate_json(payload))
                if _locations_owned(views, value, model):
                    return value, True
            except (ValueError, UnicodeError):
                pass
    value = compute()
    if any(getattr(item, 'status', 'complete') in {'cancelled', 'failed'} for item in value):
        return value, False
    if cache is not None:
        import json
        body = json.dumps([item.model_dump(mode='json') for item in value], sort_keys=True,
                          separators=(',', ':')).encode('utf-8')
        try:
            cache.put(stage, key, body, {'stage': stage})
        except EnrichmentError:
            pass
    return value, False


def _overall(stages: list[StageResult], requested_context: bool = False) -> Status:
    """Contextual ranking is optional; when it was not requested its absence is not partial."""
    statuses = [s.status for s in stages]
    if 'cancelled' in statuses:
        return 'cancelled'
    if all(s == 'complete' for s in statuses):
        return 'complete'
    if all(s == 'complete' for s in statuses[:-1]) and statuses[-1] == 'unavailable' and not requested_context:
        return 'complete'
    if statuses and statuses[0] in {'failed', 'unavailable'}:
        return statuses[0]
    return 'partial'


def _wil_outcome(pairing_id: str, view: MatchView | None, transitions: tuple[FeatureTransition, ...],
                 wil_status: Status) -> DetectorOutcome:
    """Per-pairing WIL outcome (SPEC-07h H3); the stage status only overrides when the stage itself failed."""
    def outcome(status: Status, reason: str = '') -> DetectorOutcome:
        return DetectorOutcome(pairing_id=pairing_id, detector='WIL', status=status, reason=reason)
    if wil_status != 'complete':
        return outcome(wil_status)
    if view is None or not view.two_sided:
        return outcome('unavailable', f'{signals.NOT_APPLICABLE} one-sided-pairing')
    if len(view.older) != 1 or len(view.newer) != 1:
        return outcome('unavailable', f'{signals.NOT_APPLICABLE} pairing-ambiguous')
    if any(f.code is None for f in (*view.older, *view.newer)):
        return outcome('unavailable', f'{signals.LIMIT} code-unavailable')
    notes = sorted({n for t in transitions for n in t.notes if n in {'function-too-large', 'site-limit'}})
    if notes:
        return outcome('partial', f'{signals.LIMIT} {",".join(notes)}')
    return outcome('complete')


def _merge(signal_set: SignalSet, extra: tuple[ChangeSignal, ...], outcome: DetectorOutcome) -> SignalSet:
    outcomes = signal_set.outcomes + (outcome,)
    return signal_set.model_copy(update={'signals': signal_set.signals + extra, 'outcomes': outcomes,
                                         'status': signals.aggregate_status(outcomes)})


def run(project: ComparisonProject, options: PipelineOptions | None = None,
        cancel: threading.Event | None = None, progress: Callable[[str], None] | None = None) -> PipelineResult:
    options = options or PipelineOptions()
    views = build_views(project, options.run_id)
    guard = Guard(views.project_id, views.run_id, views.raw_sha256, input_digest(views))
    stages: list[StageResult] = []
    stage_ids: dict[str, str] = {}
    enabled = tuple(d for d in options.config.enabled if d != 'WIL')

    def stage(name: str, inputs: dict[str, str]) -> str:
        stage_ids[name] = identity.stage_id(name, STAGE_VERSIONS[name], inputs)
        return stage_ids[name]

    def record(name: str, status: Status, error: EnrichmentError | None = None, limitations=()):
        stages.append(StageResult(stage=name, stage_version=STAGE_VERSIONS[name], stage_id=stage_ids[name],
                                  status=status, error_code=error.code if error else None,
                                  message=error.message if error else '', limitations=tuple(limitations)))

    detector_versions = {d.id: d.version for d in signals.DETECTORS}
    signals_key = stage('signals', {'input': guard.input_digest,
                                    'detectors': identity.domain_id('detectors', 1, {
                                        'enabled': sorted(enabled), 'versions': detector_versions})})
    signal_sets: tuple[SignalSet, ...] = ()
    try:
        def compute_signals():
            out = []
            for index, match in enumerate(views.matches):
                if index % CANCEL_EVERY == 0:
                    _check(cancel)
                    if progress:
                        progress(f'Change signals {index}/{len(views.matches)}')
                out.append(signals.detect(match, enabled, cancel))
            if any(item.status == 'cancelled' for item in out):
                raise EnrichmentError('PT-ENRICH-CANCEL', 'enrichment cancelled; completed stages were kept')
            return tuple(out)
        signal_sets, _ = _cached(options.cache, 'signals', signals_key, SignalSet, compute_signals, views)
        # Structural not-applicable pairings (added/removed functions) are `unavailable` sets, not degradation.
        record('signals', 'partial' if any(s.status == 'partial' for s in signal_sets) else 'complete')
    except EnrichmentError as exc:
        record('signals', 'cancelled' if exc.code == 'PT-ENRICH-CANCEL' else 'failed', exc)

    wil_key = stage('wil', {'input': guard.input_digest, 'rules': f'wil/{wil.DETECTOR_VERSION}',
                            'filter': _filter_text(options.feature_ids)})
    transitions: tuple[FeatureTransition, ...] = ()
    wil_status: Status = 'unavailable'
    if stages[-1].status in {'complete', 'partial'}:
        try:
            def compute_wil():
                out: list[FeatureTransition] = []
                for index, match in enumerate(views.matches):
                    if index % CANCEL_EVERY == 0:
                        _check(cancel)
                    out.extend(t for t in wil.analyze(match)
                               if options.feature_ids is None or t.feature_id in options.feature_ids)
                return tuple(out)
            transitions, _ = _cached(options.cache, 'wil', wil_key, FeatureTransition, compute_wil, views)
            wil_status = 'complete'
            record('wil', 'complete')
        except EnrichmentError as exc:
            record('wil', 'cancelled' if exc.code == 'PT-ENRICH-CANCEL' else 'failed', exc)
            wil_status = 'failed'
    else:
        record('wil', 'unavailable')
    by_pairing: dict[str, list[FeatureTransition]] = {}
    for transition in transitions:
        by_pairing.setdefault(transition.pairing_id, []).append(transition)
    matches: dict[str, MatchView] = {m.pairing_id: m for m in views.matches}
    if 'WIL' in options.config.enabled and signal_sets:
        merged = []
        for item in signal_sets:
            view = matches.get(item.pairing_id)
            mine = tuple(by_pairing.get(item.pairing_id, ()))
            extra = wil.wil_signals(view, mine) if wil_status == 'complete' and view is not None else ()
            merged.append(_merge(item, extra, _wil_outcome(item.pairing_id, view, mine, wil_status)))
        signal_sets = tuple(merged)

    ranking_result: RankingResult | None = None
    stage('ranking', {'signals': signals_key, 'wil': wil_key,
                      'config': ranking.config_digest(options.config)})
    if cancel is not None and cancel.is_set():
        record('ranking', 'cancelled')
    elif stages[0].status in {'complete', 'partial'}:
        # A run with zero pairings is complete evidence of nothing to rank (empty, not unavailable).
        certainty = {m.match_id: m.quality for m in views.matches}
        ranking_result = ranking.rank(signal_sets, options.config, certainty)
        record('ranking', ranking_result.status)
    else:
        record('ranking', 'unavailable')

    contextual: ContextualRanking | None = None
    snapshot_ids = ','.join(sorted(s.snapshot_id for s in options.snapshots))
    stage('contextual', {'ranking': stage_ids['ranking'], 'snapshots': snapshot_ids or 'none'})
    if options.snapshots and ranking_result is not None:
        from . import cve  # pure; imported lazily to keep the base path minimal
        try:
            from datetime import UTC, datetime
            names = {m.pairing_id: tuple(f.name for f in m.older + m.newer) for m in views.matches}
            # One snapshot per CVE so a duplicate can never double-count contributions.
            latest, _ = cve.select_latest(options.snapshots)
            contextual = cve.contextual_rank(ranking_result, signal_sets, transitions, latest,
                                             (views.older_name, views.newer_name), names,
                                             now=datetime.now(UTC), max_age_days=options.max_age_days)
            record('contextual', contextual.status)
        except EnrichmentError as exc:
            record('contextual', 'failed', exc)
    else:
        record('contextual', 'unavailable')

    status = PipelineStatus(project_id=views.project_id, revision=views.revision, run_id=views.run_id,
                            raw_sha256=views.raw_sha256, stages=tuple(stages),
                            status=_overall(stages, bool(options.snapshots)))
    default = options.config == RankingConfig() and options.feature_ids is None
    return PipelineResult(views, guard, signal_sets, transitions, ranking_result, contextual, status, stage_ids,
                          ranking.config_digest(options.config), default)


def publish(store: EnrichmentStore, project: ComparisonProject, result: PipelineResult) -> list[Entry]:
    """Owner-thread publication with an immediate currency recheck against the live project.
    Cancelled results are never published: they would leave an incomplete profile row set."""
    if result.status.status == 'cancelled':
        return []
    try:
        current = guard_for(project, result.views.run_id)
    except EnrichmentError:
        current = Guard('', '', '', '')
    revision = result.views.revision  # the revision the result was computed from
    written = []
    # Rows that depend on configuration or the WIL filter are keyed by the ranking stage ID,
    # which digests detectors, weights, filter and inputs, so profiles never overwrite or
    # impersonate each other. The pipeline row records which profile produced them.
    rid = result.stage_ids['ranking']
    # Orphan rows (no pipeline row yet) younger than this belong to a concurrent publish: never reaped.
    started = (datetime.now(UTC) - ORPHAN_GRACE).isoformat()
    generation = [f'signals:{rid}', f'wil:{result.stage_ids["wil"]}', f'pipeline:{rid}']
    if result.ranking is not None:
        generation.append(f'ranking:{rid}')
    if result.contextual is not None:
        generation.append(f'contextual:{result.stage_ids["contextual"]}')

    def put(kind: str, items, status: Status, key: str, extra: dict | None = None):
        body = {'items': [i.model_dump(mode='json') for i in items]} | (extra or {})
        written.append(store.publish(kind, result.guard, current, revision, status, body, f'{kind}:{key}',
                                     protect=generation))

    put('signals', result.signal_sets, result.status.stages[0].status, rid)
    put('wil', result.transitions, result.status.stages[1].status, result.stage_ids['wil'])
    if result.ranking is not None:
        put('ranking', (result.ranking,), result.ranking.status, rid)
    if result.contextual is not None:
        put('contextual', (result.contextual,), result.contextual.status, result.stage_ids['contextual'])
    put('pipeline', (result.status,), result.status.status, rid,
        {'stage_ids': dict(result.stage_ids), 'config_digest': result.config_digest,
         'default_profile': result.default_profile})
    store.apply_retention(current, protect=generation, started=started)
    return written


def _versions_current(entry) -> bool:
    """A stored pipeline row is served only if every recorded stage ran at today's stage version."""
    try:
        stages = entry.body['items'][0]['stages']
        return bool(stages) and all(STAGE_VERSIONS.get(s['stage']) == s['stage_version'] for s in stages)
    except (KeyError, IndexError, TypeError):
        return False


def load_default(store: EnrichmentStore, project: ComparisonProject):
    """(RankingResult, signal sets, note) for the default profile computed from the live
    project, or (None, (), reason). Rows from other profiles are never returned."""
    import json
    try:
        guard = guard_for(project)
    except EnrichmentError:
        return None, (), 'Ranking unavailable: no completed analysis run.'
    digest = ranking.config_digest(RankingConfig())
    candidates = [e for e in store.entries('pipeline', guard)
                  if e.body.get('default_profile') is True and e.body.get('config_digest') == digest]
    current = next((e for e in candidates if not e.stale and _versions_current(e)), None)
    if current is None:
        # Only say "stale" when a default-profile row exists for an older state; rows of
        # other weight profiles are not evidence that the project changed.
        stale = bool(candidates) or any(e.body.get('default_profile') is True
                                        for e in store.entries('pipeline'))
        return None, (), ('Stored ranking is stale (project changed). Rank changes again.' if stale else '')
    rid = current.body['stage_ids']['ranking']
    rows = {e.kind: e for kind in ('ranking', 'signals') for e in store.entries(kind, guard)
            if e.id == f'{kind}:{rid}' and not e.stale}
    if set(rows) != {'ranking', 'signals'}:
        return None, (), 'Stored ranking is incomplete. Rank changes again.'
    result = RankingResult.model_validate_json(json.dumps(rows['ranking'].body['items'][0]))
    sets = tuple(SignalSet.model_validate_json(json.dumps(i)) for i in rows['signals'].body['items'])
    return result, sets, ''


def wil_stage_id(input_digest_value: str, feature_ids: frozenset[int] | None) -> str:
    """The `wil` stage identity `run` assigns; it is the only stored trace of the feature filter."""
    return identity.stage_id('wil', STAGE_VERSIONS['wil'], {
        'input': input_digest_value, 'rules': f'wil/{wil.DETECTOR_VERSION}',
        'filter': _filter_text(feature_ids)})


def load_profile(store: EnrichmentStore, project: ComparisonProject, config_digest: str,
                 feature_ids: frozenset[int] | None = None):
    """Like `load_default` for a named profile: rows whose pipeline record carries this ranking
    `config_digest` and whose WIL stage used the same feature filter. The config digest alone does
    not cover the filter, so two profiles differing only in feature IDs never share rows."""
    import json
    try:
        guard = guard_for(project)
    except EnrichmentError:
        return None, (), 'Ranking unavailable: no completed analysis run.'
    wil_id = wil_stage_id(guard.input_digest, feature_ids)
    candidates = [e for e in store.entries('pipeline', guard) if e.body.get('config_digest') == config_digest
                  and e.body.get('stage_ids', {}).get('wil') == wil_id]
    current = next((e for e in candidates if not e.stale and _versions_current(e)), None)
    if current is None:
        stale = bool(candidates) or any(e.body.get('config_digest') == config_digest
                                        for e in store.entries('pipeline'))
        return None, (), ('Stored ranking is stale (project changed). Rank changes again.' if stale else '')
    rid = current.body['stage_ids']['ranking']
    rows = {e.kind: e for kind in ('ranking', 'signals') for e in store.entries(kind, guard)
            if e.id == f'{kind}:{rid}' and not e.stale}
    if set(rows) != {'ranking', 'signals'}:
        return None, (), 'Stored ranking is incomplete. Rank changes again.'
    result = RankingResult.model_validate_json(json.dumps(rows['ranking'].body['items'][0]))
    if result.config_digest != config_digest:
        return None, (), 'Stored ranking is inconsistent. Rank changes again.'
    sets = tuple(SignalSet.model_validate_json(json.dumps(i)) for i in rows['signals'].body['items'])
    return result, sets, ''
