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
from .storage import EnrichmentStore, Entry, Guard
from .views import MatchView, RunView, build_views

STAGE_VERSIONS = {'signals': 1, 'wil': 1, 'ranking': 1, 'contextual': 1}
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


def _cached(cache, stage: str, key: str, model, compute: Callable[[], tuple]):
    """Return (value_tuple, from_cache). Cache admission failure never fails the stage."""
    if cache is not None:
        try:
            payload = cache.get(stage, key)
        except EnrichmentError:
            payload = None
        if payload is not None:
            import json
            try:
                items = json.loads(payload.decode('utf-8'))
                return tuple(model.model_validate_json(json.dumps(item)) for item in items), True
            except (ValueError, UnicodeError):
                payload = None
    value = compute()
    if cache is not None:
        import json
        body = json.dumps([item.model_dump(mode='json') for item in value], sort_keys=True,
                          separators=(',', ':')).encode('utf-8')
        try:
            cache.put(stage, key, body, {'stage': stage})
        except EnrichmentError:
            pass
    return value, False


def _overall(stages: list[StageResult]) -> Status:
    statuses = [s.status for s in stages]
    if 'cancelled' in statuses:
        return 'cancelled'
    if all(s == 'complete' for s in statuses):
        return 'complete'
    if statuses and statuses[0] in {'failed', 'unavailable'}:
        return statuses[0]
    return 'partial'


def _merge(signal_set: SignalSet, extra: tuple[ChangeSignal, ...], wil_status: Status) -> SignalSet:
    outcome = DetectorOutcome(pairing_id=signal_set.pairing_id, detector='WIL', status=wil_status)
    return signal_set.model_copy(update={'signals': signal_set.signals + extra,
                                         'outcomes': signal_set.outcomes + (outcome,)})


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
            return tuple(out)
        signal_sets, _ = _cached(options.cache, 'signals', signals_key, SignalSet, compute_signals)
        record('signals', 'complete' if all(s.status == 'complete' for s in signal_sets) else 'partial')
    except EnrichmentError as exc:
        record('signals', 'cancelled' if exc.code == 'PT-ENRICH-CANCEL' else 'failed', exc)

    wil_key = stage('wil', {'input': guard.input_digest, 'rules': f'wil/{wil.DETECTOR_VERSION}',
                            'filter': ','.join(str(i) for i in sorted(options.feature_ids or ()))})
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
            transitions, _ = _cached(options.cache, 'wil', wil_key, FeatureTransition, compute_wil)
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
        signal_sets = tuple(_merge(s, wil.wil_signals(matches[s.pairing_id], tuple(by_pairing.get(s.pairing_id, ())))
                                   if wil_status == 'complete' else (), wil_status) for s in signal_sets)

    ranking_result: RankingResult | None = None
    stage('ranking', {'signals': signals_key, 'wil': wil_key,
                      'config': ranking.config_digest(options.config)})
    if cancel is not None and cancel.is_set():
        record('ranking', 'cancelled')
    elif signal_sets:
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
            contextual = cve.contextual_rank(ranking_result, signal_sets, transitions, options.snapshots,
                                             (views.older_name, views.newer_name), names,
                                             now=datetime.now(UTC), max_age_days=options.max_age_days)
            record('contextual', contextual.status)
        except EnrichmentError as exc:
            record('contextual', 'failed', exc)
    else:
        record('contextual', 'unavailable')

    status = PipelineStatus(project_id=views.project_id, revision=views.revision, run_id=views.run_id,
                            raw_sha256=views.raw_sha256, stages=tuple(stages), status=_overall(stages))
    return PipelineResult(views, guard, signal_sets, transitions, ranking_result, contextual, status, stage_ids)


def publish(store: EnrichmentStore, project: ComparisonProject, result: PipelineResult) -> list[Entry]:
    """Owner-thread publication with an immediate currency recheck against the live project."""
    try:
        current = guard_for(project, result.views.run_id)
    except EnrichmentError:
        current = Guard('', '', '', '')
    revision = project.revision
    written = []

    def put(kind: str, items, status: Status, key: str):
        body = {'items': [i.model_dump(mode='json') for i in items]}
        written.append(store.publish(kind, result.guard, current, revision, status, body, f'{kind}:{key}'))

    put('signals', result.signal_sets, result.status.stages[0].status, result.stage_ids['signals'])
    put('wil', result.transitions, result.status.stages[1].status, result.stage_ids['wil'])
    if result.ranking is not None:
        put('ranking', (result.ranking,), result.ranking.status, result.stage_ids['ranking'])
    if result.contextual is not None:
        put('contextual', (result.contextual,), result.contextual.status, result.stage_ids['contextual'])
    put('pipeline', (result.status,), result.status.status, result.stage_ids['ranking'])
    return written
