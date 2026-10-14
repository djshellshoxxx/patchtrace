"""Headless `secondary run` orchestration (SPEC-28 §7): schedule, persist, reconcile, classify exit code.

Kept out of cli.py so argument parsing stays separate from engine logic. No Qt. All store access
happens on the caller's thread; scheduler workers only see an in-memory cache snapshot.
"""
from __future__ import annotations

import os
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ..enrichment.storage import EnrichmentStore, Guard
from . import scheduler
from .contracts import SecondaryMatchSet
from .engine_env import engine_env
from .reconcile import reconcile
from .registry import REGISTRY, BinDiffAdapter, build_registry
from .runs import EngineId, EngineOutcome, EngineRun, argv_digest, as_v2, cache_key, new_run_id
from .store import cache_snapshot, publish_engine_set, publish_run

OK, ENVIRONMENT, RUNTIME, NO_RESULTS, CANCELLED = 0, 2, 3, 4, 5
ENV_CODES = frozenset({'PT-SECONDARY-INPUT', 'PT-SECONDARY-UNSUPPORTED', 'PT-SECONDARY-PAIR',
                       'PT-SECONDARY-ORIENTATION', 'PT-SECONDARY-FORMAT'})
DEFAULT_ENGINES: tuple[EngineId, ...] = ('rz-diff', 'bindiff')
TIMEOUT_RANGE = (60, 86_400)


@dataclass(frozen=True)
class RunReport:
    status: str  # complete | partial | failed | cancelled
    exit_code: int
    result: dict
    warnings: list[str]
    text: str


def classify(outcomes: Sequence[EngineOutcome], cancelled: bool) -> tuple[str, int]:
    """Exit code and status for a set of outcomes (partial success is 3, never 0)."""
    produced = [o for o in outcomes if o.run.status in ('ok', 'cached')]
    bad = [o for o in outcomes if o.run.status in ('failed', 'timeout', 'unsupported')]
    if cancelled or any(o.run.status == 'cancelled' for o in outcomes):
        return 'cancelled', CANCELLED
    if not bad:
        return ('complete', OK) if any(o.match_set and o.match_set.matches for o in produced) else ('complete', NO_RESULTS)
    if produced:
        return 'partial', RUNTIME
    if all(o.run.status == 'unsupported' or o.run.error_code in ENV_CODES for o in bad):
        return 'failed', ENVIRONMENT
    return 'failed', RUNTIME


def execute(service, store: EnrichmentStore, run, sides: dict, engines: Sequence[EngineId] | None, *,
            rz_diff: str, max_parallel: int, timeout: int, use_cache: bool,
            cancel: threading.Event, bindiff: BinDiffAdapter | None = None) -> RunReport:
    project = service.project
    registry = build_registry(rz_diff=rz_diff, bindiff=bindiff) if rz_diff != 'rz-diff' or bindiff else REGISTRY
    env = engine_env(os.environ, 'rz-diff')  # the one shared allow-list; BinDiff builds its own from it
    if engines is None:
        engines = [e for e in DEFAULT_ENGINES if registry[e].probe(env, cancel).supported]
        if not engines:
            return RunReport('failed', ENVIRONMENT, {'runs': [], 'reconciliation': {'reports': []}}, [],
                             'No runnable secondary engine found (rz-diff >= 0.9.0 is required; '
                             'BinDiff 8 needs --bindiff and both --older-binexport/--newer-binexport).')
    older, newer = (Path(service.root / sides[s].relative_path).resolve() for s in ('older', 'newer'))
    ref = scheduler.ProjectRef(older, newer, sides['older'].sha256, sides['newer'].sha256)
    snapshot = cache_snapshot(store, ref.older_sha256, ref.newer_sha256) if use_cache else {}

    class Snapshot:
        def find(self, key):
            return snapshot.get(key)

    warnings: list[str] = []
    rows, reports = [], []

    def persist(outcome: EngineOutcome) -> None:
        """Runs on this thread as each engine finishes, so Ctrl+C never loses a completed outcome."""
        record, match_set = outcome.run, outcome.match_set
        digest = match_set.file_sha256 if match_set else record.cache_key
        guard = Guard(project.id, run.id, run.raw_sha256, digest)
        if match_set is not None and record.status == 'ok':  # a cache hit never rewrites the set
            publish_engine_set(store, guard, guard, project.revision, match_set)
        publish_run(store, guard, guard, project.revision, record)
        if match_set is not None:
            reports.append(reconcile(project.matches, match_set))
        rows.append({'engine': record.engine, 'status': record.status, 'error_code': record.error_code,
                     'run_id': record.run_id, 'cache': record.status == 'cached',
                     'duration_ms': record.duration_ms,
                     'matches': len(match_set.matches) if match_set else 0,
                     'alternatives': len(match_set.alternatives) if match_set else 0})
        if outcome.error is not None:
            warnings.append(f'{record.engine}: {outcome.error}')

    outcomes = scheduler.run_engines(
        ref, list(engines), max_parallel=max_parallel, per_engine_timeout=dict.fromkeys(engines, float(timeout)),
        cancel=cancel, cache=Snapshot() if use_cache else None, env=env, registry=registry, on_outcome=persist)
    # Report in plan order (completion order only matters for persistence).
    order = {e: i for i, e in enumerate(o.run.engine for o in outcomes)}
    rows.sort(key=lambda r: order[r['engine']])
    reports.sort(key=lambda r: order[r.engine])
    status, code = classify(outcomes, cancel.is_set())
    result = {'runs': rows,
              'reconciliation': {'reports': [{'engine': r.engine, 'engine_version': r.engine_version,
                                              'counts': r.counts(), 'limitations': list(r.limitations)}
                                             for r in reports]}}
    lines = [f'{r["engine"]}: {r["status"]}' + (f' ({r["matches"]} matches)' if r['matches'] else '')
             + (f' [{r["error_code"]}]' if r['error_code'] else '') for r in rows]
    if status == 'partial':
        lines.append('Partial success: at least one engine failed; successful sets are stored.')
    return RunReport(status, code, result, warnings, '\n'.join(lines))


def record_import(store: EnrichmentStore, guard: Guard, revision: int, match_set: SecondaryMatchSet):
    """Store an imported `.BinDiff` set as the engine's current secondary/2 set plus an EngineRun row."""
    started = datetime.now(UTC).isoformat()
    ident = argv_digest(['import-bindiff'])
    key = cache_key(match_set.engine, match_set.engine_version, ident, match_set.older_sha256,
                    match_set.newer_sha256)
    run_id = new_run_id(key, started)
    stored = as_v2(match_set, run_id)
    entry = publish_engine_set(store, guard, guard, revision, stored)
    publish_run(store, guard, guard, revision, EngineRun(
        run_id=run_id, engine=stored.engine, engine_version=stored.engine_version, executable_path_sha256=None,
        argv_digest=ident, older_sha256=stored.older_sha256, newer_sha256=stored.newer_sha256,
        orientation='older->newer', cache_key=key, status='ok', error_code=None, returncode=None,
        started_utc=started, duration_ms=0, stderr_tail='', output_sha256=stored.file_sha256,
        match_set_id=stored.entry_id))
    return entry
