"""Pure orchestration for the evidence panel (C6 spec §4, §6). No Qt.

Thread rule: the GUI thread (owner of the project service and its SQLite connection) builds the
immutable :class:`EvidenceRequest` / :class:`RunRequest`; worker threads only run
:func:`load_evidence` / :func:`execute_run` on them. Persisting an engine result
(:func:`persist_outcome`) is called on the GUI thread only.
"""
from __future__ import annotations

import os
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ..enrichment.storage import EnrichmentStore, Entry, Guard
from ..models import FunctionMatch
from . import load_secondary, scheduler
from .contracts import Capability, SecondaryMatchSet
from .engine_env import engine_env
from .evidence_view import (
    CALIBRATION_FALLBACK,
    LOG_LINES,
    SECONDARY_ENGINES,
    STALE_PAIR,
    STALE_REVISION,
    STALE_RUN,
    Cancelled,
    EngineOutcomeView,
    EvidenceViewModel,
    build_view_model,
    failed_model,
    sanitize_text,
)
from .registry import REGISTRY, EngineAdapter
from .runs import EngineOutcome
from .store import cache_snapshot, publish_engine_set, publish_run, select_current

TIMEOUT_RANGE = (60, 86_400)
DEFAULT_TIMEOUT = 1800
PARALLEL_RANGE = (1, scheduler.MAX_PARALLEL)
STDERR_VIEW = 2 * 1024 * 1024

__all__ = ['EngineOutcomeView', 'EvidenceRequest', 'RunRequest', 'load_evidence', 'detect_stale',
           'select_sets', 'outcome_view', 'capability_view', 'probe_engines', 'execute_run', 'persist_outcome',
           'build_request', 'Cancelled']


@dataclass(frozen=True)
class EvidenceRequest:
    project_id: str
    run_id: str | None
    revision: int
    older_sha256: str
    newer_sha256: str
    matches: tuple[FunctionMatch, ...]        # snapshot; read-only in the worker
    sets: tuple[tuple[Entry, SecondaryMatchSet], ...]
    outcomes: tuple[EngineOutcomeView, ...] = ()
    calibration_level: str = CALIBRATION_FALLBACK
    generation: int = 0
    ghidriff_version: str | None = None


@dataclass(frozen=True)
class RunRequest:
    project_id: str
    revision: int
    generation: int
    engines: tuple[str, ...]
    max_parallel: int
    timeout_s: int
    older_path: Path
    newer_path: Path
    older_sha256: str
    newer_sha256: str
    run_id: str | None = None
    capabilities: Mapping[str, Capability] = field(default_factory=dict)
    cache: Mapping[str, SecondaryMatchSet] = field(default_factory=dict)  # snapshot built on the GUI thread

    def __post_init__(self):
        if not self.engines:
            raise ValueError('select at least one engine')
        if not PARALLEL_RANGE[0] <= self.max_parallel <= PARALLEL_RANGE[1]:
            raise ValueError(f'parallel engines must be between {PARALLEL_RANGE[0]} and {PARALLEL_RANGE[1]}')
        if not TIMEOUT_RANGE[0] <= self.timeout_s <= TIMEOUT_RANGE[1]:
            raise ValueError('timeout must be between 60 and 86400 seconds')


def select_sets(rows: Sequence[tuple[Entry, SecondaryMatchSet]]
                ) -> tuple[tuple[tuple[Entry, SecondaryMatchSet], ...], tuple[str, ...]]:
    """Newest non-stale set per engine (SPEC-28 C5); duplicates never reach reconcile/assess."""
    chosen, notes = select_current(list(rows))
    engines = sorted({note.split(':', 1)[0] for note in notes})
    warnings = tuple(f'Multiple stored sets for {engine}; showing the newest.' for engine in engines)
    return tuple(chosen), warnings


def load_evidence(request: EvidenceRequest, cancel: Callable[[], bool] = lambda: False) -> EvidenceViewModel:
    """Worker-side: pure over the immutable request. Raises Cancelled; any other failure is an E5 model."""
    common = dict(project_id=request.project_id, run_id=request.run_id, revision=request.revision,
                  older_sha256=request.older_sha256, newer_sha256=request.newer_sha256,
                  calibration_level=request.calibration_level, generation=request.generation)
    try:
        chosen, warnings = select_sets(request.sets)
        stale = None
        for entry, match_set in chosen:
            if (match_set.older_sha256, match_set.newer_sha256) != (request.older_sha256, request.newer_sha256):
                stale = STALE_PAIR
                break
            if request.run_id is not None and entry.guard.run_id != request.run_id:
                stale = stale or STALE_RUN
        return build_view_model(matches=request.matches, sets=tuple(s for _, s in chosen),
                                outcomes=request.outcomes, warnings=warnings, stale_reason=stale,
                                ghidriff_version=request.ghidriff_version, cancel=cancel, **common)
    except Cancelled:
        raise
    except ValueError as exc:
        return failed_model(f'PT-EVIDENCE-ASSEMBLY: {exc}', **common)
    except Exception as exc:  # noqa: BLE001 - a bug degrades to E5 with the class name only
        return failed_model(f'PT-EVIDENCE-ASSEMBLY: unexpected {type(exc).__name__}', **common)


def detect_stale(vm: EvidenceViewModel | EvidenceRequest, current_revision: int, current_run_id: str | None,
                 current_pair: tuple[str, str]) -> str | None:
    """First matching reason (spec §4.3), evaluated on the GUI thread without re-running anything."""
    run_id = vm.ghidriff_run_id if isinstance(vm, EvidenceViewModel) else vm.run_id
    if (vm.older_sha256, vm.newer_sha256) != tuple(current_pair):
        return STALE_PAIR
    if run_id != current_run_id:
        return STALE_RUN
    if vm.revision != current_revision:
        return STALE_REVISION
    return None


def build_request(service, *, generation: int = 0, outcomes: Sequence[EngineOutcomeView] = (),
                  calibration_level: str = CALIBRATION_FALLBACK) -> EvidenceRequest | None:
    """GUI-thread only: snapshot the project and read stored sets through its own connection."""
    project = service.project if service else None
    if project is None:
        return None
    sides = {a.side: a.sha256 for a in project.artifacts}
    run = latest_run(project)
    rows = tuple(load_secondary(EnrichmentStore(service.store)))
    return EvidenceRequest(project.id, run.id if run else None, project.revision, sides.get('older', ''),
                           sides.get('newer', ''), tuple(project.matches), rows, tuple(outcomes),
                           calibration_level, generation, run.backend_version if run else None)


def latest_run(project):
    return next((r for r in reversed(project.runs) if r.status == 'completed' and r.raw_sha256), None)


# ---- engine runs (SPEC-28 scheduler) ----------------------------------------------------------


def _tail_lines(text: str, lines: int = LOG_LINES) -> str:
    clipped = text[-STDERR_VIEW:]
    clean = '\n'.join(sanitize_text(line, 2000) for line in clipped.splitlines()[-lines:])
    return clean


def outcome_view(outcome: EngineOutcome) -> EngineOutcomeView:
    """Adapter from the SPEC-28 `EngineOutcome`; the only place that knows its shape."""
    run = outcome.run
    message = str(outcome.error.message) if outcome.error is not None else ''
    engine = run.engine if run.engine in SECONDARY_ENGINES else 'rz-diff'
    return EngineOutcomeView(engine, run.status, run.engine_version, run.error_code,
                             sanitize_text(message.splitlines()[0] if message else '', 200),
                             _tail_lines(run.stderr_tail), run.duration_ms, run.run_id, run.started_utc,
                             outcome.match_set, run)


def capability_view(cap: Capability) -> EngineOutcomeView | None:
    """An unsupported probe result as a panel outcome (E7 reasons); supported engines yield None."""
    if cap.supported or cap.engine not in SECONDARY_ENGINES:
        return None
    reason = (cap.reason or 'engine unsupported').removeprefix('PT-SECONDARY-UNSUPPORTED: ')
    return EngineOutcomeView(cap.engine, 'unsupported', cap.version, 'PT-SECONDARY-UNSUPPORTED',
                             sanitize_text(reason, 200))


def probe_engines(cancel: threading.Event, *, registry: Mapping[str, EngineAdapter] = REGISTRY,
                  env: Mapping[str, str] | None = None) -> dict[str, Capability]:
    """Capability probes only; nothing is run on the binaries. A probe that raises is unsupported."""
    env = engine_env(os.environ, 'rz-diff') if env is None else env
    found: dict[str, Capability] = {}
    for engine in SECONDARY_ENGINES:
        adapter = registry.get(engine)
        try:
            found[engine] = adapter.probe(env, cancel) if adapter else Capability(
                engine=engine, supported=False, version=None, path='', supports_json=False, reason='not registered')
        except Exception as exc:  # noqa: BLE001
            found[engine] = Capability(engine=engine, supported=False, version=None, path='',
                                       supports_json=False, reason=f'probe failed: {type(exc).__name__}')
    return found


def execute_run(request: RunRequest, cancel: threading.Event, *,
                on_event: Callable[[scheduler.EngineEvent], None] | None = None,
                on_outcome: Callable[[EngineOutcome], None] | None = None,
                registry: Mapping[str, EngineAdapter] = REGISTRY, env: Mapping[str, str] | None = None,
                runner: Callable | None = None) -> tuple[EngineOutcome, ...]:
    """Worker-side: run through the SPEC-28 scheduler; never touches a store or a widget."""
    ref = scheduler.ProjectRef(request.older_path, request.newer_path, request.older_sha256, request.newer_sha256)
    snapshot = dict(request.cache)

    class Snapshot:
        def find(self, key):
            return snapshot.get(key)

    extra = {'runner': runner} if runner is not None else {}
    return scheduler.run_engines(
        ref, list(request.engines), max_parallel=request.max_parallel,
        per_engine_timeout=dict.fromkeys(request.engines, float(request.timeout_s)), cancel=cancel,
        cache=Snapshot(), env=engine_env(os.environ, 'rz-diff') if env is None else env, on_event=on_event,
        on_outcome=on_outcome, registry=registry, **extra)


def run_cache(service, older_sha256: str, newer_sha256: str) -> dict[str, SecondaryMatchSet]:
    """GUI-thread cache snapshot for RunRequest.cache."""
    return cache_snapshot(EnrichmentStore(service.store), older_sha256, newer_sha256)


def persist_outcome(service, request: RunRequest, view: EngineOutcomeView) -> str | None:
    """GUI-thread only. Store the engine set and run record when the project still matches the request.

    Returns None on success or a stale reason (result discarded, nothing written).
    """
    project = service.project if service else None
    if project is None or project.id != request.project_id:
        return 'the project changed while the engine ran'
    run = latest_run(project)
    sides = {a.side: a.sha256 for a in project.artifacts}
    if (sides.get('older'), sides.get('newer')) != (request.older_sha256, request.newer_sha256):
        return STALE_PAIR
    if run is None or run.id != request.run_id:
        return STALE_RUN
    if view.run is None:
        return None
    store = EnrichmentStore(service.store)
    match_set = view.match_set
    digest = match_set.file_sha256 if match_set else view.run.cache_key
    guard = Guard(project.id, run.id, run.raw_sha256, digest)
    if match_set is not None and view.status == 'ok':
        publish_engine_set(store, guard, guard, project.revision, match_set)
    publish_run(store, guard, guard, project.revision, view.run)
    return None
