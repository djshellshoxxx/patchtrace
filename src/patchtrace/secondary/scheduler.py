"""Bounded, cancellable, failure-isolated engine scheduler (SPEC-28 §5). stdlib threading only; no Qt.

The scheduler never writes to a store and never spawns processes itself: adapters spawn through
`EngineJob.runner` (`jobs.run_process`, which owns the Windows Job Object / killpg containment).
"""
from __future__ import annotations

import hashlib
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from ..jobs import run_process
from .contracts import Capability, SecondaryError, SecondaryMatchSet
from .registry import REGISTRY, EngineAdapter, EngineJob, RawResult
from .runs import (
    EngineId,
    EngineOutcome,
    EngineRun,
    Status,
    argv_digest,
    as_v2,
    cache_key,
    new_run_id,
    path_sha256,
    sanitize_stderr,
)
from .rzdiff import STDOUT_LIMIT

MAX_PARALLEL = 2
DEFAULT_DEADLINE = 1800.0


@dataclass(frozen=True)
class ProjectRef:
    older: Path
    newer: Path
    older_sha256: str
    newer_sha256: str


@dataclass(frozen=True)
class EngineEvent:
    engine: EngineId
    phase: Literal['started', 'finished']
    status: Status | None = None


class CacheLookup(Protocol):
    def find(self, key: str) -> SecondaryMatchSet | None: ...


def _code(error: SecondaryError | None) -> str | None:
    return error.code if error else None


def run_engines(project: ProjectRef, engines: Sequence[EngineId], *, max_parallel: int = 1,
                per_engine_timeout: Mapping[EngineId, float] | None = None, cancel: threading.Event,
                cache: CacheLookup | None = None, env: Mapping[str, str],
                on_event: Callable[[EngineEvent], None] | None = None,
                on_outcome: Callable[[EngineOutcome], None] | None = None,
                registry: Mapping[EngineId, EngineAdapter] = REGISTRY, runner: Callable = run_process,
                stdout_limit: int = STDOUT_LIMIT) -> tuple[EngineOutcome, ...]:
    if isinstance(max_parallel, bool) or not isinstance(max_parallel, int) or not 1 <= max_parallel <= MAX_PARALLEL:
        raise ValueError(f'max_parallel must be between 1 and {MAX_PARALLEL}')
    plan = tuple(dict.fromkeys(engines))
    unknown = [e for e in plan if e not in registry]
    if unknown:
        raise ValueError(f'unknown engine {unknown[0]!r}')
    deadlines = per_engine_timeout or {}

    def emit(event: EngineEvent) -> None:
        if on_event:
            try:
                on_event(event)
            except Exception:  # a faulty observer must not fail an engine
                pass

    def provenance(eid, status: Status, error: SecondaryError | None) -> dict[str, str]:
        """Optional adapter hook (SPEC-29 §5); adapters without it keep empty provenance (unchanged rows)."""
        hook = getattr(registry[eid], 'provenance', None)
        if hook is None:
            return {}
        try:
            data = {str(k): str(v)[:256] for k, v in dict(hook()).items()}
        except Exception:  # provenance must never turn an outcome into a crash
            data = {}
        kind = getattr(error, 'kind', None) or {'timeout': 'timeout', 'cancelled': 'cancelled'}.get(status)
        if kind:
            data['failure_kind'] = kind
        return dict(list(data.items())[:16])

    def outcome(eid, status: Status, started: str, t0: float, *, cap: Capability | None = None,
                digest: str | None = None, key: str | None = None, error: SecondaryError | None = None,
                raw: RawResult | None = None, match_set: SecondaryMatchSet | None = None,
                output_sha256: str | None = None) -> EngineOutcome:
        digest = digest or argv_digest(())
        key = key or cache_key(eid, cap.version if cap else None, digest, project.older_sha256,
                               project.newer_sha256)
        run = EngineRun(
            run_id=new_run_id(key, started), engine=eid, engine_version=cap.version if cap else None,
            executable_path_sha256=path_sha256(cap.path) if cap and cap.path else None, argv_digest=digest,
            older_sha256=project.older_sha256, newer_sha256=project.newer_sha256, orientation='older->newer',
            cache_key=key, status=status, error_code=_code(error), returncode=raw.returncode if raw else None,
            started_utc=started, duration_ms=int((time.monotonic() - t0) * 1000),
            stderr_tail=sanitize_stderr(raw.stderr_tail) if raw else '', output_sha256=output_sha256,
            match_set_id=match_set.entry_id if match_set else None, provenance=provenance(eid, status, error))
        emit(EngineEvent(eid, 'finished', status))
        return EngineOutcome(run, match_set, error)

    def work(eid: EngineId) -> EngineOutcome:
        started, t0 = datetime.now(UTC).isoformat(), time.monotonic()
        if cancel.is_set():
            return outcome(eid, 'cancelled', started, t0, error=SecondaryError('PT-SECONDARY-CANCEL', 'not started'))
        emit(EngineEvent(eid, 'started'))
        adapter = registry[eid]
        cap = digest = key = raw = None
        try:
            cap = adapter.probe(env, cancel)
            if cancel.is_set():
                return outcome(eid, 'cancelled', started, t0, cap=cap,
                               error=SecondaryError('PT-SECONDARY-CANCEL', 'cancelled'))
            if not cap.supported:
                return outcome(eid, 'unsupported', started, t0, cap=cap, error=SecondaryError(
                    'PT-SECONDARY-UNSUPPORTED', (cap.reason or 'engine unsupported').removeprefix(
                        'PT-SECONDARY-UNSUPPORTED: ')))
            with tempfile.TemporaryDirectory(prefix='patchtrace-engine-') as workdir:
                job = EngineJob(project.older, project.newer, project.older_sha256, project.newer_sha256, env,
                                Path(workdir), cancel, float(deadlines.get(eid, DEFAULT_DEADLINE)), runner,
                                stdout_limit)
                digest = argv_digest(adapter.argv(cap, job), project.older, project.newer)
                extra = getattr(adapter, 'cache_extra', None)  # SPEC-29 §5: e.g. the .BinExport hashes
                key = cache_key(eid, cap.version, digest, project.older_sha256, project.newer_sha256,
                                extra=tuple(extra(cap, job)) if extra else ())
                hit = cache.find(key) if cache else None
                if hit is not None:
                    return outcome(eid, 'cached', started, t0, cap=cap, digest=digest, key=key, match_set=hit,
                                   output_sha256=hit.file_sha256)
                raw = adapter.run(cap, job)
                if raw.reason == 'cancelled':
                    return outcome(eid, 'cancelled', started, t0, cap=cap, digest=digest, key=key, raw=raw,
                                   error=SecondaryError('PT-SECONDARY-CANCEL', 'cancelled'))
                if raw.reason == 'timeout':
                    return outcome(eid, 'timeout', started, t0, cap=cap, digest=digest, key=key, raw=raw,
                                   error=SecondaryError('PT-SECONDARY-TIMEOUT',
                                                        f'exceeded the {job.deadline_seconds:g} s deadline'))
                if raw.reason:
                    return outcome(eid, 'failed', started, t0, cap=cap, digest=digest, key=key, raw=raw,
                                   error=SecondaryError('PT-SECONDARY-RUN', f'stopped: {raw.reason}'))
                parsed = adapter.parse(raw, cap, job)
            ident = new_run_id(key, started)
            stamped = as_v2(parsed, ident) if parsed is not None else None
            sha = stamped.file_sha256 if stamped else hashlib.sha256(raw.stdout or b'').hexdigest()
            return outcome(eid, 'ok', started, t0, cap=cap, digest=digest, key=key, raw=raw,
                           match_set=stamped, output_sha256=sha)
        except SecondaryError as exc:
            status: Status = {'PT-SECONDARY-CANCEL': 'cancelled', 'PT-SECONDARY-UNSUPPORTED': 'unsupported',
                              'PT-SECONDARY-TIMEOUT': 'timeout'}.get(exc.code, 'failed')
            return outcome(eid, status, started, t0, cap=cap, digest=digest, key=key, error=exc, raw=raw)
        except Exception as exc:  # isolation: only the class name is recorded, never the message
            return outcome(eid, 'failed', started, t0, cap=cap, digest=digest, key=key,
                           error=SecondaryError('PT-SECONDARY-RUN', type(exc).__name__))

    # `on_outcome` runs on the caller's thread, once per finished engine, as each finishes. A caller that
    # persists there keeps completed work when Ctrl+C (KeyboardInterrupt) interrupts the wait for later engines.
    pool = ThreadPoolExecutor(max_workers=max_parallel, thread_name_prefix='patchtrace-engine')
    futures = {eid: pool.submit(work, eid) for eid in plan}
    delivered: set[str] = set()

    def deliver(eid) -> None:
        delivered.add(eid)
        if on_outcome:
            on_outcome(futures[eid].result())

    try:
        by_future = {future: eid for eid, future in futures.items()}
        pending = set(futures.values())
        while pending:  # short waits keep Ctrl+C responsive: a blocking lock wait is not interruptible on Windows
            done, pending = wait(pending, timeout=0.2, return_when=FIRST_COMPLETED)
            for future in sorted(done, key=lambda f: plan.index(by_future[f])):
                deliver(by_future[future])
        return tuple(futures[eid].result() for eid in plan)
    except BaseException:
        cancel.set()
        raise
    finally:
        pool.shutdown(wait=True)  # workers are joined: no child process outlives this call
        if sys.exc_info()[0] is not None:  # interrupted: still hand over everything that did finish
            for eid in plan:
                if eid not in delivered and futures[eid].done() and not futures[eid].cancelled() \
                        and futures[eid].exception() is None:
                    try:
                        deliver(eid)
                    except Exception:  # best effort while already unwinding
                        pass
