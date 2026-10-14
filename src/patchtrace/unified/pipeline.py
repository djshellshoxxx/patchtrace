"""SPEC-31 pipeline (01 s4-s5): inputs -> published result in S0 mode (no ProgramIR).

Everything that touches SQLite stays on the owner thread (the CLI main thread, later the GUI thread); `execute` may
run on a plain thread (S4's `UnifiedRunThread`):

* `make_plan` / `prepare` (owner, read-only): the completed Ghidriff run, the PE layouts, the stored secondary sets and
  the analyst's corrections give the immutable `Plan` / `UnifiedRequest` and the `result_id` BEFORE the run.
* `cached` (owner): a verified result with that id is reused and recorded as a `cached` run.
* `execute` (any thread, no SQLite): private directory, then the worker child through `jobs.run_process` with C3's
  `worker_argv()`, its allow-listed environment, the L-42 memory cap and C3's OOM classification, or the same code in
  process (`compute.run_request`). It returns a `WorkerOutput` value and never raises for a worker failure.
* `publish` (owner): re-derive the identity from what the worker observed, verify every part of the staged result,
  publish the pointer row and record the `unified-run` row. A failure never replaces the current result.

The project snapshot and every other enrichment kind are never written. Spawning happens here and only through
`jobs.run_process` (01 s3 rule 2).
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from ..artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
from ..enrichment.contracts import EnrichmentError
from ..enrichment.storage import EnrichmentStore, Guard
from ..ingestion import safe_path
from ..jobs import run_process
from ..secondary.binexport_run import (  # C3's OOM rule and spawn recipe
    _out_of_memory,
    worker_argv,
    worker_env,
)
from ..secondary.store import current_sets
from . import keys, store
from .addressing import AddressMap, PeLayout, layout_from_reader
from .compute import Identity, plan_identity, run_request
from .contracts import Counts, StageRecord, UnifiedResultManifest, UnifiedRun
from .exchange import (
    ALL_SOURCES,
    StageEvent,
    WorkerFile,
    WorkerLayout,
    WorkerReport,
    WorkerRequest,
    fail,
    read_report,
)
from .limits import DEFAULT_LIMITS, ERROR_CODES, UnifiedError, UnifiedLimits
from .registry import REGISTRY, Registry
from .sources import (
    GhidriffRun,
    LoadedSecondary,
    RawGhidriff,
    SnapshotMatch,
    SourceInputs,
    snapshot_from_project,
    write_snapshot,
)
from .sources.ghidriff import MAX_RAW_BYTES
from .sources.secondary import write_loaded

__all__ = ['ALL_SOURCES', 'Plan', 'RunReport', 'StageEvent', 'UnifiedOptions', 'UnifiedRequest', 'WorkerOutput',
           'cached', 'execute', 'load_current', 'make_plan', 'prepare', 'publish', 'recent_runs', 'run_unified',
           'total_ram_bytes']

SECONDARY_ENGINES = ('bindiff', 'rz-diff')
MODE = 's0'
RUN_STATUS = {'PT-UNIFIED-CANCEL': 'cancelled', 'PT-UNIFIED-TIMEOUT': 'timeout', 'PT-UNIFIED-UNSUPPORTED': 'unsupported'}


@dataclass(frozen=True)
class UnifiedOptions:
    sources: tuple[str, ...] = ALL_SOURCES
    isolate: bool = True                    # worker child (default); False = in process (tests, debugging, B-20)
    timeout_s: int = DEFAULT_LIMITS.l34_worker_timeout_s
    refresh: bool = False                   # recompute even when a verified result with this id exists
    total_ram_bytes: int | None = None      # None: probe (POSIX); unknown -> the absolute L-42 cap
    runner: Callable = field(default=run_process, compare=False)


@dataclass(frozen=True)
class Plan:
    """What a result would be OF (everything in `result_key`), read from the project without running anything."""
    project_id: str
    revision: int
    run_id: str
    raw_sha256: str
    raw_path: Path | None
    raw_status: str
    backend_version: str
    older_sha256: str
    newer_sha256: str
    older_layout: PeLayout
    newer_layout: PeLayout
    sources: tuple[str, ...]
    secondary: tuple[LoadedSecondary, ...]
    manual: tuple[SnapshotMatch, ...]
    identity: Identity | None = None

    @property
    def result_id(self) -> str:
        return self.identity.result_id  # type: ignore[union-attr]

    @property
    def config_digest(self) -> str:
        return self.identity.config_digest  # type: ignore[union-attr]

    def addr(self) -> AddressMap:
        return AddressMap(self.older_layout, self.newer_layout)

    def inputs(self, matches: Iterable[SnapshotMatch] | None = None, raw_status: str | None = None) -> SourceInputs:
        raw = RawGhidriff(status=raw_status or self.raw_status, sha256=self.raw_sha256)  # type: ignore[arg-type]
        return SourceInputs(older_sha256=self.older_sha256, newer_sha256=self.newer_sha256,
                            run=GhidriffRun(self.run_id, self.backend_version, raw),
                            matches=self.manual if matches is None else tuple(matches), secondary=self.secondary)

    def guard(self, result_id: str | None = None) -> Guard:
        return Guard(self.project_id, self.run_id, self.raw_sha256, result_id or self.result_id)


@dataclass(frozen=True)
class UnifiedRequest:
    """Immutable, built on the owner thread; `execute` needs nothing else (01 s4)."""
    root: Path
    plan: Plan
    snapshot: tuple[SnapshotMatch, ...]
    timeout_s: int
    isolate: bool
    refresh: bool
    total_ram_bytes: int | None
    started_utc: str
    started_monotonic: float
    prepare_ms: int


@dataclass(frozen=True)
class WorkerOutput:
    """What `execute` hands back to the owner thread: exactly one of `report` (with a staged directory) or `error`."""
    report: WorkerReport | None
    error: UnifiedError | None
    staged: Path | None
    stderr_tail: str = ''
    peak_rss_bytes: int | None = None
    compute_ms: int = 0


@dataclass(frozen=True)
class RunReport:
    status: Literal['ok', 'partial', 'cached']
    result_id: str
    run_id: str
    counts: Counts
    limitations: tuple[str, ...]
    sources: tuple[str, ...]            # the sources that are inputs of the result (the manifest's)
    selected: tuple[str, ...]           # the sources the run was asked to use
    stages: tuple[StageRecord, ...]
    warnings: tuple[str, ...]
    directory: Path
    result_status: Literal['complete', 'partial']
    mode: str = MODE


def total_ram_bytes() -> int | None:
    """Physical memory for the L-42 cap. stdlib `os.sysconf` on POSIX; Windows would need ctypes, which `unified/`
    must not import (01 s3), so the absolute 4 GiB cap applies there (02 s10 item 8d)."""
    try:
        return os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
    except (AttributeError, ValueError, OSError):
        return None


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec='microseconds')


def _ms(since: float) -> int:
    return max(0, int((time.monotonic() - since) * 1000))


def _stage(name: str, since: float, status: str = 'ok') -> StageRecord:
    return StageRecord(stage=name, status=status, duration_ms=_ms(since))  # type: ignore[arg-type]


def _stderr_text(text: str) -> str:
    """Printable, bounded diagnostics for the run row (no control or bidi characters)."""
    clean = ''.join(ch if ch.isprintable() or ch in '\t\n' else ' ' for ch in text or '')
    return clean.encode('utf-8')[-DEFAULT_LIMITS.l31_stderr_tail_bytes:].decode('utf-8', errors='ignore')


def _completed_run(project):
    return next((r for r in reversed(project.runs) if r.status == 'completed' and r.raw_sha256), None)


def _current_guard(project, result_id: str) -> Guard:
    run = _completed_run(project)
    return Guard(project.id, run.id if run else '', run.raw_sha256 if run else '', result_id)


def _raw_state(root: Path, run) -> tuple[Path | None, str]:
    """Existence, size and SHA-256 of the preserved raw output; the (heavy) parse is the worker's job."""
    if not run.raw_path or not run.raw_sha256:
        return None, 'missing'
    try:
        path = safe_path(root, run.raw_path)
        if path.is_symlink() or not path.is_file():
            return None, 'missing'
        if path.stat().st_size > MAX_RAW_BYTES:
            return path, 'hash-mismatch'
        digest = hashlib.sha256()
        with open(path, 'rb') as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b''):
                digest.update(chunk)
    except (OSError, ValueError):
        return None, 'missing'
    return path, 'ok' if digest.hexdigest() == run.raw_sha256 else 'hash-mismatch'


def _layouts(service) -> tuple[PeLayout, PeLayout]:
    found: dict[str, PeLayout] = {}
    for artifact in service.project.artifacts:
        try:
            reader = VerifiedArtifactReader.open_artifact(artifact, service.root)
        except ArtifactBytesError:
            raise fail('PT-UNIFIED-INPUT', 'artifact-unreadable') from None
        try:
            found[artifact.side] = layout_from_reader(reader)
        finally:
            reader.close()
    if set(found) != {'older', 'newer'}:
        raise fail('PT-UNIFIED-INPUT', 'artifact-missing')
    return found['older'], found['newer']


def _validate_sources(sources: Iterable[str]) -> tuple[str, ...]:
    chosen = tuple(sorted(set(sources)))
    if not chosen or not set(chosen) <= set(ALL_SOURCES):
        raise fail('PT-UNIFIED-INPUT', 'bad-sources')
    return chosen


def _stored_sets(service, sources: tuple[str, ...]) -> tuple[LoadedSecondary, ...]:
    wanted = set(sources) & set(SECONDARY_ENGINES)
    if not wanted:
        return ()
    try:
        rows = current_sets(EnrichmentStore(service.store))
    except (EnrichmentError, sqlite3.Error, ValueError):
        raise fail('PT-UNIFIED-STORE', 'secondary-unreadable') from None
    return tuple(LoadedSecondary(entry.id, match_set) for entry, match_set in rows if match_set.engine in wanted)


def make_plan(service, sources: Iterable[str] = ALL_SOURCES, *, limits: UnifiedLimits = DEFAULT_LIMITS,
              registry: Registry = REGISTRY) -> Plan:
    """Owner thread, read-only. Raises `UnifiedError(INPUT)` when there is nothing to build a result from."""
    chosen = _validate_sources(sources)
    project = service.project
    run = _completed_run(project)
    if run is None:
        raise fail('PT-UNIFIED-INPUT', 'no-completed-run')
    older, newer = _layouts(service)
    raw_path, raw_status = _raw_state(service.root, run)
    manual = snapshot_from_project(project, run.id, limits, manual_only=True)
    secondary = _stored_sets(service, chosen)
    sides = {a.side: a.sha256 for a in project.artifacts}
    base = Plan(project_id=project.id, revision=project.revision, run_id=run.id, raw_sha256=run.raw_sha256,
                raw_path=raw_path, raw_status=raw_status, backend_version=str(run.backend_version)[:64],
                older_sha256=sides['older'], newer_sha256=sides['newer'], older_layout=older, newer_layout=newer,
                sources=chosen, secondary=secondary, manual=manual)
    return dataclasses.replace(base, identity=plan_identity(base.inputs(), base.addr(), chosen, registry, limits))


def prepare(service, options: UnifiedOptions | None = None, *, limits: UnifiedLimits = DEFAULT_LIMITS,
            registry: Registry = REGISTRY) -> UnifiedRequest:
    """Owner thread: everything `execute` needs, copied out of the project."""
    options = options or UnifiedOptions()
    timeout = limits.checked_timeout(options.timeout_s, kind='worker')
    started_utc, started = _now(), time.monotonic()
    plan = make_plan(service, options.sources, limits=limits, registry=registry)
    snapshot = snapshot_from_project(service.project, plan.run_id, limits)
    ram = options.total_ram_bytes if options.total_ram_bytes is not None else total_ram_bytes()
    return UnifiedRequest(root=service.root, plan=plan, snapshot=snapshot, timeout_s=timeout,
                          isolate=options.isolate, refresh=options.refresh, total_ram_bytes=ram,
                          started_utc=started_utc, started_monotonic=started, prepare_ms=_ms(started))


# --- execute (no SQLite; any thread) ------------------------------------------------------------------------------

def _write_request(request: UnifiedRequest, private: Path) -> Path:
    plan = request.plan
    snapshot_path = private / 'matches.jsonl'
    digest, size, lines = write_snapshot(snapshot_path, request.snapshot)
    files = []
    for index, loaded in enumerate(sorted(plan.secondary, key=lambda s: (s.match_set.engine, s.entry_id))):
        path = private / f'secondary-{index}.json'
        sha, length = write_loaded(path, loaded)
        files.append(WorkerFile(path=str(path), sha256=sha, size=length))
    req = WorkerRequest(
        older_sha256=plan.older_sha256, newer_sha256=plan.newer_sha256,
        older_layout=WorkerLayout(image_base=plan.older_layout.image_base,
                                  size_of_image=plan.older_layout.size_of_image),
        newer_layout=WorkerLayout(image_base=plan.newer_layout.image_base,
                                  size_of_image=plan.newer_layout.size_of_image),
        run_id=plan.run_id, backend_version=plan.backend_version, raw_sha256=plan.raw_sha256,
        raw_status=plan.raw_status,  # type: ignore[arg-type]
        raw_path=str(plan.raw_path) if plan.raw_path is not None and plan.raw_status == 'ok' else None,
        snapshot=WorkerFile(path=str(snapshot_path), sha256=digest, size=size), snapshot_lines=lines,
        secondary=tuple(files), sources=plan.sources,  # type: ignore[arg-type]
        report_path=str(private / 'report.json'), progress_path=str(private / 'progress.json'),
        budget_seconds=request.timeout_s)
    request_path = private / 'request.json'
    request_path.write_text(req.model_dump_json(), encoding='utf-8')
    return request_path


def _error_from_report(report: WorkerReport) -> UnifiedError:
    code = report.error_code if report.error_code in ERROR_CODES else 'PT-UNIFIED-INTERNAL'
    return fail(code, report.reason)


def _exit_reason(returncode: int) -> str:
    return f'worker-signal-{-returncode}' if returncode < 0 else f'worker-exit-{returncode}'


def _spawn(request: UnifiedRequest, request_path: Path, staged: Path, private: Path, cancel: threading.Event,
           emit, runner, limits: UnifiedLimits) -> tuple[WorkerReport | None, UnifiedError | None, str, int | None]:
    """Run `patchtrace unified _worker` as a child: C3's argv and environment recipe, L-42 cap, C3's OOM rule."""
    memory = limits.worker_memory_cap(request.total_ram_bytes)
    argv = [*worker_argv(), 'unified', '_worker', '--request', str(request_path), '--result-dir', str(staged)]
    env = {k: v for k, v in worker_env().items() if k != 'PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'}
    last: dict = {}

    def poll() -> str | None:
        """Progress events from the child's `progress.json` (absent = indeterminate); never ends the run."""
        if emit is not None:
            try:
                path = private / 'progress.json'
                if path.stat().st_size <= limits.l37_progress_bytes:
                    data = json.loads(path.read_text(encoding='utf-8'))
                    if data != last:
                        last.clear()
                        last.update(data)
                        emit(StageEvent(str(data['stage']), int(data['done']),
                                        None if data.get('total') is None else int(data['total'])))
            except (OSError, ValueError, KeyError, TypeError):
                pass
        return None
    try:
        res = runner(argv, cwd=private, env=env, cancel=cancel, timeout_seconds=request.timeout_s, check_output=poll,
                     log_limit=64 * 1024, separate_streams=True, stderr_limit=limits.l31_stderr_tail_bytes,
                     memory_limit_bytes=memory)
    except (OSError, ValueError, RuntimeError):
        return None, fail('PT-UNIFIED-INTERNAL', 'worker-spawn-failed'), '', None
    tail, peak = _stderr_text(res.stderr_tail), res.peak_memory_bytes
    if res.reason == 'cancelled' or cancel.is_set():
        return None, fail('PT-UNIFIED-CANCEL', 'cancelled'), tail, peak
    if res.reason == 'timeout':
        return None, fail('PT-UNIFIED-TIMEOUT', 'worker-deadline'), tail, peak
    report = read_report(private / 'report.json')
    if report is not None and not report.ok:
        return None, _error_from_report(report), tail, peak
    if res.returncode == 0 and report is not None:
        return report, None, tail, peak
    if _out_of_memory(res, memory):
        return None, fail('PT-UNIFIED-LIMIT', 'worker-oom'), tail, peak
    return None, fail('PT-UNIFIED-INTERNAL', 'worker-no-report' if res.returncode == 0
                      else _exit_reason(res.returncode)), tail, peak


def _discard(path: Path | None) -> None:
    if path is not None:
        shutil.rmtree(path, ignore_errors=True)


def execute(request: UnifiedRequest, cancel: threading.Event | None = None,
            emit: Callable[[StageEvent], None] | None = None, *, runner: Callable = run_process,
            limits: UnifiedLimits = DEFAULT_LIMITS, registry: Registry = REGISTRY) -> WorkerOutput:
    """Any thread, no SQLite. Cancel and deadline never leave a staged directory behind."""
    cancel = cancel or threading.Event()
    if cancel.is_set():
        return WorkerOutput(None, fail('PT-UNIFIED-CANCEL', 'cancelled'), None)
    started = time.monotonic()
    private = staged = None
    report, error, tail, peak = None, None, '', None
    try:
        if request.isolate and (limits is not DEFAULT_LIMITS or registry is not REGISTRY):
            raise fail('PT-UNIFIED-INPUT', 'custom-config-in-process-only')  # the child always uses the defaults
        private = Path(tempfile.mkdtemp(prefix='pt-unified-')).resolve()
        staged = store.new_staging_dir(request.root, request.plan.run_id)
        request_path = _write_request(request, private)
        if request.isolate:
            report, error, tail, peak = _spawn(request, request_path, staged, private, cancel, emit, runner, limits)
        else:
            report = run_request(request_path, staged, cancel=cancel, emit=emit, limits=limits, registry=registry)
    except UnifiedError as exc:
        error = exc
    except MemoryError:
        error = fail('PT-UNIFIED-LIMIT', 'worker-oom')
    except Exception as exc:  # noqa: BLE001 - class name only, never the message (01 s6)
        error = fail('PT-UNIFIED-INTERNAL', type(exc).__name__)
    finally:
        _discard(private)
    if error is not None or report is None:
        _discard(staged)
        return WorkerOutput(None, error or fail('PT-UNIFIED-INTERNAL', 'worker-no-report'), None, tail, peak,
                            _ms(started))
    return WorkerOutput(report, None, staged, tail, peak, _ms(started))


# --- publish (owner thread) ------------------------------------------------------------------------------------------

def _provenance(request: UnifiedRequest, config_digest: str | None) -> dict[str, str]:
    out = {'mode': MODE, 'engine_version': keys.ENGINE_VERSION, 'sources': ','.join(request.plan.sources),
           'worker': 'child' if request.isolate else 'in-process',
           'python': '.'.join(str(n) for n in sys.version_info[:3]), 'registry': REGISTRY.digest()[:16]}
    if config_digest:
        out['config'] = config_digest[:16]
    return out


def _record(enrichment: EnrichmentStore, service, request: UnifiedRequest, *, status: str, result_id: str | None,
            error: UnifiedError | None, stages: list[StageRecord], stderr_tail: str = '',
            peak: int | None = None, config_digest: str | None = None) -> tuple[str, ...]:
    """The `unified-run` row of this attempt; failing to store it never hides the real outcome."""
    plan = request.plan
    key = result_id or plan.result_id
    try:
        row = UnifiedRun(
            run_id=keys.unified_run_id(key, request.started_utc), result_id=result_id,
            status=status, error_code=None if error is None else error.code,  # type: ignore[arg-type]
            stages=tuple(stages)[:16], provenance=_provenance(request, config_digest or plan.config_digest),
            stderr_tail=stderr_tail, peak_rss_bytes=peak, started_utc=request.started_utc,
            duration_ms=_ms(request.started_monotonic))
        store.publish_run(enrichment, row, guard=plan.guard(key), current=_current_guard(service.project, key),
                          revision=service.project.revision)
    except (UnifiedError, EnrichmentError, sqlite3.Error, ValueError) as exc:
        return (f'The unified-run row could not be stored ({type(exc).__name__}).',)
    return ()


def _report(status: str, manifest: UnifiedResultManifest, directory: Path, run_id: str, plan: Plan,
            stages: list[StageRecord], warnings: tuple[str, ...]) -> RunReport:
    return RunReport(status=status, result_id=manifest.result_id, run_id=run_id,  # type: ignore[arg-type]
                     counts=manifest.counts, limitations=manifest.limitations,
                     sources=tuple(sorted({s.source for s in manifest.sources})), selected=plan.sources,
                     stages=tuple(stages), warnings=warnings, directory=Path(directory),
                     result_status=manifest.status)


def cached(service, request: UnifiedRequest, *, enrichment: EnrichmentStore | None = None,
           limits: UnifiedLimits = DEFAULT_LIMITS) -> RunReport | None:
    """Owner thread: a verified, not-stale result with the planned id, or None (then `execute`)."""
    if request.refresh:
        return None
    enrichment = enrichment or EnrichmentStore(service.store)
    hit = store.cached_result(enrichment, request.plan.result_id, limits)  # a damaged result is a miss, not an error
    if hit is None or hit.manifest is None or hit.directory is None or (hit.entry is not None and hit.entry.stale):
        return None
    t = time.monotonic()
    stages = [StageRecord(stage='prepare', status='ok', duration_ms=request.prepare_ms), _stage('cache', t)]
    warnings = _record(enrichment, service, request, status='cached', result_id=hit.manifest.result_id, error=None,
                       stages=stages, config_digest=hit.manifest.config_digest)
    return _report('cached', hit.manifest, hit.directory,
                   keys.unified_run_id(hit.manifest.result_id, request.started_utc), request.plan, stages, warnings)


def publish(service, request: UnifiedRequest, output: WorkerOutput, *, enrichment: EnrichmentStore | None = None,
            limits: UnifiedLimits = DEFAULT_LIMITS) -> RunReport:
    """Owner thread. Raises the worker's error (after recording it) or `UnifiedError(STORE)`; on success the staged
    directory has been moved into the project and the pointer row is current (or stale if the project moved)."""
    enrichment = enrichment or EnrichmentStore(service.store)
    plan = request.plan
    stages = [StageRecord(stage='prepare', status='ok', duration_ms=request.prepare_ms)]
    try:
        if output.error is not None or output.report is None or output.staged is None:
            raise output.error or fail('PT-UNIFIED-INTERNAL', 'worker-no-report')
        report = output.report
        stages.append(StageRecord(stage='compute', status='partial' if report.status == 'partial' else 'ok',
                                  duration_ms=output.compute_ms))
        expected = plan_identity(plan.inputs(raw_status=report.raw_status or plan.raw_status), plan.addr(),
                                 plan.sources, REGISTRY, limits)
        if report.result_id != expected.result_id:
            raise fail('PT-UNIFIED-STORE', 'result-id-mismatch')
        t = time.monotonic()
        manifest = store.verify_result_dir(output.staged, expected_result_id=expected.result_id, limits=limits)
        stages.append(_stage('verify', t))
        t = time.monotonic()
        published = store.publish_result(enrichment, output.staged, guard=plan.guard(expected.result_id),
                                         current=_current_guard(service.project, expected.result_id),
                                         revision=service.project.revision, limits=limits)
        stages.append(_stage('publish', t))
    except UnifiedError as error:
        _discard(output.staged)
        _record(enrichment, service, request, status=RUN_STATUS.get(error.code, 'failed'), result_id=None,
                error=error, stages=stages, stderr_tail=output.stderr_tail, peak=output.peak_rss_bytes)
        raise
    except BaseException:
        _discard(output.staged)
        raise
    status = 'partial' if manifest.status == 'partial' else 'ok'
    warnings = _record(enrichment, service, request, status=status, result_id=expected.result_id, error=None,
                       stages=stages, stderr_tail=output.stderr_tail, peak=output.peak_rss_bytes,
                       config_digest=expected.config_digest)
    return _report(status, published.manifest, published.directory,
                   keys.unified_run_id(expected.result_id, request.started_utc), plan, stages, warnings)


def run_unified(service, options: UnifiedOptions | None = None, *, cancel: threading.Event | None = None,
                emit: Callable[[StageEvent], None] | None = None,
                enrichment: EnrichmentStore | None = None) -> RunReport:
    """prepare -> cached -> execute -> publish on the calling (owner) thread; the CLI's path."""
    options = options or UnifiedOptions()
    cancel = cancel or threading.Event()
    if cancel.is_set():
        raise fail('PT-UNIFIED-CANCEL', 'cancelled')
    request = prepare(service, options)
    hit = cached(service, request, enrichment=enrichment)
    if hit is not None:
        return hit
    output = execute(request, cancel, emit, runner=options.runner)
    return publish(service, request, output, enrichment=enrichment)


# --- reading the current result (never creates the enrichment tables) ----------------------------------------------------

def _has_enrichment(service) -> bool:
    try:
        row = service.store.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='enrichment_entries'").fetchone()
    except sqlite3.Error:
        return False
    return row is not None


def load_current(service, plan: Plan | None = None, *, limits: UnifiedLimits = DEFAULT_LIMITS) -> store.LoadedResult:
    """The current verified result, else the newest stale one, else `none`/`invalid`. Without a plan every stored
    result counts as stale (its inputs cannot be compared)."""
    if not _has_enrichment(service):
        return store.LoadedResult('none', 'no-result')
    guard = plan.guard() if plan is not None else _current_guard(service.project, '')
    try:
        return store.load_result(EnrichmentStore(service.store), guard, limits)
    except EnrichmentError:
        raise fail('PT-UNIFIED-STORE', 'enrichment-unreadable') from None


def read_rows(loaded: store.LoadedResult) -> Iterator:
    """The rows of a loaded result, streamed; a damaged part is a typed STORE error."""
    yield from store.read_rows(loaded.directory, loaded.manifest)


def read_facts(loaded: store.LoadedResult) -> Iterator:
    yield from store.read_facts(loaded.directory, loaded.manifest)


def recent_runs(service, limit: int = 5) -> list[UnifiedRun]:
    """The newest `unified-run` rows (valid ones only)."""
    if not _has_enrichment(service):
        return []
    out: list[UnifiedRun] = []
    try:
        entries = EnrichmentStore(service.store).entries(store.RUN_KIND, on_corrupt=lambda _row: None)
    except (EnrichmentError, sqlite3.Error):
        return []
    for entry in entries:
        try:
            out.append(UnifiedRun.model_validate_json(json.dumps(entry.body)))
        except ValidationError:
            continue
        if len(out) >= limit:
            break
    return out
