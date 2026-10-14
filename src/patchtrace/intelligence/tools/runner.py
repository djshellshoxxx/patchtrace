"""Profiles, scheduler and one-job execution for the capa / FLOSS / diec adapters (SPEC-29 tools T4, T7).

Jobs = engines x {older, newer}. Each job runs in a private scratch (verified read-only copy of the artifact, copies
of rule/signature/database directories, allow-listed environment) through `jobs.run_process` only: Job Object /
process-group containment, separated and bounded streams, cooperative cancel, optional memory cap. The target is
never executed; the tools analyse it statically (FLOSS emulation only with its recorded consent). Worker threads
only compute immutable results; the caller's thread persists them (SQLite thread ownership), so a cancelled or
crashed job never loses a finished one. One job's exception is that job's `failed` run.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ...artifact_bytes import VerifiedArtifactReader
from ...jobs import run_process
from . import capa, diec, floss, process
from .common import (
    DEFAULT_LIMITS,
    LICENSES,
    PROFILES,
    ToolError,
    ToolEvidenceSet,
    ToolManifest,
    ToolRun,
    cache_key,
    config_digest,
    new_run_id,
)
from .normalize import PeMap
from .store import ToolStore, write_raw

TIMEOUT_RANGE = (10, 86_400)


@dataclass(frozen=True)
class ArtifactRef:
    side: str
    path: Path
    sha256: str
    size: int


@dataclass(frozen=True)
class Setup:
    """Explicit configuration per engine; an engine without a config is `absent` (PATH is never searched)."""
    capa: capa.CapaConfig | None = None
    floss: floss.FlossConfig | None = None
    diec: diec.DiecConfig | None = None

    def config(self, engine: str):
        return getattr(self, engine)


@dataclass(frozen=True)
class RunRequest:
    artifacts: tuple[ArtifactRef, ...]
    setup: Setup
    profile: str = 'basic'
    engines: tuple[str, ...] | None = None
    scratch_root: Path | None = None
    max_parallel: int = 1
    use_cache: bool = True
    timeout: int | None = None
    memory_limit_bytes: int | None = None


@dataclass(frozen=True)
class JobResult:
    run: ToolRun
    evidence: ToolEvidenceSet | None


def plan_engines(profile: str, engines: tuple[str, ...] | None) -> tuple[str, ...]:
    if profile not in PROFILES:
        raise ToolError('PT-TOOL-INPUT', f'unknown profile {profile[:20]!r}')
    allowed = PROFILES[profile]
    chosen = allowed if engines is None else engines
    if not chosen or any(e not in allowed for e in chosen) or len(set(chosen)) != len(chosen):
        raise ToolError('PT-TOOL-INPUT', f'--engines must be a subset of the {profile} profile ({",".join(allowed)})')
    return tuple(e for e in allowed if e in chosen)


def _module(engine: str):
    return {'capa': capa, 'floss': floss, 'diec': diec}[engine]


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec='microseconds')


def _timeout(engine: str, config, request: RunRequest) -> float:
    if request.timeout is not None:
        if not TIMEOUT_RANGE[0] <= request.timeout <= TIMEOUT_RANGE[1]:
            raise ToolError('PT-TOOL-INPUT', 'the timeout must be between 10 and 86400 seconds')
        return float(request.timeout)
    value = config.effective_timeout() if engine == 'floss' else config.timeout
    return float(min(max(value, TIMEOUT_RANGE[0]), TIMEOUT_RANGE[1]))


def _options(engine: str, config) -> dict[str, str]:
    return {'capa': lambda: capa.options(config), 'floss': lambda: floss.options(config),
            'diec': lambda: diec.options(config)}[engine]()


def _extra_env(engine: str, config) -> dict[str, str]:
    if engine == 'capa':
        return capa.ghidra_extra(config)
    if engine == 'diec':
        return diec.extra_env(config)
    return {}


def _failed_run(engine: str, side: str, artifact: ArtifactRef, manifest: ToolManifest, request: RunRequest,
                options: dict[str, str], status: str, code: str, message: str, *, started: str, elapsed: int = 0,
                **extra) -> ToolRun:
    key = cache_key(artifact.sha256, manifest, options)
    return ToolRun(run_id=new_run_id(key, side, started), engine=engine, side=side,
                   input_artifact_hash=artifact.sha256, config_digest=config_digest(manifest, options),
                   cache_key=key, started_at=started, elapsed=elapsed, status=status, error=message[:500],
                   error_code=code, profile=request.profile, options=options, manifest=manifest, **extra)


def probe_engine(engine: str, config, cancel: threading.Event, runner: Callable, environ=None) -> ToolManifest:
    if config is None:
        return ToolManifest(engine=engine, license=LICENSES[engine], supported=False,
                            reason=f'{engine} is not configured (pass its executable path)')
    return _module(engine).probe(config, cancel=cancel, runner=runner, environ=environ)


def _status_for_unavailable(manifest: ToolManifest) -> tuple[str, str]:
    absent = not manifest.cli_path or 'missing' in (manifest.reason or '') or 'not configured' in (
        manifest.reason or '')
    return ('absent', 'PT-TOOL-ABSENT') if absent else ('unsupported', 'PT-TOOL-UNSUPPORTED')


def run_job(engine: str, artifact: ArtifactRef, manifest: ToolManifest, request: RunRequest,
            cancel: threading.Event, runner: Callable, project_dir: Path) -> JobResult:
    """Execute one engine on one artifact. Never raises: every failure is this job's `failed` run."""
    config = request.setup.config(engine)
    options = _options(engine, config)
    started = _now()
    side = artifact.side
    fail = lambda status, code, message, **kw: JobResult(  # noqa: E731
        _failed_run(engine, side, artifact, manifest, request, options, status, code, message, started=started, **kw),
        None)
    if cancel.is_set():
        return fail('cancelled', 'PT-TOOL-CANCEL', 'cancelled before the tool was started')
    scratch: Path | None = None
    reader = None
    try:
        timeout = _timeout(engine, config, request)
        scratch = process.make_scratch(engine, request.scratch_root)
        copy = process.copy_artifact(artifact.path, scratch / 'in' / process.INPUT_NAME, artifact.sha256,
                                     expected_size=artifact.size, cancel=cancel)
        exe = process.verify_executable(Path(manifest.cli_path), manifest.executable_sha256 or '')
        if engine == 'capa':
            capa.prepare(config, scratch, manifest)
            argv = capa.build_argv(config, str(exe), scratch, copy.path)
        elif engine == 'floss':
            argv = floss.build_argv(config, str(exe), copy.path)
        else:
            diec.prepare(config, exe, scratch, manifest)
            argv = diec.build_argv(config, str(exe), scratch, copy.path)
        env = process.tool_env(exe, scratch, extra=_extra_env(engine, config))
        memory = request.memory_limit_bytes if request.memory_limit_bytes is not None else (
            config.effective_memory_limit() if engine == 'floss' else None)
        limits = DEFAULT_LIMITS[engine]
        execution = process.execute(argv, scratch=scratch, env=env, cancel=cancel, timeout=timeout, limits=limits,
                                    runner=runner, memory_limit_bytes=memory)
        common = dict(elapsed=execution.elapsed_ms, returncode=execution.returncode,
                      stderr_digest=execution.digests()[1], stderr_excerpt=process.excerpt(execution.stderr),
                      stdout_digest=execution.digests()[0])
        if execution.spawn_error:
            return fail('failed', 'PT-TOOL-RUN', f'{engine} could not be started ({execution.spawn_error})',
                        **common)
        if execution.reason == 'cancelled' or cancel.is_set():
            return fail('cancelled', 'PT-TOOL-CANCEL', f'{engine} was cancelled', **common)
        if execution.reason == 'timeout':
            return fail('timeout', 'PT-TOOL-TIMEOUT', f'{engine} did not finish within {int(timeout)} s', **common)
        if execution.oversize:
            return fail('failed', 'PT-TOOL-LIMIT', f'{engine} printed more than {limits.stdout_bytes} bytes',
                        **common)
        if execution.returncode != 0:
            status, code, message = _module(engine).classify_exit(
                execution.returncode if execution.returncode is not None else -1, execution.stdout, execution.stderr,
                memory_limit_bytes=memory, peak_memory_bytes=execution.peak_memory_bytes)
            return fail(status, code, message, **common)
        context = dict(run_id=new_run_id(cache_key(artifact.sha256, manifest, options), side, started), side=side,
                       cache_key=cache_key(artifact.sha256, manifest, options),
                       config_digest=config_digest(manifest, options))
        raw = execution.stdout_bytes
        anomalies: tuple[str, ...] = ()
        if engine == 'floss' and not raw.strip():
            evidence = floss.empty_set(floss.ParseContext(
                context['run_id'], side, copy, context['cache_key'], context['config_digest'], None, None, limits,
                config.deobfuscate))
            if config.deobfuscate:
                anomalies = ('emulation-not-run',)
        else:
            if not raw.strip():
                return fail('failed', 'PT-TOOL-OUTPUT', f'{engine} exited normally but printed nothing', **common)
            sidecar = write_raw(project_dir, engine, raw)
            common['raw_sidecar'] = sidecar
            if engine == 'diec':
                evidence = diec.parse(raw, diec.ParseContext(context['run_id'], side, artifact.sha256,
                                                             context['cache_key'], context['config_digest'], limits))
            else:
                reader = VerifiedArtifactReader.open_path(copy.path, copy.sha256)
                pe = PeMap.from_reader(reader)
                if engine == 'capa':
                    evidence = capa.parse(raw, capa.ParseContext(context['run_id'], side, copy, context['cache_key'],
                                                                 context['config_digest'], pe, limits))
                else:
                    evidence = floss.parse(raw, floss.ParseContext(
                        context['run_id'], side, copy, context['cache_key'], context['config_digest'], pe, reader,
                        limits, config.deobfuscate))
        count = evidence.evidence_count()
        run = ToolRun(
            run_id=context['run_id'], engine=engine, side=side, input_artifact_hash=artifact.sha256,
            config_digest=context['config_digest'], cache_key=context['cache_key'], started_at=started,
            status='ok' if count else 'none-found', evidence_count=count, profile=request.profile, options=options,
            manifest=manifest, anomalies=(*evidence.anomalies, *anomalies)[:64], **common)
        return JobResult(run, evidence)
    except ToolError as exc:
        status = {'PT-TOOL-CANCEL': 'cancelled', 'PT-TOOL-UNSUPPORTED': 'unsupported'}.get(exc.code, 'failed')
        return fail(status, exc.code, exc.message)
    except Exception as exc:  # noqa: BLE001 - error isolation: this job fails, the others continue
        return fail('failed', 'PT-TOOL-RUN', f'unexpected {type(exc).__name__} while running {engine}')
    finally:
        if reader is not None:
            reader.close()
        if scratch is not None:
            process.remove_tree(scratch)


def run_tools(request: RunRequest, store: ToolStore, cancel: threading.Event, *, runner: Callable = run_process,
              environ=None, on_result: Callable[[JobResult], None] | None = None) -> list[JobResult]:
    """Run the planned jobs; persist each result on the calling thread as it completes; return them in plan order."""
    engines = plan_engines(request.profile, request.engines)
    if request.max_parallel not in (1, 2):
        raise ToolError('PT-TOOL-INPUT', '--max-parallel must be 1 or 2')
    sides = {a.side: a for a in request.artifacts}
    if set(sides) != {'older', 'newer'} or sides['older'].sha256 == sides['newer'].sha256:
        raise ToolError('PT-TOOL-INPUT', 'a run needs two different artifacts, older and newer')
    order = [(engine, side) for engine in engines for side in ('older', 'newer')]
    results: dict[tuple[str, str], JobResult] = {}

    def finish(job: tuple[str, str], result: JobResult) -> None:
        store.publish_run(result.run)
        if result.evidence is not None and not result.run.cache_hit:
            store.publish_evidence(result.evidence)
        results[job] = result
        if on_result is not None:
            on_result(result)

    manifests = {e: probe_engine(e, request.setup.config(e), cancel, runner, environ) for e in engines}
    pending = []
    for engine, side in order:
        artifact, manifest = sides[side], manifests[engine]
        job = (engine, side)
        started = _now()
        options = _options(engine, request.setup.config(engine)) if request.setup.config(engine) else {}
        if cancel.is_set():
            finish(job, JobResult(_failed_run(engine, side, artifact, manifest, request, options, 'cancelled',
                                              'PT-TOOL-CANCEL', 'cancelled before the tool was started',
                                              started=started), None))
        elif not manifest.supported:
            status, code = _status_for_unavailable(manifest)
            finish(job, JobResult(_failed_run(engine, side, artifact, manifest, request, options, status, code,
                                              manifest.reason or f'{engine} is unavailable', started=started), None))
        else:
            hit = store.find_cached(artifact.sha256, cache_key(artifact.sha256, manifest, options), engine) \
                if request.use_cache else None
            if hit is not None:
                key = cache_key(artifact.sha256, manifest, options)
                count = hit.evidence_count()
                run = ToolRun(run_id=new_run_id(key, side, started), engine=engine, side=side,
                              input_artifact_hash=artifact.sha256, config_digest=config_digest(manifest, options),
                              cache_key=key, started_at=started, elapsed=0, status='ok' if count else 'none-found',
                              evidence_count=count, cache_hit=True, profile=request.profile, options=options,
                              manifest=manifest, anomalies=hit.anomalies)
                finish(job, JobResult(run, hit))
            else:
                pending.append(job)
    if pending:
        with ThreadPoolExecutor(max_workers=request.max_parallel, thread_name_prefix='patchtrace-tool') as pool:
            futures = {pool.submit(run_job, engine, sides[side], manifests[engine], request, cancel, runner,
                                   store.project_dir): (engine, side) for engine, side in pending}
            for future in as_completed(futures):
                finish(futures[future], future.result())
    return [results[job] for job in order]
