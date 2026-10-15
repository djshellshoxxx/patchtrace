"""Qt-free orchestration of one strings run (WB3 s8): FLOSS through the tools runner, or the built-in scan.

`run_strings` is a pure worker function over an immutable `StringsRunRequest`: it never touches the project store
(SQLite and the project lock belong to the GUI thread). It returns the tables plus the finished `JobResult`s;
the GUI thread calls `persist` after its stale check. FLOSS emulation needs the consent hash in the `FlossConfig`;
the runner records it in the run options and the table basis carries it. The target is never executed here.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ..intelligence.tools import runner
from ..intelligence.tools.common import ToolError
from ..intelligence.tools.floss import FlossConfig
from ..intelligence.tools.store import ToolStore
from ..jobs import run_process
from .cli import _artifacts, _inspect, table_from_source
from .contracts import StringsError
from .scan import BuiltinScanSource, ScanError
from .sources import FlossEvidenceSource
from .table import StringTable

State = Literal['ready', 'cancelled', 'failed', 'stale']
OK_STATUSES = ('ok', 'none-found')


@dataclass(frozen=True)
class StringsRunRequest:
    artifacts: tuple[runner.ArtifactRef, ...]
    project_dir: Path
    project_id: str
    revision: int
    floss: FlossConfig | None = None   # None: the built-in scan, labelled "Built-in scan" (never "FLOSS")
    min_length: int = 4
    timeout: int | None = None


def make_request(service, **kw) -> StringsRunRequest:
    """GUI thread: snapshot the open project (needs an older and a newer artifact)."""
    found = _artifacts(service)
    refs = tuple(runner.ArtifactRef(side, service.root / a.relative_path, a.sha256, a.size)
                 for side, a in sorted(found.items()))
    return StringsRunRequest(refs, service.root, service.project.id, service.project.revision, **kw)


@dataclass(frozen=True)
class SideTable:
    side: str
    source: Literal['floss', 'builtin-scan']
    table: StringTable
    run_id: str | None = None
    consent_sha256: str | None = None


@dataclass(frozen=True)
class StringsRunOutcome:
    state: State
    sides: tuple[SideTable, ...] = ()
    code: str = ''
    message: str = ''
    jobs: tuple[runner.JobResult, ...] = ()   # finished tool runs, persisted by the GUI thread


def _outcome(state: State, code: str = '', message: str = '', jobs=()) -> StringsRunOutcome:
    return StringsRunOutcome(state, (), code, message[:300], tuple(jobs))


def is_stale(request: StringsRunRequest, project_id: str, revision: int) -> bool:
    return (project_id, revision) != (request.project_id, request.revision)


def persist(outcome: StringsRunOutcome, store: ToolStore) -> None:
    """GUI thread only: publish every finished run, and the evidence of the successful ones."""
    for job in outcome.jobs:
        store.publish_run(job.run)
        if job.evidence is not None:
            store.publish_evidence(job.evidence)


def _builtin(request: StringsRunRequest, cancel: threading.Event) -> tuple[SideTable, ...]:
    out = []
    for ref in request.artifacts:
        pe = _inspect(ref.path, ref.sha256).pe
        source = BuiltinScanSource(
            ref.path, artifact_sha256=ref.sha256, side=ref.side, min_length=request.min_length,
            cancel=cancel.is_set, offset_to_rva=(lambda off, pe=pe: pe.offset_to_rva(off)[0]) if pe else None)
        out.append(SideTable(ref.side, 'builtin-scan', table_from_source(source.load())))
    return tuple(out)


def _floss_side(result: runner.JobResult) -> SideTable:
    run = result.run
    raw_sha = run.raw_sidecar.rsplit('-', 1)[-1].removesuffix('.json') if run.raw_sidecar else None
    consent = run.options.get('emulation_consent_sha256')
    source = FlossEvidenceSource(result.evidence, executable_sha256=run.manifest.executable_sha256,
                                 source_version=run.manifest.version, consent_sha256=consent, raw_sha256=raw_sha)
    return SideTable(run.side, 'floss', table_from_source(source.load()), run.run_id, consent)


def _floss(request: StringsRunRequest, cancel: threading.Event, runner_fn: Callable, environ) -> StringsRunOutcome:
    setup = runner.Setup(floss=request.floss)
    run_request = runner.RunRequest(request.artifacts, setup, profile='context', engines=('floss',),
                                    timeout=request.timeout)
    manifest = runner.probe_engine('floss', request.floss, cancel, runner_fn, environ)
    if cancel.is_set():
        return _outcome('cancelled', 'PT-STR-CANCEL', 'Extraction cancelled. Earlier results are unchanged.')
    if not manifest.supported:
        return _outcome('failed', runner._status_for_unavailable(manifest)[1],
                        manifest.reason or 'FLOSS is unavailable')
    jobs = [runner.run_job('floss', ref, manifest, run_request, cancel, runner_fn, request.project_dir)
            for ref in request.artifacts]
    if cancel.is_set() or any(j.run.status == 'cancelled' for j in jobs):
        return _outcome('cancelled', 'PT-STR-CANCEL', 'Extraction cancelled. Earlier results are unchanged.', jobs)
    bad = next((j.run for j in jobs if j.run.status not in OK_STATUSES or j.evidence is None), None)
    if bad is not None:
        return _outcome('failed', bad.error_code or 'PT-STR-SOURCE', bad.error or f'FLOSS {bad.status}', jobs)
    return StringsRunOutcome('ready', tuple(_floss_side(j) for j in jobs), jobs=tuple(jobs))


def run_strings(request: StringsRunRequest, cancel: threading.Event, *, runner_fn: Callable = run_process,
                environ=None) -> StringsRunOutcome:
    """Never raises: every failure is a typed outcome."""
    if {a.side for a in request.artifacts} != {'older', 'newer'}:
        return _outcome('failed', 'PT-STR-INPUT', 'The project needs an older and a newer artifact.')
    try:
        if request.floss is None:
            return StringsRunOutcome('ready', _builtin(request, cancel))
        return _floss(request, cancel, runner_fn, environ)
    except ScanError as exc:
        return _outcome('cancelled' if exc.code == 'PT-STR-CANCEL' else 'failed', exc.code,
                        str(exc).split(': ', 1)[-1])
    except StringsError as exc:
        return _outcome('failed', exc.code, exc.message)
    except ToolError as exc:
        return _outcome('cancelled' if exc.code == 'PT-TOOL-CANCEL' else 'failed', exc.code, exc.message)
    except Exception as exc:  # noqa: BLE001 - class name only; messages may carry local paths
        return _outcome('failed', 'PT-STR-SOURCE', f'String extraction stopped unexpectedly ({type(exc).__name__}).')
