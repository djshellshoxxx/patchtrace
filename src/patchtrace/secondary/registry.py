"""Engine adapters and the immutable registry (SPEC-28 §4.2). No Qt; spawns only via `EngineJob.runner`."""
from __future__ import annotations

import shutil
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Protocol

from ..jobs import run_process
from . import bindiff_probe, bindiff_run, rzdiff
from .bindiff_inputs import AcceptedBinExportLike, BoundPair, bind_pair
from .contracts import Capability, SecondaryError, SecondaryMatchSet
from .runs import EngineId

DISPLAY_ORDER: tuple[EngineId, ...] = ('rz-diff', 'bindiff', 'ghidriff-baseline')
BINDIFF_UNSUPPORTED = 'PT-SECONDARY-UNSUPPORTED: ' + bindiff_probe.MESSAGES['not-configured']


@dataclass(frozen=True)
class EngineJob:
    older: Path
    newer: Path
    older_sha256: str
    newer_sha256: str
    env: Mapping[str, str]
    workdir: Path
    cancel: threading.Event
    deadline_seconds: float
    runner: Callable = run_process
    stdout_limit: int = rzdiff.STDOUT_LIMIT


@dataclass(frozen=True)
class RawResult:
    returncode: int
    stdout: bytes | None
    stderr_tail: str
    file_path: Path | None
    reason: str | None


class EngineAdapter(Protocol):
    id: EngineId

    def probe(self, job_env: Mapping[str, str], cancel: threading.Event) -> Capability: ...

    def argv(self, cap: Capability, job: EngineJob) -> tuple[str, ...]: ...

    def run(self, cap: Capability, job: EngineJob) -> RawResult: ...

    def parse(self, raw: RawResult, cap: Capability, job: EngineJob) -> SecondaryMatchSet | None: ...


def _unsupported(engine, path: str, reason: str) -> Capability:
    return Capability(engine=engine, supported=False, version=None, path=path, supports_json=False, reason=reason)


class RzDiffAdapter:
    id: EngineId = 'rz-diff'

    def __init__(self, executable: str = 'rz-diff'):
        self.executable = executable

    def probe(self, job_env: Mapping[str, str], cancel: threading.Event) -> Capability:
        found = shutil.which(self.executable, path=job_env.get('PATH')) or self.executable
        if not Path(found).is_absolute():
            return _unsupported('rz-diff', found, f'rz-diff executable {self.executable!r} not found')
        return rzdiff.probe(Path(found), job_env, cancel)

    def argv(self, cap: Capability, job: EngineJob) -> tuple[str, ...]:
        return rzdiff.rzdiff_argv(cap.path, job.older, job.newer)

    def run(self, cap: Capability, job: EngineJob) -> RawResult:
        result = job.runner(list(self.argv(cap, job)), cwd=job.workdir, env=job.env, cancel=job.cancel,
                            timeout_seconds=job.deadline_seconds, log_limit=job.stdout_limit + 1,
                            separate_streams=True, stderr_limit=rzdiff.STDERR_TAIL)
        return RawResult(result.returncode, result.log_tail.encode('utf-8'), result.stderr_tail, None,
                         result.reason)

    def parse(self, raw: RawResult, cap: Capability, job: EngineJob) -> SecondaryMatchSet:
        if raw.returncode != 0:  # stderr is kept in the EngineRun, never echoed into the message
            raise SecondaryError('PT-SECONDARY-RUN', f'rz-diff exited with {raw.returncode}')
        return rzdiff.interpret(raw.returncode, (raw.stdout or b'').decode('utf-8', errors='replace'),
                                raw.stderr_tail, cap.version or '', job.older_sha256, job.newer_sha256,
                                job.stdout_limit)


Acceptor = Callable[..., AcceptedBinExportLike]
"""(path, *, artifact_sha256, role, accept_unbound, cancel, other_sha256) -> accepted snapshot; raises
SecondaryError.
Wraps C3 `accept_binexport`; injected so C4 never imports C3 modules in tested code paths."""


class BinDiffAdapter:
    """SPEC-29 BinDiff execution behind the SPEC-28 adapter shape. Reports `unsupported` until the probe
    passes and both `.BinExport` inputs are supplied. Instances are built per invocation (they hold the
    bound pair and provenance of one run); importing a user `.BinDiff` stays in `secondary import-bindiff`."""
    id: EngineId = 'bindiff'

    def __init__(self, executable: str | Path | None = None, *, older: Path | AcceptedBinExportLike | None = None,
                 newer: Path | AcceptedBinExportLike | None = None, raw_dir: Path | None = None,
                 accept_unbound: bool = False, acceptor: Acceptor | None = None,
                 output_limit: int = bindiff_run.OUTPUT_LIMIT, probe_runner: Callable = run_process):
        self.executable = executable
        self.older, self.newer = older, newer
        self.raw_dir = raw_dir
        self.accept_unbound = accept_unbound
        self.acceptor = acceptor
        self.output_limit = output_limit
        self.probe_runner = probe_runner
        self._report: bindiff_probe.ProbeReport | None = None
        self._pair: BoundPair | None = None
        self._raw: bindiff_run.BindiffRaw | None = None
        self._notes: dict[str, str] = {}

    def probe(self, job_env: Mapping[str, str], cancel: threading.Event) -> Capability:
        if self.executable is None:  # nothing configured: never discovered via PATH
            self._report = bindiff_probe.ProbeReport(_unsupported('bindiff', '', BINDIFF_UNSUPPORTED),
                                                     'not-configured')
            return self._report.capability
        self._report = bindiff_probe.probe_report(self.executable, cancel=cancel, runner=self.probe_runner)
        cap = self._report.capability
        if cap.supported and (self.older is None or self.newer is None or self.raw_dir is None):
            self._report = bindiff_probe.ProbeReport(_unsupported(
                'bindiff', cap.path, 'No .BinExport inputs were supplied (--older-binexport/--newer-binexport).'),
                'binexport-missing', self._report.major)
        return self._report.capability

    def _accept(self, item, role: str, artifact_sha256: str, other_sha256: str,
                cancel: threading.Event) -> AcceptedBinExportLike:
        if not isinstance(item, Path | str):
            return item
        if self.acceptor is None:
            raise SecondaryError('PT-SECONDARY-UNSUPPORTED', 'BinExport validation is unavailable in this build.',
                                 kind='binexport-unsupported')
        return self.acceptor(Path(item), artifact_sha256=artifact_sha256, role=role,
                             accept_unbound=self.accept_unbound, cancel=cancel, other_sha256=other_sha256)

    def bound(self, job: EngineJob) -> BoundPair:
        if self._pair is None:
            older = self._accept(self.older, 'older', job.older_sha256, job.newer_sha256, job.cancel)
            newer = self._accept(self.newer, 'newer', job.newer_sha256, job.older_sha256, job.cancel)
            self._pair = bind_pair(older, newer, job.older_sha256, job.newer_sha256,
                                   accept_unbound=self.accept_unbound)
        return self._pair

    def argv(self, cap: Capability, job: EngineJob) -> tuple[str, ...]:
        if not cap.supported:
            raise SecondaryError('PT-SECONDARY-UNSUPPORTED', cap.reason or BINDIFF_UNSUPPORTED)
        self.bound(job)  # pairing/orientation are refused here, before any spawn or cache lookup
        return bindiff_run.argv_template(cap.path)

    def cache_extra(self, cap: Capability, job: EngineJob) -> tuple[str, str]:
        pair = self.bound(job)
        return pair.older.file_sha256, pair.newer.file_sha256

    def run(self, cap: Capability, job: EngineJob) -> RawResult:
        if not cap.supported:
            raise SecondaryError('PT-SECONDARY-UNSUPPORTED', cap.reason or BINDIFF_UNSUPPORTED)
        if self.raw_dir is None:
            raise SecondaryError('PT-SECONDARY-UNSUPPORTED', 'No project raw folder was configured for BinDiff.',
                                 kind='not-configured')
        self._raw = bindiff_run.execute(cap, self.bound(job), self.raw_dir, cancel=job.cancel,
                                        timeout_seconds=job.deadline_seconds, runner=job.runner,
                                        parent_dir=job.workdir, output_limit=self.output_limit)
        raw = self._raw
        return RawResult(raw.returncode, raw.stdout.encode('utf-8'), raw.stderr_tail, raw.kept_path, raw.reason)

    def parse(self, raw: RawResult, cap: Capability, job: EngineJob) -> SecondaryMatchSet:
        if raw.file_path is None:
            raise SecondaryError('PT-SECONDARY-INPUT', 'no BinDiff file to import')
        if self._raw is None or self._raw.output_sha256 is None:  # a plain RawResult (re-import path)
            from .bindiff import import_bindiff
            return import_bindiff(raw.file_path, job.older_sha256, job.newer_sha256)
        match_set = bindiff_run.import_output(raw.file_path, self._raw.output_sha256, self.bound(job),
                                              job.older_sha256, job.newer_sha256, self._raw.summary)
        if not bindiff_run.version_consistent(match_set, cap):
            self._notes['version_warning'] = 'database version differs from the probed major version'
        return match_set

    def provenance(self) -> dict[str, str]:
        """Bounded `EngineRun.provenance` (SPEC-29 §5); the scheduler adds `failure_kind` from the error."""
        data: dict[str, str] = {}
        if self._report is not None:
            if self._report.kind:
                data['failure_kind'] = self._report.kind
            if self._report.untested_version:
                data['untested_version'] = 'true'
        if self._pair is not None:
            data.update(self._pair.provenance())
            data['config_sha256'] = bindiff_run.CONFIG_SHA256
        if self._raw is not None and self._raw.summary:
            data['bindiff_summary'] = ';'.join(f'{k}={v}' for k, v in sorted(self._raw.summary.items()))[:256]
        data.update(self._notes)
        return data


class GhidriffBaselineAdapter:
    """Provenance only: adapts an already stored primary run; it never spawns Ghidriff."""
    id: EngineId = 'ghidriff-baseline'

    def __init__(self, raw_sha256: str | None = None):
        self.raw_sha256 = raw_sha256

    def probe(self, job_env: Mapping[str, str], cancel: threading.Event) -> Capability:
        if self.raw_sha256 is None:
            return _unsupported('ghidriff-baseline', '', 'PT-SECONDARY-UNSUPPORTED: no completed primary run')
        return Capability(engine='ghidriff-baseline', supported=True, version='stored', path='',
                          supports_json=False)

    def argv(self, cap: Capability, job: EngineJob) -> tuple[str, ...]:
        return ('ghidriff-baseline',)

    def run(self, cap: Capability, job: EngineJob) -> RawResult:
        return RawResult(0, (self.raw_sha256 or '').encode('ascii'), '', None, None)

    def parse(self, raw: RawResult, cap: Capability, job: EngineJob) -> None:
        return None  # Ghidriff matches are primary records, not a SecondaryMatchSet.


def build_registry(*, rz_diff: str = 'rz-diff', ghidriff_raw_sha256: str | None = None,
                   bindiff: BinDiffAdapter | None = None) -> Mapping[EngineId, EngineAdapter]:
    return MappingProxyType({'rz-diff': RzDiffAdapter(rz_diff), 'bindiff': bindiff or BinDiffAdapter(),
                             'ghidriff-baseline': GhidriffBaselineAdapter(ghidriff_raw_sha256)})


REGISTRY: Mapping[EngineId, EngineAdapter] = build_registry()
