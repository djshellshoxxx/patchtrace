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
from . import rzdiff
from .contracts import Capability, SecondaryError, SecondaryMatchSet
from .runs import EngineId

DISPLAY_ORDER: tuple[EngineId, ...] = ('rz-diff', 'bindiff', 'ghidriff-baseline')
BINDIFF_UNSUPPORTED = 'PT-SECONDARY-UNSUPPORTED: BinDiff execution not implemented (C4)'


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


class BinDiffAdapter:
    """Execution is C4; importing a user-supplied .BinDiff stays in `secondary import-bindiff`."""
    id: EngineId = 'bindiff'

    def probe(self, job_env: Mapping[str, str], cancel: threading.Event) -> Capability:
        return _unsupported('bindiff', '', BINDIFF_UNSUPPORTED)

    def argv(self, cap: Capability, job: EngineJob) -> tuple[str, ...]:
        raise SecondaryError('PT-SECONDARY-UNSUPPORTED', BINDIFF_UNSUPPORTED)

    def run(self, cap: Capability, job: EngineJob) -> RawResult:
        raise SecondaryError('PT-SECONDARY-UNSUPPORTED', BINDIFF_UNSUPPORTED)

    def parse(self, raw: RawResult, cap: Capability, job: EngineJob) -> SecondaryMatchSet:
        from .bindiff import import_bindiff
        if raw.file_path is None:
            raise SecondaryError('PT-SECONDARY-INPUT', 'no BinDiff file to import')
        return import_bindiff(raw.file_path, job.older_sha256, job.newer_sha256)


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


def build_registry(*, rz_diff: str = 'rz-diff', ghidriff_raw_sha256: str | None = None
                   ) -> Mapping[EngineId, EngineAdapter]:
    return MappingProxyType({'rz-diff': RzDiffAdapter(rz_diff), 'bindiff': BinDiffAdapter(),
                             'ghidriff-baseline': GhidriffBaselineAdapter(ghidriff_raw_sha256)})


REGISTRY: Mapping[EngineId, EngineAdapter] = build_registry()
