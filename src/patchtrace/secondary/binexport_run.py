"""Parent side of BinExport acceptance: isolate inspection in a capped worker (SPEC-10b §6.1).

`accept_binexport` / `AcceptedBinExport` are a FROZEN seam consumed by BinDiff execution (C4). C4 must run
BinDiff on `snapshot_path` only: that is the exact byte sequence that was validated (T8).
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import sys
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, get_args

from ..jobs import run_process
from .binexport_identity import PeLayout, accept_pair
from .binexport_limits import HARD_MEMORY_MAX, BinExportLimits, err, near_cap
from .binexport_models import BinExportSummary, PeLayoutModel, WorkerRequest, WorkerResult
from .binexport_proto import ProtoUnavailable, load_binexport2_class
from .contracts import ErrorCode, SecondaryError

__all__ = ['AcceptedBinExport', 'BinExportSummary', 'accept_binexport', 'accept_pair', 'worker_argv']

STREAM_LIMIT = 64 * 1024
DIAGNOSTIC_CHARS = 4000
TIMEOUT_GRACE = 30.0
ENV_ALLOWLIST = ('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'HOME', 'USERPROFILE', 'LANG', 'LC_ALL')
_CODES = frozenset(get_args(ErrorCode))


@dataclass(frozen=True, slots=True)
class AcceptedBinExport:
    snapshot_path: Path  # read-only copy in the caller's private dir; C4 must use THIS path
    summary: BinExportSummary


def worker_argv() -> list[str]:
    """Frozen-aware: the frozen exe dispatches through the CLI; `python -m` is unusable frozen."""
    if getattr(sys, 'frozen', False):
        return [sys.executable]
    return [sys.executable, '-P', '-m', 'patchtrace']  # -P: never import from the worker's cwd


def worker_env(environ=None) -> dict[str, str]:
    environ = os.environ if environ is None else environ
    env = {k: v for k, v in environ.items() if k.upper() in ENV_ALLOWLIST}
    env['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'upb'  # pure-Python fallback refused (T4)
    env['PYTHONUTF8'] = '1'
    env['PYTHONIOENCODING'] = 'utf-8'
    if not getattr(sys, 'frozen', False):  # the child must import THIS source tree, not another install
        env['PYTHONPATH'] = str(Path(__file__).resolve().parents[2])
    return env


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        while chunk := handle.read(1 << 22):
            digest.update(chunk)
    return digest.hexdigest()


def _tail(text: str) -> str:
    """Sanitised stderr tail for diagnostics: control, format (bidi) and separator characters blanked."""
    return ''.join(ch if ch.isprintable() else ' ' for ch in text[-DIAGNOSTIC_CHARS:])


def _remove(work: Path) -> None:
    for p in work.rglob('*'):
        try:
            p.chmod(0o600)
        except OSError:
            pass
    shutil.rmtree(work, ignore_errors=True)


# Allocation-failure signatures the worker's runtimes print before dying (measured on Linux under RLIMIT_AS:
# pydantic-core/Rust aborts with SIGABRT and 'memory allocation of N bytes failed'). The worker never writes file
# content to stderr, so these come from the runtimes, not from the input.
_OOM_TEXT = re.compile(r'memory allocation of \d+ bytes failed|MemoryError|Arena alloc failed|out of memory',
                       re.IGNORECASE)


def _out_of_memory(res, memory: int) -> bool:
    """Exit 22 = MemoryError caught by the worker; a runtime's own allocation-failure text; or (Windows) the Job
    Object's peak commit >= 0.9 x cap. What a Windows child sees at the limit is measured on the runner (U7)."""
    if res.returncode == 22 or _OOM_TEXT.search(res.stderr_tail or ''):
        return True
    return res.peak_memory_bytes is not None and near_cap(memory, res.peak_memory_bytes)


def accept_binexport(path: Path, *, artifact_sha256: str, role: Literal['older', 'newer'],
                     private_dir: Path, limits: BinExportLimits = BinExportLimits(),  # noqa: B008 - frozen
                     cancel: threading.Event, pe_layout: PeLayout | None = None,
                     accept_unbound: bool = False) -> AcceptedBinExport:
    """Validate an untrusted `.BinExport` in a capped worker; raises SecondaryError (§7)."""
    if not re.fullmatch(r'[0-9a-f]{64}', artifact_sha256 or ''):
        raise ValueError('artifact_sha256 must be 64 lowercase hex')
    if role not in ('older', 'newer'):
        raise ValueError("role must be 'older' or 'newer'")
    if cancel.is_set():
        raise err('PT-SECONDARY-CANCEL', 'cancelled')
    try:
        size_hint = os.stat(path).st_size
    except OSError:
        size_hint = 0  # the worker reports `unreadable` with the open handle's error
    if size_hint > limits.max_file_bytes:
        raise err('PT-SECONDARY-LIMIT', 'too_large', f'BinExport file exceeds {limits.max_file_bytes} bytes')
    memory = limits.memory_required(size_hint)
    if memory > HARD_MEMORY_MAX:
        raise err('PT-SECONDARY-LIMIT', 'memory_cap', f'BinExport inspection would need more than {HARD_MEMORY_MAX}'
                  ' bytes of memory')
    try:
        load_binexport2_class()  # quick UNSUPPORTED in the parent; the worker re-checks its own interpreter
    except ProtoUnavailable as exc:
        raise err('PT-SECONDARY-UNSUPPORTED', exc.reason, f'BinExport support unavailable: {exc.reason}') from None
    private_dir = Path(private_dir)
    work = private_dir / f'binexport-{uuid.uuid4().hex}'
    work.mkdir(mode=0o700)
    snapshot, result = work / 'in.BinExport', work / 'out.json'
    try:
        worker_limits = limits.to_json() | {'memory_bytes': memory}
        request = WorkerRequest(src=str(Path(path).absolute()), snapshot=str(snapshot), result=str(result),
                                artifact_sha256=artifact_sha256, role=role, limits=worker_limits,
                                pe_layout=PeLayoutModel(image_base=pe_layout.image_base,
                                                        size_of_image=pe_layout.size_of_image,
                                                        machine=pe_layout.machine) if pe_layout else None,
                                accept_unbound=accept_unbound)
        (work / 'req.json').write_text(request.model_dump_json(), encoding='utf-8')
        argv = [*worker_argv(), 'secondary', '_binexport-worker', '--request', str(work / 'req.json')]
        res = run_process(argv, cwd=work, env=worker_env(), cancel=cancel,
                          timeout_seconds=limits.wall_seconds + TIMEOUT_GRACE, memory_limit_bytes=memory,
                          log_limit=STREAM_LIMIT, separate_streams=True, stderr_limit=STREAM_LIMIT)
        if cancel.is_set() or res.reason == 'cancelled':
            raise err('PT-SECONDARY-CANCEL', 'cancelled')
        if res.reason == 'timeout':
            raise err('PT-SECONDARY-RUN', 'worker_timeout', 'BinExport worker exceeded its time limit')
        if res.returncode not in (0, 20) or not result.is_file():
            reason = 'worker_oom' if _out_of_memory(res, memory) else 'worker_crash'
            error = err('PT-SECONDARY-RUN', reason, f'BinExport worker failed (exit {res.returncode})')
            error.diagnostics = _tail(res.stderr_tail)  # diagnostics only, never the message (T6)
            raise error
        doc = _read_result(result, limits)
        if doc.kind == 'error':
            e = doc.error
            raise SecondaryError(e.code, e.message, reason=e.reason)  # type: ignore[arg-type]
        summary = doc.summary
        if res.returncode != 0 or summary is None or summary.role != role or not snapshot.is_file() \
                or summary.file_size != snapshot.stat().st_size or summary.file_sha256 != _sha256(snapshot):
            raise err('PT-SECONDARY-RUN', 'worker_bad_result', 'BinExport worker result does not match its snapshot')
        for leftover in (work / 'req.json', result):
            leftover.unlink(missing_ok=True)
        snapshot.chmod(0o400)
        return AcceptedBinExport(snapshot, summary)
    except BaseException:
        _remove(work)  # no partial state; the user's original file is never touched
        raise


def _read_result(result: Path, limits: BinExportLimits) -> WorkerResult:
    from ..persistence import strict_json
    try:
        if result.stat().st_size > limits.max_summary_bytes:
            raise ValueError('result too large')
        text = result.read_bytes().decode('utf-8')
        strict_json(text)  # duplicate keys, NaN/Infinity, lone surrogates
        doc = WorkerResult.model_validate_json(text)
    except (OSError, ValueError):
        raise err('PT-SECONDARY-RUN', 'worker_bad_result', 'BinExport worker wrote an invalid result') from None
    if doc.kind == 'error' and doc.error is not None and doc.error.code not in _CODES:
        raise err('PT-SECONDARY-RUN', 'worker_bad_result', 'BinExport worker wrote an unknown error code')
    return doc
