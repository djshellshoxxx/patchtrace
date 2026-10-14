"""Parent side of the rule engine: every YARA-X call runs in the hidden worker child (`worker.py`) through
`jobs.run_process` (memory cap, wall clock, process-tree kill, bounded output), never in this process (plan s6). This
module, like everything the GUI and the CLI import, never imports `engine`, `yara_x` or `iced_x86`.

The child is untrusted in what it returns: its result is size-capped, parsed strictly, validated against the contract and
checked against the request before anything is used, and its stderr is a sanitized diagnostic that is never shown as a
message. A scan is one child for the whole target list; callers that need progress or partial results on cancel call
`scan` in batches (each call starts one child: about 0.5 s from source on Linux, most of it importing pydantic and the
contract models; the plan's frozen figure is about 0.2 s).
"""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
import stat
import sys
import tempfile
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from ..jobs import ProcessResult, run_process
from .contracts import (
    CellResult,
    EngineStamp,
    LintResult,
    WorkerLimits,
    WorkerOp,
    WorkerRequest,
    WorkerResult,
    WorkerRule,
    WorkerTarget,
    strict_json,
)
from .errors import RuleError
from .limits import DEFAULT_LIMITS, RuleLimits
from .worker import EXIT_ERROR_DOC, EXIT_MEMORY, EXIT_OK, EXIT_PANIC, EXIT_USAGE

__all__ = ['Probe', 'ScanOutcome', 'engine_installed', 'lint', 'probe', 'scan', 'worker_argv', 'worker_env']

STREAM_LIMIT = 64 * 1024
MAX_SCRATCH_PATH = 200
TIMEOUT_GRACE = 30.0
PROBE_SECONDS = 60
LINT_SECONDS = 120
ENV_ALLOWLIST = ('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'HOME', 'USERPROFILE', 'LANG', 'LC_ALL')
# Allocation-failure signatures the child's runtimes print before dying (Rust aborts with SIGABRT and "memory allocation
# of N bytes failed"; the OS reports ENOMEM). The worker never writes file content to stderr, so these come from runtimes.
_OOM_TEXT = re.compile(r'memory allocation of \d+ bytes failed|MemoryError|Cannot allocate memory|out of memory',
                       re.IGNORECASE)


@dataclass(frozen=True)
class Probe:
    engine: EngineStamp
    modules: tuple[str, ...]


@dataclass(frozen=True)
class ScanOutcome:
    """`cells` is row-major: `cells[i * len(rules) + j]` is target `i` against rule `j`. Every verdict is `unscored`."""
    engine: EngineStamp
    lint: tuple[LintResult, ...]
    cells: tuple[CellResult, ...]


# --- child process ----------------------------------------------------------------------------------------------------

def engine_installed() -> bool:
    """Cheap hint (no import, no process): is a `yara_x` module present. Only `probe` proves the engine works."""
    return importlib.util.find_spec('yara_x') is not None


def worker_argv() -> list[str]:
    """Frozen-aware: the frozen executable dispatches through the CLI verb `rules _rules-worker` (hooked up by the
    integrator); from source the module runs directly, and `-P` keeps the worker's cwd off `sys.path`."""
    if getattr(sys, 'frozen', False):
        return [sys.executable, 'rules', '_rules-worker']
    return [sys.executable, '-P', '-m', 'patchtrace.rules.worker']


def worker_env(environ=None) -> dict[str, str]:
    environ = os.environ if environ is None else environ
    env = {k: v for k, v in environ.items() if k.upper() in ENV_ALLOWLIST}
    env['PYTHONUTF8'] = '1'
    env['PYTHONIOENCODING'] = 'utf-8'
    if not getattr(sys, 'frozen', False):  # the child must import THIS source tree, not another install
        env['PYTHONPATH'] = str(Path(__file__).resolve().parents[2])
    return env


def _remove(work: Path) -> None:
    """Delete the private scratch directory; never raises, so cleanup cannot mask the error that is being reported."""
    def writable(function, path, _error):
        try:
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
            function(path)
        except OSError:
            pass
    try:
        shutil.rmtree(work, onexc=writable)
    except OSError:
        shutil.rmtree(work, ignore_errors=True)


def _tail(text: str, limit: int) -> str:
    """Sanitized stderr tail for a support log: control, format (bidi) and separator characters blanked."""
    return ''.join(ch if ch.isprintable() else ' ' for ch in text[-limit:])


def _out_of_memory(res: ProcessResult, cap: int) -> bool:
    """Exit 22 (the worker caught MemoryError), a runtime's allocation-failure text, or (Windows, where the job limit
    counts committed memory and the failure mode is a measured unknown) a peak commit at the cap."""
    if res.returncode == EXIT_MEMORY or _OOM_TEXT.search(res.stderr_tail or ''):
        return True
    return res.peak_memory_bytes is not None and res.peak_memory_bytes >= 0.9 * cap


def _bad_result() -> RuleError:
    return RuleError('PT-RULE-ENGINE', 'The rule worker wrote an invalid result', reason='worker-bad-result')


def _read_result(path: Path, limits: RuleLimits) -> WorkerResult:
    try:
        with open(path, 'rb') as handle:
            raw = handle.read(limits.result_bytes + 1)
        if len(raw) > limits.result_bytes:
            raise ValueError('result too large')
        text = raw.decode('utf-8')
        strict_json(text)
        return WorkerResult.model_validate_json(text)
    except (OSError, ValueError):  # pydantic's ValidationError is a ValueError
        raise _bad_result() from None


def _failure(res: ProcessResult, result: Path, memory: int, limits: RuleLimits) -> RuleError | None:
    """The typed error for a child that did not finish with an ok or error document, else None."""
    if res.reason == 'timeout':
        return RuleError('PT-RULE-TIMEOUT', 'The rule worker exceeded its time limit', reason='worker-timeout')
    if res.reason == 'output-limit':
        return RuleError('PT-RULE-ENGINE', 'The rule worker wrote more output than allowed', reason='worker-output')
    if res.returncode in (EXIT_OK, EXIT_ERROR_DOC) and result.is_file():
        return None
    if _out_of_memory(res, memory):
        error = RuleError('PT-RULE-LIMIT', 'The rule worker ran out of memory', reason='worker-oom')
    elif res.returncode == EXIT_PANIC:
        error = RuleError('PT-RULE-ENGINE', 'The rule engine stopped with an internal fault', reason='worker-panic')
    elif res.returncode == EXIT_USAGE:
        error = RuleError('PT-RULE-ENGINE', 'The rule worker refused its request', reason='worker-usage')
    else:
        error = RuleError('PT-RULE-ENGINE', f'The rule worker failed (exit {res.returncode & 0xFFFFFFFF:#x})',
                          reason='worker-crash')
    error.diagnostics = _tail(res.stderr_tail or '', limits.stderr_tail_bytes)
    return error


def _check_against_request(doc: WorkerResult, request: WorkerRequest) -> None:
    ok = doc.op == request.op and doc.engine is not None
    if request.op != 'probe':
        ok = ok and [r.name for r in doc.lint] == [r.name for r in request.rules]
    if request.op == 'scan':
        ok = ok and len(doc.cells) == len(request.targets) * len(request.rules)
    if not ok:
        raise _bad_result()


def _run(request: WorkerRequest, work: Path, *, wall_seconds: float, limits: RuleLimits,
         cancel: threading.Event) -> WorkerResult:
    result = Path(request.result)
    argv = [*worker_argv(), '--request', str(work / 'req.json')]
    try:
        (work / 'req.json').write_text(request.model_dump_json(), encoding='utf-8', newline='\n')
        res = run_process(argv, cwd=work, env=worker_env(), cancel=cancel, timeout_seconds=wall_seconds + TIMEOUT_GRACE,
                          memory_limit_bytes=request.limits.memory_bytes, log_limit=STREAM_LIMIT,
                          separate_streams=True, stderr_limit=limits.stderr_tail_bytes, max_output_bytes=STREAM_LIMIT)
    except RuntimeError:  # the contained child did not exit
        raise RuleError('PT-RULE-ENGINE', 'The rule worker could not be stopped', reason='worker-stuck') from None
    except (OSError, ValueError):
        raise RuleError('PT-RULE-ENGINE', 'The rule worker could not be started', reason='spawn-failed') from None
    if cancel.is_set() or res.reason == 'cancelled':
        raise RuleError('PT-RULE-CANCEL', 'Rule work was cancelled', reason='cancelled')
    failure = _failure(res, result, request.limits.memory_bytes, limits)
    if failure is not None:
        raise failure
    doc = _read_result(result, limits)
    if doc.kind == 'error':
        if res.returncode != EXIT_ERROR_DOC:
            raise _bad_result()
        raise RuleError(doc.error.code, doc.error.message, reason=doc.error.reason)
    if res.returncode != EXIT_OK:
        raise _bad_result()
    _check_against_request(doc, request)
    return doc


def _execute(op: WorkerOp, rules: Sequence[WorkerRule], targets: Sequence[WorkerTarget], worker_limits: WorkerLimits,
             *, wall_seconds: float, limits: RuleLimits, cancel: threading.Event | None,
             scratch_dir: Path | None) -> WorkerResult:
    cancel = cancel or threading.Event()
    if cancel.is_set():
        raise RuleError('PT-RULE-CANCEL', 'Rule work was cancelled', reason='cancelled')
    try:
        work = Path(tempfile.mkdtemp(prefix='patchtrace-rules-', dir=scratch_dir))  # 0o700 on POSIX
    except OSError:
        raise RuleError('PT-RULE-ENGINE', 'A private scratch folder could not be created',
                        reason='scratch-failed') from None
    try:
        if len(str(work / 'out.json')) > MAX_SCRATCH_PATH:  # Windows MAX_PATH leaves the worker no margin beyond this
            raise RuleError('PT-RULE-INPUT', 'The scratch folder path is too long; choose a shorter location',
                            reason='scratch-path')
        try:
            request = WorkerRequest(op=op, rules=tuple(rules), targets=tuple(targets), limits=worker_limits,
                                    result=str(work / 'out.json'))
        except ValidationError:
            raise RuleError('PT-RULE-INPUT', 'The rule request is not valid', reason='request-invalid') from None
        return _run(request, work, wall_seconds=wall_seconds, limits=limits, cancel=cancel)
    finally:
        _remove(work)


def _worker_limits(limits: RuleLimits, timeout_s: int | None = None) -> WorkerLimits:
    timeout = limits.target_timeout_s if timeout_s is None else timeout_s
    if not limits.target_timeout_min_s <= timeout <= limits.target_timeout_max_s:
        raise RuleError('PT-RULE-INPUT', f'The per-file timeout must be {limits.target_timeout_min_s} to '
                        f'{limits.target_timeout_max_s} seconds', reason='timeout-range')
    try:
        return WorkerLimits(memory_bytes=limits.worker_memory_bytes, file_bytes=limits.file_bytes,
                            target_timeout_s=timeout, max_matches_per_pattern=limits.max_matches_per_pattern,
                            offsets_per_cell=limits.offsets_per_cell, patterns_per_rule=limits.patterns_per_rule,
                            diagnostics_per_rule=limits.diagnostics_per_rule)
    except ValidationError:
        raise RuleError('PT-RULE-INPUT', 'The limits are outside what the worker contract allows',
                        reason='limits-invalid') from None


def _check_request(rules: Sequence[WorkerRule], targets: Sequence[WorkerTarget], limits: RuleLimits) -> None:
    if not rules or not targets:
        raise RuleError('PT-RULE-INPUT', 'A scan needs at least one rule and one file', reason='empty-request')
    if not all(os.path.isabs(t.path) for t in targets):  # the child's cwd is its private folder, not the caller's
        raise RuleError('PT-RULE-INPUT', 'File paths must be absolute', reason='relative-path')
    if len(rules) > limits.rules_per_run:
        raise RuleError('PT-RULE-LIMIT', f'More than {limits.rules_per_run} rules in one run', reason='rules')
    if len(targets) > limits.targets_per_run:  # with the rule cap this also bounds the cells (RuleLimits checks that)
        raise RuleError('PT-RULE-LIMIT', f'More than {limits.targets_per_run} files in one run', reason='targets')
    if sum(t.size for t in targets) > limits.run_bytes:
        raise RuleError('PT-RULE-LIMIT', f'More than {limits.run_bytes} bytes of files in one run', reason='run-bytes')


# --- public operations --------------------------------------------------------------------------------------------------

def probe(*, cancel: threading.Event | None = None, limits: RuleLimits = DEFAULT_LIMITS,
          scratch_dir: Path | None = None) -> Probe:
    """Start the worker and ask the engine for its stamp and modules. Every failure other than cancel is
    `PT-RULE-UNAVAILABLE` (blocked state R1: the engine, or its JIT, is not usable here)."""
    try:
        doc = _execute('probe', (), (), _worker_limits(limits), wall_seconds=min(PROBE_SECONDS, limits.run_wall_s),
                       limits=limits, cancel=cancel, scratch_dir=scratch_dir)
    except RuleError as error:
        if error.code in ('PT-RULE-CANCEL', 'PT-RULE-UNAVAILABLE', 'PT-RULE-INPUT'):
            raise
        raise RuleError('PT-RULE-UNAVAILABLE', 'The rule engine (YARA-X) did not start in this installation',
                        reason=error.reason, diagnostics=error.diagnostics) from None
    return Probe(doc.engine, doc.modules)


def lint(rules: Sequence[WorkerRule], *, cancel: threading.Event | None = None, limits: RuleLimits = DEFAULT_LIMITS,
         scratch_dir: Path | None = None) -> tuple[LintResult, ...]:
    """Compile each rule text with the PatchTrace linters in the worker; one result per rule, request order."""
    if not rules:
        raise RuleError('PT-RULE-INPUT', 'Linting needs at least one rule', reason='empty-request')
    if len(rules) > limits.rules_per_run:
        raise RuleError('PT-RULE-LIMIT', f'More than {limits.rules_per_run} rules in one run', reason='rules')
    doc = _execute('lint', rules, (), _worker_limits(limits), wall_seconds=min(LINT_SECONDS, limits.run_wall_s),
                   limits=limits, cancel=cancel, scratch_dir=scratch_dir)
    return doc.lint


def scan(rules: Sequence[WorkerRule], targets: Sequence[WorkerTarget], *, timeout_s: int | None = None,
         cancel: threading.Event | None = None, limits: RuleLimits = DEFAULT_LIMITS,
         scratch_dir: Path | None = None) -> ScanOutcome:
    """Scan every target against every rule in one worker. A target that cannot be scanned (unreadable, too large,
    changed, not a PE image) yields `not-scanned` cells; a per-file timeout yields `timeout` cells; neither is a miss."""
    worker_limits = _worker_limits(limits, timeout_s)
    _check_request(rules, targets, limits)
    wall = min(limits.run_wall_s, 30 + len(targets) * worker_limits.target_timeout_s)
    doc = _execute('scan', rules, targets, worker_limits, wall_seconds=wall, limits=limits, cancel=cancel,
                   scratch_dir=scratch_dir)
    return ScanOutcome(doc.engine, doc.lint, doc.cells)
