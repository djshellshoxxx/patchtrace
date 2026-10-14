"""Parent side of the rule engine: run every YARA-X call in a capped worker child (plan s6, s7).

This module never imports `yara_x` or `engine`: the `.pyd` loads in the child only. The child is started with
`jobs.run_process` (Job Object / process group kill, memory cap, wall deadline, bounded output), an allow-listed
environment and a private working directory. Cancel is cooperative on the caller's `threading.Event`.
"""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
import sys
import threading
import uuid
from collections.abc import Callable, Sequence
from pathlib import Path

from ..jobs import ProcessResult, run_process
from ..persistence import strict_json
from .contracts import (
    CellResult,
    EngineStamp,
    LintFinding,
    RuleText,
    WorkerOp,
    WorkerRequest,
    WorkerResult,
    WorkerTarget,
)
from .errors import RulesError
from .limits import LIMITS, RuleLimits

ENV_ALLOWLIST = ('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'HOME', 'USERPROFILE', 'LANG', 'LC_ALL')
MAX_RESULT_BYTES = 64 * 1024 * 1024
MAX_STDOUT_BYTES = 1024 * 1024
SHORT_OP_SECONDS = 60
EXIT_OK, EXIT_ERROR_DOC, EXIT_MEMORY, EXIT_PANIC = 0, 20, 22, 23
# Allocation-failure text the engine's runtimes print before dying under the memory cap.
_OOM_TEXT = re.compile(r'memory allocation of \d+ bytes failed|MemoryError|out of memory|Arena alloc failed',
                       re.IGNORECASE)
ArgvFactory = Callable[[Path], list[str]]


def engine_installed() -> bool:
    """True when the `yara_x` wheel can be found, without importing it (the parent must not load the `.pyd`)."""
    return importlib.util.find_spec('yara_x') is not None


def worker_argv(request: Path) -> list[str]:
    """Frozen-aware: the frozen exe dispatches through the CLI verb; `python -m` is unusable frozen."""
    if getattr(sys, 'frozen', False):
        return [sys.executable, 'rules', '_worker', '--request', str(request)]
    return [sys.executable, '-P', '-m', 'patchtrace.yarax.worker', '--request', str(request)]  # -P: no cwd imports


def worker_env(environ=None) -> dict[str, str]:
    environ = os.environ if environ is None else environ
    env = {k: v for k, v in environ.items() if k.upper() in ENV_ALLOWLIST}
    env['PYTHONUTF8'] = '1'
    env['PYTHONIOENCODING'] = 'utf-8'
    if not getattr(sys, 'frozen', False):  # the child must import THIS source tree, not another install
        env['PYTHONPATH'] = str(Path(__file__).resolve().parents[2])
    return env


def worker_limits(limits: RuleLimits = LIMITS) -> dict[str, int]:
    memory = min(limits.worker_memory_bytes, limits.worker_memory_hard_max_bytes)
    return {'target_timeout_s': min(max(limits.target_timeout_s, limits.target_timeout_min_s),
                                    limits.target_timeout_max_s),
            'max_matches_per_pattern': limits.max_matches_per_pattern, 'target_file_bytes': limits.target_file_bytes,
            'cell_offsets': limits.cell_offsets, 'worker_memory_bytes': memory}


def _tail(text: str, limit: int) -> str:
    """Sanitised stderr tail for diagnostics: control, format (bidi) and separator characters blanked."""
    return ''.join(ch if ch.isprintable() else ' ' for ch in text[-limit:])


def _failure(code, message: str, res: ProcessResult | None = None, limits: RuleLimits = LIMITS) -> RulesError:
    error = RulesError(code, message)
    if res is not None:  # diagnostics only, never the message: it can carry paths or tool output
        error.diagnostics = _tail(res.stderr_tail or '', limits.stderr_tail_bytes)
    return error


def _crash(res: ProcessResult, limits: RuleLimits) -> RulesError:
    if res.returncode == EXIT_MEMORY or _OOM_TEXT.search(res.stderr_tail or ''):
        return _failure('PT-RULE-ENGINE', 'The rule engine ran out of memory and was stopped.', res, limits)
    if res.returncode == EXIT_PANIC:
        return _failure('PT-RULE-ENGINE', 'The rule engine failed internally and was stopped.', res, limits)
    return _failure('PT-RULE-ENGINE', f'The rule engine worker failed (exit {res.returncode}).', res, limits)


def _read_result(path: Path) -> WorkerResult:
    try:
        if path.stat().st_size > MAX_RESULT_BYTES:
            raise ValueError('result too large')
        text = path.read_bytes().decode('utf-8')
        strict_json(text)  # duplicate keys, NaN/Infinity, lone surrogates
        return WorkerResult.model_validate_json(text)
    except (OSError, ValueError):
        raise RulesError('PT-RULE-ENGINE', 'The rule engine wrote an invalid result.') from None


def _check_cells(doc: WorkerResult, rules: Sequence[RuleText], targets: Sequence[WorkerTarget]) -> None:
    """A scan answers exactly rules x targets: a missing cell must never read as no-hit."""
    expected = {(r.name, t.target_id) for r in rules for t in targets}
    got = [(c.rule_name, c.target_id) for c in doc.cells]
    if len(got) != len(expected) or set(got) != expected:
        raise RulesError('PT-RULE-ENGINE', 'The rule engine result does not match the request.')


def run_worker(op: WorkerOp, *, cancel: threading.Event, private_dir: Path, rules: Sequence[RuleText] = (),
               targets: Sequence[WorkerTarget] = (), limits: RuleLimits = LIMITS, timeout_seconds: float | None = None,
               argv_for: ArgvFactory = worker_argv) -> WorkerResult:
    """One capped worker run; raises `RulesError` (cancel, timeout, crash, unavailable, compile, bad result)."""
    if cancel.is_set():
        raise RulesError('PT-RULE-CANCEL', 'The rule run was cancelled.')
    if op == 'scan':
        total = sum(t.size for t in targets)
        if total > limits.run_bytes or len(rules) * len(targets) > limits.cells:
            raise RulesError('PT-RULE-LIMIT', 'Too many files or cells for one rule run.')
    if timeout_seconds is None:
        timeout_seconds = limits.run_wall_s if op == 'scan' else SHORT_OP_SECONDS
    work = Path(private_dir) / f'rules-{uuid.uuid4().hex}'
    work.mkdir(mode=0o700)
    result, request_path = work / 'out.json', work / 'req.json'
    try:
        request = WorkerRequest(op=op, rules=tuple(rules), targets=tuple(targets), limits=worker_limits(limits),
                                result=str(result))
        request_path.write_text(request.model_dump_json(), encoding='utf-8')
        memory = request.limits['worker_memory_bytes']
        res = run_process(argv_for(request_path), cwd=work, env=worker_env(), cancel=cancel,
                          timeout_seconds=timeout_seconds, memory_limit_bytes=memory,
                          log_limit=8192, separate_streams=True, stderr_limit=limits.stderr_tail_bytes,
                          max_output_bytes=MAX_STDOUT_BYTES)
        if cancel.is_set() or res.reason == 'cancelled':
            raise RulesError('PT-RULE-CANCEL', 'The rule run was cancelled.')
        if res.reason == 'timeout':
            raise RulesError('PT-RULE-TIMEOUT', 'The rule engine exceeded its time limit.')
        if res.reason or res.returncode not in (EXIT_OK, EXIT_ERROR_DOC) or not result.is_file():
            raise _crash(res, limits)
        doc = _read_result(result)
        if doc.kind == 'error':
            raise RulesError(doc.error_code, doc.message or 'The rule engine reported an error.')  # type: ignore[arg-type]
        if res.returncode != EXIT_OK:
            raise _crash(res, limits)
        if op == 'scan':
            _check_cells(doc, rules, targets)
        return doc
    finally:
        shutil.rmtree(work, ignore_errors=True)


def probe(*, cancel: threading.Event, private_dir: Path, **kwargs) -> EngineStamp:
    """The engine stamp the worker sees; `PT-RULE-UNAVAILABLE` (blocked state R1) when the wheel is missing."""
    if not engine_installed():
        raise RulesError('PT-RULE-UNAVAILABLE', 'The rule engine (YARA-X) is not available in this installation.')
    return run_worker('probe', cancel=cancel, private_dir=private_dir, **kwargs).engine  # type: ignore[return-value]


def lint(rules: Sequence[RuleText], *, cancel: threading.Event, private_dir: Path,
         **kwargs) -> tuple[EngineStamp, tuple[LintFinding, ...]]:
    doc = run_worker('lint', cancel=cancel, private_dir=private_dir, rules=rules, **kwargs)
    return doc.engine, doc.lint  # type: ignore[return-value]


def scan(rules: Sequence[RuleText], targets: Sequence[WorkerTarget], *, cancel: threading.Event, private_dir: Path,
         **kwargs) -> tuple[EngineStamp, tuple[CellResult, ...]]:
    doc = run_worker('scan', cancel=cancel, private_dir=private_dir, rules=rules, targets=targets, **kwargs)
    return doc.engine, doc.cells  # type: ignore[return-value]

