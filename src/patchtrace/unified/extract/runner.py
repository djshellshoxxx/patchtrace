"""PatchTrace side of the extraction (03 s3, s12.2): private directory, verified script copy, request file, argv and
environment, `jobs.run_process` supervision, progress and output guard, failure classification.

One extractor child per side, sequential by default (two JVMs may exhaust RAM, L-03). The child is the user's external
Python running the packaged script; the JVM is never memory-capped (RLIMIT_AS breaks JVM reservations, T-38), `-Xmx`
bounds it. The target binary is never executed: Ghidra loads it as data. All paths handed to Ghidra are private,
absolute, without dot-prefixed components and shorter than 240 characters (the `ExtractRequest` contract checks it).
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import stat
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from ... import backend as backend_module
from ...backend import BackendConfig
from ...jobs import ProcessResult, run_process
from .. import keys
from ..contracts import ExtractRequest, IrKeyInputs
from ..limits import DEFAULT_LIMITS, Budget, BudgetExhausted, UnifiedError, UnifiedLimits
from . import PRIVATE_SCRIPT_NAME, SYMBOLS_BY_MODE, analysis_options_digest, script_bytes, script_sha256

DEFAULT_HEAP_MB = 4096                     # unknown RAM (the package may not import ctypes, 03 s12.2 item 1)
STDOUT_LIMIT = 64 * 1024
STDERR_LIMIT = 256 * 1024
REQUEST_LIMIT_KEYS = ('l01_functions_per_side', 'l02_instructions_per_side', 'l05_string_bytes', 'l06_fn_raw_bytes',
                      'l06_fn_instructions')
_SLUG = re.compile(r'^[a-z0-9-]{1,48}$')
_STDERR_UNSAFE = re.compile('[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]')
_PROBE_KEYS = frozenset({'ghidra', 'pyghidra', 'java', 'python', 'script_sha256'})
# Child reason slug -> error code. A slug the table does not know is untrusted text: it becomes EXTRACT/crash.
_REASONS = {
    'artifact-hash': 'PT-UNIFIED-PAIR', 'program-hash': 'PT-UNIFIED-PAIR', 'gzf-not-analyzed': 'PT-UNIFIED-EXTRACT',
    'unsupported-language': 'PT-UNIFIED-UNSUPPORTED', 'unsupported-format': 'PT-UNIFIED-UNSUPPORTED',
    'ghidra-version': 'PT-UNIFIED-UNSUPPORTED', 'pyghidra-missing': 'PT-UNIFIED-UNSUPPORTED',
    'operand-flags': 'PT-UNIFIED-UNSUPPORTED', 'unsupported-mode': 'PT-UNIFIED-UNSUPPORTED',
    'jvm-start': 'PT-UNIFIED-UNSUPPORTED', 'import-failed': 'PT-UNIFIED-UNSUPPORTED',
    'bad-request': 'PT-UNIFIED-INTERNAL', 'bad-option': 'PT-UNIFIED-INPUT', 'cancelled': 'PT-UNIFIED-CANCEL',
    'crash': 'PT-UNIFIED-EXTRACT',
}
_EXIT_CODES = {2: 'bad-request', 3: 'artifact-hash', 4: 'ghidra-version', 5: 'cancelled'}


@dataclass(frozen=True)
class ExtractProgress:
    """Stage event of one extraction; S0b adapts it to its `StageEvent`."""
    stage: str
    done: int
    total: int | None


@dataclass(frozen=True)
class ExtractJob:
    side: Literal['older', 'newer']
    artifact_path: Path
    artifact_sha256: str
    backend: BackendConfig
    mode: Literal['gzf', 'analyze'] = 'analyze'
    gzf_path: Path | None = None
    gzf_sha256: str | None = None
    analysis_options: Mapping[str, str] | None = None
    limits: UnifiedLimits = DEFAULT_LIMITS
    timeout_seconds: int | None = None
    max_heap_mb: int | None = None
    total_ram_bytes: int | None = None


@dataclass
class ExtractOutput:
    """The private directory holds `out/ir.jsonl` (and `out/program.gzf` in analyze mode); the caller ingests it and
    then calls `cleanup()` (or moves the GZF first)."""
    work_dir: Path
    jsonl: Path
    gzf: Path | None
    mode: str
    probe: dict = field(default_factory=dict)
    stderr_tail: str = ''
    analysis_options_digest: str = ''
    script_sha256: str = ''

    def cleanup(self) -> None:
        remove_tree(self.work_dir)


def _error(code: str, message: str, reason: str) -> UnifiedError:
    return UnifiedError(code, message, reason=reason)


def remove_tree(path: Path) -> None:
    """Remove a private directory; read-only files and brief Windows handle holds are retried, never raised."""
    def retry(function, target, _exc):
        try:
            os.chmod(target, stat.S_IRWXU)
            function(target)
        except OSError:
            pass
    for attempt in range(5):
        shutil.rmtree(path, onexc=retry)
        if not Path(path).exists():
            return
        time.sleep(0.1 * (attempt + 1))


def default_analysis_options(mode: str) -> dict[str, str]:
    """`analyze` mode mirrors PatchTrace's Ghidriff call (plain defaults, `--no-symbols` = PDB Universal off, T-06)."""
    return {'PDB Universal': 'false'} if mode == 'analyze' else {}


def effective_options(job: ExtractJob) -> dict[str, str]:
    """The options the script receives (and digests): `gzf` mode analyses nothing, so it never carries any."""
    if job.mode != 'analyze':
        return {}
    return dict(job.analysis_options) if job.analysis_options is not None else default_analysis_options(job.mode)


def heap_mb(job: ExtractJob) -> int:
    if job.max_heap_mb is not None:
        return job.max_heap_mb
    if job.total_ram_bytes:
        return job.limits.jvm_heap_mib(job.total_ram_bytes)
    return DEFAULT_HEAP_MB


def predict_ir_key(job: ExtractJob, *, ghidra_version: str, pyghidra_version: str,
                   python_version: str) -> tuple[IrKeyInputs, str]:
    """The `ir_key` an extraction would produce, computable BEFORE running it (02 s5): the versions come from
    `Ghidra/application.properties` and the Ghidriff run settings. A different actual key only costs a cache miss."""
    inputs = IrKeyInputs(
        artifact_sha256=job.artifact_sha256, producer_kind='ghidra', mode=job.mode, symbols=SYMBOLS_BY_MODE[job.mode],
        ghidra=ghidra_version, pyghidra=pyghidra_version, python=python_version, script_sha256=script_sha256(),
        analysis_options_digest=analysis_options_digest(job.mode, effective_options(job)),
        ingest_limits_digest=keys.ingest_limits_digest(job.limits))
    return inputs, keys.ir_key(inputs)


def sanitize_stderr(text: str, limit: int = DEFAULT_LIMITS.l31_stderr_tail_bytes) -> str:
    cleaned = _STDERR_UNSAFE.sub('?', text.replace('\r\n', '\n'))
    raw = cleaned.encode('utf-8', 'replace')
    return raw[-limit:].decode('utf-8', 'ignore') if len(raw) > limit else cleaned


class OutputGuard:
    """`run_process(check_output=...)` callback: forwards `progress.json` and enforces the output caps.

    Returns 'output-limit' when `out/` holds more than L-05 bytes of IR text, more than L-36 bytes of GZF, a symlink
    or a directory; it never raises (a bad progress file or a failing listener is ignored). Polled by `run_process`
    about every 50 ms from the supervising thread."""

    GZF_NAME = 'program.gzf'

    def __init__(self, directory: Path, emit: Callable[[ExtractProgress], None] | None, cap: int, progress_cap: int,
                 gzf_cap: int = DEFAULT_LIMITS.l36_retained_gzf_bytes) -> None:
        self.directory = Path(directory)
        self.emit = emit
        self.cap = cap
        self.gzf_cap = gzf_cap
        self.progress_cap = progress_cap
        self.last: tuple | None = None

    def __call__(self) -> str | None:
        try:
            text = gzf = 0
            with os.scandir(self.directory) as entries:
                for entry in entries:
                    if entry.is_symlink() or entry.is_dir(follow_symlinks=False):
                        return 'output-limit'
                    if entry.name == 'progress.json':
                        self._progress(Path(entry.path))
                    elif entry.name.endswith('.part'):
                        continue
                    elif entry.name == self.GZF_NAME:
                        gzf += entry.stat(follow_symlinks=False).st_size
                    else:
                        text += entry.stat(follow_symlinks=False).st_size
            return 'output-limit' if text > self.cap or gzf > self.gzf_cap else None
        except OSError:
            return None

    def _progress(self, path: Path) -> None:
        if self.emit is None:
            return
        try:
            if path.stat().st_size > self.progress_cap:
                return
            document = json.loads(path.read_text(encoding='utf-8'))
            phase, done, total = document['phase'], document['done'], document['total']
            if not (isinstance(phase, str) and _SLUG.match(phase) and type(done) is int and done >= 0
                    and (total is None or (type(total) is int and total >= 0))):
                return
        except (OSError, ValueError, KeyError, TypeError):
            return
        current = (phase, done, total)
        if current != self.last:
            self.last = current
            try:
                self.emit(ExtractProgress(phase, done, total))
            except Exception:  # noqa: BLE001 - a listener must not interrupt containment (backend.run_comparison)
                logging.getLogger(__name__).warning('Extraction progress listener failed at stage %s', phase)


def _child_documents(stdout: str) -> tuple[dict, str | None]:
    """(probe, error reason) from the child's stdout JSON lines; everything else is ignored."""
    probe: dict = {}
    reason = None
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            document = json.loads(line)
        except ValueError:
            continue
        if isinstance(document, dict) and isinstance(document.get('probe'), dict):
            probe = {k: v[:64] for k, v in document['probe'].items() if k in _PROBE_KEYS and isinstance(v, str)}
        elif isinstance(document, dict) and isinstance(document.get('error'), dict):
            candidate = document['error'].get('reason')
            reason = candidate if isinstance(candidate, str) and _SLUG.match(candidate) else 'crash'
    return probe, reason


def classify(result: ProcessResult) -> UnifiedError | None:
    """Map a finished child to a typed error (03 s9); None = success. Child text never enters a message."""
    if result.reason == 'cancelled':
        return BudgetExhausted('PT-UNIFIED-CANCEL', 'Unified extraction was cancelled', reason='cancelled')
    if result.reason == 'timeout':
        return BudgetExhausted('PT-UNIFIED-TIMEOUT', 'Unified extraction reached its time limit', reason='timeout')
    if result.reason == 'output-limit':
        return _error('PT-UNIFIED-LIMIT', 'The extractor output exceeded its size limit (L-05 or L-36)', 'output-limit')
    if result.reason:
        return _error('PT-UNIFIED-EXTRACT', 'The extractor was stopped', 'crash')
    if result.returncode == 0:
        return None
    _probe, reason = _child_documents(result.log_tail)
    reason = reason or _EXIT_CODES.get(result.returncode, 'crash')
    if reason not in _REASONS:
        reason = 'crash'
    code = _REASONS[reason]
    messages = {'PT-UNIFIED-PAIR': 'The extractor analysed a different file than the project artifact',
                'PT-UNIFIED-UNSUPPORTED': 'The configured Ghidra runtime cannot run the extractor',
                'PT-UNIFIED-EXTRACT': 'The extractor failed', 'PT-UNIFIED-CANCEL': 'Unified extraction was cancelled',
                'PT-UNIFIED-INPUT': 'The extractor request was rejected', 'PT-UNIFIED-INTERNAL': 'The extractor request was invalid'}
    if code == 'PT-UNIFIED-CANCEL':
        return BudgetExhausted(code, messages[code], reason=reason)
    return _error(code, messages[code], reason)


def _timeout_seconds(job: ExtractJob, budget: Budget) -> float:
    limits = job.limits
    seconds = job.timeout_seconds if job.timeout_seconds is not None else (
        limits.l04_analyze_timeout_s if job.mode == 'analyze' else limits.l04_gzf_timeout_s)
    seconds = limits.checked_timeout(seconds, kind='extract')
    if budget.deadline is not None:
        remaining = budget.deadline - budget.clock()
        if remaining <= 0:
            raise BudgetExhausted('PT-UNIFIED-TIMEOUT', 'Unified analysis reached its deadline', reason='deadline')
        seconds = min(float(seconds), remaining)
    return float(seconds)


def _build_request(job: ExtractJob, work: Path) -> ExtractRequest:
    options = effective_options(job)
    limits = {k: v for k, v in job.limits.as_dict().items() if k in REQUEST_LIMIT_KEYS}
    try:
        return ExtractRequest(
            side=job.side, artifact_path=str(Path(job.artifact_path).absolute()), artifact_sha256=job.artifact_sha256,
            mode=job.mode, gzf_path=str(Path(job.gzf_path).absolute()) if job.gzf_path else None,
            gzf_sha256=job.gzf_sha256, out_dir=str(work / 'out'), work_dir=str(work / 'ghidra'),
            max_heap_mb=heap_mb(job), analysis_options=options, limits=limits)
    except ValidationError:
        raise _error('PT-UNIFIED-INPUT', 'The extraction paths or parameters are not usable (dot-prefixed folder, '
                     'path of 240 characters or more, or an out-of-range value)', 'request-invalid') from None


def private_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix='patchtrace-ir-')).resolve()


def extract_side(job: ExtractJob, budget: Budget | None = None, emit: Callable[[ExtractProgress], None] | None = None,
                 *, runner: Callable[..., ProcessResult] = run_process) -> ExtractOutput:
    """Run the extractor for one side and return its private output (03 s3). Raises `UnifiedError`."""
    budget = budget or Budget()
    cfg = job.backend
    if not cfg.python_executable or not cfg.ghidra_dir or backend_module._config_errors(cfg):
        raise _error('PT-UNIFIED-UNSUPPORTED', 'Ghidra extraction needs the configured Python and Ghidra', 'no-backend')
    if job.mode == 'gzf' and (job.gzf_path is None or job.gzf_sha256 is None):
        raise _error('PT-UNIFIED-INPUT', 'gzf mode needs the retained GZF and its SHA-256', 'request-invalid')
    timeout = _timeout_seconds(job, budget)
    work = private_dir()
    try:
        for name in ('script', 'ghidra', 'out', 'ghidra-settings'):
            (work / name).mkdir()
        # The interpreter puts the script's directory first on sys.path: it holds only the script, so no sibling
        # (not even the `ghidra` project directory, which would shadow Ghidra's Java package) is importable.
        script = work / 'script' / PRIVATE_SCRIPT_NAME
        script.write_bytes(script_bytes())
        request = _build_request(job, work)
        request_path = work / 'request.json'
        request_path.write_text(request.model_dump_json(), encoding='utf-8', newline='\n')
        env = backend_module._environment(cfg, work / 'ghidra-settings')
        # Not resolved: a venv interpreter is a symlink/launcher whose location selects its site-packages.
        argv = [os.path.abspath(cfg.python_executable), '-B', '-X', 'utf8', str(script), '--request', str(request_path)]
        guard = OutputGuard(work / 'out', emit, job.limits.l05_output_bytes, job.limits.l37_progress_bytes,
                            job.limits.l36_retained_gzf_bytes)
        result = runner(argv, cwd=work, env=env, cancel=budget.cancel or threading.Event(), timeout_seconds=timeout,
                        check_output=guard, log_limit=STDOUT_LIMIT, separate_streams=True, stderr_limit=STDERR_LIMIT)
        failure = classify(result)
        if failure is not None:
            failure.diagnostics = sanitize_stderr(result.stderr_tail)   # plain text for a log, never in the message
            raise failure
        remove_tree(work / 'ghidra')                       # the Ghidra project can be large; only `out/` is kept
        remove_tree(work / 'ghidra-settings')
        jsonl = work / 'out' / 'ir.jsonl'
        if not jsonl.is_file() or jsonl.is_symlink():
            raise _error('PT-UNIFIED-IR', 'The extractor produced no output', 'no-output')
        probe, _reason = _child_documents(result.log_tail)
        gzf = work / 'out' / 'program.gzf'
        return ExtractOutput(work, jsonl, gzf if gzf.is_file() and not gzf.is_symlink() else None, job.mode, probe,
                             sanitize_stderr(result.stderr_tail), analysis_options_digest(job.mode, effective_options(job)),
                             script_sha256())
    except BaseException:
        remove_tree(work)
        raise


def self_check(cfg: BackendConfig, budget: Budget | None = None, *,
               runner: Callable[..., ProcessResult] = run_process) -> dict:
    """Run the script's `--self-check` (no target, no request) and return its JSON; raises UNSUPPORTED if it fails."""
    budget = budget or Budget()
    if not cfg.python_executable or not cfg.ghidra_dir or backend_module._config_errors(cfg):
        raise _error('PT-UNIFIED-UNSUPPORTED', 'Ghidra extraction needs the configured Python and Ghidra', 'no-backend')
    work = private_dir()
    try:
        (work / 'script').mkdir()
        script = work / 'script' / PRIVATE_SCRIPT_NAME
        script.write_bytes(script_bytes())
        (work / 'ghidra-settings').mkdir()
        env = backend_module._environment(cfg, work / 'ghidra-settings')
        argv = [os.path.abspath(cfg.python_executable), '-B', '-X', 'utf8', str(script), '--self-check']
        result = runner(argv, cwd=work, env=env, cancel=budget.cancel or threading.Event(), timeout_seconds=120.0,
                        separate_streams=True, log_limit=STDOUT_LIMIT, stderr_limit=STDERR_LIMIT)
        for line in result.log_tail.splitlines():
            try:
                document = json.loads(line)
            except ValueError:
                continue
            if isinstance(document, dict) and isinstance(document.get('self_check'), dict):
                check = document['self_check']
                if result.returncode == 0 and check.get('ok') is True:
                    return check
                missing = [m for m in check.get('missing', []) if isinstance(m, str)][:32]
                failure = UnifiedError('PT-UNIFIED-UNSUPPORTED', 'The extractor self-check found missing classes '
                                       f'({len(missing)})', reason='self-check')
                failure.diagnostics = sanitize_stderr(', '.join(missing))     # names of Ghidra classes, for a log
                raise failure
        failure = classify(result)
        raise failure or _error('PT-UNIFIED-UNSUPPORTED', 'The extractor self-check failed', 'self-check')
    finally:
        remove_tree(work)
