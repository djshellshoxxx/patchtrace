"""Hidden rules worker: the memory- and time-capped child that holds every YARA-X call (plan s6, s7, s8).

Invoked as `python -m patchtrace.rules.worker --request REQ.json` from source, and as
`patchtrace rules _rules-worker --request REQ.json` from the frozen executable (the integrator wires that verb to `main`).
It reads one strict JSON `WorkerRequest` and writes exactly one strict JSON `WorkerResult` to the request's `result`
path; nothing goes to stdout. Exit codes: 0 ok document, 20 error document, 21 internal error (traceback on stderr only),
22 MemoryError, 23 any other BaseException (a Rust panic surfaces as `PanicException`, which `except Exception` misses),
2 unusable request.

Targets are untrusted files: each is read once as bytes through a descriptor checked to be a regular file, bounded,
compared with the recorded size and SHA-256, and only those exact bytes are scanned.
"""
from __future__ import annotations

import errno
import hashlib
import os
import stat
import sys
import traceback
from pathlib import Path

from .contracts import (
    CellResult,
    WorkerError,
    WorkerLimits,
    WorkerRequest,
    WorkerResult,
    WorkerTarget,
    clean_line,
    strict_json,
)
from .errors import RuleError
from .limits import DEFAULT_LIMITS

EXIT_OK, EXIT_ERROR_DOC, EXIT_INTERNAL, EXIT_MEMORY, EXIT_PANIC, EXIT_USAGE = 0, 20, 21, 22, 23, 2


def _self_limit(memory_bytes: int) -> None:
    """Lower our own RLIMIT_AS before touching input; closes the prlimit-after-spawn window (POSIX; Windows is capped by
    the Job Object the parent created)."""
    if os.name == 'nt':
        return
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    cap = memory_bytes if hard == resource.RLIM_INFINITY else min(hard, memory_bytes)
    if soft == resource.RLIM_INFINITY or soft > cap:
        resource.setrlimit(resource.RLIMIT_AS, (cap, hard))


def _load_request(path: Path) -> WorkerRequest:
    with open(path, 'rb') as handle:
        raw = handle.read(DEFAULT_LIMITS.request_bytes + 1)
    if len(raw) > DEFAULT_LIMITS.request_bytes:
        raise ValueError('request too large')
    text = raw.decode('utf-8')
    strict_json(text)
    return WorkerRequest.model_validate_json(text)


def _publish(path: str, document: WorkerResult) -> None:
    data = document.model_dump_json().encode('utf-8')
    if len(data) > DEFAULT_LIMITS.result_bytes:
        raise RuleError('PT-RULE-LIMIT', 'The result is larger than the limit', reason='result-size')
    with open(path, 'xb') as out:  # never overwrite: the directory is private to this run
        out.write(data)


# What the dynamic loader reports when RLIMIT_AS leaves no room to map the extension.
_NO_MEMORY_TEXT = ('failed to map segment', 'cannot allocate memory')


def _engine():
    """The facade module; importing it is what loads the extension, so this is the "is the engine here" check."""
    try:
        from . import engine
    except (ImportError, OSError) as exc:
        if getattr(exc, 'errno', None) == errno.ENOMEM or any(text in str(exc).lower() for text in _NO_MEMORY_TEXT):
            raise MemoryError from None  # the address-space cap stopped the extension loading: a limit, not a missing engine
        print(f'rules worker: engine import failed: {type(exc).__name__}', file=sys.stderr)
        raise RuleError('PT-RULE-UNAVAILABLE', 'The rule engine (YARA-X) is not available in this installation',
                        reason='engine-missing') from None
    return engine


def _read_target(target: WorkerTarget, limits: WorkerLimits) -> bytes | str:
    """The exact bytes of a target, or the closed `not-scanned` reason why they cannot be used."""
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
    try:
        descriptor = os.open(target.path, flags)
    except OSError:
        return 'unreadable'
    try:
        handle = os.fdopen(descriptor, 'rb')
    except OSError:
        os.close(descriptor)
        return 'unreadable'
    with handle:
        try:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                return 'unreadable'  # a directory, a pipe or a device: never read it
            if info.st_size > limits.file_bytes:
                return 'too-large'
            data = handle.read(limits.file_bytes + 1)
        except OSError:
            return 'unreadable'
    if len(data) > limits.file_bytes:
        return 'too-large'
    if len(data) != target.size or (target.sha256 is not None and hashlib.sha256(data).hexdigest() != target.sha256):
        return 'file-changed'
    return data


def _scan(engine, request: WorkerRequest) -> WorkerResult:
    rules = engine.RuleSet.compile(request.rules, request.limits)
    cells: list[CellResult] = []
    for target in request.targets:
        loaded = _read_target(target, request.limits)
        cells.extend(rules.skip(loaded) if isinstance(loaded, str) else rules.scan(loaded))
    return WorkerResult(op='scan', kind='ok', engine=engine.stamp(), lint=rules.lint, cells=tuple(cells))


def _execute(request: WorkerRequest) -> WorkerResult:
    engine = _engine()
    if request.op == 'probe':
        stamp, modules = engine.probe()
        return WorkerResult(op='probe', kind='ok', engine=stamp, modules=modules)
    if request.op == 'lint':
        lint = tuple(engine.lint(rule.name, rule.text, request.limits) for rule in request.rules)
        return WorkerResult(op='lint', kind='ok', engine=engine.stamp(), lint=lint)
    return _scan(engine, request)


def _error_document(op: str, error: RuleError) -> WorkerResult:
    return WorkerResult(op=op, kind='error', error=WorkerError(
        code=error.code, message=clean_line(error.message, 400) or error.code, reason=error.reason))


def run(request_path: Path) -> int:
    try:
        request = _load_request(request_path)
    except (OSError, ValueError) as exc:  # pydantic's ValidationError is a ValueError
        print(f'rules worker: unusable request: {type(exc).__name__}', file=sys.stderr)
        return EXIT_USAGE
    try:
        _self_limit(request.limits.memory_bytes)
        try:
            _publish(request.result, _execute(request))
            return EXIT_OK
        except RuleError as error:
            _publish(request.result, _error_document(request.op, error))
            return EXIT_ERROR_DOC
    except MemoryError:
        return EXIT_MEMORY
    except Exception:
        traceback.print_exc(limit=8, file=sys.stderr)  # diagnostics only: the parent never shows stderr as a message
        return EXIT_INTERNAL
    except BaseException as exc:  # a Rust panic is a BaseException: it must end as exit 23, not as a raw traceback
        print(f'rules worker: aborted by {type(exc).__name__}', file=sys.stderr)
        return EXIT_PANIC


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != '--request':
        print('usage: _rules-worker --request FILE', file=sys.stderr)
        return EXIT_USAGE
    return run(Path(argv[1]))


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
