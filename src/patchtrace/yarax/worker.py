"""Hidden rule-engine worker: every YARA-X call runs here, in a memory- and time-capped child (plan s6).

Run as `python -m patchtrace.yarax.worker --request REQ.json` (the frozen build re-launches its own exe with the
CLI verb the integrator wires to `main`). Writes one strict JSON `WorkerResult` to the request's `result` path, or
to stdout when the path is `-`. Exit codes: 0 ok document, 20 error document, 21 internal error (traceback on
stderr only), 22 MemoryError, 23 engine panic or other BaseException, 2 unusable request.
"""
from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path

from .contracts import WorkerRequest, WorkerResult
from .errors import RulesError

EXIT_OK, EXIT_ERROR_DOC, EXIT_INTERNAL, EXIT_MEMORY, EXIT_PANIC, EXIT_USAGE = 0, 20, 21, 22, 23, 2
MAX_REQUEST_BYTES = 8 * 1024 * 1024  # 50 rules x 64 KiB plus targets
STDOUT_RESULT = '-'


def _self_limit(memory_bytes: int) -> None:
    """Lower our own RLIMIT_AS before touching input; closes the prlimit-after-spawn window (POSIX)."""
    if os.name == 'nt':
        return
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    cap = memory_bytes if hard == resource.RLIM_INFINITY else min(hard, memory_bytes)
    if soft == resource.RLIM_INFINITY or soft > cap:
        resource.setrlimit(resource.RLIMIT_AS, (cap, hard))


def _write(target: str, doc: WorkerResult) -> None:
    data = doc.model_dump_json().encode('utf-8')
    if target == STDOUT_RESULT:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return
    with open(target, 'xb') as out:  # never overwrite; the directory is private to this run
        out.write(data)


def _execute(request: WorkerRequest) -> WorkerResult:
    from . import engine
    stamp = engine.stamp()
    if request.op == 'probe':
        return WorkerResult(kind='ok', engine=stamp)
    if request.op == 'lint':
        return WorkerResult(kind='ok', engine=stamp, lint=engine.lint(request.rules))
    return WorkerResult(kind='ok', engine=stamp, cells=engine.scan(request.rules, request.targets, request.limits))


def _load(path: Path) -> WorkerRequest:
    from ..persistence import strict_json
    raw = path.read_bytes()
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError('request too large')
    strict_json(raw.decode('utf-8'))
    return WorkerRequest.model_validate_json(raw)


def run(request_path: Path) -> int:
    try:
        request = _load(request_path)
        _self_limit(request.limits['worker_memory_bytes'])
    except (OSError, ValueError, KeyError) as exc:
        print(f'rules worker: unusable request: {type(exc).__name__}', file=sys.stderr)
        return EXIT_USAGE
    try:
        doc, code = _execute(request), EXIT_OK
    except RulesError as exc:
        error_code = exc.code if exc.code in ('PT-RULE-COMPILE', 'PT-RULE-UNAVAILABLE') else 'PT-RULE-ENGINE'
        doc, code = WorkerResult(kind='error', error_code=error_code, message=exc.message), EXIT_ERROR_DOC
    except MemoryError:
        return EXIT_MEMORY
    except Exception:
        traceback.print_exc(limit=8, file=sys.stderr)
        return EXIT_INTERNAL
    except BaseException:  # pyo3 PanicException derives from BaseException and must not escape as a traceback
        print('rules worker: engine panic', file=sys.stderr)
        return EXIT_PANIC
    try:
        _write(request.result, doc)
    except MemoryError:
        return EXIT_MEMORY
    return code


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != '--request':
        print('usage: rules worker --request FILE', file=sys.stderr)
        return EXIT_USAGE
    return run(Path(argv[1]))


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
