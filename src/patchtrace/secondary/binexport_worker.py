"""BinExport inspection worker: runs in a memory/time-capped child (SPEC-10b §6.1, §7).

Invoked as `patchtrace secondary _binexport-worker --request REQ.json`. Writes exactly one strict JSON
`WorkerResult` to the request's `result` path. Exit codes: 0 ok document, 20 error document,
21 internal error (traceback on stderr only), 22 MemoryError, 2 unusable request.
"""
from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path

EXIT_OK, EXIT_ERROR_DOC, EXIT_INTERNAL, EXIT_MEMORY, EXIT_USAGE = 0, 20, 21, 22, 2
MAX_REQUEST_BYTES = 64 * 1024


def _self_limit(memory_bytes: int | None) -> None:
    """Lower our own RLIMIT_AS before touching input; closes the prlimit-after-spawn window (POSIX)."""
    if memory_bytes is None or os.name == 'nt':
        return
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    cap = memory_bytes if hard == resource.RLIM_INFINITY else min(hard, memory_bytes)
    if soft == resource.RLIM_INFINITY or soft > cap:
        resource.setrlimit(resource.RLIMIT_AS, (cap, hard))


def _write(path: Path, doc) -> None:
    data = doc.model_dump_json().encode('utf-8')
    with open(path, 'xb') as out:  # never overwrite; the directory is private to this run
        out.write(data)


def run(request_path: Path) -> int:
    from ..persistence import strict_json
    from .binexport_identity import PeLayout
    from .binexport_limits import BinExportLimits, Budget
    from .binexport_models import WorkerError, WorkerRequest, WorkerResult
    from .binexport_pipeline import inspect_binexport
    from .contracts import SecondaryError
    try:
        raw = request_path.read_bytes()
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError('request too large')
        strict_json(raw.decode('utf-8'))
        req = WorkerRequest.model_validate_json(raw)
        limits = BinExportLimits.from_json(req.limits)
    except (OSError, ValueError) as exc:
        print(f'binexport worker: unusable request: {type(exc).__name__}', file=sys.stderr)
        return EXIT_USAGE
    result = Path(req.result)
    try:
        _self_limit(limits.memory_bytes)
        layout = PeLayout(**req.pe_layout.model_dump()) if req.pe_layout else None
        summary = inspect_binexport(req.src, req.snapshot, artifact_sha256=req.artifact_sha256, role=req.role,
                                    limits=limits, budget=Budget.for_seconds(limits.wall_seconds),
                                    pe_layout=layout, accept_unbound=req.accept_unbound)
    except SecondaryError as exc:
        _write(result, WorkerResult(kind='error', error=WorkerError(code=exc.code, message=exc.message[:400],
                                                                     reason=exc.reason)))
        return EXIT_ERROR_DOC
    except MemoryError:
        return EXIT_MEMORY
    except Exception:
        traceback.print_exc(limit=8, file=sys.stderr)
        return EXIT_INTERNAL
    try:
        _write(result, WorkerResult(kind='ok', summary=summary))
    except MemoryError:
        return EXIT_MEMORY
    return EXIT_OK


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != '--request':
        print('usage: _binexport-worker --request FILE', file=sys.stderr)
        return EXIT_USAGE
    return run(Path(argv[1]))
