"""The hidden `patchtrace unified _worker` entry (01 s2, s4): one request file in, one staged result directory out.

The worker never opens the project database and never publishes: it reads the strict request, re-hashes every input
file, writes only the staged result directory and a report next to the request, and exits. The owner thread
(`pipeline.publish`) verifies and publishes. Cancellation from outside is a process-tree kill by the parent
(`jobs.run_process`); the memory cap L-42 is applied by the parent as well. The logic lives in `compute` and
`exchange`; this module only maps outcomes to exit codes: 0 ok, 1 internal error (traceback on stderr), 2 usage or
unusable request, 3 error report written, 5 cancelled, 22 MemoryError (C3's code, so `binexport_run._out_of_memory`
classifies it).
"""
from __future__ import annotations

import sys
import traceback
from pathlib import Path

from . import compute, exchange
from .limits import BudgetExhausted, UnifiedError

EXIT_OK, EXIT_INTERNAL, EXIT_USAGE, EXIT_ERROR_DOC, EXIT_CANCEL, EXIT_MEMORY = 0, 1, 2, 3, 5, 22
# Every module of the package except the extractor script (it runs in the external Python and is never imported). The
# frozen smoke imports exactly this list, and tests/test_unified_import_dag.py compares it with the files on disk, so
# a module cannot be left out and a removed one cannot linger.
MODULES = (
    'addressing', 'cli', 'compute', 'contracts', 'exchange', 'extract', 'extract.decomp', 'extract.retain',
    'extract.runner', 'facts', 'facts.align', 'facts.anchors', 'facts.channels', 'facts.datamap', 'facts.eh',
    'facts.fnview', 'facts.irchannels', 'facts.layout', 'facts.operands', 'facts.pseudo', 'facts.refacts',
    'facts.trace', 'facts.verdict', 'fusion', 'fusion.arbiter', 'fusion.components', 'ir', 'ir.cfg', 'ir.features',
    'ir.ingest', 'ir.ins', 'ir.ladder_port', 'ir.mdindex', 'ir.operands', 'ir.pe_tables', 'ir.place', 'ir.reader',
    'ir.records', 'ir.schema', 'keys', 'ladder', 'ladder.assign', 'ladder.blocking', 'ladder.engine',
    'ladder.groups', 'ladder.passes', 'ladder.passspec', 'ladder.ports', 'ladder.propagate', 'ladder.residual',
    'ladder.side', 'ladder.state', 'ladder.types', 'limits', 'panel', 'pipeline', 'read_model', 'read_text', 'registry',
    'sources', 'sources.ghidriff', 'sources.ladder', 'sources.manual', 'sources.secondary', 'store', 'worker')
USAGE = 'usage: unified _worker --request FILE --result-dir DIR | --self-check'


def self_check() -> int:
    """Frozen smoke: every unified module imports (a missing hidden import shows up here, not in a user's run)."""
    import importlib
    for name in MODULES:
        importlib.import_module(f'{__package__}.{name}')
    print(f'unified worker self-check ok: {len(MODULES)} modules')
    return EXIT_OK


def main(argv: list[str]) -> int:
    if argv == ['--self-check']:
        return self_check()
    if len(argv) != 4 or argv[0] != '--request' or argv[2] != '--result-dir':
        print(USAGE, file=sys.stderr)
        return EXIT_USAGE
    request_path, result_dir = Path(argv[1]), Path(argv[3])
    try:
        exchange.read_request(request_path)
    except UnifiedError:
        print('unified worker: unusable request', file=sys.stderr)
        return EXIT_USAGE
    try:
        report = compute.run_request(request_path, result_dir)
    except BudgetExhausted as exc:
        exchange.write_report(request_path, exchange.error_report(exc))
        return EXIT_CANCEL if exc.code == 'PT-UNIFIED-CANCEL' else EXIT_ERROR_DOC
    except UnifiedError as exc:
        exchange.write_report(request_path, exchange.error_report(exc))
        return EXIT_ERROR_DOC
    except MemoryError:
        return EXIT_MEMORY
    except Exception:  # noqa: BLE001 - last resort: a diagnostic on stderr, never a message in a result
        traceback.print_exc(limit=8, file=sys.stderr)
        return EXIT_INTERNAL
    exchange.write_report(request_path, report)
    return EXIT_OK
