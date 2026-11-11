"""`patchtrace compare`: the primary Ghidriff analysis for one project pair (docs/specs/cli-project-compare.md s.4).

Qt-free dispatcher; `cli_commands/compare.py` is the registry adapter. The flow is the one `cli._run_pair` runs
for `series create --run` and the desktop runs for F5: `backend.run_comparison`, then `prepare_analysis` and
`apply_import`; a result the service rejects is quarantined; a failed, cancelled or identical run is recorded.
`_run_pair` itself cannot force a new run and returns neither the run nor a cancellation, so the flow is repeated
here and tests/test_compare_cli.py pins that both record the same project. Exit codes: 0 compared or already
compared, 2 invalid runtime flags (checked before the project is opened), 3 failed run or locked project,
5 cancelled. The target binaries are analysed statically by the external runtime and never executed.
"""
from __future__ import annotations

import sys
import threading
from argparse import ArgumentParser, Namespace, _SubParsersAction
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .cli import CANCELLED, ENVIRONMENT, OK, RUNTIME, CliError, _emit
from .hostile_text import escape_text
from .project_cli import counted, error_code, match_counts, open_service, output_dir, safe

TIMEOUT_RANGE = (10, 86400)
DONE = frozenset({'completed', 'identical'})


def register(sub: _SubParsersAction, common, handlers: dict) -> ArgumentParser:
    from .symbols import cli_args as symbol_args
    handlers['compare'] = dispatch
    summary = 'run the primary Ghidriff analysis for the project pair (static; never executes the files)'
    parser = common(sub.add_parser('compare', help=summary, description=summary + '. A project that already has '
                                   'a completed run is left alone unless --force is given.'))
    parser.add_argument('project', type=Path)
    parser.add_argument('--python', required=True, help='absolute path of the external Python that has ghidriff')
    parser.add_argument('--ghidra-dir', required=True, help='Ghidra installation root')
    parser.add_argument('--timeout', type=int, default=3600,
                        help=f'analysis timeout in seconds ({TIMEOUT_RANGE[0]}..{TIMEOUT_RANGE[1]}; default 3600)')
    parser.add_argument('--cache-dir', type=Path, default=None, help='raw-output cache (default: no cache)')
    symbol_args.add_arguments(parser)
    for action in parser._actions:  # the shared help text is written for `series create --run`
        if action.help:
            action.help = action.help.replace(' for --run', '')
    parser.add_argument('--force', action='store_true',
                        help='run again although the project has a completed run (the earlier run is kept)')
    return parser


def backend_config(args: Namespace):
    """`BackendConfig` from the runtime flags, built as `series create --run` builds it, then fully checked."""
    from . import backend
    from .symbols import cli_args as symbol_args
    if not TIMEOUT_RANGE[0] <= args.timeout <= TIMEOUT_RANGE[1]:
        raise CliError(ENVIRONMENT, f'--timeout must be between {TIMEOUT_RANGE[0]} and {TIMEOUT_RANGE[1]} seconds')
    config = backend.BackendConfig(python_executable=args.python, ghidra_dir=args.ghidra_dir,
                                   timeout_seconds=args.timeout, **symbol_args.backend_kwargs(args),
                                   cache_dir=str(args.cache_dir.resolve()) if args.cache_dir else '')
    errors = backend._config_errors(config)  # run_comparison would record a failed run for these; refuse earlier
    if errors:
        raise CliError(ENVIRONMENT, '; '.join(errors))
    return config


@contextmanager
def _first_ctrl_c_cancels(cancel: threading.Event) -> Iterator[None]:
    """While the backend runs, the first Ctrl+C sets `cancel` (the backend stops its child and returns a cancelled
    run that can be recorded) and restores the previous handler, so a second Ctrl+C interrupts as usual."""
    import signal
    previous = signal.getsignal(signal.SIGINT)
    if previous is None or threading.current_thread() is not threading.main_thread():
        yield  # a handler cannot be installed or restored from here: Ctrl+C keeps its default path
        return

    def handler(signum, frame):
        cancel.set()
        signal.signal(signal.SIGINT, previous)

    signal.signal(signal.SIGINT, handler)
    try:
        yield
    finally:
        if signal.getsignal(signal.SIGINT) is handler:
            signal.signal(signal.SIGINT, previous)


def _progress(event) -> None:
    message = escape_text(event.message, keep='\n')  # backend log text is untrusted
    print(f'compare: {event.stage}: {message}', file=sys.stderr)


def _run(service, config, cancel: threading.Event):
    """One comparison through the backend and the service; returns the run as it now stands in the project."""
    from . import backend
    from .cli_backend_progress import CliBackendProgress
    snapshot = service.project.model_copy(deep=True)
    raw_path, run = backend.run_comparison(config, snapshot, service.root, cancel, CliBackendProgress(_progress))
    if run.status == 'completed':
        try:
            if cancel.is_set():
                raise ValueError('PT-CANCEL: cancelled before normalization')
            service.apply_import(service.prepare_analysis(raw_path, run))
            return next(item for item in service.project.runs if item.id == run.id)
        except Exception as exc:
            run = backend.quarantine_failed_run(service.root, run, str(exc))
            if cancel.is_set():
                run = run.model_copy(update={'status': 'cancelled'})
    service.record_terminal_run(run)
    return run


def _reused(args: Namespace, project, run) -> int:
    result = {'ran': False, 'forced': False, 'run_id': run.id, 'status': run.status,
              'revision': project.revision, 'matches': match_counts(project)}
    reason = ('recorded the two inputs as identical (same SHA-256)' if run.status == 'identical'
              else 'is already completed for this pair')
    text = (f'run {safe(run.id, 128)} {reason}; nothing was run.\n'
            'Use --force to run the comparison again; the earlier run is kept.')
    _emit(args, 'compare', 'complete', result, [], text)
    return OK


def _finished(args: Namespace, base: dict[str, Any], project, run) -> int:
    matches = match_counts(project)
    result = base | {'backend': run.backend, 'backend_version': run.backend_version, 'raw_path': run.raw_path,
                     'raw_sha256': run.raw_sha256, 'revision': project.revision, 'matches': matches}
    lines = [f'compared: run {run.id} {run.status} ({safe(run.backend, 24)} {safe(run.backend_version, 24)})']
    if run.status == 'identical':
        lines.append('The two inputs are identical (same SHA-256); analysis was skipped.')
    else:
        lines += [f'matches: {counted(matches["total"], matches["by_category"])}; project revision '
                  f'{project.revision}', f'raw result preserved: {safe(run.raw_path)} sha256 {run.raw_sha256}']
    _emit(args, 'compare', 'complete', result, [], '\n'.join(lines))
    return OK


def _unfinished(args: Namespace, base: dict[str, Any], root: Path, run) -> int:
    kept = output_dir(root, run.id)
    result = base | {'error': run.error, 'error_code': error_code(run.error), 'output_dir': kept}
    print(f'error: {safe(run.error or f"comparison {run.status}", 4000)}', file=sys.stderr)
    text = (f'comparison {run.status}: run {run.id} was recorded; earlier results are unchanged'
            + (f'; its output is kept under {kept}' if kept else ''))
    _emit(args, 'compare', run.status, result, [], text)
    return CANCELLED if run.status == 'cancelled' else RUNTIME


def dispatch(args: Namespace, cancel: threading.Event) -> int:
    config = backend_config(args)
    with open_service(args.project) as service:
        existing = next((run for run in reversed(service.project.runs) if run.status in DONE), None)
        if existing is not None and not args.force:
            return _reused(args, service.project, existing)
        with _first_ctrl_c_cancels(cancel):
            run = _run(service, config, cancel)
        base = {'ran': True, 'forced': existing is not None, 'run_id': run.id, 'status': run.status}
        if run.status in DONE:
            return _finished(args, base, service.project, run)
        return _unfinished(args, base, service.root, run)
