"""`patchtrace secondary binexport-check` and the hidden `_binexport-worker` (SPEC-10b §3).

Registered from cli.py through `register`; dispatched before any project is opened. Importing this module is
cheap (no protobuf import) because the parser is built on every CLI call.
"""
from __future__ import annotations

import argparse
import re
import sys
import tempfile
import threading
from pathlib import Path

ACTIONS = frozenset({'binexport-check', '_binexport-worker'})
ROLES = ('older', 'newer')


def _sha256(value: str) -> str:
    value = value.strip().lower()
    if not re.fullmatch(r'[0-9a-f]{64}', value):
        raise argparse.ArgumentTypeError('must be 64 hex digits')
    return value


def register(sec, common) -> None:
    check = common(sec.add_parser(
        'binexport-check', help='validate a user-supplied .BinExport for one artifact (isolated worker)',
        description='Validates a .BinExport (Ghidra: File > Export > Binary BinExport (v2) for BinDiff; '
                    'IDA: Edit > Plugins > BinExport) in a memory/time-capped worker. Choose '
                    '"Subtract Imagebase" identically for both files of a pair. Nothing is uploaded and the '
                    'file is never modified.'))
    check.add_argument('file', type=Path)
    check.add_argument('--artifact-sha256', type=_sha256, required=True,
                       help='SHA-256 of the binary this export claims to describe')
    check.add_argument('--role', choices=ROLES, required=True)
    check.add_argument('--accept-unbound', action='store_true',
                       help='I confirm this file belongs to the artifact although its executable_id is not a '
                            'SHA-256 (MD5/empty ids from IDA); recorded as id_binding')
    worker = sec.add_parser('_binexport-worker')
    _hide_from_help(sec, '_binexport-worker')
    worker.add_argument('--request', required=True)


def _hide_from_help(sub, name: str) -> None:
    """Drop a subcommand from the parent's help listing while keeping it parseable.

    argparse.add_parser(help=SUPPRESS) still adds a pseudo-action whose help text is the literal
    '==SUPPRESS==' (Python 3.12), so the hidden worker used to appear in `secondary --help`.
    """
    sub._choices_actions = [a for a in sub._choices_actions if a.dest != name]


def dispatch(args, cancel: threading.Event) -> int:
    if args.action == '_binexport-worker':
        from .binexport_worker import main
        return main(['--request', args.request])
    return _check(args, cancel)


def _check(args, cancel: threading.Event) -> int:
    from ..cli import CANCELLED, ENVIRONMENT, OK, RUNTIME, CliError, _emit
    from .binexport_run import accept_binexport
    from .contracts import SecondaryError
    with tempfile.TemporaryDirectory(prefix='patchtrace-binexport-') as tmp:
        try:
            accepted = accept_binexport(args.file, artifact_sha256=args.artifact_sha256, role=args.role,
                                        private_dir=Path(tmp), cancel=cancel, accept_unbound=args.accept_unbound)
        except SecondaryError as exc:
            code = CANCELLED if exc.code == 'PT-SECONDARY-CANCEL' else (
                RUNTIME if exc.code == 'PT-SECONDARY-RUN' else ENVIRONMENT)
            suffix = f' [{exc.reason}]' if exc.reason else ''
            if getattr(exc, 'diagnostics', ''):  # sanitised worker stderr, kept off stdout/JSON
                print(f'diagnostics: {exc.diagnostics}', file=sys.stderr)
            raise CliError(code, f'{exc}{suffix}') from None
        finally:
            for p in Path(tmp).rglob('*'):  # snapshots are read-only; allow cleanup on Windows
                try:
                    p.chmod(0o700 if p.is_dir() else 0o600)
                except OSError:
                    pass
        s = accepted.summary
        result = {k: v for k, v in s.model_dump(mode='json').items() if k != 'function_addresses'}
        result['functions'] = len(s.function_addresses)
        result['vertex_types'] = {str(t): s.vertex_types.count(t) for t in sorted(set(s.vertex_types))}
        text = (f'valid BinExport2: {len(s.function_addresses)} functions, id_binding {s.id_binding}, '
                f'address basis {s.address_basis}, protobuf {s.protobuf_version}'
                + (f'\nwarnings: {", ".join(s.warnings)}' if s.warnings else ''))
        _emit(args, 'secondary binexport-check', 'complete', result, list(s.warnings), text)
    return OK
