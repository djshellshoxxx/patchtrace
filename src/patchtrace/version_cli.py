"""Headless, read-only version observations through enrichment-cli/1."""
from __future__ import annotations

from .buildinfo import BuildInfoCancelled, read_info


def add_parser(sub):
    parser = sub.add_parser('version', help='version and available source/build provenance',
                            description='Read local package/source observations; no network or analysis tool.')
    parser.add_argument('--json', action='store_true', help='emit exactly one JSON document on stdout')
    return parser


def run(args, cancel):
    from .cli_commands import CANCELLED, OK, CliError, emit
    try:
        result, warnings = read_info(cancel=cancel)
    except BuildInfoCancelled:
        raise CliError(CANCELLED, 'cancelled') from None
    lines = [f'PatchTrace {result["version"]}', f'Python: {result["python"]}',
             f'Build basis: {result["basis"]}', f'Git commit: {result["git_commit"]}',
             f'Git description: {result["git_describe"]}',
             f'Git dirty: {"unknown" if result["dirty"] is None else str(result["dirty"]).lower()}',
             f'Source SHA-256: {result["source_sha256"]}']
    emit(args, 'version', 'complete', result, warnings, '\n'.join(lines))
    return OK
