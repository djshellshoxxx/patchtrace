"""`patchtrace panels list|check` (GUI plan 8.1): the display-free gate every feature PR runs. Never imports Qt.

`add_parser` and `run` are what the CLI-registry adapter `cli_commands/panels.py` calls. Exit codes follow the CLI
contract: 0 ok, 2 invalid argument or a broken manifest or spec rule, 3 a spec module raised on import, 4 no panel is
built yet, 5 cancelled; 3 wins over 2 because findings about a panel that failed to load are incomplete. In `--json`
mode stdout is one `enrichment-cli/1` document: `{"panels": [...]}` and, for `check`, `"conflicts": [...]`.
"""
from __future__ import annotations

import argparse
import threading
from collections.abc import Sequence

from .registry import LintReport, Loaded, ManifestEntry, lint, load_manifest
from .shortcuts import normalize
from .text import sanitize_text

VERBS = {'list': 'list every reserved panel and whether it is built',
         'check': 'lint the panel manifest and every built panel spec'}
HEADERS = ('id', 'state', 'area', 'tabify', 'shortcut', 'requires', 'title')


def add_parser(sub) -> argparse.ArgumentParser:
    parser = sub.add_parser('panels', help='list or check the GUI panel manifest',
                            description='List the reserved GUI panels, or lint the manifest and every built panel '
                                        'spec (ids, shortcuts, tab groups, tooltip prefixes, claims, imports). '
                                        'Runs without a display.')
    verbs = parser.add_subparsers(dest='action', required=True)
    for name, summary in VERBS.items():
        leaf = verbs.add_parser(name, help=summary)
        leaf.add_argument('--json', action='store_true', help='emit exactly one JSON document on stdout')
        leaf.set_defaults(command_label=f'panels {name}')
    return parser


def run(args, cancel: threading.Event, *, manifest: Sequence[ManifestEntry] | None = None) -> int:
    from ..cli import CANCELLED, ENVIRONMENT, NO_RESULTS, OK, RUNTIME, _emit
    entries = _shipped_manifest() if manifest is None else manifest
    command = f'panels {args.action}'
    loaded = load_manifest(entries, cancel.is_set)
    if loaded.cancelled:
        _emit(args, command, 'cancelled', None, [], 'panels: cancelled')
        return CANCELLED
    check = args.action == 'check'
    report = lint(entries, loaded) if check else LintReport(())
    rows = [_row(entry, loaded) for entry in sorted(entries, key=lambda entry: entry.id)]
    result: dict = {'panels': rows}
    if check:
        result['conflicts'] = [finding.as_dict() for finding in report.findings]
    if loaded.errors:
        code, status = RUNTIME, 'failed'
    elif report.findings:
        code, status = ENVIRONMENT, 'failed'
    else:
        code, status = (OK if loaded.specs else NO_RESULTS), 'ok'
    _emit(args, command, status, result, list(report.warnings), _text(rows, loaded, report, check))
    return code


def _shipped_manifest() -> Sequence[ManifestEntry]:
    from ..panel_manifest import MANIFEST
    return MANIFEST


def _row(entry: ManifestEntry, loaded: Loaded) -> dict:
    spec = loaded.specs.get(entry.id)
    source = entry if spec is None else spec  # what the host will use once built; the slot until then
    error = loaded.errors.get(entry.id)
    shortcut = source.shortcut and (normalize(source.shortcut) or source.shortcut)
    return {'id': sanitize_text(entry.id, 40),
            'state': 'error' if error else 'built' if spec is not None else 'not-built',
            'title': None if spec is None else sanitize_text(spec.title, 40),
            'area': sanitize_text(source.area, 12),
            'tabify_with': None if source.tabify_with is None else sanitize_text(source.tabify_with, 40),
            'shortcut': None if source.shortcut is None else sanitize_text(shortcut, 40),
            'requires': [] if spec is None else [sanitize_text(item, 40) for item in spec.requires],
            'error': None if error is None else sanitize_text(error, 80)}


def _text(rows: list[dict], loaded: Loaded, report: LintReport, check: bool) -> str:
    cells = [[row['id'], row['state'], row['area'], row['tabify_with'] or '-', row['shortcut'] or '-',
              ','.join(row['requires']) or '-', row['title'] or row['error'] or '-'] for row in rows]
    widths = [max([len(header), *(len(line[index]) for line in cells)]) for index, header in enumerate(HEADERS)]
    built, failed = len(loaded.specs), len(loaded.errors)
    lines = [f'panels: {len(rows)} listed, {built} built, {len(loaded.not_built)} not built, {failed} failed to load']
    lines += [' '.join(value.ljust(width) for value, width in zip(line, widths, strict=True)).rstrip()
              for line in (HEADERS, *cells)]
    if check:
        lines += [f'{finding.code} {finding.rule} {finding.panel}: {finding.message}'
                  for finding in report.findings] or ['conflicts: none']
    if not built:
        lines.append('no panel is built yet')
    return '\n'.join(lines)
