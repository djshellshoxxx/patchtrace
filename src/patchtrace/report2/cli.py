"""``patchtrace export`` (SPEC-50 section 8). Headless: no Qt. Output is the ``enrichment-cli/1`` envelope.

With ``--json`` stdout carries one document whose ``result`` is the ``ExportManifest``. Exit codes: 0 exported; 2 invalid
arguments or an unopenable project; 3 export failure; 4 nothing to export (the project has no matches); 5 cancelled.
No network is used. Only the sections a stored producer can supply headlessly are included: the symbol mode from the
run settings and the unified result reference; the rest are listed under ``unknowns`` in the report.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from ..cli import ENVIRONMENT, _open
from ..cli_commands import CANCELLED, NO_RESULTS, OK, RUNTIME, CliError, emit
from . import options as options_module

SUMMARY = 'export a project as a report (json, md, html; report/1 or report/2)'


class _UnifiedPort:
    """Read-only: the verified pointer and manifest of the current unified result, never its rows."""

    def __init__(self, service):
        self._service = service

    def load(self):
        from ..unified import pipeline
        from ..unified.limits import UnifiedError
        try:
            plan = pipeline.make_plan(self._service)
        except UnifiedError:
            plan = None
        return pipeline.load_current(self._service, plan)


def add_parser(sub) -> argparse.ArgumentParser:
    parser = sub.add_parser('export', help=SUMMARY)
    parser.add_argument('project', type=Path)
    parser.add_argument('--format', choices=('json', 'md', 'html'), default='json')
    parser.add_argument('--report-version', type=int, choices=(1, 2), default=1)
    parser.add_argument('--profile', choices=('local', 'share'), default='local')
    parser.add_argument('--include-code', action='store_true', help='include decompiled code and assembly')
    parser.add_argument('--include-notes', action=argparse.BooleanOptionalAction, default=None,
                        help='include analyst notes (default: on for local, off for share)')
    parser.add_argument('--finding', action='append', default=None, metavar='ID', help='export only this finding')
    parser.add_argument('--out', type=Path, required=True, metavar='PATH')
    parser.add_argument('--include-ordinal-index', action='store_true',
                        help='report/2: add the 0..83 ordinal evidence index (an uncalibrated triage aid)')
    parser.add_argument('--urls', choices=('text', 'defanged', 'removed'), default=None,
                        help='report/2: how web addresses are written (default: text, share: defanged)')
    parser.add_argument('--json', action='store_true', help='emit exactly one JSON document on stdout')
    return parser


def run(args, cancel) -> int:
    from ..reports import ExportError
    try:
        chosen = options_module.resolve(
            report_version=args.report_version, profile=args.profile, include_code=args.include_code,
            include_notes=args.include_notes, urls=args.urls, include_ordinal_index=args.include_ordinal_index)
    except ValueError as exc:
        raise CliError(ENVIRONMENT, str(exc)) from None
    service = _open(args.project)
    try:
        if not service.project.matches:
            emit(args, 'export', 'no-results', None, [], 'Nothing to export: no matches yet.')
            return NO_RESULTS
        if cancel.is_set():
            emit(args, 'export', 'cancelled', None, [], '')
            return CANCELLED
        extra = {}
        if chosen.report_version == 2:
            from .sections import collect
            extra = {'report_version': 2, 'redaction': chosen.profile,
                     'sections': collect(unified=_UnifiedPort(service))}
        try:
            manifest = service.export_report(args.format, args.out, include_code=chosen.include_code,
                                             include_notes=chosen.include_notes, finding_ids=args.finding, **extra)
        except ExportError as exc:
            raise CliError(RUNTIME, f'Export failed: {exc}. The previous file, if any, is unchanged.') from None
    finally:
        service.close()
    digest = f'; content digest {manifest.content_digest}' if manifest.content_digest else ''
    emit(args, 'export', 'complete', manifest.model_dump(mode='json'), [],
         f'Exported report/{manifest.report_version} ({args.format}) to {args.out}; '
         f'sha256 {manifest.sha256}{digest}')
    return OK
