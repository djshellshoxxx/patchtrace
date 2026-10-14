"""`patchtrace kev status|plan|fetch|import|lookup|diff|prune` (KEV-integration-plan section 8). Qt-free.

``main(argv)`` takes the arguments after ``kev``. With ``--json`` stdout holds exactly one ``enrichment-cli/1``
document whose ``result`` is a ``kev/1`` record; diagnostics (the request about to be sent, errors) go to stderr.
Exit codes: 0 usable result (a stale catalog is ``partial`` with a warning), 2 invalid use or missing consent, 3 runtime
failure, 4 no catalog, 5 cancelled. Only ``fetch`` touches the network, and only after ``--consent-hosts`` names the
exact host of the displayed request.

Hook for ``patchtrace/cli.py`` (integrator; the CLI is frozen for this slice). Until slice F1b creates
``cli_commands/``, add with the other dispatcher imports and in ``main()`` next to the ``search`` branch:

    from .kev import cli as kev_cli
    COMMANDS = (..., 'kev')
    if argv[:1] == ['kev']:
        return kev_cli.main(argv[1:])
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
import threading
from collections.abc import Callable
from pathlib import Path

from . import limits, service, teach
from .contracts import KevCatalog, KevError, KevLookup
from .join import lookup
from .store import KevStore, default_kev_dir
from .transport import KevTransport, default_sleep, urllib_open
from .view_model import banner, cell_for, delta_lines, status_line

CLI_CONTRACT = 'enrichment-cli/1'
OK, USAGE, RUNTIME, NO_CATALOG, CANCELLED = 0, 2, 3, 4, 5
SOURCES = tuple(limits.SOURCE_URLS)


class KevUsage(Exception):
    """Invalid arguments: exit 2."""


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise KevUsage(f'{self.prog}: {message}')


def _nonnegative(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError('must not be negative')
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog='patchtrace kev', description='CISA Known Exploited Vulnerabilities context for CVEs. '
                     'Only "fetch" uses the network, and only with --consent-hosts.')
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--kev-dir', type=Path, metavar='D', help='catalog folder (default: per-user data folder)')
    common.add_argument('--json', action='store_true', help='emit exactly one JSON document on stdout')
    sub = parser.add_subparsers(dest='verb', required=True, parser_class=_Parser)
    status = sub.add_parser('status', parents=[common], help='catalog version, age and freshness')
    status.add_argument('--max-age-days', type=_nonnegative, metavar='N')
    plan = sub.add_parser('plan', parents=[common], help='show the exact request; no network')
    plan.add_argument('--source', required=True, choices=SOURCES)
    fetch = sub.add_parser('fetch', parents=[common], help='download the catalog (one GET)')
    fetch.add_argument('--source', required=True, choices=SOURCES)
    fetch.add_argument('--consent-hosts', action='append', default=[], metavar='HOST',
                       help='must equal the request host exactly')
    fetch.add_argument('--accept-shrink', action='store_true', help='install a catalog with far fewer entries')
    sub.add_parser('import', parents=[common], help='load a KEV JSON file you saved').add_argument('file', type=Path)
    find = sub.add_parser('lookup', parents=[common], help='look CVE IDs up in the stored catalog')
    find.add_argument('cves', nargs='*', metavar='CVE')
    find.add_argument('--from-cve-snapshot', action='append', default=[], type=Path, metavar='FILE')
    find.add_argument('--catalog', type=Path, metavar='FILE', help='use this catalog file instead of the stored one')
    find.add_argument('--md', action='store_true', help='Markdown table')
    changes = sub.add_parser('diff', parents=[common], help='what changed between two stored catalogs')
    changes.add_argument('--from', dest='from_id', metavar='ID')
    changes.add_argument('--to', dest='to_id', metavar='ID')
    prune = sub.add_parser('prune', parents=[common], help='delete old stored catalogs (the only deletion)')
    prune.add_argument('--keep', type=_nonnegative, required=True, metavar='N')
    prune.add_argument('--yes', action='store_true')
    return parser


class Report:
    """One verb's answer: status, record fields, warnings and plain text."""

    def __init__(self, record: str, status: str = 'ok', exit_code: int = OK, **fields) -> None:
        self.record, self.status, self.exit_code, self.fields = record, status, exit_code, fields
        self.warnings: list[str] = []
        self.text: list[str] = []


def _meta_summary(catalog: KevCatalog) -> dict:
    meta = catalog.meta
    return {'snapshot_id': meta.snapshot_id, 'catalog_version': meta.catalog_version,
            'date_released': meta.date_released, 'entry_count': meta.entry_count, 'count': meta.count,
            'skipped_entries': meta.skipped_entries, 'source': meta.source, 'retrieved_at': meta.retrieved_at,
            'content_digest': meta.content_digest, 'raw_sha256': meta.raw_sha256, 'license': meta.license}


def _store(args) -> KevStore:
    return KevStore(args.kev_dir or default_kev_dir())


def _note_size(report: Report, store: KevStore) -> Report:
    warning = store.size_warning()
    if warning:
        report.warnings.append(warning)
    return report


# --------------------------------------------------------------------------------------------- verbs

def _status(args, ctx) -> Report:
    store = _store(args)
    info = service.status(store, ctx.now, args.max_age_days)
    if info.loaded is None:
        report = Report('status', 'unavailable', NO_CATALOG, catalog=None)
        report.text = [teach.K0_NO_CATALOG]
        return report
    catalog = info.loaded.catalog
    line = status_line(catalog, ctx.now())
    report = Report('status', catalog=_meta_summary(catalog), freshness=info.freshness, age_days=info.age_days)
    report.text = [line]
    notice = banner(catalog, ctx.now())
    report.warnings += [w for w in (info.loaded.note, notice) if w]
    if info.older_than_limit:
        report.warnings.append(f'The catalog is older than --max-age-days {args.max_age_days}.')
    if report.warnings:
        report.status = 'partial'
    return _note_size(report, store)


def _plan(args, ctx) -> Report:
    kev_plan = service.plan(args.source)
    report = Report('plan', plan=kev_plan.model_dump(mode='json'))
    report.text = [f'GET {kev_plan.url}', 'Headers: Accept: application/json, User-Agent: PatchTrace',
                   f'Limit {kev_plan.max_bytes} bytes; plan {kev_plan.plan_sha}', teach.K1_SENT]
    return report


def _fetch(args, ctx) -> Report:
    kev_plan = service.plan(args.source)
    consent = service.consent_for(kev_plan, [h for value in args.consent_hosts for h in value.split(',')])
    store = _store(args)
    before = store.load_current()
    transport = KevTransport(consent, opener=ctx.opener, cancel=ctx.cancel, now=ctx.now, sleep=ctx.sleep,
                             announce=lambda line: print(line, file=ctx.err))
    outcome = service.fetch_catalog(store, kev_plan, transport.fetch, ctx.now, accept_shrink=args.accept_shrink)
    meta = outcome.catalog.meta
    report = Report('fetch', plan=kev_plan.model_dump(mode='json'), catalog=_meta_summary(outcome.catalog),
                    final_url=meta.final_url, installed=outcome.installed.current_changed)
    if not outcome.installed.current_changed and before and before.catalog.meta.snapshot_id != meta.snapshot_id:
        report.status = 'partial'
        report.warnings.append(teach.K9_OLDER.format(v1=meta.catalog_version, v2=before.catalog.meta.catalog_version))
    report.text = [status_line(outcome.catalog, ctx.now())]
    return _note_size(report, store)


def _import(args, ctx) -> Report:
    store = _store(args)
    outcome = service.import_file(store, args.file, ctx.now)
    report = Report('import', catalog=_meta_summary(outcome.catalog), installed=outcome.installed.current_changed)
    if not outcome.installed.current_changed:
        report.status = 'partial'
        report.warnings.append(outcome.installed.note or '')
    report.warnings += list(outcome.catalog.meta.warnings)
    report.text = [status_line(outcome.catalog, ctx.now())]
    return _note_size(report, store)


def _md_escape(text: str) -> str:
    return re.sub(r'([\\`*_{}\[\]<>()#+!|~&])', r'\\\1', text.replace('\r', ' ').replace('\n', ' ')) or '-'


def _lookup_row(result: KevLookup, version: str) -> list[str]:
    entry = result.entry
    return [result.cve_id, cell_for(result, version).text, entry.date_added if entry else '-',
            entry.due_date if entry else '-', entry.ransomware_use if entry else '-',
            entry.forensic_triage if entry else '-']


def _markdown(results: tuple[KevLookup, ...], catalog: KevCatalog | None) -> str:
    version = catalog.meta.catalog_version if catalog else ''
    lines = ['### Exploitation context (CISA KEV)', '']
    if catalog:
        meta = catalog.meta
        lines += [f'Catalog {_md_escape(meta.catalog_version)}, released {meta.date_released}, {meta.entry_count} '
                  f'entries, retrieved {meta.retrieved_at[:10]} from {teach.SOURCE_LABELS[meta.source]}, SHA-256 '
                  f'{meta.raw_sha256}, CC0 1.0.', '']
    lines += ['| CVE | KEV | Added to KEV | CISA due date | Known ransomware campaign use | '
              'Forensic triage required by CISA |', '|---|---|---|---|---|---|']
    lines += ['| ' + ' | '.join(_md_escape(cell) for cell in _lookup_row(r, version)) + ' |' for r in results]
    lines += ['', 'KEV lists a CVE as a known exploited vulnerability. It does not identify builds, KBs, files or '
              'functions. Not listed does not mean not exploited.']
    return '\n'.join(lines)


def _lookup(args, ctx) -> Report:
    cves = service.gather_cves(args.cves, args.from_cve_snapshot)
    if not cves:
        raise KevUsage('give at least one CVE ID or --from-cve-snapshot FILE')
    store = _store(args)
    if args.catalog:
        catalog, note = service.open_catalog_file(args.catalog, ctx.now), None
    else:
        loaded = store.load_current()
        catalog, note = (loaded.catalog, loaded.note) if loaded else (None, None)
    results = lookup(catalog, cves, ctx.now())
    version = catalog.meta.catalog_version if catalog else ''
    rows = [{**r.model_dump(mode='json'), 'kev': cell_for(r, version).text} for r in results]
    report = Report('lookup', catalog=_meta_summary(catalog) if catalog else None, lookups=rows)
    if catalog is None:
        report.status, report.exit_code = 'unavailable', NO_CATALOG
        report.text = [teach.K0_NO_CATALOG]
        return report
    report.warnings += [w for w in (note, banner(catalog, ctx.now())) if w]
    invalid = sum(r.status == 'invalid-id' for r in results)
    if invalid:
        report.warnings.append(f'{invalid} input(s) are not valid CVE IDs.')
    report.status = 'partial' if report.warnings else 'ok'
    if args.md:
        report.fields['markdown'] = _markdown(results, catalog)
        report.text = [report.fields['markdown']]
    else:
        report.text = [f'{r.cve_id}  {cell_for(r, version).text}' for r in results]
    return report


def _diff(args, ctx) -> Report:
    delta, newer = service.diff_snapshots(_store(args), args.from_id, args.to_id)
    lines = delta_lines(delta, newer)
    report = Report('diff', delta=delta.model_dump(mode='json'), lines=lines)
    report.text = lines
    return report


def _prune(args, ctx) -> Report:
    store = _store(args)
    removed = store.prune(args.keep, confirmed=args.yes)
    report = Report('prune', removed=removed, kept=len(store.list_snapshots()))
    report.text = [f'Removed {len(removed)} stored catalog(s).']
    return report


VERBS: dict[str, Callable] = {'status': _status, 'plan': _plan, 'fetch': _fetch, 'import': _import,
                              'lookup': _lookup, 'diff': _diff, 'prune': _prune}


class _Context:
    def __init__(self, err, opener, now, sleep, cancel) -> None:
        self.err, self.opener, self.now, self.sleep, self.cancel = err, opener, now, sleep, cancel


def _emit(out, err, args, report: Report) -> None:
    if args.json:
        doc = {'contract': CLI_CONTRACT, 'command': 'kev', 'status': report.status,
               'result': {'contract': limits.CONTRACT, 'record': report.record, **report.fields},
               'warnings': [w for w in report.warnings if w]}
        out.write(json.dumps(doc, sort_keys=True) + '\n')
        return
    out.write('\n'.join(report.text) + '\n')
    for warning in filter(None, report.warnings):  # stderr, so a piped --md table stays clean
        print(f'warning: {warning}', file=err)


def _fail(out, err, argv: list[str], code: int, message: str, status: str = 'failed',
          error: KevError | None = None) -> int:
    print(f'error: {message}' if status == 'failed' else message, file=err)
    if '--json' in argv:
        doc = {'contract': CLI_CONTRACT, 'command': 'kev', 'status': status, 'result': None, 'warnings': []}
        if error is not None:
            doc['error'] = {'code': error.code, 'message': error.message, 'recoverable': error.recoverable}
        elif status == 'failed':
            doc['error'] = {'code': 'PT-KEV-INPUT', 'message': message, 'recoverable': True}
        out.write(json.dumps(doc, sort_keys=True) + '\n')
    return code


def main(argv: list[str] | None = None, *, opener: Callable = urllib_open,
         now: Callable[[], datetime.datetime] | None = None, sleep: Callable | None = None,
         stdout=None, stderr=None) -> int:
    """Run ``kev ...``. ``opener``, ``now`` and ``sleep`` replace the production collaborators (tests)."""
    argv = list(sys.argv[1:] if argv is None else argv)
    out, err = stdout or sys.stdout, stderr or sys.stderr
    clock = now or (lambda: datetime.datetime.now(datetime.UTC))
    try:
        args = build_parser().parse_args(argv)
        ctx = _Context(err, opener, clock, sleep or default_sleep, threading.Event())
        report = VERBS[args.verb](args, ctx)
        _emit(out, err, args, report)
        return report.exit_code
    except KevUsage as exc:
        return _fail(out, err, argv, USAGE, str(exc))
    except KevError as exc:
        return _fail(out, err, argv, exc.exit_code, f'{exc.code}: {exc.message}', error=exc)
    except KeyboardInterrupt:
        return _fail(out, err, argv, CANCELLED, 'cancelled', 'cancelled')
    except SystemExit as exc:  # --help
        return int(exc.code or 0)
    except Exception as exc:  # contract: an unexpected failure is a runtime error, never a traceback
        return _fail(out, err, argv, RUNTIME, type(exc).__name__)
