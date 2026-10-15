"""`patchtrace pilot leads|why|review` (PIL-integration-plan.md s8). Headless: never imports Qt.

`leads` ranks every changed function pair for the code evidence alone and for each stored CVE, stores the result beside
the project (`store.py`) and lists it; `why` explains a lead from the STORED result (nothing is recomputed); `review`
appends a pin, dismissal or note (`review.py`). Output is the `enrichment-cli/1` envelope: with `--json` stdout carries
exactly one document. Exit codes: 0 ok; 2 invalid arguments or input; 3 runtime, storage, integrity or a partial result (an
adapter failed); 4 a legitimate no result (no completed run, no stored advisory for a named CVE, no lead, nothing stored);
5 cancelled. Nothing here sends anything, runs a tool or executes a binary: it reads what the project already holds.

The inputs of a run come from `collect.py`. The parser is built only when the verb is invoked (the registry lists the
others bare), so this module may import pydantic at the top.
"""
from __future__ import annotations

import argparse
import contextlib
import functools
import hashlib
import re
import sqlite3
import threading
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import get_args

from ..cli_commands import CANCELLED, ENVIRONMENT, NO_RESULTS, OK, RUNTIME, CliError, emit
from ..enrichment.contracts import EnrichmentError
from ..enrichment.storage import EnrichmentStore
from ..intelligence.contracts import IntelError
from ..intelligence.reports import plain_text
from . import report, review, store
from .collect import CONFIG, NO_RUN, collect
from .contracts import LEAD_CLASSES, CveContext, Lead, PilotAssessment, ReviewAction
from .limits import PilotError
from .review import LeadReview
from .why import CHANNEL_LABELS, FOOTER, Explainer

DEFAULT_SHOWN = 20  # leads per list unless --limit says otherwise (0 = all)
MAX_CVE_CHARS = 24
NO_STORED = 'No stored leads for this project. Run `patchtrace pilot leads` first.'
_CVE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,19}')
_KEY = re.compile(r'[0-9a-f]{64}')
_INPUT_WORDS = {'older_sha256': 'the older build', 'newer_sha256': 'the newer build',
                'ghidriff_run_id': 'the analysis run', 'raw_sha256': 'the analysis output'}


def _cve(value: str) -> str:
    text = value.strip().upper()
    if not text.isascii() or len(text) > MAX_CVE_CHARS or _CVE.fullmatch(text) is None:
        raise argparse.ArgumentTypeError('must look like CVE-YYYY-NNNN')
    return text


def _key(value: str) -> str:
    if _KEY.fullmatch(value) is None:
        raise argparse.ArgumentTypeError('must be a candidate key: 64 lower-case hexadecimal digits')
    return value


def _count(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError('must be 0 or greater')
    return number


def add_parser(sub) -> argparse.ArgumentParser:
    parser = sub.add_parser(
        'pilot', help='rank changed functions against an advisory: leads, why, review',
        description='Ordered, explained leads for changed function pairs. A lead is a place to look: the order follows '
                    'explainable rules, not likelihood, and a lead does not show that a function contains or fixes '
                    'any CVE. Reads stored results only; nothing is sent or run.')
    actions = parser.add_subparsers(dest='verb', required=True)  # `--action` of review keeps `args.action`

    def leaf(name: str, help_: str, description: str) -> argparse.ArgumentParser:
        p = actions.add_parser(name, help=help_, description=description)
        p.add_argument('project', type=Path)
        p.add_argument('--json', action='store_true', help='emit exactly one JSON document on stdout')
        p.set_defaults(command_label=f'pilot {name}')
        return p

    leads = leaf('leads', 'compute, store and list the leads of the project',
                 'Ranks every changed function pair for the code evidence alone and for each stored CVE advisory '
                 '(--cve only chooses what is shown), stores the result in the project and lists it.')
    leads.add_argument('--cve', action='append', type=_cve, default=[], metavar='CVE-YYYY-NNNN',
                       help='show only this CVE (repeatable)')
    leads.add_argument('--assume-applies', action='append', type=_cve, default=[], metavar='CVE-YYYY-NNNN',
                       help='analyst assumption: this CVE applies to these builds (only fills a gap the advisory leaves)')
    leads.add_argument('--class', dest='classes', action='append', choices=LEAD_CLASSES, default=[],
                       help='show only leads of this class (repeatable)')
    leads.add_argument('--limit', type=_count, default=DEFAULT_SHOWN,
                       help=f'leads shown per list (default {DEFAULT_SHOWN}, 0 = all)')
    leads.add_argument('--no-unified', action='store_true', help='ignore a unified result; pair by Ghidriff and BinDiff')
    leads.add_argument('--show-dismissed', action='store_true', help='also list leads the analyst dismissed')
    leads.add_argument('--dry-run', action='store_true', help='do not store the result in the project')
    leads.add_argument('--export', type=Path, metavar='FILE', help='also write the report; .json or .md (escaped, LF)')
    why = leaf('why', 'explain one lead from the stored result',
               "Prints the plain-text explanation of a lead exactly as stored, with the analyst's statements.")
    why.add_argument('--candidate', required=True, type=_key, metavar='KEY')
    why.add_argument('--cve', type=_cve, metavar='CVE-YYYY-NNNN', help='only the lead of this CVE')
    note = leaf('review', 'pin, dismiss or annotate a lead (append only)',
                "Appends an analyst event. Events never change a lead's class and are never edited or deleted.")
    note.add_argument('--candidate', required=True, type=_key, metavar='KEY')
    note.add_argument('--action', required=True, choices=get_args(ReviewAction))
    note.add_argument('--cve', type=_cve, metavar='CVE-YYYY-NNNN',
                      help='the CVE list the lead is in (omit for the code-only list)')
    note.add_argument('--text', default='', help='a note or a reason (plain text, at most 2 KiB)')
    return parser


# --- plumbing ----------------------------------------------------------------------------------------------------

def _exit_of(exc: Exception) -> int:
    if isinstance(exc, PilotError):
        return exc.exit_code
    code = getattr(exc, 'code', '')
    if code in ('PT-INTEL-CANCEL', 'PT-ENRICH-CANCEL'):
        return CANCELLED
    return ENVIRONMENT if code in ('PT-INTEL-INPUT', 'PT-INTEL-CONFIG', 'PT-ENRICH-INPUT', 'PT-ENRICH-CONFIG') else RUNTIME


def _handled(command: str):
    """Map the typed failures of this feature, K and the enrichment store onto the CLI contract."""
    def wrap(run):
        @functools.wraps(run)
        def inner(args, cancel):
            try:
                return run(args, cancel)
            except (PilotError, IntelError, EnrichmentError) as exc:
                code = _exit_of(exc)
                if code == CANCELLED:
                    emit(args, command, 'cancelled', None, [], '')
                    return CANCELLED
                raise CliError(code, plain_text(str(exc), 600)) from None
            except sqlite3.Error as exc:
                raise CliError(RUNTIME, f'the project database could not be used ({type(exc).__name__})') from None
        return inner
    return wrap


def _say(args, command: str, status: str, result, warnings: Sequence[str], text: str) -> None:
    """Emit the envelope; text mode prints warnings to a terminal, so they are sanitised first."""
    if not args.json:
        warnings = [plain_text(w, 500) for w in warnings]
    emit(args, command, status, result, list(warnings), text)


def _none(args, command: str, result: dict, message: str) -> int:
    _say(args, command, 'complete', result, [], plain_text(message, 600))
    return NO_RESULTS


@contextlib.contextmanager
def _project(path: Path) -> Iterator[tuple[object, EnrichmentStore]]:
    from ..service import ProjectService
    try:
        service = ProjectService.open(path)
    except ValueError as exc:
        raise CliError(ENVIRONMENT, plain_text(str(exc), 300)) from None
    try:
        yield service, EnrichmentStore(service.store)
    finally:
        service.close()


def _export_target(path: Path | None):
    """(path, format) after checking the target; the checks run before any work."""
    if path is None:
        return None
    fmt = report.format_for(path)
    if not path.parent.is_dir():
        raise CliError(ENVIRONMENT, 'the directory of --export does not exist')
    if path.is_dir():
        raise CliError(ENVIRONMENT, '--export names a directory')
    return path, fmt


def _known(project) -> dict[str, object]:
    """What a stored result's identity can be compared with without recomputing it: the pair and its orientation, the
    analysis run and its output."""
    sides = {a.side: a.sha256 for a in project.artifacts}
    run = store.completed_run(project)
    return {'older_sha256': sides.get('older'), 'newer_sha256': sides.get('newer'),
            'ghidriff_run_id': run.id if run else None, 'raw_sha256': run.raw_sha256 if run else None}


def _terminal_line(line: str) -> str:
    """One explanation line for a terminal: controls and bidi marks as `\\uXXXX`, its indentation kept."""
    return ' ' * (len(line) - len(line.lstrip(' '))) + plain_text(line, 300)


def _stale_line(changed: Sequence[str]) -> str:
    what = ', '.join(_INPUT_WORDS.get(name, name.replace('_', ' ')) for name in changed) or 'the project'
    return f'These leads are out of date ({what} changed). They are shown for reference only.'


# --- what a run shows --------------------------------------------------------------------------------------------

def _refs(lead: Lead, side: str) -> list[dict]:
    return [{'rva': ref.rva, 'name': ref.name} for ref in getattr(lead, side)]


def _row(lead: Lead, explainer: Explainer, state: LeadReview | None) -> dict:
    fit = lead.fits[0] if lead.fits else None
    return {'cve': lead.cve, 'rank': lead.rank, 'tie': lead.tie.model_dump(), 'candidate_key': lead.candidate_key,
            'older': _refs(lead, 'older'), 'newer': _refs(lead, 'newer'), 'class': lead.lead_class,
            'badge': report.badge(lead), 'mechanism': lead.mechanism, 'identity': lead.identity, 'depth': lead.depth,
            'expected_changes': {'met': fit.met, 'total': fit.total} if fit else None,
            'components': lead.components.count, 'flags': list(report.flags(lead, state)),
            'pinned': bool(state and state.pinned), 'dismissed': bool(state and state.dismissed),
            'why': list(explainer.explain(lead))}


def _selection(a: PilotAssessment, args, reviews: Mapping) -> tuple[list[tuple[CveContext | None, list[Lead]]], int]:
    """The leads each list shows (class filter, dismissed hidden, the Pinned band first, `--limit`) and how many were
    dismissed. `--cve` picks the lists; without it every CVE list is shown, then the code-only list."""
    contexts = [c for c in a.cves if c.cve in args.cve] if args.cve else [
        *a.cves, *([None] if any(lead.cve is None for lead in a.leads) else [])]
    shown, hidden = [], 0
    for context in contexts:
        key = context.cve if context else None
        leads = [x for x in a.leads if x.cve == key and (not args.classes or x.lead_class in args.classes)]
        kept = [x for x in leads if args.show_dismissed or not reviews.get((x.candidate_key, key), LeadReview()).dismissed]
        hidden += len(leads) - len(kept)
        kept = review.pinned_first(kept, reviews)
        shown.append((context, kept[:args.limit] if args.limit else kept))
    return shown, hidden


def _listing(leads: Sequence[Lead], reviews: Mapping) -> list[str]:
    head = f'  {"#":<11} {"class":<16} {"seen":<7} {"groups":<6} function'
    return [head, *(f'  {report.rank_text(x):<11} {report.badge(x):<16} {report.expected_seen(x):<7} '
                    f'{x.components.count:<6} {report.plain_label(x)}'
                    + ''.join(f' [{w}]' for w in report.flags(x, reviews.get((x.candidate_key, x.cve))))
                    for x in leads)]


def _context_lines(context: CveContext | None, leads: Sequence[Lead], reviews: Mapping) -> list[str]:
    if context is None:
        return ['', report.CODE_ONLY_TITLE, *_listing(leads, reviews)]
    n = context.counts
    lines = ['', f'{context.cve}  {report.CWE_WORDS[context.cwe.status]}  {report.kev_text(context.kev)}',
             f'  leads: fits advisory {n.fit}; needs review {n.review}; partial fit {n.partial}; code change {n.code}; '
             f'changed, no fit {n.queue}']
    if context.gate in report.GATE_BANNERS:
        lines.append(f'  {report.GATE_BANNERS[context.gate]}')
    if context.confounding.state == 'yes':
        lines.append(f'  {report.window_text(len(context.confounding.cves))}')
    return [*lines, *_listing(leads, reviews)] if leads else lines


def _text(a: PilotAssessment, shown, reviews: Mapping, hidden: int, stored: bool) -> str:
    gaps = [CHANNEL_LABELS[c.channel] for c in a.channels if c.state != 'available']
    lines = [f'result {a.result_id[:16]} ({report.STATUS_WORDS[a.status]}), older build {a.older_sha256[:12]}, '
             f'newer build {a.newer_sha256[:12]}, {"stored" if stored else "not stored"}']
    if gaps:
        lines.append(f'Some evidence was not available: {", ".join(gaps)}. {report.MISSING_EVIDENCE}')
    for context, leads in shown:
        lines += _context_lines(context, leads, reviews)
    if hidden:
        lines.append(f'\n{hidden} dismissed leads are hidden (--show-dismissed lists them).')
    if a.queue_count:
        lines.append(f'{a.queue_count} changed functions with no fit are counted but not listed.')
    notes = [plain_text(line, 300) for line in a.limitations]
    return '\n'.join([*lines, '', *([*notes, ''] if notes else []), FOOTER])


def _result(a: PilotAssessment, shown, reviews: Mapping, hidden: int, stored: bool, stale: bool) -> dict:
    explainer = Explainer(a)
    return {
        'result_id': a.result_id, 'status': a.status, 'created_utc': a.created_utc, 'older_sha256': a.older_sha256,
        'newer_sha256': a.newer_sha256, 'orientation': a.orientation, 'stored': stored, 'stale': stale,
        'channels': [c.model_dump(mode='json') for c in a.channels],
        'cves': [{'cve': c.cve, 'gate': c.gate, 'kev': c.kev.model_dump(mode='json'),
                  'window': c.confounding.state, 'counts': c.counts.model_dump()} for c in a.cves],
        'leads': [_row(x, explainer, reviews.get((x.candidate_key, x.cve))) for _c, leads in shown for x in leads],
        'dismissed_hidden': hidden, 'queue_count': a.queue_count, 'limitations': list(a.limitations),
        'limits_hit': list(a.limits_hit), 'export': None}


# --- leads -------------------------------------------------------------------------------------------------------

def _persist(enrichment: EnrichmentStore, service, assessment: PilotAssessment, warnings: list[str]):
    try:
        published = store.publish(enrichment, assessment, CONFIG,
                                  current=store.current_guard(service.project, assessment.result_id))
    except PilotError as exc:
        warnings.append(f'results not persisted: {exc.message}')
        return None
    if published.entry.stale:
        warnings.append('the project changed while the leads were computed; the result was stored as out of date')
    return published


def _nothing_to_rank(args, command: str, exc: PilotError) -> int:
    """A named CVE without a stored advisory, or a project without a completed run: legitimate no result (exit 4)."""
    empty = {'result_id': None, 'leads': [], 'cves': [], 'channels': [], 'limitations': [exc.message]}
    if exc.reason == 'no-run':
        return _none(args, command, empty | {'status': 'abstained'}, NO_RUN)
    return _none(args, command, empty | {'status': 'complete'}, f'{exc.message}; import it with '
                 '`patchtrace intelligence import` first')


@_handled('pilot leads')
def _run_leads(args, cancel: threading.Event) -> int:
    from .service import localize
    command = 'pilot leads'
    target = _export_target(args.export)
    with _project(args.project) as (service, enrichment):
        try:
            collected = collect(service, enrichment, named=args.cve, assume=args.assume_applies,
                                unified=not args.no_unified, cancel=cancel)
        except PilotError as exc:
            if exc.code != 'PT-PILOT-NOTFOUND':
                raise
            return _nothing_to_rank(args, command, exc)
        assessment = localize(collected, CONFIG, cancel)
        warnings = list(collected.notes)
        published = None if args.dry_run else _persist(enrichment, service, assessment, warnings)
        reviews = review.fold(review.read(enrichment).events)
    selection, hidden = _selection(assessment, args, reviews)
    result = _result(assessment, selection, reviews, hidden, published is not None,
                     bool(published and published.entry.stale))
    text = _text(assessment, selection, reviews, hidden, published is not None)
    if target is not None:
        path, fmt = target
        data = report.render(assessment, fmt, reviews)
        report.write_export(path, data)
        result['export'] = {'format': fmt, 'path': str(path), 'bytes': len(data),
                            'sha256': hashlib.sha256(data).hexdigest()}
        text += f'\nexported the {fmt} report to {plain_text(path, 300)} ({len(data)} bytes)'
    _say(args, command, 'partial' if assessment.status == 'partial' else 'complete', result, warnings, text)
    if assessment.status == 'partial':
        return RUNTIME
    return NO_RESULTS if assessment.status == 'abstained' or not result['leads'] else OK


# --- why and review ----------------------------------------------------------------------------------------------

def _stored(service, enrichment: EnrichmentStore) -> store.Loaded:
    """The stored result: nothing stored has no assessment (exit 4), one that does not verify is exit 3."""
    loaded = store.load(enrichment, _known(service.project))
    if loaded.state == 'invalid':
        raise PilotError('PT-PILOT-INTEGRITY', 'The stored result does not verify; run `patchtrace pilot leads` again',
                         reason=loaded.reason)
    return loaded


def _statement(event) -> dict:
    return {'created_utc': event.created_utc, 'action': event.action, 'text': event.text}


@_handled('pilot why')
def _run_why(args, cancel: threading.Event) -> int:
    command = 'pilot why'
    with _project(args.project) as (service, enrichment):
        loaded = _stored(service, enrichment)
        reviews = review.fold(review.read(enrichment).events)
    base = {'result_id': None, 'candidate_key': args.candidate, 'stale': False, 'changed': [], 'leads': []}
    assessment = loaded.assessment
    if assessment is None:
        return _none(args, command, base, NO_STORED)
    leads = [x for x in assessment.leads if x.candidate_key == args.candidate and args.cve in (None, x.cve)]
    stale = loaded.state == 'stale'
    base |= {'result_id': assessment.result_id, 'stale': stale, 'changed': list(loaded.changed)}
    if not leads:
        return _none(args, command, base, 'The stored result has no lead with this key'
                     + (f' in the list of {args.cve}' if args.cve else '') + '.')
    explainer, rows, lines = Explainer(assessment), [], []
    for lead in leads:
        state = reviews.get((lead.candidate_key, lead.cve))
        rows.append(_row(lead, explainer, state) | {'statements': [_statement(e) for e in state.statements] if state else []})
        lines += ['', f'{lead.cve or report.CODE_ONLY_TITLE}: {report.badge(lead)}, rank {report.rank_text(lead)}',
                  *map(_terminal_line, rows[-1]['why'])]
        if state and state.statements:
            lines += ['Analyst statement', *(f'- {e.created_utc[:10]}: {plain_text(e.text.strip(), 2000)}'
                                             for e in state.statements)]
    _say(args, command, 'complete', base | {'leads': rows}, [_stale_line(loaded.changed)] if stale else [],
         '\n'.join(lines).lstrip('\n'))
    return OK


@_handled('pilot review')
def _run_review(args, cancel: threading.Event) -> int:
    command = 'pilot review'
    with _project(args.project) as (service, enrichment):
        loaded = _stored(service, enrichment)
        base = {'candidate_key': args.candidate, 'cve': args.cve, 'event': None}
        if loaded.assessment is None:
            return _none(args, command, base, NO_STORED)
        if not any(x.candidate_key == args.candidate and x.cve == args.cve for x in loaded.assessment.leads):
            return _none(args, command, base, 'The stored result has no such lead; nothing was recorded.')
        event = review.append(enrichment, project_id=service.project.id, revision=service.project.revision,
                              candidate_key=args.candidate, cve=args.cve, action=args.action, text=args.text)
        state = review.fold(review.read(enrichment).events)[(args.candidate, args.cve)]
    result = base | {'event': event.model_dump(mode='json'), 'pinned': state.pinned, 'dismissed': state.dismissed}
    _say(args, command, 'complete', result, [],
         f'recorded {args.action} for the lead of {args.cve or "the code-only list"}')
    return OK


RUNNERS = {'leads': _run_leads, 'why': _run_why, 'review': _run_review}


def run(args, cancel: threading.Event) -> int:
    return RUNNERS[args.verb](args, cancel)
