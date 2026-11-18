"""`patchtrace review match|finding|note` (docs/specs/manual-corrections-exchange.md section 6). No Qt.

Thin wrappers over `ProjectService.review_match`, `review_finding` and `annotate`: the desktop's review boxes and
note field for a script. Output is the `enrichment-cli/1` envelope. Exit codes: 0 done; 2 invalid arguments, an
identifier the project does not own, a project that cannot be opened; 3 storage or lock failure; 5 cancelled.
The status and kind vocabularies are read from the models. Text given on the command line is stored unchanged as
data and never printed back in text mode.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import get_args

from .cli_commands import CANCELLED, OK, emit
from .corrections_cli import open_project, service_error
from .corrections_exchange import MAX_NOTE
from .hostile_text import escape_text
from .models import AnalystAnnotation, Finding, FunctionMatch

SUMMARY = 'set the review state of a match or finding, add an analyst note'
MATCH_STATES = get_args(FunctionMatch.model_fields['review'].annotation)
FINDING_STATES = get_args(Finding.model_fields['review'].annotation)
_SERVICE_KINDS = frozenset({'match-override', 'validation'})  # written by correct_match and restore_match_override only
NOTE_KINDS = tuple(kind for kind in get_args(AnalystAnnotation.model_fields['kind'].annotation)
                   if kind not in _SERVICE_KINDS)


def _bounded(text: str) -> str:
    if len(text) > MAX_NOTE:
        raise argparse.ArgumentTypeError(f'must be at most {MAX_NOTE} characters')
    return text


def _note_text(text: str) -> str:
    if not text.strip():
        raise argparse.ArgumentTypeError('must not be blank')
    return _bounded(text)


def add_parser(sub) -> argparse.ArgumentParser:
    parser = sub.add_parser('review', help=SUMMARY)
    actions = parser.add_subparsers(dest='action', required=True)

    def leaf(name: str, help_: str) -> argparse.ArgumentParser:
        item = actions.add_parser(name, help=help_)
        item.set_defaults(command_label=f'review {name}')
        item.add_argument('project', type=Path, help='project directory')
        item.add_argument('--json', action='store_true', help='emit exactly one JSON document on stdout')
        return item

    item = leaf('match', 'set the review state of one function relation')
    item.add_argument('--match', required=True, metavar='ID')
    item.add_argument('--status', required=True, choices=MATCH_STATES)
    item = leaf('finding', 'set the review state and the analyst conclusion of one finding')
    item.add_argument('--finding', required=True, metavar='ID')
    item.add_argument('--status', required=True, choices=FINDING_STATES)
    item.add_argument('--conclusion', type=_bounded, default=None, metavar='TEXT',
                      help='analyst conclusion; omitted: the stored one is kept; "": cleared')
    item = leaf('note', 'add an analyst note or bookmark to a record of the project')
    item.add_argument('--target', required=True, metavar='ID', help='a match, finding or other identifier of the project')
    item.add_argument('--text', required=True, type=_note_text, metavar='TEXT')
    item.add_argument('--kind', choices=NOTE_KINDS, default='note')
    return parser


def _match(service, args) -> tuple[dict, str]:
    previous = next((match.review for match in service.project.matches if match.id == args.match), None)
    service.review_match(args.match, args.status)
    return ({'match_id': args.match, 'status': args.status, 'previous': previous},
            f'Relation {escape_text(args.match)}: review {previous} -> {args.status}.')


def _finding(service, args) -> tuple[dict, str]:
    stored = next((finding for run in service.project.interpretations for finding in run.findings
                   if finding.id == args.finding), None)
    previous, kept = (stored.review, stored.analyst_conclusion) if stored is not None else (None, '')
    # The service call replaces the conclusion; without --conclusion the stored one is passed back.
    conclusion = kept if args.conclusion is None else args.conclusion
    service.review_finding(args.finding, args.status, conclusion)
    told = 'kept' if args.conclusion is None else f'set ({len(conclusion)} characters)' if conclusion else 'cleared'
    return ({'finding_id': args.finding, 'status': args.status, 'previous': previous, 'conclusion': conclusion},
            f'Finding {escape_text(args.finding)}: review {previous} -> {args.status}; conclusion {told}.')


def _note(service, args) -> tuple[dict, str]:
    service.annotate(args.target, args.text, kind=args.kind)
    added = service.project.annotations[-1]
    return ({'annotation_id': added.id, 'target_id': args.target, 'kind': args.kind},
            f'Saved {args.kind} {escape_text(added.id)} on {escape_text(args.target)} ({len(args.text)} characters).')


_LEAVES = {'match': _match, 'finding': _finding, 'note': _note}


def run(args, cancel) -> int:
    label = f'review {args.action}'
    if cancel.is_set():
        emit(args, label, 'cancelled', None, [], '')
        return CANCELLED
    service = open_project(args.project)
    try:
        if cancel.is_set():
            emit(args, label, 'cancelled', None, [], '')
            return CANCELLED
        result, text = _LEAVES[args.action](service, args)
    except ValueError as exc:
        raise service_error(exc) from None
    finally:
        service.close()
    emit(args, label, 'complete', result, [], text)
    return OK
