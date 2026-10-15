"""``patchtrace rules probe|propose|show|decide|test|export|history`` (YRX-integration-plan section 8). Headless: no Qt, and the
YARA-X engine only ever runs in the hidden worker child.

Output is the ``enrichment-cli/1`` envelope; with ``--json`` stdout carries one document whose ``result`` is
``{"contract": "yara-rules/1", "record": ...}``. Exit codes: 0 success; 2 invalid use, refusal or unavailable engine; 3 runtime
failure or a partial result (a file that was not scanned, a stored row that could not be read); 4 complete but empty (no rule
passed the checks); 5 cancelled.

Every action works on ONE candidate, ONE version, ONE project: there is no flag that accepts, rejects or exports many at once.
Accepting stores a version in the project and writes no file; exporting writes the one file named, and never replaces one.
Nothing here touches the network.

The pair of a match, and the evidence of its strings, imports, capabilities and bytes, come from the project through the
`BACKEND` seam (`PairBackend`). It is set by the code that wires the live evidence stores; without it `propose` says so and
changes nothing, and every other action works on what the project already stores.
"""
from __future__ import annotations

import argparse
import contextlib
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from ..cli_commands import CANCELLED, NO_RESULTS, OK, RUNTIME, CliError, emit
from ..enrichment.storage import EnrichmentStore
from ..persistence import safe_path
from ..service import ProjectService
from . import candidates as cd
from . import export as exporting
from . import gates as g
from . import matrix, runner, store
from .contracts import (
    CONTRACT,
    ENGINE_PIN,
    BytesFeature,
    CapabilityFeature,
    ImportFeature,
    MatrixRun,
    PairSource,
    RuleCandidate,
    RuleVersion,
    StringFeature,
    WorkerRule,
)
from .errors import RuleError
from .limits import DEFAULT_LIMITS
from .store import RuleStore

SUMMARY = 'detection rules from reviewed changes: probe, propose, show, decide, test, export, history'
WORKER_VERB = '_rules-worker'
READ_ACTIONS = ('show', 'history')
NO_RULE_TEXT = ('No rule passed the checks for this pair: {reason}. Bytes are unavailable when the function size is not '
                'known (leaf functions without exception data).')
FOOTER = ('A match means the file contains this pattern. It does not show whether the file is affected by a flaw. '
          'No match does not show that it is unaffected. Counts are raw numbers, not scores.')


@dataclass(frozen=True)
class Loaded:
    """What a project knows about one accepted match: the pair, the evidence ports and the local file of each build."""
    pair: PairSource
    sources: cd.Sources
    builds: Mapping[str, str]
    flags: Sequence[str] | None = None


class PairBackend(Protocol):
    def load(self, service: ProjectService, match_id: str) -> Loaded:
        """Raises `RuleError`: `PT-RULE-INPUT` (`no-such-match`, `not-accepted`) or `PT-RULE-STALE`."""
        ...


BACKEND: PairBackend | None = None
CLOCK: Callable[[], str] = lambda: datetime.now(UTC).isoformat(timespec='seconds')   # noqa: E731 - replaced by tests


# --- parser ----------------------------------------------------------------------------------------------------------

def _seconds(text: str) -> int:
    low, high = DEFAULT_LIMITS.target_timeout_min_s, DEFAULT_LIMITS.target_timeout_max_s
    if not (text.isascii() and text.isdigit() and low <= int(text) <= high):
        raise argparse.ArgumentTypeError(f'must be a whole number of seconds, {low} to {high}')
    return int(text)


def add_parser(sub) -> argparse.ArgumentParser:
    parser = sub.add_parser('rules', help=SUMMARY)
    shown = 'probe,propose,show,decide,test,export,history'
    actions = parser.add_subparsers(dest='action', required=True, metavar='{' + shown + '}')

    def leaf(name: str, help_: str, *, project: bool = True) -> argparse.ArgumentParser:
        item = actions.add_parser(name, help=help_)
        item.set_defaults(command_label=f'rules {name}')
        if project:
            item.add_argument('project', type=Path, metavar='PROJECT', help='project directory')
        item.add_argument('--json', action='store_true', help='emit exactly one JSON document on stdout')
        return item

    leaf('probe', 'check that the rule engine starts here (no project needed)', project=False)
    propose = leaf('propose', 'propose rules for one accepted changed-function pair; nothing is accepted')
    propose.add_argument('--match', required=True, metavar='ID', help='the match of the accepted pair')
    propose.add_argument('--direction', choices=('older', 'newer', 'both'), default='both')
    propose.add_argument('--confirm-material', action='store_true',
                         help='you confirm the change is material (the rules are marked unvetted)')
    show = leaf('show', 'show the stored candidates and versions, or one of them')
    one = show.add_mutually_exclusive_group()
    one.add_argument('--candidate', metavar='ID')
    one.add_argument('--version', metavar='ID')
    decide = leaf('decide', 'accept, reject, defer or archive ONE candidate; accepting saves a version and writes no file')
    decide.add_argument('--candidate', required=True, metavar='ID')
    how = decide.add_mutually_exclusive_group(required=True)
    for flag in ('accept', 'reject', 'defer', 'archive'):
        how.add_argument(f'--{flag}', dest='decision', action='store_const', const=flag)
    decide.add_argument('--label', metavar='TEXT', help='required to accept (1 to 120 characters)')
    decide.add_argument('--cve', action='append', default=[], metavar='ID', help='an advisory id you give (repeatable)')
    decide.add_argument('--kb', action='append', default=[], metavar='ID')
    decide.add_argument('--cwe', action='append', default=[], metavar='ID')
    decide.add_argument('--note', default='', metavar='TEXT')
    test = leaf('test', 'scan builds with ONE rule version: the grid of matches and expectations')
    test.add_argument('--version', required=True, metavar='ID')
    test.add_argument('--series', type=Path, metavar='DIR', help='a folder of the series builds (at most 8 files)')
    test.add_argument('--extra', type=Path, action='append', default=[], metavar='FILE', help='another build (repeatable)')
    test.add_argument('--clean-dir', type=Path, metavar='DIR', help='a folder of files that must not match')
    test.add_argument('--expect', type=Path, metavar='FILE.json', help='what you expect: file name or SHA-256 to hit or no-hit')
    test.add_argument('--timeout', type=_seconds, metavar='S', default=None, help='seconds per file (5 to 300)')
    export = leaf('export', 'save ONE rule version as a .yar file on this computer; nothing is uploaded')
    export.add_argument('--version', required=True, metavar='ID')
    export.add_argument('--out', type=Path, required=True, metavar='FILE.yar', help='a new file; it is never replaced')
    export.add_argument('--include-names', action='store_true', help='write function names (they may come from symbols)')
    export.add_argument('--allow-git-tree', action='store_true', help='allow a path inside a Git working tree')
    export.add_argument('--with-warnings', action='store_true', help='export although the checklist has warnings')
    leaf('history', 'decisions, versions, tests and exports in time order').add_argument('--lineage', metavar='ID')
    worker = actions.add_parser(WORKER_VERB)   # no help text: unlisted. The frozen executable's child, not for people
    worker.set_defaults(command_label=f'rules {WORKER_VERB}')
    worker.add_argument('--request', required=True, metavar='REQ.json')
    return parser


# --- run -------------------------------------------------------------------------------------------------------------

def run(args, cancel: threading.Event) -> int:
    if args.action == WORKER_VERB:
        from . import worker
        return worker.main(['--request', args.request])
    command = f'rules {args.action}'
    if cancel.is_set():
        emit(args, command, 'cancelled', None, [], '')
        return CANCELLED
    try:
        if args.action == 'probe':
            return _probe(args, command, cancel)
        with _open(args.project) as (service, rules):
            return _ACTIONS[args.action](args, command, cancel, service, rules)
    except RuleError as exc:
        if exc.code == 'PT-RULE-CANCEL':
            emit(args, command, 'cancelled', None, [], '')
            return CANCELLED
        raise CliError(exc.exit_code, str(exc)) from None


@contextlib.contextmanager
def _open(path: Path) -> Iterator[tuple[ProjectService, RuleStore]]:
    try:
        service = ProjectService.open(path, maintenance=False)
    except ValueError as exc:
        raise CliError(2, str(exc)) from None
    try:
        yield service, RuleStore(EnrichmentStore(service.store), service.root, service.project.id,
                                 service.project.revision)
    finally:
        service.close()


def _conclude(args, command: str, result: dict, rules: RuleStore | None, text: str, *, empty: bool = False,
              warnings: Sequence[str] = ()) -> int:
    """A partial read beats a no-result: a row that could not be read may be the very one that was asked for."""
    found = [*warnings, *(f'{row} could not be read and was not used' for row in dict.fromkeys(rules.skipped if rules else ()))]
    code = RUNTIME if found else NO_RESULTS if empty else OK
    emit(args, command, 'partial' if found else 'complete', {'contract': CONTRACT, **result}, found, text)
    return code


def _lines(rows: Sequence[str]) -> str:
    return '\n'.join(rows)


def _gate(gate) -> dict:
    return {'gate_id': gate.gate_id, 'state': gate.state, 'measured': gate.measured, 'text': g.sentence(gate)}


def _candidate_row(c: RuleCandidate, decisions) -> dict:
    last = decisions[-1].action if decisions else None
    return {'candidate_id': c.candidate_id, 'lineage_id': c.lineage_id, 'direction': c.direction,
            'rule_name': c.rule_name, 'unvetted': c.unvetted, 'decision': last,
            'gates': [_gate(gate) for gate in c.gates]}


def _version_row(v: RuleVersion) -> dict:
    return {'version_id': v.version_id, 'lineage_id': v.lineage_id, 'version': v.version, 'rule_sha256': v.rule_sha256,
            'candidate_id': v.candidate_id, 'created_at': v.created_at}


def _feature_line(f) -> str:
    tick = 'x' if f.included else ' '
    if isinstance(f, BytesFeature):
        what = f'bytes at 0x{f.window_rva:x}: {f.pattern}'
    elif isinstance(f, StringFeature):
        what = f'string "{f.text}"'
    elif isinstance(f, ImportFeature):
        what = f'import {f.dll}!{f.name if f.name is not None else "#" + str(f.ordinal)}'
    elif isinstance(f, CapabilityFeature):
        what = f'capability {f.rule_id}'
    else:
        what = f.kind
    return f'  [{tick}] {what} ({f.separation})'


# --- probe -----------------------------------------------------------------------------------------------------------

def _probe(args, command: str, cancel: threading.Event) -> int:
    found = runner.probe(cancel=cancel)
    stamp = found.engine.model_dump(mode='json')
    result = {'record': 'probe', 'engine': stamp, 'modules': list(found.modules)}
    emit(args, command, 'complete', {'contract': CONTRACT, **result}, [],
         f'{stamp["engine"]} {stamp["version"]} ({stamp["version_source"]}), modules: {" ".join(found.modules)}')
    return OK


# --- propose ---------------------------------------------------------------------------------------------------------

def _propose(args, command, cancel, service, rules: RuleStore) -> int:
    if BACKEND is None:
        raise RuleError('PT-RULE-INPUT', 'This installation cannot read the evidence of a match yet; nothing was proposed',
                        reason='pair-source-missing')
    loaded = BACKEND.load(service, args.match)
    pair = loaded.pair
    if args.confirm_material and pair.materiality != 'material':
        pair = pair.model_copy(update={'analyst_confirmed_material': True})
    directions = cd.DIRECTIONS if args.direction == 'both' else (args.direction,)
    proposal = cd.propose(pair, loaded.sources, check=cd.RunnerChecker(loaded.builds, cancel=cancel),
                          directions=directions, flags=loaded.flags)
    for candidate in proposal.candidates:
        rules.add_candidate(candidate)
    rows = [_candidate_row(c, []) for c in proposal.candidates]
    refused = [{'direction': r.direction, 'reason': r.reason, 'text': r.sentence()} for r in proposal.rejected]
    result = {'record': 'propose', 'match_id': pair.match_id, 'candidates': rows, 'rejected': refused,
              'notes': list(proposal.notes)}
    if not proposal.candidates:
        return _conclude(args, command, result, rules, NO_RULE_TEXT.format(reason=proposal.first_failure() or 'nothing'),
                         empty=True)
    text = [f'{len(rows)} rules proposed. Nothing is accepted until you decide.']
    for c in proposal.candidates:
        text.append(f'{c.candidate_id} {c.rule_name} ({c.direction}){" unvetted" if c.unvetted else ""}')
        text += [f'  {g.sentence(gate)}: {gate.state}' for gate in c.gates]
    return _conclude(args, command, result, rules, _lines(text))


# --- show, history ---------------------------------------------------------------------------------------------------

def _need(found, what: str):
    if found is None:
        raise RuleError('PT-RULE-INPUT', f'No stored {what} has that id', reason=f'no-such-{what}')
    return found


def _show(args, command, cancel, service, rules: RuleStore) -> int:
    if args.version:
        v = _need(rules.version(args.version), 'version')
        result = {'record': 'version', 'version': {**_version_row(v), 'rule_text': v.rule_text}}
        return _conclude(args, command, result, rules, f'{v.version_id} version {v.version}\n{v.rule_text}')
    if args.candidate:
        c = _need(rules.candidate(args.candidate), 'candidate')
        decisions = rules.decisions(c.candidate_id)
        result = {'record': 'candidate', 'candidate': {**_candidate_row(c, decisions), 'rule_text': c.rule_text,
                                                       'features': [f.model_dump(mode='json') for f in c.features]}}
        text = [f'{c.candidate_id} {c.rule_name} ({c.direction})', *(g.sentence(gate) + f': {gate.state}' for gate in c.gates),
                *map(_feature_line, c.features), c.rule_text]
        return _conclude(args, command, result, rules, _lines(text))
    candidates, versions = rules.candidates(), rules.versions()
    result = {'record': 'list', 'candidates': [_candidate_row(c, rules.decisions(c.candidate_id)) for c in candidates],
              'versions': [_version_row(v) for v in versions]}
    text = [f'candidate {c.candidate_id} {c.rule_name}' for c in candidates] + [
        f'version {v.version_id} {v.lineage_id[:12]} v{v.version}' for v in versions]
    return _conclude(args, command, result, rules, _lines(text), empty=not (candidates or versions))


def _history(args, command, cancel, service, rules: RuleStore) -> int:
    lineage = args.lineage
    versions = [v for v in rules.versions() if lineage in (None, v.lineage_id)]
    mine = {v.version_id for v in versions}
    candidates = {c.candidate_id for c in rules.candidates() if lineage in (None, c.lineage_id)}
    events = [(d.decided_at, 'decision', d.decision_id, d.action) for d in rules.decisions() if d.candidate_id in candidates]
    events += [(v.created_at, 'version', v.version_id, f'v{v.version}') for v in versions]
    events += [(r.finished_at, 'test', r.run_id, r.status) for r in rules.tests() if mine & {x.version_id for x in r.rules}]
    events += [(e.exported_at, 'export', e.export_id, e.basename) for e in rules.exports() if e.version_id in mine]
    events.sort()
    result = {'record': 'history', 'events': [{'at': at, 'kind': kind, 'id': ident, 'detail': detail}
                                              for at, kind, ident, detail in events]}
    return _conclude(args, command, result, rules, _lines(f'{at} {kind} {ident} {detail}' for at, kind, ident, detail in events),
                     empty=not events)


# --- decide ----------------------------------------------------------------------------------------------------------

def _decide(args, command, cancel, service, rules: RuleStore) -> int:
    candidate = _need(rules.candidate(args.candidate), 'candidate')
    if args.decision != 'accept':
        if args.label or args.cve or args.kb or args.cwe:
            raise RuleError('PT-RULE-INPUT', 'A label and advisory ids belong to --accept', reason='accept-only')
        decision = store.decision_for(candidate, args.decision, CLOCK(), note=args.note)
        rules.add_decision(decision, candidate.source)
        result = {'record': 'decision', 'decision_id': decision.decision_id, 'action': decision.action}
        return _conclude(args, command, result, rules, f'{decision.decision_id} {decision.action}')
    if not args.label:
        raise RuleError('PT-RULE-INPUT', 'Accepting a rule needs --label', reason='label-required')
    blocked = g.first_blocking(candidate.gates)
    if blocked is not None:
        raise RuleError('PT-RULE-GATE', f'The rule cannot be accepted: {g.sentence(blocked)}', reason='hard-gate')
    version, written = _accept(args, candidate, rules)
    result = {'record': 'version', 'version': _version_row(version), 'written': written}
    text = f'{version.version_id} version {version.version} saved in the project; no file was written'
    return _conclude(args, command, result, rules, text if written else f'{version.version_id} already accepted')


def _accept(args, candidate: RuleCandidate, rules: RuleStore) -> tuple[RuleVersion, bool]:
    """The decision and the version it makes. The same command again after a crash between the two rows finishes the
    second row; an accept that equals the one in force changes nothing; a changed label or id list is a new version."""
    advisories = {name: sorted(set(getattr(args, name))) for name in ('cve', 'kb', 'cwe')}
    held = rules.decisions(candidate.candidate_id)
    last = held[-1] if held else None
    same = last is not None and last.action == 'accept' and (last.analyst_label, last.note) == (args.label, args.note) \
        and all(list(getattr(last, name)) == values for name, values in advisories.items())
    decision = last if same else store.decision_for(candidate, 'accept', CLOCK(), label=args.label, note=args.note,
                                                    **advisories)
    chain = rules.versions(candidate.lineage_id)
    existing = next((v for v in chain if v.decision_id == decision.decision_id), None)
    if existing is not None:
        return existing, False
    version = store.version_for(candidate, decision, chain[-1] if chain else None,
                                store.accepted_text(candidate, decision, len(chain) + 1))
    _must_compile(version)
    rules.add_decision(decision, candidate.source)
    rules.add_version(version)
    return version, True


def _must_compile(version: RuleVersion) -> None:
    (lint,) = runner.lint((WorkerRule(name='accept', text=version.rule_text),))
    gate = g.compiles(lint)
    if not g.passed(gate):
        raise RuleError('PT-RULE-COMPILE', f'The accepted rule does not compile: {g.sentence(gate)}', reason='accept-compile')


# --- test ------------------------------------------------------------------------------------------------------------

def _anchors(service: ProjectService, pair: PairSource) -> dict[str, matrix.Anchor]:
    found = {}
    for artifact in service.project.artifacts:
        if artifact.sha256 == (pair.older_sha256 if artifact.side == 'older' else pair.newer_sha256):
            found[artifact.side] = matrix.Anchor(safe_path(service.root, artifact.relative_path), artifact.name)
    return found


def _test(args, command, cancel, service, rules: RuleStore) -> int:
    version = _need(rules.version(args.version), 'version')
    entries, notes = matrix.gather(version.source, _anchors(service, version.source), series=args.series, extra=args.extra,
                                   clean_dir=args.clean_dir, expect=matrix.read_expectations(args.expect) if args.expect else None)
    timeout = args.timeout
    engine_version = runner.probe(cancel=cancel).engine.version
    key = matrix.cache_key([version], [e.target for e in entries], engine_version,
                           timeout or DEFAULT_LIMITS.target_timeout_s)
    cached = rules.find_test(key)
    if cached is not None:
        grid, reused = matrix.rescored(cached, [e.target for e in entries], [version]), True
    else:
        grid, reused = matrix.run_matrix(entries, [version], scan=runner.scan, timeout_s=timeout, cancel=cancel), False
        rules.add_test(grid, version.source)
    return _report_grid(args, command, rules, grid, reused, notes)


def _report_grid(args, command, rules: RuleStore, grid: MatrixRun, reused: bool, notes: Sequence[str]) -> int:
    count = matrix.totals(grid, 0)
    rows = [{'target_id': t.target_id, 'label': t.label, 'role': t.role, 'sha256': t.sha256, 'expect': t.expect,
             'state': c.state, 'reason': c.reason, 'hits': c.hits, 'rvas': list(c.rvas), 'verdict': c.verdict}
            for t, c in zip(grid.targets, grid.cells, strict=True)]
    result = {'record': 'test', 'run_id': grid.run_id, 'cache_key': grid.cache_key, 'status': grid.status, 'reused': reused,
              'totals': {'match': count.match, 'no_match': count.no_match, 'not_scanned': count.not_scanned,
                         'unexpected_hit': count.unexpected_hit, 'unexpected_miss': count.unexpected_miss},
              'rows': rows, 'footer': FOOTER}
    text = [f'{r["label"]} ({r["role"]}): {_cell_text(r)}' for r in rows]
    text.append(f'{count.match} match, {count.no_match} no match, {count.not_scanned} not scanned, '
                f'{count.unexpected_hit + count.unexpected_miss} unexpected. {FOOTER}')
    warnings = [*notes, *grid.anomalies]
    if grid.status == 'cancelled':
        emit(args, command, 'cancelled', {'contract': CONTRACT, **result}, warnings, _lines(text))
        return CANCELLED
    code = _conclude(args, command, result, rules, _lines(text), warnings=warnings)
    return RUNTIME if grid.status == 'partial' else code


def _cell_text(row: dict) -> str:
    if row['state'] == 'hit':
        return 'Match'
    if row['state'] == 'no-hit':
        return 'No match'
    return {'timeout': 'Timed out', 'error': 'Error'}.get(row['state'], f'Not scanned: {row["reason"]}')


# --- export ----------------------------------------------------------------------------------------------------------

def _export(args, command, cancel, service, rules: RuleStore) -> int:
    version = _need(rules.version(args.version), 'version')
    decision = next((d for d in rules.decisions(version.candidate_id) if d.decision_id == version.decision_id), None)
    basenames = {a.side: a.name for a in service.project.artifacts
                 if a.sha256 == (version.source.older_sha256 if a.side == 'older' else version.source.newer_sha256)}
    plan = exporting.build(version, _need(decision, 'decision'), rules.candidate(version.candidate_id), rules.tests(),
                           include_names=args.include_names, basenames=basenames, engine_version=ENGINE_PIN)
    if plan.warnings and not args.with_warnings:
        raise RuleError('PT-RULE-EXPORT', f'The export has warnings ({", ".join(plan.warnings)}); repeat with --with-warnings '
                        'to export anyway', reason='warnings')
    record = exporting.write(plan, version, args.out, allow_git_tree=args.allow_git_tree)
    rules.add_export(record, version.source)
    result = {'record': 'export', 'export_id': record.export_id, 'basename': record.basename, 'sha256': record.sha256,
              'warnings': list(record.warnings)}
    return _conclude(args, command, result, rules, f'{record.basename} saved on this computer ({record.sha256}); nothing was uploaded',
                     warnings=[f'export warning: {w}' for w in record.warnings])


_ACTIONS: dict[str, Callable] = {'propose': _propose, 'show': _show, 'decide': _decide, 'test': _test, 'export': _export,
                                 'history': _history}
