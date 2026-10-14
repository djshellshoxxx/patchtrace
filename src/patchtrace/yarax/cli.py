"""`patchtrace rules probe|propose|show|decide|test|export|history` (plan s8). Qt-free dispatcher; `cli.py` registers it.

Envelope `enrichment-cli/1`, exits 0 ok / 2 invalid or unavailable / 3 runtime or partial / 4 complete but empty /
5 cancelled. Every verb acts on exactly one named candidate or version: there is no bulk flag. Nothing is uploaded and
no target is executed; the engine runs only in the capped worker child. Output shows basenames and hashes, never paths.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import tempfile
import threading
import uuid
from collections.abc import Sequence
from pathlib import Path

from .contracts import CONTRACT, RuleCandidate, RuleVersion
from .errors import RulesError

VERBS = ('probe', 'propose', 'show', 'decide', 'test', 'export', 'history')
GATE_LABELS: dict[str, str] = {
    'elig': 'Change reviewed as material', 'len': 'Long enough', 'wild': 'Not mostly wildcards',
    'uniq': 'Appears in one place in its own build', 'sep': 'Does not appear in the other build',
    'compile': 'Compiles with YARA-X', 'secret': 'No secret-looking strings', 'dist': 'Builds share one toolchain'}
DISCLAIMER = ('A match means the file contains this pattern. It does not show whether the file is affected by a flaw. '
              'No match does not show that it is unaffected. Counts are raw numbers, not scores.')
UNAVAILABLE_TEXT = ('The rule engine (YARA-X) is not available in this installation. Rules cannot be proposed or '
                    'tested. Saved rules stay readable.')
_RUNTIME_CODES = frozenset({'PT-RULE-ENGINE', 'PT-RULE-TIMEOUT', 'PT-RULE-COMPILE', 'PT-RULE-STORAGE', 'PT-RULE-DECODE',
                            'PT-RULE-MASK', 'PT-RULE-INTEGRITY'})
MAX_EXPECT_BYTES = 1024 * 1024


def register(sub, common, handlers) -> None:
    parser = sub.add_parser('rules', help='detection rules from an accepted function pair (YARA-X; every test runs '
                            'in a capped child process; nothing is uploaded)')
    actions = parser.add_subparsers(dest='action', required=True, parser_class=type(parser))
    common(actions.add_parser('probe', help='engine and decoder versions'))
    propose = common(actions.add_parser('propose', help='propose rules for one accepted function pair'))
    propose.add_argument('project', type=Path)
    propose.add_argument('--match', required=True, metavar='ID')
    propose.add_argument('--direction', choices=('older', 'newer', 'both'), default='both')
    propose.add_argument('--confirm-material', action='store_true',
                         help='you confirm the change is material (the rule is marked unvetted)')
    show = common(actions.add_parser('show', help='list candidates and versions, or show one'))
    show.add_argument('project', type=Path)
    which = show.add_mutually_exclusive_group()
    which.add_argument('--candidate', metavar='ID')
    which.add_argument('--version', metavar='ID')
    decide = common(actions.add_parser('decide', help='accept, reject, defer or archive one candidate'))
    decide.add_argument('project', type=Path)
    decide.add_argument('--candidate', required=True, metavar='ID')
    action = decide.add_mutually_exclusive_group(required=True)
    for name in ('accept', 'reject', 'defer', 'archive'):
        action.add_argument(f'--{name}', dest='decision', action='store_const', const=name)
    decide.add_argument('--label', default='', help='required to accept (1..120 characters)')
    decide.add_argument('--note', default='')
    for name in ('cve', 'kb', 'cwe'):
        decide.add_argument(f'--{name}', action='append', default=[], metavar=name.upper())
    test = common(actions.add_parser('test', help='scan builds and clean files with one saved rule version'))
    test.add_argument('project', type=Path)
    test.add_argument('--version', required=True, metavar='ID')
    test.add_argument('--series', type=Path, metavar='DIR')
    test.add_argument('--extra', type=Path, nargs='+', default=[], metavar='FILE')
    test.add_argument('--clean-dir', type=Path, metavar='DIR')
    test.add_argument('--expect', type=Path, metavar='FILE.json',
                      help='JSON object of file sha256 to "hit" or "no-hit"')
    test.add_argument('--timeout', type=int, default=None, metavar='S', help='seconds per file (5..300)')
    export = common(actions.add_parser('export', help='write one saved rule version as a .yar text file'))
    export.add_argument('project', type=Path)
    export.add_argument('--version', required=True, metavar='ID')
    export.add_argument('--out', required=True, type=Path, metavar='FILE.yar')
    export.add_argument('--include-names', action='store_true', help='include function names (they may come from '
                        'symbol files)')
    export.add_argument('--allow-git-tree', action='store_true', help='I understand and want to save it inside a Git '
                        'working tree')
    export.add_argument('--with-warnings', action='store_true', help='export although the checklist has warnings')
    history = common(actions.add_parser('history', help='saved versions, decisions and exports'))
    history.add_argument('project', type=Path)
    history.add_argument('--lineage', metavar='ID')
    worker = actions.add_parser('_worker', help=argparse.SUPPRESS)
    worker.add_argument('--request', required=True, type=Path)
    handlers['rules'] = dispatch


def dispatch(args, cancel: threading.Event) -> int:
    if args.action == '_worker':   # hidden: the frozen build re-launches itself as the capped child
        from . import worker
        return worker.main(['--request', str(args.request)])
    try:
        return {'probe': _probe, 'propose': _propose, 'show': _show, 'decide': _decide, 'test': _test,
                'export': _export, 'history': _history}[args.action](args, cancel)
    except RulesError as exc:
        return _fail(args, exc)


def _t(value: object, limit: int = 200) -> str:
    from ..intelligence.tools.common import display_text
    return display_text(str('' if value is None else value), limit)


def _fail(args, error: RulesError) -> int:
    from ..cli import CANCELLED, ENVIRONMENT, RUNTIME, _emit
    code = CANCELLED if error.code == 'PT-RULE-CANCEL' else RUNTIME if error.code in _RUNTIME_CODES else ENVIRONMENT
    text = UNAVAILABLE_TEXT if error.code == 'PT-RULE-UNAVAILABLE' else f'{error.code}: {error.message}'
    _emit(args, f'rules {args.action}', 'cancelled' if code == CANCELLED else 'failed',
          {'contract': CONTRACT, 'error_code': error.code, 'message': _t(error.message, 400)}, [], text)
    return code


def _ok(args, result: dict, text: str, *, status: str = 'complete', warnings: Sequence[str] = ()) -> None:
    from ..cli import _emit
    _emit(args, f'rules {args.action}', status, {'contract': CONTRACT, **result}, list(warnings), text)


class _Session:
    """An open project with its rule store; `engine()` binds the capped worker with a private scratch folder."""

    def __init__(self, project: Path, cancel: threading.Event):
        from ..cli import _open
        from ..enrichment.storage import EnrichmentStore
        from .store import RuleStore
        self.cancel = cancel
        self.service = _open(project)
        info = self.service.project
        self.store = RuleStore(EnrichmentStore(self.service.store), self.service.root, info.id, info.revision)
        self._scratch = tempfile.TemporaryDirectory(prefix='ptrules-')

    def engine(self, limits=None):
        from .limits import LIMITS
        from .matrix import worker_engine
        return worker_engine(cancel=self.cancel, private_dir=Path(self._scratch.name), limits=limits or LIMITS)

    def artifact(self, sha256: str):
        found = next((a for a in self.service.project.artifacts if a.sha256 == sha256), None)
        if found is None:
            raise RulesError('PT-RULE-STALE', 'The analysed files of this rule are no longer part of the project.')
        return found

    def anchors(self, older_sha256: str, newer_sha256: str):
        from .matrix import file_target
        out = {}
        for side, sha in (('older', older_sha256), ('newer', newer_sha256)):
            artifact = self.artifact(sha)
            made = file_target(self.service.root / artifact.relative_path, f'{side}-anchor', None, label=artifact.name,
                               sha256=artifact.sha256, size=artifact.size)
            if isinstance(made, str):
                raise RulesError('PT-RULE-STALE', f'The {side} file cannot be read: {made}')
            out[side] = made
        return out

    def close(self) -> None:
        self.service.close()
        self._scratch.cleanup()


def _pick(items: Sequence, key: str, prefix: str, what: str):
    if len(prefix) < 8:
        raise RulesError('PT-RULE-INPUT', f'Give at least 8 characters of the {what} id.')
    found = [item for item in items if getattr(item, key).startswith(prefix)]
    if len(found) != 1:
        raise RulesError('PT-RULE-INPUT', f'The {what} id matches {len(found)} saved items; give a longer id.')
    return found[0]


def _gate_rows(candidate: RuleCandidate) -> list[dict]:
    return [{'gate': g.gate_id, 'label': GATE_LABELS[g.gate_id], 'state': g.state, 'measured': g.measured,
             'detail': _t(g.detail, 300)} for g in candidate.gates]


def _gate_lines(rows: Sequence[dict]) -> list[str]:
    return [f'  {r["label"]}: {r["state"]}' + (f' ({_t(r["measured"], 60)})' if r['measured'] not in (None, '') else '')
            for r in rows]


def _candidate_row(candidate: RuleCandidate, status: str) -> dict:
    return {'candidate_id': candidate.candidate_id, 'lineage_id': candidate.lineage_id,
            'direction': candidate.direction, 'rule_name': candidate.rule_name, 'status': status,
            'unvetted': candidate.unvetted, 'gates': _gate_rows(candidate)}


# ---- probe ------------------------------------------------------------------------------------------------------------

def _probe(args, cancel: threading.Event) -> int:
    from .matrix import worker_engine
    with tempfile.TemporaryDirectory(prefix='ptrules-') as scratch:
        stamp = worker_engine(cancel=cancel, private_dir=Path(scratch)).probe()
    _ok(args, {'engine': stamp.model_dump(mode='json')},
        f'YARA-X {stamp.version} ({stamp.version_source}); decoder {stamp.decoder} {stamp.decoder_version}')
    return 0


# ---- propose ----------------------------------------------------------------------------------------------------------

def _pair_source(session: _Session, match, bases: dict, confirm: bool):
    from ..intelligence.tools.normalize import _record_rva
    from .contracts import FunctionRef, PairSource
    project = session.service.project
    if match.review != 'accepted':
        raise RulesError('PT-RULE-INPUT', 'Select a function pair you have accepted. Rules are only proposed for '
                         'pairs you have reviewed.')
    if match.category not in ('modified', 'added', 'removed') or len(match.older) > 1 or len(match.newer) > 1:
        raise RulesError('PT-RULE-INPUT', 'Rules are proposed for one modified, added or removed function.')
    refs = {}
    for side in ('older', 'newer'):
        records = getattr(match, side)
        if records:
            rva = _record_rva(records[0], bases[side], None)
            if rva is None:
                raise RulesError('PT-RULE-INPUT', 'The function address cannot be placed in its build.')
            refs[side] = FunctionRef(name=records[0].name[:256], rva=rva, size=0, extent='unknown')
    sha = {a.side: a.sha256 for a in project.artifacts}
    return PairSource(project_id=project.id, revision=project.revision, run_id=match.run_id,
                      older_sha256=sha['older'], newer_sha256=sha['newer'], match_id=match.id, category=match.category,
                      materiality='unknown', analyst_confirmed_material=confirm,
                      older=refs.get('older'), newer=refs.get('newer'))


def _sources(session: _Session, pair, cancel: threading.Event):
    """(strings, capabilities, imports, flag codes, secrets left out) from stored evidence; missing is fewer features."""
    from ..artifact_bytes import VerifiedArtifactReader
    from ..intelligence.tools import capa_pairs
    from ..intelligence.tools import delta as delta_mod
    from ..intelligence.tools.cli import _groups
    from ..intelligence.tools.normalize import FunctionPairing
    from ..intelligence.tools.store import ToolStore
    from ..pe_overview import inspect_pe
    from .adapters import pe_imports, tools_delta
    service, project = session.service, session.service.project
    tools = ToolStore(session.store.enrichment, service.root, project.id, project.revision)
    sides = ('older', 'newer')
    floss = {s: tools.latest('floss', s) for s in sides}
    capa = {s: tools.latest('capa', s) for s in sides}
    flags_in = [(tools.latest('diec', s) or (None, None))[1] for s in sides]
    capa_delta = floss_delta = None
    if all(capa.values()):
        flags = delta_mod.quality_flags((flags_in[0], flags_in[1]), (capa['older'][1], capa['newer'][1]))
        capa_delta = capa_pairs.compute_pairs(*capa['older'], *capa['newer'], _groups(service, capa), flags=flags)
    if all(floss.values()):
        bases = {s: floss[s][1].image_base for s in sides}
        pairing = (FunctionPairing.from_project(project.matches, None, older_base=bases['older'],
                                                newer_base=bases['newer'])
                   if project.matches and all(bases.values()) else FunctionPairing.empty())
        floss_delta = delta_mod.compute(*floss['older'], *floss['newer'], pairing=pairing)
    readers = {s: VerifiedArtifactReader.open_artifact(session.artifact(getattr(pair, f'{s}_sha256')), service.root,
                                                       cancel.is_set) for s in sides}
    try:
        overviews = {s: inspect_pe(readers[s], cancel=cancel.is_set) for s in sides}
        capabilities = tools_delta.CapaCapabilitySource(capa_delta)
        strings = tools_delta.FlossStringSource(floss_delta, readers)
        imports = pe_imports.PeImportSource(overviews['older'], overviews['newer'], capabilities)
        # the adapters read lazily, so build the features while the readers are open
        return (_Fixed(strings.string_features(pair)), _Fixed(capabilities.capability_features(pair)),
                _Fixed(imports.import_features(pair)), tools_delta.quality_flag_codes(floss_delta, capa_delta),
                tools_delta.secrets_excluded(floss_delta))
    finally:
        for reader in readers.values():
            reader.close()


class _Fixed:
    """Features already read; satisfies the three source ports."""

    def __init__(self, items):
        self.items = tuple(items)

    def string_features(self, _pair):
        return self.items

    capability_features = import_features = string_features


def _image_bases(session: _Session) -> dict:
    from ..intelligence.tools.store import ToolStore
    project = session.service.project
    tools = ToolStore(session.store.enrichment, session.service.root, project.id, project.revision)
    bases = {}
    for side in ('older', 'newer'):
        found = next((f for f in (tools.latest(e, side) for e in ('capa', 'floss')) if f is not None), None)
        if found is None or not found[1].image_base:
            raise RulesError('PT-RULE-INPUT', 'Stored tool evidence is needed to place function addresses: run '
                             '`intel-tools run` first.')
        bases[side] = found[1].image_base
    return bases


def _propose(args, cancel: threading.Event) -> int:
    from ..cli import CANCELLED, NO_RESULTS, OK
    from . import candidates, gates
    from .matrix import evaluate, synth_writer
    session = _Session(args.project, cancel)
    try:
        match = next((m for m in session.service.project.matches if m.id == args.match), None)
        if match is None:
            raise RulesError('PT-RULE-INPUT', 'No function pair with this id in the project.')
        pair = _pair_source(session, match, _image_bases(session), args.confirm_material)
        if not pair.analyst_confirmed_material:
            raise RulesError('PT-RULE-INPUT', 'The pair has no recorded material verdict here; confirm the change is '
                             'material with --confirm-material (the rule is then marked unvetted).')
        engine = session.engine()
        stamp = engine.probe()
        strings, capabilities, imports, flag_codes, secrets = _sources(session, pair, cancel)
        found = candidates.propose(pair, writer=synth_writer(), engine=stamp, strings=strings,
                                   capabilities=capabilities, imports=imports, flag_codes=flag_codes,
                                   secrets_excluded=secrets)
        found = tuple(c for c in found if args.direction in ('both', c.direction))
        anchors = {side: made.worker() for side, made in session.anchors(pair.older_sha256, pair.newer_sha256).items()}
        checked = [evaluate(c, anchors, engine) for c in found]
        if cancel.is_set():
            return CANCELLED
        for candidate in checked:
            session.store.add_candidate(candidate)
        passing = [c for c in checked if not gates.refused(c.gates)]
        rows = [_candidate_row(c, 'Proposed') for c in checked]
        lines = [f'{r["direction"]} {r["rule_name"]} {r["candidate_id"][:16]}' + (' (unvetted)' if r['unvetted'] else '')
                 for r in rows]
        for row in rows:
            lines += _gate_lines(row['gates'])
        if not checked:
            lines = ['No rule can be anchored in this pair: no string, import or capability belongs to one build only.']
        elif not passing:
            lines.append('No rule passed the checks for this pair.')
        _ok(args, {'match_id': match.id, 'candidates': rows}, '\n'.join(lines),
            status='complete' if passing else 'empty')
        return OK if passing else NO_RESULTS
    finally:
        session.close()


# ---- show / history ---------------------------------------------------------------------------------------------------

def _version_row(version: RuleVersion) -> dict:
    return {'version_id': version.version_id, 'lineage_id': version.lineage_id, 'version': version.version,
            'supersedes': version.supersedes, 'candidate_id': version.candidate_id,
            'rule_sha256': version.rule_sha256, 'created_at': version.created_at}


def _test_row(store, version: RuleVersion) -> dict | None:
    from .matrix import summarize
    tested, candidate = store.latest_test(version.version_id), store.candidate_for(version)
    if tested is None or candidate is None:
        return None
    run, at = tested
    return {'run_id': run.run_id, 'tested_at': at, 'status': run.status,
            **dataclasses.asdict(summarize(run, candidate.rule_name))}


def _show(args, cancel: threading.Event) -> int:
    from .store import lineage_status
    session = _Session(args.project, cancel)
    try:
        store = session.store
        if args.candidate:
            candidate = _pick(store.candidates(), 'candidate_id', args.candidate, 'candidate')
            row = _candidate_row(candidate, lineage_status(store)[candidate.candidate_id])
            row['rule_text'] = candidate.rule_text
            row['features'] = [{'kind': f.kind, 'included': f.included, 'separation': f.separation}
                               for f in candidate.features]
            _ok(args, row, '\n'.join([candidate.rule_text, *_gate_lines(row['gates']), DISCLAIMER]))
            return 0
        if args.version:
            version = _pick(store.versions(), 'version_id', args.version, 'version')
            row = {**_version_row(version), 'rule_text': version.rule_text, 'test': _test_row(store, version)}
            _ok(args, row, '\n'.join([version.rule_text, DISCLAIMER]))
            return 0
        status = lineage_status(store)
        rows = {'candidates': [{'candidate_id': c.candidate_id, 'direction': c.direction, 'rule_name': c.rule_name,
                                'status': status[c.candidate_id]} for c in store.candidates()],
                'versions': [_version_row(v) for v in store.versions()]}
        lines = [f'candidate {c["candidate_id"][:16]} {c["rule_name"]} {c["status"]}' for c in rows['candidates']]
        lines += [f'version {v["version_id"][:16]} {v["lineage_id"][:12]} v{v["version"]}' for v in rows['versions']]
        _ok(args, rows, '\n'.join(lines) or 'No saved rules in this project.')
        return 0
    finally:
        session.close()


def _history(args, cancel: threading.Event) -> int:
    session = _Session(args.project, cancel)
    try:
        store = session.store
        lineage = args.lineage
        if lineage is not None and len(lineage) < 8:
            raise RulesError('PT-RULE-INPUT', 'Give at least 8 characters of the lineage id.')
        versions = [v for v in store.versions() if lineage is None or v.lineage_id.startswith(lineage)]
        decisions = {d.decision_id: d for d in store.decisions()}
        exports = [e for e in store.exports() if e.version_id in {v.version_id for v in versions}]
        rows = [{**_version_row(v), 'label': _t(decisions[v.decision_id].analyst_label, 120)
                 if v.decision_id in decisions else '',
                 'exports': [e.export_id for e in exports if e.version_id == v.version_id]} for v in versions]
        lines = [f'{r["lineage_id"][:12]} v{r["version"]} {r["version_id"][:16]} "{r["label"]}" {r["created_at"]}'
                 f' exports {len(r["exports"])}' for r in rows]
        _ok(args, {'versions': rows}, '\n'.join(lines) or 'No saved rule versions.')
        return 0
    finally:
        session.close()


# ---- decide -----------------------------------------------------------------------------------------------------------

def _decide(args, cancel: threading.Event) -> int:
    session = _Session(args.project, cancel)
    try:
        candidate = _pick(session.store.candidates(), 'candidate_id', args.candidate, 'candidate')
        decision, version = session.store.decide(candidate, args.decision, label=args.label, note=args.note,
                                                 cve=args.cve, kb=args.kb, cwe=args.cwe)
        result = {'decision_id': decision.decision_id, 'action': decision.action,
                  'version': _version_row(version) if version else None}
        text = (f'Accepted as version {version.version} ({version.version_id[:16]}). Nothing was exported.'
                if version else f'Recorded: {decision.action}.')
        _ok(args, result, text)
        return 0
    finally:
        session.close()


# ---- test -------------------------------------------------------------------------------------------------------------

def _expectations(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    from ..persistence import strict_json
    try:
        if path.stat().st_size > MAX_EXPECT_BYTES:
            raise ValueError
        text = path.read_bytes().decode('utf-8')
        strict_json(text)
        data = json.loads(text)
    except (OSError, ValueError):
        raise RulesError('PT-RULE-INPUT', 'The expectation file is not valid JSON.') from None
    import re
    if not isinstance(data, dict) or any(not re.fullmatch(r'[0-9a-f]{64}', k) or v not in ('hit', 'no-hit')
                                         for k, v in data.items()):
        raise RulesError('PT-RULE-INPUT', 'The expectation file must map file sha256 to "hit" or "no-hit".')
    return data


def _limits(timeout: int | None):
    from .limits import LIMITS
    if timeout is None:
        return LIMITS
    if not LIMITS.target_timeout_min_s <= timeout <= LIMITS.target_timeout_max_s:
        raise RulesError('PT-RULE-INPUT', f'--timeout must be {LIMITS.target_timeout_min_s}..'
                         f'{LIMITS.target_timeout_max_s} seconds.')
    return dataclasses.replace(LIMITS, target_timeout_s=timeout)


def _test(args, cancel: threading.Event) -> int:
    from ..cli import CANCELLED, OK, RUNTIME
    from . import matrix
    limits = _limits(args.timeout)
    expected = _expectations(args.expect)
    session = _Session(args.project, cancel)
    try:
        store = session.store
        version = _pick(store.versions(), 'version_id', args.version, 'version')
        candidate = store.candidate_for(version)
        if candidate is None:
            raise RulesError('PT-RULE-INTEGRITY', 'The candidate of this rule version is missing from the project.')
        anchors = session.anchors(version.source.older_sha256, version.source.newer_sha256)
        collected = matrix.collect_targets(tuple(anchors.values()), series_dir=args.series, extra=args.extra,
                                           clean_dir=args.clean_dir, expected=expected, limits=limits)
        rules = [matrix.MatrixRule(name=candidate.rule_name, text=version.rule_text, direction=candidate.direction,
                                   version_id=version.version_id, rule_sha256=version.rule_sha256)]
        engine = session.engine(limits)
        stamp = engine.probe()
        key = matrix.cache_key(rules, collected.targets, stamp, limits)
        older, newer = version.source.older_sha256, version.source.newer_sha256
        run = matrix.run_matrix(
            rules, collected.targets, engine=engine, stamp=stamp, cancel=cancel, run_id=uuid.uuid4().hex,
            skipped=collected.skipped, known=store.checkpoint_cells(key), limits=limits,
            on_chunk=lambda cells: store.add_checkpoint(key, older, newer, cells))
        if run.status != 'cancelled':
            store.add_test(run, [version])
        summary = matrix.summarize(run, candidate.rule_name)
        counts = {state: sum(c.state == state for c in run.cells) for state in
                  ('hit', 'no-hit', 'not-scanned', 'timeout', 'error')}
        verdicts = {v: sum(c.verdict == v for c in run.cells) for v in
                    ('as-expected', 'unexpected-hit', 'unexpected-miss', 'unscored')}
        targets = {t.target_id: t for t in run.targets}
        result = {'run_id': run.run_id, 'cache_key': run.cache_key, 'run_status': run.status, 'counts': counts,
                  'verdicts': verdicts, 'summary': dataclasses.asdict(summary), 'anomalies': list(run.anomalies),
                  'cells': [{'target_id': c.target_id, 'label': _t(targets[c.target_id].label, 120),
                             'role': targets[c.target_id].role, 'sha256': targets[c.target_id].sha256,
                             'state': c.state, 'hits': c.hits, 'rvas': list(c.rvas), 'verdict': c.verdict,
                             'reason': _t(c.reason, 200)} for c in run.cells]}
        lines = [f'{counts["hit"]} match, {counts["no-hit"]} no match, {counts["not-scanned"]} not scanned, '
                 f'{counts["timeout"]} timed out, {counts["error"]} error; unexpected matches '
                 f'{verdicts["unexpected-hit"]}, unexpected no match {verdicts["unexpected-miss"]}']
        lines += [f'Not scanned: {_t(a, 200)}' for a in run.anomalies]
        lines += [DISCLAIMER]
        _ok(args, result, '\n'.join(lines), status=run.status)
        return {'complete': OK, 'cancelled': CANCELLED}.get(run.status, RUNTIME)
    finally:
        session.close()


# ---- export -----------------------------------------------------------------------------------------------------------

def _export(args, cancel: threading.Event) -> int:
    from .. import __version__
    from .export import export_rule
    session = _Session(args.project, cancel)
    try:
        store = session.store
        version = _pick(store.versions(), 'version_id', args.version, 'version')
        older = session.artifact(version.source.older_sha256)
        newer = session.artifact(version.source.newer_sha256)
        try:
            current = session.engine().probe().version
        except RulesError:
            current = None   # an unavailable engine only skips the stale-grid warning; saved rules stay exportable
        record, warnings = export_rule(
            store, version, args.out, product_version=__version__, older_name=Path(older.name).name,
            newer_name=Path(newer.name).name, include_names=args.include_names, allow_git_tree=args.allow_git_tree,
            with_warnings=args.with_warnings, current_engine=current)
        _ok(args, {'export': record.model_dump(mode='json'), 'warnings': [_t(w, 300) for w in warnings]},
            f'Saved {record.basename} (sha256 {record.sha256[:16]}). This computer only; nothing was uploaded.\n'
            'The rule contains byte patterns copied from the analysed files. If those files are third-party software, '
            'check its licence before sharing the rule or committing it to a repository.',
            warnings=[_t(w, 300) for w in warnings])
        return 0
    finally:
        session.close()

