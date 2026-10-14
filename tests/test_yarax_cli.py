"""R5 CLI: `patchtrace rules ...` through the real argparse tree and the real worker, on a project built from the
SYNTHETIC floss-static pair with a FAKE floss executable that prints committed real FLOSS output."""
from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

yara_x = pytest.importorskip('yara_x')

from intel_tools_support import fake_engine, golden  # noqa: E402
from test_intel_tools_cli import clean_env  # noqa: E402, F401  (clean_env is a fixture)
from test_intel_tools_pe import PAIRS  # noqa: E402

from patchtrace import cli  # noqa: E402
from patchtrace.models import AnalysisRun, FunctionMatch, FunctionRecord  # noqa: E402
from patchtrace.service import ProjectService  # noqa: E402
from patchtrace.yarax import cli as rules_cli  # noqa: E402
from patchtrace.yarax import runner  # noqa: E402
from patchtrace.yarax.contracts import WorkerRequest  # noqa: E402

BASE = 0x140000000
SRC = Path(__file__).resolve().parents[1] / 'src'
YARAX = SRC / 'patchtrace' / 'yarax'


def add_matches(root):
    service = ProjectService.open(root)
    try:
        project = service.project
        ids = {a.side: a.id for a in project.artifacts}
        project.runs.append(AnalysisRun(id='run-1', status='completed'))

        def records(side, rva):
            return [FunctionRecord(id=f'fn-{side}-{rva:x}', artifact_id=ids[side], run_id='run-1', name=f'{side}_{rva:x}',
                                   address=f'{BASE + rva:x}', address_space='virtual')]
        for match_id, review, rva in (('m-accepted', 'accepted', 0x1000), ('m-open', 'unreviewed', 0x1010)):
            project.matches.append(FunctionMatch(id=match_id, run_id='run-1', category='modified', review=review,
                                                 older=records('older', rva), newer=records('newer', rva)))
        service.save()
    finally:
        service.close()


@pytest.fixture
def root(tmp_path, clean_env):  # noqa: F811
    """A project with stored FLOSS evidence for both builds and two matched functions."""
    files = {}
    for side, data in zip(('older', 'newer'), PAIRS['floss-static'](), strict=True):
        files[side] = tmp_path / f'{side}.exe'
        files[side].write_bytes(data)
    service = ProjectService.create(files['older'], files['newer'], 'rules', tmp_path / 'case')
    root = service.root
    try:
        outputs = {a.sha256: golden(f'floss/floss-static-{a.side}.static.json').decode() for a in service.project.artifacts}
    finally:
        service.close()
    body = ('import hashlib\nsha = hashlib.sha256(open(ARGS[-1], "rb").read()).hexdigest()\n'
            f'OUT = {outputs!r}\nsys.stdout.write(OUT[sha])\n')
    exe = fake_engine(tmp_path / 'bin', 'floss', run_body=body)
    assert cli.main(['intel-tools', 'run', str(root), '--profile', 'context', '--engines', 'floss', '--floss', str(exe), '--floss-accept-untested', '--json']) == 0
    add_matches(root)
    return root


def run_rules(capsys, *argv):
    parser = cli._Parser(prog='patchtrace')
    sub = parser.add_subparsers(dest='command', required=True, parser_class=cli._Parser)
    handlers: dict = {}
    rules_cli.register(sub, lambda p: p.add_argument('--json', action='store_true') and p or p, handlers)
    capsys.readouterr()
    try:
        code = handlers['rules'](parser.parse_args(['rules', *argv]), threading.Event())
    except cli.CliError as exc:
        code = exc.code
    out, err = capsys.readouterr()
    return code, out, err


def doc(out):
    return json.loads(out)


def propose(capsys, root, *extra, match='m-accepted'):
    return run_rules(capsys, 'propose', str(root), '--match', match, '--confirm-material', '--json', *extra)


def test_probe_reports_the_engine_stamp(capsys):
    code, out, _err = run_rules(capsys, 'probe', '--json')
    document = doc(out)
    assert code == 0 and document['contract'] == 'enrichment-cli/1' and document['command'] == 'rules probe'
    assert document['result']['engine']['version'] == '1.21.0' and document['result']['contract'] == 'yara-rules/1'


def test_probe_without_the_wheel_is_exit_2_with_the_unavailable_text(capsys, monkeypatch):
    monkeypatch.setattr(runner, 'engine_installed', lambda: False)
    code, out, _err = run_rules(capsys, 'probe', '--json')
    assert code == 2 and doc(out)['result']['error_code'] == 'PT-RULE-UNAVAILABLE'
    code, out, _err = run_rules(capsys, 'probe')
    assert 'The rule engine (YARA-X) is not available in this installation.' in out


def test_propose_runs_the_real_gates_and_saves_candidates(capsys, root):
    code, out, _err = propose(capsys, root)
    result = doc(out)['result']
    assert code == 0 and {c['direction'] for c in result['candidates']} == {'older', 'newer'}
    for candidate in result['candidates']:
        states = {g['gate']: g['state'] for g in candidate['gates']}
        assert states['compile'] == 'pass' and states['sep'] == 'pass' and candidate['unvetted'] is True
    assert str(root) not in out
    listed = doc(run_rules(capsys, 'show', str(root), '--json')[1])['result']
    assert {c['status'] for c in listed['candidates']} == {'Proposed'} and len(listed['candidates']) == 2


def test_propose_one_direction_only(capsys, root):
    code, out, _err = propose(capsys, root, '--direction', 'newer')
    assert code == 0 and [c['direction'] for c in doc(out)['result']['candidates']] == ['newer']


@pytest.mark.parametrize('argv,needle', [
    (['--match', 'nope', '--confirm-material'], 'No function pair with this id'),
    (['--match', 'm-open', '--confirm-material'], 'Select a function pair you have accepted'),
    (['--match', 'm-accepted'], '--confirm-material')], ids=['unknown', 'unreviewed', 'unconfirmed'])
def test_propose_refuses_pairs_that_are_not_eligible(capsys, root, argv, needle):
    code, out, _err = run_rules(capsys, 'propose', str(root), *argv, '--json')
    assert code == 2 and needle in doc(out)['result']['message']
    assert doc(run_rules(capsys, 'show', str(root), '--json')[1])['result']['candidates'] == []


def candidate_ids(capsys, root):
    return {c['direction']: c['candidate_id'] for c in
            doc(run_rules(capsys, 'show', str(root), '--json')[1])['result']['candidates']}


def accept(capsys, root, direction='newer', label='Length check added', *extra):
    ids = candidate_ids(capsys, root)
    return run_rules(capsys, 'decide', str(root), '--candidate', ids[direction][:16], '--accept', '--label', label,
                     '--json', *extra)


def test_decide_accept_needs_a_label_and_an_unambiguous_id(capsys, root):
    propose(capsys, root)
    ids = candidate_ids(capsys, root)
    code, out, _err = run_rules(capsys, 'decide', str(root), '--candidate', ids['newer'], '--accept', '--json')
    assert code == 2 and 'label' in doc(out)['result']['message']
    code, out, _err = run_rules(capsys, 'decide', str(root), '--candidate', ids['newer'][:4], '--reject', '--json')
    assert code == 2 and 'at least 8' in doc(out)['result']['message']
    code, out, _err = run_rules(capsys, 'decide', str(root), '--candidate', 'f' * 16, '--reject', '--json')
    assert code == 2 and 'matches 0' in doc(out)['result']['message']


def test_accept_saves_a_version_and_exports_nothing(capsys, root, tmp_path):
    propose(capsys, root)
    code, out, _err = accept(capsys, root, 'newer', 'Length check added', '--cve', 'CVE-2026-0001', '--kb', 'KB5000001')
    result = doc(out)['result']
    assert 'Nothing was exported' in run_rules(capsys, 'decide', str(root), '--candidate', result['version']['candidate_id'],
                                               '--accept', '--label', 'Length check added', '--cve', 'CVE-2026-0001',
                                               '--kb', 'KB5000001')[1]
    assert code == 0 and result['version']['version'] == 1
    shown = doc(run_rules(capsys, 'show', str(root), '--version', result['version']['version_id'][:16], '--json')[1])
    assert 'analyst_label' in shown['result']['rule_text'] and shown['result']['test'] is None
    history = doc(run_rules(capsys, 'history', str(root), '--json')[1])['result']['versions']
    assert [(v['version'], v['label'], v['exports']) for v in history] == [(1, 'Length check added', [])]
    assert list(tmp_path.glob('*.yar')) == []


@pytest.mark.parametrize('flag,status', [('--reject', 'Rejected'), ('--defer', 'Deferred'), ('--archive', 'Archived')],
                         ids=['reject', 'defer', 'archive'])
def test_other_decisions_change_the_status_only(capsys, root, flag, status):
    propose(capsys, root)
    ids = candidate_ids(capsys, root)
    assert run_rules(capsys, 'decide', str(root), '--candidate', ids['older'], flag, '--json')[0] == 0
    shown = doc(run_rules(capsys, 'show', str(root), '--candidate', ids['older'], '--json')[1])['result']
    assert shown['status'] == status
    assert doc(run_rules(capsys, 'show', str(root), '--json')[1])['result']['versions'] == []


def version_id(capsys, root):
    propose(capsys, root)
    return doc(accept(capsys, root)[1])['result']['version']['version_id']


def clean_dir(tmp_path, *, with_text=False):
    clean = tmp_path / 'clean'
    clean.mkdir()
    (clean / 'a.dll').write_bytes(PAIRS['capa-api']()[0])
    if with_text:
        (clean / 'notes.txt').write_bytes(b'not an executable')
    return clean


def test_test_scans_the_builds_and_clean_files_with_raw_counts(capsys, root, tmp_path):
    vid = version_id(capsys, root)
    code, out, _err = run_rules(capsys, 'test', str(root), '--version', vid, '--clean-dir', str(clean_dir(tmp_path)),
                                '--json')
    result = doc(out)['result']
    assert code == 0 and result['run_status'] == 'complete'
    assert result['counts'] == {'hit': 1, 'no-hit': 2, 'not-scanned': 0, 'timeout': 0, 'error': 0}
    assert result['verdicts']['as-expected'] == 3 and result['summary']['clean'] == 1
    assert str(tmp_path) not in out and 'confidence' not in out
    shown = doc(run_rules(capsys, 'show', str(root), '--version', vid, '--json')[1])['result']
    assert shown['test']['builds'] == 2 and shown['test']['unexpected_hits'] == 0


def test_a_file_that_is_not_a_pe_makes_the_run_partial_never_no_match(capsys, root, tmp_path):
    vid = version_id(capsys, root)
    code, out, _err = run_rules(capsys, 'test', str(root), '--version', vid,
                                '--clean-dir', str(clean_dir(tmp_path, with_text=True)), '--json')
    result = doc(out)['result']
    assert code == 3 and doc(out)['status'] == 'partial' and result['counts']['not-scanned'] == 1
    cell = next(c for c in result['cells'] if c['label'] == 'notes.txt')
    assert (cell['state'], cell['reason'], cell['verdict']) == ('not-scanned', 'not a PE image', 'unscored')


def test_expectations_turn_unexpected_results_into_verdicts(capsys, root, tmp_path):
    vid = version_id(capsys, root)
    extra = tmp_path / 'extra.dll'
    extra.write_bytes(PAIRS['floss-static']()[1])   # the newer build again: the rule is newer-side and must hit
    sha = hashlib.sha256(extra.read_bytes()).hexdigest()
    expect = tmp_path / 'expect.json'
    expect.write_text(json.dumps({sha: 'no-hit'}), encoding='utf-8')
    code, out, _err = run_rules(capsys, 'test', str(root), '--version', vid, '--extra', str(extra),
                                '--expect', str(expect), '--json')
    assert code == 0 and doc(out)['result']['verdicts']['unexpected-hit'] == 1
    assert doc(run_rules(capsys, 'export', str(root), '--version', vid, '--out', str(tmp_path / 'u.yar'),
                         '--json')[1])['result']['message'].startswith('Export needs confirmation')


@pytest.mark.parametrize('timeout', ['1', '301'], ids=['low', 'high'])
def test_timeout_is_bounded(capsys, root, timeout):
    vid = version_id(capsys, root)
    code, out, _err = run_rules(capsys, 'test', str(root), '--version', vid, '--timeout', timeout, '--json')
    assert code == 2 and '5..300' in doc(out)['result']['message']


@pytest.mark.parametrize('content', ['{bad', '[]', '{"zz": "hit"}', '{"%s": "maybe"}' % ('a' * 64)],
                         ids=['syntax', 'list', 'key', 'value'])
def test_expectation_files_are_validated(capsys, root, tmp_path, content):
    vid = version_id(capsys, root)
    expect = tmp_path / 'e.json'
    expect.write_text(content, encoding='utf-8')
    code, out, _err = run_rules(capsys, 'test', str(root), '--version', vid, '--expect', str(expect), '--json')
    assert code == 2 and doc(out)['result']['error_code'] == 'PT-RULE-INPUT'


def test_export_writes_one_file_after_a_test_and_records_it(capsys, root, tmp_path):
    vid = version_id(capsys, root)
    run_rules(capsys, 'test', str(root), '--version', vid, '--clean-dir', str(clean_dir(tmp_path)), '--json')
    out_dir = tmp_path / 'out'
    out_dir.mkdir()
    argv = ['export', str(root), '--version', vid, '--out', str(out_dir / 'rule.yar'), '--json']
    code, out, _err = run_rules(capsys, *argv)   # CLI proposals are analyst-confirmed, so they are unvetted
    assert code == 2 and 'not reviewed as material' in doc(out)['result']['message']
    code, out, _err = run_rules(capsys, *argv, '--with-warnings')
    result = doc(out)['result']
    text = (out_dir / 'rule.yar').read_text(encoding='utf-8')
    assert code == 0 and result['export']['basename'] == 'rule.yar'
    assert result['warnings'] == ['the change was not reviewed as material; the analyst confirmed it']
    assert text.startswith('// patchtrace-rule-export/1\n') and 'Tested 20' in text and str(tmp_path) not in text
    history = doc(run_rules(capsys, 'history', str(root), '--json')[1])['result']['versions']
    assert len(history[0]['exports']) == 1
    code, out, _err = run_rules(capsys, *argv, '--with-warnings')
    assert code == 2 and 'already exists' in doc(out)['result']['message']


def test_export_of_an_untested_rule_needs_the_warning_box(capsys, root, tmp_path):
    vid = version_id(capsys, root)
    target = tmp_path / 'u.yar'
    code, out, _err = run_rules(capsys, 'export', str(root), '--version', vid, '--out', str(target), '--json')
    assert code == 2 and 'not tested' in doc(out)['result']['message'] and not target.exists()
    code, out, _err = run_rules(capsys, 'export', str(root), '--version', vid, '--out', str(target), '--with-warnings',
                                '--json')
    assert code == 0 and 'not tested on any build or clean file' in doc(out)['warnings']
    assert 'Not tested' in target.read_text(encoding='utf-8')


def test_export_into_a_git_tree_needs_its_own_confirmation(capsys, root, tmp_path):
    vid = version_id(capsys, root)
    repo = tmp_path / 'repo'
    (repo / '.git').mkdir(parents=True)
    argv = ['export', str(root), '--version', vid, '--out', str(repo / 'r.yar'), '--with-warnings', '--json']
    assert run_rules(capsys, *argv)[0] == 2
    assert run_rules(capsys, *argv, '--allow-git-tree')[0] == 0


def test_the_hidden_worker_verb_runs_one_request(capsys, tmp_path):
    result = tmp_path / 'out.json'
    request = tmp_path / 'req.json'
    request.write_text(WorkerRequest(op='probe', limits=runner.worker_limits(), result=str(result)).model_dump_json(),
                       encoding='utf-8')
    code, _out, _err = run_rules(capsys, '_worker', '--request', str(request))
    assert code == 0 and json.loads(result.read_text(encoding='utf-8'))['engine']['version'] == '1.21.0'


def test_cli_has_no_bulk_flags():
    parser = cli._Parser(prog='patchtrace')
    sub = parser.add_subparsers(dest='command', required=True, parser_class=cli._Parser)
    rules_cli.register(sub, lambda p: p, {})
    verbs = next(a for a in sub.choices['rules']._actions if a.choices).choices
    flags = {opt for verb in verbs.values() for action in verb._actions for opt in action.option_strings}
    assert not flags & {'--all', '--bulk', '--yes', '--force', '--all-candidates', '--accept-all', '--no-confirm'}
    for verb in ('decide', 'test', 'export'):
        ids = [a for a in verbs[verb]._actions if a.dest in ('candidate', 'version')]
        assert ids and all(a.nargs is None and a.required for a in ids)
    assert set(verbs) == {'probe', 'propose', 'show', 'decide', 'test', 'export', 'history', '_worker'}


def test_rules_cli_never_loads_qt_or_the_engine():
    code = ('import sys, patchtrace.yarax.cli, patchtrace.yarax.store, patchtrace.yarax.export, '
            'patchtrace.yarax.matrix\n'
            'bad = [m for m in sys.modules if m.split(".")[0] in ("PySide6", "yara_x", "iced_x86")]\n'
            'assert not bad, bad')
    done = subprocess.run([sys.executable, '-c', code], env={'PYTHONPATH': str(SRC)}, capture_output=True,
                          text=True, timeout=60, check=False)
    assert done.returncode == 0, done.stderr


def test_rules_have_no_network_imports():
    banned = {'socket', 'ssl', 'http', 'urllib', 'requests', 'httpx', 'ftplib', 'smtplib', 'aiohttp', 'webbrowser'}
    for path in sorted(YARAX.rglob('*.py')):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        names = {a.name.split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        names |= {n.module.split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module and n.level == 0}
        assert not names & banned, (path.name, names & banned)
