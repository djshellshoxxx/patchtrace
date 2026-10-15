"""R5: ``patchtrace rules ...`` (YRX-integration-plan section 8) over a real project made from the SYNTHETIC `capa-api` images.
The engine runs in this process (the stand-ins of `rules_store_support`) except in the two tests that start the real hidden
worker child; the evidence of a match comes through the `BACKEND` seam, as the live stores will provide it. Pinned: the
envelope and exit codes, one object per action (no bulk flag), accepting writes no file, exporting never replaces one, a crash
between the two rows of an accept is finished by repeating it, and the adapter stays an adapter.
"""
from __future__ import annotations

import argparse
import ast
import itertools
import json
import os
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

import pytest
import rules_fixtures as rf
from rules_store_support import engine_scan, project_of
from test_rules_synergy import capa_sources

from patchtrace import cli, cli_commands
from patchtrace.rules import candidates as cd
from patchtrace.rules import cli as rules_cli
from patchtrace.rules import runner, store
from patchtrace.rules.contracts import WorkerRequest, WorkerResult
from patchtrace.rules.errors import RuleError

SRC = Path(__file__).resolve().parents[1] / 'src'
ADAPTER = SRC / 'patchtrace' / 'cli_commands' / 'rules.py'
KINDS = ('rule-candidate', 'rule-decision', 'rule-version', 'rule-test', 'rule-export')


class Backend:
    """The live evidence stores, replaced by the fixtures of the pair: matches `match-term` (removed function, one older
    rule) and `match-log` (modified function, a newer rule only)."""

    def __init__(self, bench, paths: dict[str, str]):
        self.bench, self.paths = bench, paths

    def load(self, service, match_id):
        which = match_id.removeprefix('match-')
        if which not in ('term', 'log'):
            raise RuleError('PT-RULE-INPUT', 'No such match in the project', reason='no-such-match')
        pair = rf.capa_pair(self.bench, which).model_copy(update={'project_id': service.project.id})
        return rules_cli.Loaded(pair, capa_sources(self.bench), self.paths)


@pytest.fixture
def bench(tmp_path):
    pytest.importorskip('yara_x', reason='YARA-X (pip install "patchtrace[rules]") is not installed')
    bench = rf.Bench(tmp_path)
    yield bench
    bench.close()


@pytest.fixture
def clock(monkeypatch):
    ticks = itertools.count()
    monkeypatch.setattr(rules_cli, 'CLOCK', lambda: f'2026-10-14T09:{next(ticks):02d}:00+00:00')


@pytest.fixture
def project(bench, tmp_path, clock):
    service = project_of(bench, tmp_path)
    root = service.root
    paths = {a.side: str(root / a.relative_path) for a in service.project.artifacts}
    service.close()
    return root, paths


@pytest.fixture
def live(project, bench, monkeypatch):
    """The in-process engine and a backend for the project."""
    from patchtrace.rules import engine
    _, paths = project
    monkeypatch.setattr(runner, 'probe', lambda **kw: runner.Probe(engine.stamp(), ('pe',)))
    monkeypatch.setattr(runner, 'lint', lambda rules, **kw: engine.RuleSet.compile(tuple(rules)).lint)
    monkeypatch.setattr(runner, 'scan', engine_scan)
    monkeypatch.setattr(cd, 'RunnerChecker', lambda builds, **kw: rf.engine_checker(
        {side: Path(path).read_bytes() for side, path in builds.items()}))
    monkeypatch.setattr(rules_cli, 'BACKEND', Backend(bench, paths))
    return project[0]


def invoke(capsys, *argv: str) -> tuple[int, dict | str, str]:
    code = cli.main(['rules', *argv])
    out, err = capsys.readouterr()
    return code, (json.loads(out) if '--json' in argv and out.strip() else out), err


def result(capsys, *argv: str, expect: int = 0) -> dict:
    code, document, err = invoke(capsys, *argv, '--json')
    assert code == expect, (document, err)
    assert document['contract'] == 'enrichment-cli/1' and document['command'] == f'rules {argv[0]}'
    return document['result']


def count(root: Path, kind: str) -> int:
    db = sqlite3.connect(root / 'project.sqlite3')
    try:
        return db.execute('SELECT COUNT(*) FROM enrichment_entries WHERE kind=?', (kind,)).fetchone()[0]
    except sqlite3.OperationalError:
        return 0
    finally:
        db.close()


def rows(root: Path) -> dict[str, int]:
    return {kind: count(root, kind) for kind in KINDS}


def proposed(capsys, root, match='match-term', *extra) -> dict:
    return result(capsys, 'propose', str(root), '--match', match, *extra)


def accept(capsys, root, candidate_id, *extra, label='Terminate removed', expect: int = 0) -> dict:
    return result(capsys, 'decide', str(root), '--candidate', candidate_id, '--accept', '--label', label, *extra, expect=expect)


def a_series(root: Path, bench) -> tuple[Path, Path]:
    series, clean = root / 'series-files', root / 'clean-files'
    series.mkdir()
    clean.mkdir()
    for name, side in (('a-V1', 'older'), ('b-V2', 'newer')):
        (series / f'{name}.dll').write_bytes(bench.build('capa-api', side).data)
    for index, name in enumerate(('floss-static', 'floss-decode')):
        (clean / f'{index}.dll').write_bytes(bench.build(name, 'older').data)
    return series, clean


# --- the parser and the adapter ---------------------------------------------------------------------------------------

def leaves() -> dict[str, argparse.ArgumentParser]:
    parser = cli._parser(['rules'])
    rules = next(a for a in parser._subparsers._group_actions[0].choices.values() if a.prog.endswith(' rules'))
    return next(a for a in rules._subparsers._group_actions).choices


def test_cli_has_no_bulk_flags():
    found = leaves()
    assert sorted(found) == ['_rules-worker', 'decide', 'export', 'history', 'probe', 'propose', 'show', 'test']
    banned = {'all', 'every', 'bulk', 'batch', 'yes', 'force', 'recursive', 'glob', 'pattern', 'each', 'accept-all'}
    for name, leaf in found.items():
        for action in leaf._actions:
            options = {o.lstrip('-') for o in action.option_strings}
            assert not options & banned, (name, options)
            if action.dest in ('candidate', 'version', 'match') or action.dest == 'lineage':
                assert action.nargs is None and action.type is None, (name, action.dest)      # exactly one id, no list
    how = [a for a in found['decide']._mutually_exclusive_groups if a.required]
    assert len(how) == 1 and {o.option_strings[0] for o in how[0]._group_actions} == {
        '--accept', '--reject', '--defer', '--archive'}


def test_the_worker_verb_is_hidden_but_present(capsys):
    assert cli.main(['rules']) == 2 and 'required' in capsys.readouterr().err
    text = subprocess.run([sys.executable, '-m', 'patchtrace', 'rules', '--help'], capture_output=True, text=True,
                          env={**os.environ, 'PYTHONPATH': str(SRC)}).stdout
    assert 'probe' in text and 'history' in text and '_rules-worker' not in text and 'SUPPRESS' not in text
    assert '_rules-worker' in leaves()


def test_the_adapter_is_an_adapter():
    source = ADAPTER.read_text(encoding='utf-8')
    assert len(source.splitlines()) <= 25
    top = [n for n in ast.parse(source).body if isinstance(n, ast.ImportFrom | ast.Import)]
    assert [(n.module, n.level) for n in top if isinstance(n, ast.ImportFrom)] == [('__future__', 0), (None, 1)]
    verbs, failed = cli_commands.discover()
    assert 'rules' in verbs and not failed and 'rules' in cli_commands.names()


def test_rules_have_no_network_imports():
    banned = {'socket', 'ssl', 'urllib', 'http', 'requests', 'httpx', 'aiohttp', 'ftplib', 'smtplib', 'telnetlib', 'xmlrpc',
              'websockets', 'PySide6', 'PyQt5', 'PyQt6'}
    for path in sorted((SRC / 'patchtrace' / 'rules').glob('**/*.py')):
        for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module] \
                if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module else []
            assert not {n.split('.')[0] for n in names} & banned, (path.name, names)


def test_the_cli_imports_neither_the_engine_nor_qt():
    code = ('import sys, patchtrace.rules.cli, patchtrace.rules.store, patchtrace.rules.matrix, patchtrace.rules.export;'
            'print(sorted({"yara_x", "iced_x86", "PySide6"} & set(sys.modules)))')
    done = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env={**os.environ, 'PYTHONPATH': str(SRC)})
    assert done.stdout.strip() == '[]', done.stderr


# --- propose ---------------------------------------------------------------------------------------------------------

def test_propose_without_the_evidence_stores_says_so_and_changes_nothing(project, capsys):
    root, _ = project
    code, _, _ = invoke(capsys, 'propose', str(root), '--match', 'match-term')
    assert code == 2 and rows(root) == dict.fromkeys(KINDS, 0)


def test_propose_stores_the_candidates_and_nothing_else(live, capsys):
    out = proposed(capsys, live)
    (candidate,) = out['candidates']
    assert candidate['direction'] == 'older' and candidate['decision'] is None and not candidate['unvetted']
    assert {g['gate_id']: g['state'] for g in candidate['gates']}.items() >= {'len': 'pass', 'sep': 'pass', 'compile': 'pass'}.items()
    assert rows(live) == {**dict.fromkeys(KINDS, 0), 'rule-candidate': 1}
    again = proposed(capsys, live)
    assert again['candidates'][0]['candidate_id'] == candidate['candidate_id'] and rows(live)['rule-candidate'] == 1


def test_propose_exits_4_when_no_rule_passes_and_says_why(live, capsys):
    code, text, _ = invoke(capsys, 'propose', str(live), '--match', 'match-log', '--direction', 'older')
    assert code == 4 and text.startswith('No rule passed the checks for this pair: Long enough: 3 literal bytes')
    assert 'leaf functions without exception data' in text and rows(live)['rule-candidate'] == 0


def test_propose_input_errors_exit_2(live, capsys):
    for argv in (['--match', 'match-none'], ['--match', 'match-term', '--direction', 'newer']):
        assert invoke(capsys, 'propose', str(live), *argv)[0] == 2
    assert invoke(capsys, 'propose', str(live / 'nowhere'), '--match', 'match-term')[0] == 2


# --- decide ----------------------------------------------------------------------------------------------------------

def test_accepting_saves_a_version_and_writes_no_file(live, capsys, tmp_path):
    candidate = proposed(capsys, live)['candidates'][0]['candidate_id']
    before = set(tmp_path.rglob('*'))
    out = accept(capsys, live, candidate, '--cve', 'CVE-2026-0001', '--note', 'checked')
    version = out['version']
    assert out['written'] is True and version['version'] == 1 and version['candidate_id'] == candidate
    assert rows(live) == {**dict.fromkeys(KINDS, 0), 'rule-candidate': 1, 'rule-decision': 1, 'rule-version': 1}
    assert not [p for p in set(tmp_path.rglob('*')) - before if p.suffix == '.yar']
    shown = result(capsys, 'show', str(live), '--version', version['version_id'])['version']
    assert 'analyst_label         = "Terminate removed"' in shown['rule_text'] and '"CVE-2026-0001"' in shown['rule_text']


def test_accepting_needs_a_label_and_a_known_candidate(live, capsys):
    candidate = proposed(capsys, live)['candidates'][0]['candidate_id']
    assert invoke(capsys, 'decide', str(live), '--candidate', candidate, '--accept')[0] == 2
    assert invoke(capsys, 'decide', str(live), '--candidate', 'f' * 64, '--accept', '--label', 'x')[0] == 2
    assert invoke(capsys, 'decide', str(live), '--candidate', candidate, '--accept', '--label', 'x', '--cve', 'CVE-1')[0] == 2
    assert invoke(capsys, 'decide', str(live), '--candidate', candidate, '--reject', '--label', 'x')[0] == 2
    assert invoke(capsys, 'decide', str(live), '--candidate', candidate)[0] == 2           # an action is required
    assert rows(live)['rule-decision'] == 0 == rows(live)['rule-version']


def test_a_candidate_whose_checks_failed_cannot_be_accepted(live, capsys, monkeypatch):
    candidate = proposed(capsys, live)['candidates'][0]['candidate_id']
    held = store.RuleStore.candidate

    def failing(self, candidate_id):
        found = held(self, candidate_id)
        gates = tuple(g.model_copy(update={'state': 'fail'}) if g.gate_id == 'sep' else g for g in found.gates)
        return found.model_copy(update={'gates': gates})
    monkeypatch.setattr(store.RuleStore, 'candidate', failing)
    assert invoke(capsys, 'decide', str(live), '--candidate', candidate, '--accept', '--label', 'x')[0] == 2
    assert rows(live)['rule-decision'] == 0


@pytest.mark.parametrize('flag,action', [('--reject', 'reject'), ('--defer', 'defer'), ('--archive', 'archive')],
                         ids=['reject', 'defer', 'archive'])
def test_the_other_decisions_store_a_decision_and_no_version(live, capsys, flag, action):
    candidate = proposed(capsys, live)['candidates'][0]['candidate_id']
    out = result(capsys, 'decide', str(live), '--candidate', candidate, flag, '--note', 'not now')
    assert out['action'] == action and rows(live)['rule-decision'] == 1 and rows(live)['rule-version'] == 0
    listed = result(capsys, 'show', str(live), '--candidate', candidate)['candidate']
    assert listed['decision'] == action


def test_the_same_accept_twice_changes_nothing_and_a_new_label_is_the_next_version(live, capsys):
    candidate = proposed(capsys, live)['candidates'][0]['candidate_id']
    first = accept(capsys, live, candidate)
    again = accept(capsys, live, candidate)
    assert again['written'] is False and again['version']['version_id'] == first['version']['version_id']
    assert rows(live)['rule-decision'] == 1 == rows(live)['rule-version']
    second = accept(capsys, live, candidate, label='Terminate removed (rechecked)')
    assert second['written'] is True and second['version']['version'] == 2
    history = result(capsys, 'history', str(live))['events']
    assert [(e['kind'], e['detail']) for e in history] == [('decision', 'accept'), ('version', 'v1'), ('decision', 'accept'),
                                                          ('version', 'v2')]


def test_a_crash_between_the_decision_and_the_version_is_finished_by_repeating(live, capsys, monkeypatch):
    candidate = proposed(capsys, live)['candidates'][0]['candidate_id']

    def dies(self, version):
        raise RuleError('PT-RULE-STORAGE', 'The rule row was not stored', reason='publish')
    with monkeypatch.context() as patched:
        patched.setattr(store.RuleStore, 'add_version', dies)
        assert invoke(capsys, 'decide', str(live), '--candidate', candidate, '--accept', '--label', 'Terminate removed')[0] == 3
    assert (rows(live)['rule-decision'], rows(live)['rule-version']) == (1, 0)             # the process died here
    out = accept(capsys, live, candidate)
    assert out['written'] is True and (rows(live)['rule-decision'], rows(live)['rule-version']) == (1, 1)
    assert accept(capsys, live, candidate)['written'] is False


# --- show and history ------------------------------------------------------------------------------------------------

def test_show_lists_and_history_orders_events(live, capsys):
    assert invoke(capsys, 'show', str(live))[0] == 4 and invoke(capsys, 'history', str(live))[0] == 4     # nothing yet
    candidate = proposed(capsys, live)['candidates'][0]['candidate_id']
    accept(capsys, live, candidate)
    listing = result(capsys, 'show', str(live))
    assert [c['candidate_id'] for c in listing['candidates']] == [candidate] and len(listing['versions']) == 1
    detail = result(capsys, 'show', str(live), '--candidate', candidate)['candidate']
    assert detail['features'] and detail['rule_text'].startswith('import "pe"') and detail['decision'] == 'accept'
    code, text, _ = invoke(capsys, 'show', str(live), '--candidate', candidate)
    assert code == 0 and '[x] bytes at 0x104d' in text and 'Long enough' in text
    assert invoke(capsys, 'show', str(live), '--version', 'e' * 64)[0] == 2
    lineage = detail['lineage_id']
    assert len(result(capsys, 'history', str(live), '--lineage', lineage)['events']) == 2
    assert invoke(capsys, 'history', str(live), '--lineage', 'd' * 64)[0] == 4


def test_a_row_that_cannot_be_read_makes_the_answer_partial(live, capsys):
    proposed(capsys, live)
    db = sqlite3.connect(live / 'project.sqlite3')
    db.execute("UPDATE enrichment_entries SET body_sha256='0' WHERE kind='rule-candidate'")
    db.commit()
    db.close()
    code, document, _ = invoke(capsys, 'show', str(live), '--json')
    assert code == 3 and document['status'] == 'partial' and 'could not be read' in document['warnings'][0]


# --- test and export -------------------------------------------------------------------------------------------------

def accepted_version(capsys, root) -> str:
    candidate = proposed(capsys, root)['candidates'][0]['candidate_id']
    return accept(capsys, root, candidate, '--cve', 'CVE-2026-0001')['version']['version_id']


def test_the_grid_is_scored_stored_and_reused(live, capsys, bench):
    version = accepted_version(capsys, live)
    series, clean = a_series(live, bench)
    argv = ('test', str(live), '--version', version, '--series', str(series), '--clean-dir', str(clean))
    out = result(capsys, *argv)
    assert out['status'] == 'complete' and out['reused'] is False and out['footer'].startswith('A match means')
    assert out['totals'] == {'match': 1, 'no_match': 3, 'not_scanned': 0, 'unexpected_hit': 0, 'unexpected_miss': 0}
    verdicts = {r['label']: (r['state'], r['verdict']) for r in out['rows']}
    assert verdicts['older.exe'] == ('hit', 'as-expected') and verdicts['newer.exe'] == ('no-hit', 'as-expected')
    assert str(live) not in json.dumps(out) and rows(live)['rule-test'] == 1
    again = result(capsys, *argv)
    assert again['reused'] is True and again['run_id'] == out['run_id'] and rows(live)['rule-test'] == 1
    changed = result(capsys, *argv, '--timeout', '60')
    assert changed['reused'] is False and rows(live)['rule-test'] == 2                    # the limits are part of the key


def test_expectations_given_again_re_score_the_stored_grid(live, capsys, bench):
    version = accepted_version(capsys, live)
    series, clean = a_series(live, bench)
    expect = live / 'expect.json'
    expect.write_text(json.dumps({'older.exe': 'no-hit'}), encoding='utf-8')
    base = ('test', str(live), '--version', version, '--series', str(series), '--clean-dir', str(clean))
    assert result(capsys, *base)['totals']['unexpected_hit'] == 0
    out = result(capsys, *base, '--expect', str(expect))
    assert out['reused'] is True and out['totals']['unexpected_hit'] == 1


def test_a_file_that_was_not_scanned_makes_the_test_partial(live, capsys, bench, monkeypatch):
    version = accepted_version(capsys, live)
    series, clean = a_series(live, bench)

    def vanishing(rules, targets, **kw):
        (clean / '0.dll').unlink()
        return engine_scan(rules, targets, **kw)
    monkeypatch.setattr(runner, 'scan', vanishing)
    code, document, _ = invoke(capsys, 'test', str(live), '--version', version, '--series', str(series), '--clean-dir', str(clean),
                               '--json')
    assert code == 3 and document['status'] == 'partial'
    assert document['result']['totals']['not_scanned'] == 1 and 'unreadable' in document['warnings'][0]
    row = next(r for r in document['result']['rows'] if r['label'] == '0.dll')
    assert (row['state'], row['reason'], row['hits'], row['verdict']) == ('not-scanned', 'unreadable', None, 'unscored')


def test_a_test_with_an_unknown_version_or_a_missing_folder_exits_2(live, capsys):
    assert invoke(capsys, 'test', str(live), '--version', 'e' * 64)[0] == 2
    version = accepted_version(capsys, live)
    assert invoke(capsys, 'test', str(live), '--version', version, '--series', str(live / 'nowhere'))[0] == 2
    assert invoke(capsys, 'test', str(live), '--version', version, '--timeout', '1')[0] == 2


def test_a_cancelled_test_exits_5(live, capsys, bench):
    version = accepted_version(capsys, live)
    cancelled = threading.Event()
    cancelled.set()
    args = cli._parser(['rules']).parse_args(['rules', 'test', str(live), '--version', version, '--json'])
    assert rules_cli.run(args, cancelled) == 5
    assert json.loads(capsys.readouterr().out)['status'] == 'cancelled'


def test_export_writes_one_file_and_is_a_separate_action(live, capsys, bench, tmp_path):
    version = accepted_version(capsys, live)
    series, clean = a_series(live, bench)
    out = tmp_path / 'term.yar'
    before = rows(live)
    code, text, _ = invoke(capsys, 'export', str(live), '--version', version, '--out', str(out))
    assert code == 2 and not out.exists() and rows(live) == before                       # never tested: needs the word
    result(capsys, 'test', str(live), '--version', version, '--series', str(series), '--clean-dir', str(clean))
    before = rows(live)
    exported = result(capsys, 'export', str(live), '--version', version, '--out', str(out), '--allow-git-tree')
    assert exported['basename'] == 'term.yar' and exported['warnings'] == []
    assert rows(live) == {**before, 'rule-export': 1}                                    # exactly one row; no version, no decision
    data = out.read_bytes()
    assert b'\r' not in data and data.startswith(b'// patchtrace-rule-export/1\n') and b'older.exe' in data
    assert str(tmp_path).encode() not in data
    assert invoke(capsys, 'export', str(live), '--version', version, '--out', str(out), '--allow-git-tree')[0] == 2   # no replace
    assert rows(live)['rule-export'] == 1


def test_an_untested_rule_exports_only_with_its_warning_acknowledged(live, capsys, tmp_path):
    version = accepted_version(capsys, live)
    out = tmp_path / 'untested.yar'
    code, document, _ = invoke(capsys, 'export', str(live), '--version', version, '--out', str(out), '--allow-git-tree',
                               '--with-warnings', '--json')
    assert code == 3 and document['status'] == 'partial' and document['warnings'] == ['export warning: not-tested']
    assert 'Not tested' in out.read_text(encoding='ascii')
    history = result(capsys, 'history', str(live))['events']
    assert history[-1]['kind'] == 'export' and history[-1]['detail'] == 'untested.yar'


# --- the real worker child -------------------------------------------------------------------------------------------

def test_the_hidden_worker_verb_answers_a_request_file(tmp_path):
    pytest.importorskip('yara_x', reason='YARA-X (pip install "patchtrace[rules]") is not installed')
    request = tmp_path / 'req.json'
    request.write_text(WorkerRequest(op='probe', result=str(tmp_path / 'out.json')).model_dump_json(), encoding='utf-8')
    done = subprocess.run([sys.executable, '-m', 'patchtrace', 'rules', '_rules-worker', '--request', str(request)],
                          capture_output=True, text=True, env={**os.environ, 'PYTHONPATH': str(SRC)}, cwd=tmp_path)
    assert (done.returncode, done.stdout) == (0, '')                                     # nothing on stdout, one result file
    document = WorkerResult.model_validate_json((tmp_path / 'out.json').read_text(encoding='utf-8'))
    assert document.kind == 'ok' and document.engine.engine == 'yara-x' and 'pe' in document.modules
    request.write_text('{}', encoding='utf-8')
    bad = subprocess.run([sys.executable, '-m', 'patchtrace', 'rules', '_rules-worker', '--request', str(request)],
                         capture_output=True, text=True, env={**os.environ, 'PYTHONPATH': str(SRC)}, cwd=tmp_path)
    assert bad.returncode == 2 and bad.stdout == ''


def test_probe_and_a_grid_through_the_real_worker(project, bench, capsys, monkeypatch):
    root, paths = project
    document = result(capsys, 'probe')
    assert document['engine']['engine'] == 'yara-x' and 'pe' in document['modules']
    monkeypatch.setattr(rules_cli, 'BACKEND', Backend(bench, paths))
    monkeypatch.setattr(cd, 'RunnerChecker', lambda builds, **kw: rf.engine_checker(
        {side: Path(path).read_bytes() for side, path in builds.items()}))
    version = accepted_version(capsys, root)
    series, clean = a_series(root, bench)
    out = result(capsys, 'test', str(root), '--version', version, '--series', str(series), '--clean-dir', str(clean))
    assert out['status'] == 'complete' and out['totals']['match'] == 1 and out['totals']['not_scanned'] == 0
