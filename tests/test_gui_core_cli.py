"""GUI core (slice F1): `patchtrace panels list|check` (GUI-integration-plan 8.1). Qt-free, hermetic.

The verb is reached through `gui.cli.add_parser` and `gui.cli.run`, exactly as the F1b registry adapter will call
them; the manifest is injected, so the exit codes 0/2/3/4/5 do not depend on which features exist yet.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from patchtrace.cli import CliError, _Parser
from patchtrace.gui import cli as panels
from patchtrace.gui.registry import ManifestEntry, PanelSpec
from patchtrace.tooltips import TooltipEntry

SRC = str(Path(__file__).resolve().parents[1] / 'src')
ROW_KEYS = {'id', 'state', 'title', 'area', 'tabify_with', 'shortcut', 'requires', 'error'}


def unused_factory(ctx):
    raise AssertionError('not called here')


def spec(panel_id, **kwargs):
    tips = {f'{panel_id}.dock': TooltipEntry(f'Fixture {panel_id} dock.', 'Why.', 'Effect.'),
            f'{panel_id}.action': TooltipEntry(f'Fixture {panel_id} toggle.', 'Why.', 'Effect.')}
    return PanelSpec(panel_id, kwargs.pop('title', panel_id.title()), unused_factory, tips=tips, **kwargs)


def built(panel_id, area='right', tabify=None, shortcut=None, **kwargs):
    return ManifestEntry(panel_id, 'patchtrace.fixture.panel',
                         lambda: spec(panel_id, area=area, tabify_with=tabify, shortcut=shortcut, **kwargs),
                         area, tabify, shortcut)


def absent(panel_id, area='bottom', tabify=None, shortcut=None):
    def load():
        raise ModuleNotFoundError('absent', name='patchtrace.fixture')
    return ManifestEntry(panel_id, 'patchtrace.fixture.panel', load, area, tabify, shortcut)


def broken(panel_id, error=None):
    def load():
        raise error or RuntimeError('secret boom')
    return ManifestEntry(panel_id, 'patchtrace.fixture.panel', load, 'right')


def parse(argv):
    root = _Parser(prog='patchtrace')
    sub = root.add_subparsers(dest='command', required=True, parser_class=_Parser)
    panels.add_parser(sub)
    return root.parse_args(argv)


def invoke(argv, manifest, capsys, cancel=None):
    code = panels.run(parse(argv), cancel or threading.Event(), manifest=manifest)
    out, err = capsys.readouterr()
    return code, out, err


def envelope(out):
    assert out.count('\n') == 1  # exactly one document
    return json.loads(out)


GOOD = [built('alpha', shortcut='Ctrl+Shift+A', requires=('project',)), absent('beta', shortcut='Ctrl+Shift+B')]


# ---- exit codes -------------------------------------------------------------------------------------------------


@pytest.mark.parametrize('verb', ['list', 'check'])
def test_exit_0_when_something_is_built_and_nothing_is_wrong(verb, capsys):
    code, out, err = invoke(['panels', verb, '--json'], GOOD, capsys)
    assert (code, err) == (0, '')
    assert envelope(out)['status'] == 'ok'


@pytest.mark.parametrize('verb', ['list', 'check'])
def test_exit_4_when_no_panel_is_built_yet(verb, capsys):
    code, out, _ = invoke(['panels', verb, '--json'], [absent('alpha'), absent('beta')], capsys)
    document = envelope(out)
    assert code == 4 and document['status'] == 'ok'
    assert [row['state'] for row in document['result']['panels']] == ['not-built', 'not-built']


def test_exit_2_when_check_finds_a_manifest_conflict_but_list_still_lists(capsys):
    clash = [built('alpha', shortcut='Ctrl+Shift+A'), absent('beta', shortcut='ctrl+shift+a')]
    code, out, _ = invoke(['panels', 'check', '--json'], clash, capsys)
    document = envelope(out)
    assert code == 2 and document['status'] == 'failed'
    assert [(c['code'], c['rule'], c['panel']) for c in document['result']['conflicts']] == [
        ('PT-GUI-MANIFEST', 'duplicate-shortcut', 'beta')]
    assert [row['id'] for row in document['result']['panels']] == ['alpha', 'beta']
    code, out, _ = invoke(['panels', 'list', '--json'], clash, capsys)
    assert code == 0 and 'conflicts' not in envelope(out)['result']


def test_exit_2_for_a_spec_that_disagrees_with_its_slot(capsys):
    entry = built('alpha', shortcut='Ctrl+Shift+A')
    wrong = ManifestEntry('alpha', entry.module, entry.load, 'left', None, 'Ctrl+Shift+A')
    code, out, _ = invoke(['panels', 'check', '--json'], [wrong], capsys)
    document = envelope(out)
    assert code == 2 and document['result']['conflicts'][0]['rule'] == 'placement'
    assert document['result']['panels'][0]['area'] == 'right'  # a built panel shows what its spec will do


@pytest.mark.parametrize('verb', ['list', 'check'])
def test_exit_3_when_a_spec_module_raises_and_the_message_stays_out_of_the_output(verb, capsys):
    code, out, err = invoke(['panels', verb, '--json'], [broken('zeta'), GOOD[0]], capsys)
    document = envelope(out)
    assert code == 3 and document['status'] == 'failed'
    rows = {row['id']: row for row in document['result']['panels']}
    assert rows['zeta']['state'] == 'error' and rows['zeta']['error'] == 'RuntimeError'
    assert rows['zeta']['title'] is None and 'secret boom' not in out + err
    assert [row['state'] for row in document['result']['panels']] == ['built', 'error']  # the others still load


def test_exit_3_wins_over_exit_2_because_findings_on_a_failed_load_are_incomplete(capsys):
    manifest = [broken('alpha', error=ImportError('x')), absent('beta', shortcut='Ctrl+Shift+B'),
                absent('gamma', shortcut='Ctrl+Shift+B')]
    code, out, _ = invoke(['panels', 'check', '--json'], manifest, capsys)
    assert code == 3 and envelope(out)['result']['conflicts'][0]['rule'] == 'duplicate-shortcut'


def test_exit_5_when_cancelled_before_anything_loads(capsys):
    cancel = threading.Event()
    cancel.set()
    loaded = []
    entry = ManifestEntry('alpha', 'patchtrace.fixture.panel', lambda: loaded.append(1), 'right')
    code, out, _ = invoke(['panels', 'check', '--json'], [entry], capsys, cancel)
    document = envelope(out)
    assert (code, document['status'], document['result']) == (5, 'cancelled', None) and loaded == []


def test_exit_2_for_invalid_arguments():
    for argv in (['panels'], ['panels', 'explode'], ['panels', 'list', '--bogus'], ['panels', 'check', 'extra']):
        with pytest.raises(CliError) as caught:
            parse(argv)
        assert caught.value.code == 2, argv


# ---- the envelope and the text -----------------------------------------------------------------------------------


def test_the_json_document_is_the_enrichment_cli_envelope(capsys):
    manifest = [built('alpha', shortcut='ctrl+shift+a', requires=('project', 'tool:capa'), title='Alpha view'),
                absent('beta', tabify='alpha', shortcut='Ctrl+Shift+B'), broken('gamma')]
    code, out, _ = invoke(['panels', 'list', '--json'], manifest, capsys)
    assert code == 3
    assert json.loads(out) == {
        'contract': 'enrichment-cli/1', 'command': 'panels list', 'status': 'failed', 'warnings': [],
        'result': {'panels': [
            {'id': 'alpha', 'state': 'built', 'title': 'Alpha view', 'area': 'right', 'tabify_with': None,
             'shortcut': 'Ctrl+Shift+A', 'requires': ['project', 'tool:capa'], 'error': None},
            {'id': 'beta', 'state': 'not-built', 'title': None, 'area': 'bottom', 'tabify_with': 'alpha',
             'shortcut': 'Ctrl+Shift+B', 'requires': [], 'error': None},
            {'id': 'gamma', 'state': 'error', 'title': None, 'area': 'right', 'tabify_with': None, 'shortcut': None,
             'requires': [], 'error': 'RuntimeError'}]}}
    assert out == json.dumps(json.loads(out), sort_keys=True) + '\n'  # keys sorted, one line


def test_check_adds_conflicts_and_lint_warnings(capsys):
    emitter = built('alpha', shortcut='Ctrl+Shift+A', anchors_out=frozenset({'string'}))
    code, out, _ = invoke(['panels', 'check', '--json'], [emitter], capsys)
    document = envelope(out)
    assert code == 0 and document['result']['conflicts'] == []
    assert len(document['warnings']) == 1 and 'string' in document['warnings'][0]


def test_rows_are_sorted_by_id_and_carry_the_command_label(capsys):
    manifest = [absent('zeta'), built('alpha'), absent('mid')]
    _, out, _ = invoke(['panels', 'list', '--json'], manifest, capsys)
    assert [row['id'] for row in envelope(out)['result']['panels']] == ['alpha', 'mid', 'zeta']
    assert parse(['panels', 'list']).command_label == 'panels list'
    assert parse(['panels', 'check']).command_label == 'panels check'


def test_text_mode_prints_a_table_and_keeps_warnings_on_stderr(capsys):
    manifest = [built('alpha', shortcut='Ctrl+Shift+A', requires=('project',), anchors_out=frozenset({'string'})),
                absent('beta', area='right', tabify='alpha', shortcut='Ctrl+Shift+B')]
    code, out, err = invoke(['panels', 'check'], manifest, capsys)
    lines = out.splitlines()
    assert code == 0 and not out.lstrip().startswith('{')
    assert lines[0].split() == ['panels:', '2', 'listed,', '1', 'built,', '1', 'not', 'built,', '0', 'failed', 'to',
                                'load']
    assert lines[1].split() == ['id', 'state', 'area', 'tabify', 'shortcut', 'requires', 'title']
    assert lines[2].split() == ['alpha', 'built', 'right', '-', 'Ctrl+Shift+A', 'project', 'Alpha']
    assert lines[3].split() == ['beta', 'not-built', 'right', 'alpha', 'Ctrl+Shift+B', '-', '-']
    assert 'conflicts: none' in out and 'warning:' in err and 'string' in err
    assert all(line == line.rstrip() for line in lines)


def test_text_mode_lists_every_conflict(capsys):
    clash = [built('alpha', shortcut='Ctrl+Shift+A'), absent('beta', shortcut='Ctrl+Shift+A')]
    code, out, _ = invoke(['panels', 'check'], clash, capsys)
    assert code == 2 and 'PT-GUI-MANIFEST duplicate-shortcut beta:' in out


def test_text_mode_says_so_when_nothing_is_built(capsys):
    code, out, _ = invoke(['panels', 'list'], [absent('alpha')], capsys)
    assert code == 4 and 'no panel is built yet' in out


def test_hostile_titles_cannot_forge_lines_in_text_mode(capsys):
    manifest = [built('alpha', title='Alpha\nbeta built right')]
    _, out, _ = invoke(['panels', 'list'], manifest, capsys)
    assert len(out.splitlines()) == 3 and 'Alpha beta built right' in out  # summary, header, one row


def test_the_json_flag_is_per_verb_and_off_by_default():
    assert parse(['panels', 'list']).json is False and parse(['panels', 'check', '--json']).json is True


def test_text_mode_names_the_exception_class_of_a_failed_panel(capsys):
    _, out, err = invoke(['panels', 'list'], [broken('alpha')], capsys)
    row = next(line for line in out.splitlines() if line.startswith('alpha'))
    assert row.split()[:2] == ['alpha', 'error'] and 'RuntimeError' in row and 'secret boom' not in out + err


# ---- the real manifest and a fresh process ----------------------------------------------------------------------


def test_the_shipped_manifest_lists_fourteen_panels(capsys):
    code, out, _ = invoke(['panels', 'list', '--json'], None, capsys)
    assert code in (0, 4)  # 4 until the first feature builds its panel
    assert len(envelope(out)['result']['panels']) == 14


def run_in_fresh_process(argv):
    code = ('import sys, threading\n'
            'from patchtrace.cli import _Parser\nfrom patchtrace.gui import cli\n'
            'root = _Parser(prog="patchtrace")\n'
            'sub = root.add_subparsers(dest="command", required=True, parser_class=_Parser)\n'
            'cli.add_parser(sub)\nrc = cli.run(root.parse_args(sys.argv[1:]), threading.Event())\n'
            'bad = sorted(m for m in sys.modules if m.split(".")[0] in ("PySide6", "shiboken6", "networkx", "pygments",\n'
            '             "rapidfuzz") or m.startswith(("patchtrace.ui", "patchtrace.gui.qt")))\n'
            'print("BAD", bad, file=sys.stderr)\nraise SystemExit(90 if bad else rc)\n')
    env = dict(os.environ, PYTHONPATH=SRC + os.pathsep + os.environ.get('PYTHONPATH', ''), PYTHONUTF8='1')
    return subprocess.run([sys.executable, '-c', code, *argv], capture_output=True, text=True, env=env, timeout=120)


@pytest.mark.parametrize('verb', ['list', 'check'])
def test_the_verb_runs_in_a_fresh_process_without_qt_or_heavy_libraries(verb):
    result = run_in_fresh_process(['panels', verb, '--json'])
    assert result.returncode in (0, 4), result.stderr  # 90 would mean Qt or a heavy library was imported
    document = json.loads(result.stdout)
    assert document['command'] == f'panels {verb}' and len(document['result']['panels']) == 14
    assert {key for row in document['result']['panels'] for key in row} == ROW_KEYS
