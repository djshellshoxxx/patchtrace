"""`patchtrace intel-tools pairs` and the probe rules label (CAP-5) through the real `cli.main`, with FAKE capa
executables that print committed real capa output captured on SYNTHETIC PE pairs. Not live evidence."""
from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest
from test_intel_tools_cli import clean_env, fake_capa, invoke, make_project  # noqa: F401  (clean_env is a fixture)

from patchtrace import cli
from patchtrace.intelligence.tools import capa_pairs
from patchtrace.intelligence.tools import cli as tools_cli
from patchtrace.models import AnalysisRun, FunctionMatch, FunctionRecord
from patchtrace.service import ProjectService

BASE = 0x140000000
CHANGED = (('main', 'modified', [0x1000], [0x1000]), ('log', 'modified', [0x108b], [0x1096]),
           ('env', 'added', [], [0x1030]), ('term', 'removed', [0x104d], []))


def add_matches(root, matches=CHANGED):
    service = ProjectService.open(root)
    try:
        project = service.project
        ids = {a.side: a.id for a in project.artifacts}
        project.runs.append(AnalysisRun(id='run-1', status='completed'))

        def records(side, rvas):
            return [FunctionRecord(id=f'fn-{side}-{rva:x}', artifact_id=ids[side], run_id='run-1',
                                   name=f'{side}_{rva:x}', address=f'{BASE + rva:x}', address_space='virtual')
                    for rva in rvas]
        project.matches.extend(FunctionMatch(id=mid, run_id='run-1', category=cat, older=records('older', o),
                                             newer=records('newer', n)) for mid, cat, o, n in matches)
        service.save()
    finally:
        service.close()


def stored_project(tmp_path, pair='capa-api', matches=CHANGED, analysed=True):
    root, mapping = make_project(tmp_path, pair)
    exe = fake_capa(tmp_path, mapping)
    assert cli.main(['intel-tools', 'run', str(root), '--capa', str(exe), '--capa-accept-untested', '--json']) == 0
    if analysed:
        add_matches(root, matches)
    return root


def pairs(capsys, root, *argv):
    capsys.readouterr()
    code, out, err = invoke(capsys, 'pairs', str(root), '--json', *argv)
    return code, json.loads(out), err


def test_pairs_reports_gained_and_lost_rows_with_exit_0(tmp_path, capsys):
    root = stored_project(tmp_path)
    code, document, _err = pairs(capsys, root)
    result = document['result']
    assert code == 0 and document['command'] == 'intel-tools pairs' and document['contract'] == 'enrichment-cli/1'
    assert result['contract'] == 'capa-pairs/1' and result['comparable'] and result['pairing'] == 'available'
    assert result['value_gate'] == 'unvalidated'
    assert result['changes'] and {row['change'] for row in result['changes']} <= {'gained', 'lost', 'moved'}
    assert str(tmp_path) not in json.dumps(document)


def test_change_filter_namespace_and_unchanged_rows(tmp_path, capsys):
    root = stored_project(tmp_path)
    _code, document, _err = pairs(capsys, root, '--change', 'gained')
    assert {row['change'] for row in document['result']['changes']} == {'gained'}
    _code, document, _err = pairs(capsys, root, '--namespace', 'no/such/prefix')
    assert document['result']['changes'] == []
    _code, document, _err = pairs(capsys, root, '--change', 'unchanged', '--include-library')
    assert {row['change'] for row in document['result']['changes']} <= {'unchanged'}


def test_features_are_dropped_unless_asked(tmp_path, capsys):
    root = stored_project(tmp_path)
    _code, document, _err = pairs(capsys, root)
    assert all(not row[side]['features'] for row in document['result']['changes'] for side in ('older', 'newer'))
    _code, document, _err = pairs(capsys, root, '--show-features')
    assert any(row[side]['features'] for row in document['result']['changes'] for side in ('older', 'newer'))


def test_secret_looking_feature_values_are_redacted_unless_shown():
    row = {'older': {'features': [{'kind': 'string', 'value': 'AKIAIOSFODNN7EXAMPLE', 'rva': None}]},
           'newer': {'features': []}}
    hidden = tools_cli._present_row(json.loads(json.dumps(row)), features=True, show_secrets=False)
    assert hidden['older']['features'][0]['value'].startswith('[redacted')
    shown = tools_cli._present_row(json.loads(json.dumps(row)), features=True, show_secrets=True)
    assert shown['older']['features'][0]['value'] == 'AKIAIOSFODNN7EXAMPLE'
    assert tools_cli._present_row(json.loads(json.dumps(row)), features=False, show_secrets=True)[
        'older']['features'] == []


def test_comparable_without_rows_is_exit_4(tmp_path, capsys):
    root = stored_project(tmp_path, 'capa-control', matches=(('main', 'unchanged', [0x1000], [0x1000]),))
    code, document, _err = pairs(capsys, root)
    assert code == 4 and document['result']['comparable'] and document['result']['changes'] == []


def test_no_stored_evidence_is_exit_2_and_stderr_says_which_side(tmp_path, capsys):
    root, _mapping = make_project(tmp_path, 'capa-api')
    code, document, err = pairs(capsys, root)
    assert code == 2 and document['status'] == 'failed' and 'older' in err and 'newer' in err


def test_no_completed_analysis_is_exit_2_with_the_pairing_code(tmp_path, capsys):
    root = stored_project(tmp_path, analysed=False)
    code, document, err = pairs(capsys, root)
    assert code == 2 and document['result']['pairing'] == 'unavailable'
    assert document['result']['error_code'] == 'PT-TOOL-PAIRING' and 'completed analysis' in err
    assert 'older_capabilities' in document['result']['counts']


def test_a_mismatched_pair_is_exit_3(tmp_path, capsys, monkeypatch):
    root = stored_project(tmp_path)
    real = capa_pairs.compute_pairs
    monkeypatch.setattr(capa_pairs, 'compute_pairs', lambda *a, **k: real(a[0], a[1], a[0], a[1], a[4]))
    code, document, _err = pairs(capsys, root)
    assert code == 3 and document['status'] == 'failed' and not document['result']['comparable']
    assert document['result']['reasons']


def test_text_output_lists_counts_and_rows(tmp_path, capsys):
    root = stored_project(tmp_path)
    capsys.readouterr()
    code, out, _err = invoke(capsys, 'pairs', str(root))
    assert code == 0 and 'gained' in out and '\x1b' not in out


def test_cancelled_is_exit_5(tmp_path):
    root = stored_project(tmp_path)
    event = threading.Event()
    event.set()
    args = SimpleNamespace(project=root, action='pairs', json=True, engine='capa', change=None, namespace=None,
                           include_noise=False, include_library=False, show_features=False, show_secrets=False)
    assert tools_cli.dispatch(args, event) == 5


@pytest.mark.parametrize('code,exit_code', [('PT-TOOL-INPUT', 2), ('PT-TOOL-CONSENT', 2), ('PT-TOOL-PAIRING', 2),
                                            ('PT-TOOL-LIMIT', 3), ('PT-TOOL-STALE', 3), ('PT-TOOL-MISMATCH', 3)],
                         ids=['input', 'consent', 'pairing', 'limit', 'stale', 'mismatch'])
def test_error_code_exit_mapping(code, exit_code):
    assert tools_cli._error_exit(code) == exit_code


def test_probe_prints_the_rules_label_and_the_pin_status(tmp_path, capsys):
    _root, mapping = make_project(tmp_path, 'capa-api')
    exe = fake_capa(tmp_path, mapping)
    code, out, _err = invoke(capsys, 'probe', '--capa', str(exe), '--capa-accept-untested')
    assert code == 0 and '(unpinned)' in out and 'rules: built-in rules of capa 9.4.0 (embedded)' in out
    code, out, _err = invoke(capsys, 'probe', '--capa', str(exe), '--capa-accept-untested', '--json')
    row = json.loads(out)['result']['engines'][0]
    assert row['rules_label'] == 'built-in rules of capa 9.4.0 (embedded)'
