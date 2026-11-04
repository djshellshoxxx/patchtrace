"""`patchtrace intel-tools pairs --hypothesis CVE-ID` (CAP plan s8): hypothesis context from a stored advisory joined
to the printed pair rows through `capa_hints.capability_context`. FAKE capa executables print committed real capa
output captured on SYNTHETIC PE pairs; the advisory is the synthetic CSAF fixture. Not live evidence."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_capa_cli import CHANGED, pairs, stored_project
from test_intel_tools_cli import clean_env, invoke  # noqa: F401  (clean_env is a fixture)

from patchtrace import cli
from patchtrace.intelligence.tools import capa_hints

CSAF = Path(__file__).resolve().parent / 'fixtures' / 'csaf' / 'synthetic-advisory-rev1.json'
CVE = 'CVE-2099-10001'


def advisory(tmp_path, cwe: str | None):
    """The rev1 fixture, with the CWE of CVE-2099-10001 replaced when `cwe` is given (test-local copy)."""
    document = json.loads(CSAF.read_text(encoding='utf-8'))
    if cwe is not None:
        document['vulnerabilities'][0]['cwe'] = {'id': cwe, 'name': 'External Control of File Name or Path'}
    path = tmp_path / f'advisory-{cwe or "rev1"}.json'
    path.write_text(json.dumps(document), encoding='utf-8', newline='\n')
    return path


def imported(tmp_path, capsys, cwe: str | None = 'CWE-73', **kwargs):
    root = stored_project(tmp_path, **kwargs)
    assert cli.main(['intelligence', 'import', str(root), str(advisory(tmp_path, cwe)), '--cve', CVE]) == 0
    capsys.readouterr()
    return root


def without_hypothesis(result: dict) -> dict:
    return {key: value for key, value in result.items() if key != 'hypothesis'}


def test_path_cwe_gives_one_context_on_the_log_pair(tmp_path, capsys):
    root = imported(tmp_path, capsys)
    plain_code, plain, _err = pairs(capsys, root)
    code, document, _err = pairs(capsys, root, '--hypothesis', CVE)
    assert code == plain_code == 0 and document['warnings'] == []
    assert without_hypothesis(document['result']) == plain['result'] and 'hypothesis' not in plain['result']
    hypothesis = document['result']['hypothesis']
    assert (hypothesis['cve'], hypothesis['contract'], hypothesis['available']) == (CVE, 'capability-hints/1', True)
    assert hypothesis['limitations'] == list(capa_hints.LIMITATIONS)
    (context,) = hypothesis['contexts']
    assert (context['rule_id'], context['group_id'], context['support']) == ('R-PATH', 'm:log', 'context')
    assert [(o['rule_id'], o['change']) for o in context['observations']] == [('write file on Windows', 'gained')]


def test_integer_cwe_gives_no_context_and_identical_rows(tmp_path, capsys):
    root = imported(tmp_path, capsys, cwe=None)
    plain_code, plain, _err = pairs(capsys, root)
    code, document, _err = pairs(capsys, root, '--hypothesis', CVE)
    assert code == plain_code and without_hypothesis(document['result']) == plain['result']
    assert document['result']['hypothesis']['available'] and document['result']['hypothesis']['contexts'] == []


def test_cve_without_a_stored_advisory_is_unavailable_with_a_warning(tmp_path, capsys):
    root = stored_project(tmp_path)
    plain_code, plain, _err = pairs(capsys, root)
    code, document, _err = pairs(capsys, root, '--hypothesis', 'CVE-2099-99999')
    hypothesis = document['result']['hypothesis']
    assert code == plain_code == 0 and document['status'] == plain['status']
    assert without_hypothesis(document['result']) == plain['result']
    assert (hypothesis['available'], hypothesis['contexts'], hypothesis['cve']) == (False, [], 'CVE-2099-99999')
    assert any('CVE-2099-99999' in warning for warning in document['warnings'])


def test_context_never_changes_a_no_results_exit(tmp_path, capsys):
    root = imported(tmp_path, capsys, pair='capa-control', matches=(('main', 'unchanged', [0x1000], [0x1000]),))
    code, document, _err = pairs(capsys, root, '--hypothesis', CVE)
    assert code == 4 and document['result']['changes'] == [] and document['result']['hypothesis']['contexts'] == []


@pytest.mark.parametrize('value', ['CVE-99-1', 'not-a-cve', 'CVE-2099-' + '1' * 30], ids=['short', 'junk', 'long'])
def test_malformed_id_exits_2_before_any_store_is_opened(tmp_path, capsys, value):
    code, out, err = invoke(capsys, 'pairs', str(tmp_path / 'no-such-project'), '--hypothesis', value)
    assert code == 2 and 'PT-TOOL-INPUT' in err and 'Traceback' not in err + out


@pytest.mark.parametrize('argv', [('--namespace', 'no/such/prefix'), ('--change', 'lost')], ids=['namespace', 'change'])
def test_a_filter_that_hides_the_row_yields_no_context(tmp_path, capsys, argv):
    root = imported(tmp_path, capsys)
    _code, document, _err = pairs(capsys, root, '--hypothesis', CVE, *argv)
    assert all(row['rule_id'] != 'write file on Windows' for row in document['result']['changes'])
    assert document['result']['hypothesis']['contexts'] == []


def test_text_output_has_a_bounded_context_line(tmp_path, capsys):
    hostile = 'log\x1b[31m‮' + 'x' * 110
    matches = tuple((hostile if name == 'log' else name, *rest) for name, *rest in CHANGED)
    root = imported(tmp_path, capsys, matches=matches)
    code, out, _err = invoke(capsys, 'pairs', str(root), '--hypothesis', CVE)
    (line,) = [line for line in out.splitlines() if line.startswith('context: ')]
    assert code == 0 and 'R-PATH' in line and 'write file on Windows' in line and 'm:log' in line
    assert 'x' * 110 not in line and len(line) <= 400
    assert '\x1b' not in out and '‮' not in out
    _code, document, _err = pairs(capsys, root, '--hypothesis', CVE)
    assert document['result']['hypothesis']['contexts'][0]['group_id'] == 'm:' + hostile   # JSON keeps the data
