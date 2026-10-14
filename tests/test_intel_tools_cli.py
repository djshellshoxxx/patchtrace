"""`patchtrace intel-tools` (SPEC-29 tools T8) through the real `cli.main`, with FAKE engine executables that print
committed real-tool output captured on SYNTHETIC PE pairs. Orchestration and envelope only; not live evidence."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from intel_tools_support import fake_engine, golden
from test_intel_tools_pe import PAIRS

from patchtrace import cli
from patchtrace.intelligence.tools import cli as tools_cli
from patchtrace.service import ProjectService


def make_project(tmp_path, pair: str):
    older, newer = PAIRS[pair]()
    files = {}
    for side, data in (('older', older), ('newer', newer)):
        files[side] = tmp_path / f'{side}.exe'
        files[side].write_bytes(data)
    service = ProjectService.create(files['older'], files['newer'], 'tools', tmp_path / 'case')
    mapping = {a.sha256: golden(f'capa/{pair}-{a.side}.json').decode() for a in service.project.artifacts}
    root = service.root
    service.store.close()
    return root, mapping


def fake_capa(tmp_path, mapping):
    body = ('import hashlib\nsha = hashlib.sha256(open(ARGS[-1], "rb").read()).hexdigest()\n'
            f'OUT = {mapping!r}\nsys.stdout.write(OUT[sha])\n')
    return fake_engine(tmp_path / 'bin', 'capa', run_body=body)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in tools_cli.ENV.values():
        monkeypatch.delenv(name, raising=False)


def invoke(capsys, *argv):
    code = cli.main(['intel-tools', *argv])
    out, err = capsys.readouterr()
    return code, out, err


def test_probe_reports_configured_engines_in_the_envelope(tmp_path, capsys):
    _root, mapping = make_project(tmp_path, 'capa-api')
    exe = fake_capa(tmp_path, mapping)
    code, out, _err = invoke(capsys, 'probe', '--capa', str(exe), '--capa-accept-untested', '--json')
    document = json.loads(out)
    assert code == 0 and document['contract'] == 'enrichment-cli/1' and document['command'] == 'intel-tools probe'
    row = document['result']['engines'][0]
    assert row['engine'] == 'capa' and row['supported'] and row['untested_version'] and row['executable'] == exe.name
    assert str(tmp_path) not in out        # basenames only
    code, out, _err = invoke(capsys, 'probe', '--capa', str(exe), '--json')   # unpinned, no opt-in
    assert code == 2 and not json.loads(out)['result']['engines'][0]['supported']


def test_probe_with_nothing_configured_or_a_relative_path_is_exit_2(tmp_path, capsys, monkeypatch):
    code, out, _err = invoke(capsys, 'probe', '--json')
    assert code == 2 and len(json.loads(out)['result']['engines']) == 3
    code, out, err = invoke(capsys, 'probe', '--capa', 'capa', '--json')
    assert code == 2 and 'absolute' in err and json.loads(out)['status'] == 'failed'
    monkeypatch.setenv('PATCHTRACE_CAPA', 'relative/capa')
    assert invoke(capsys, 'probe', '--json')[0] == 2


def test_run_then_delta_end_to_end(tmp_path, capsys):
    root, mapping = make_project(tmp_path, 'capa-api')
    exe = fake_capa(tmp_path, mapping)
    code, out, _err = invoke(capsys, 'run', str(root), '--capa', str(exe), '--capa-accept-untested', '--json')
    document = json.loads(out)
    assert code == 0 and document['status'] == 'complete'
    assert [(r['engine'], r['side'], r['status']) for r in document['result']['runs']] == [
        ('capa', 'older', 'ok'), ('capa', 'newer', 'ok')]
    assert 'stderr' not in out and str(tmp_path) not in out
    code, out, _err = invoke(capsys, 'delta', str(root), '--json')
    deltas = json.loads(out)['result']['deltas']
    assert code == 0 and deltas[0]['engine'] == 'capa' and deltas[0]['comparable']
    assert deltas[0]['value_gate'] == 'unvalidated'


def test_delta_of_an_unchanged_pair_is_exit_4(tmp_path, capsys):
    root, mapping = make_project(tmp_path, 'capa-control')
    exe = fake_capa(tmp_path, mapping)
    assert invoke(capsys, 'run', str(root), '--capa', str(exe), '--capa-accept-untested', '--json')[0] == 0
    assert invoke(capsys, 'delta', str(root), '--json')[0] == 4


def test_delta_without_evidence_is_exit_2(tmp_path, capsys):
    root, _mapping = make_project(tmp_path, 'capa-api')
    code, out, _err = invoke(capsys, 'delta', str(root), '--json')
    assert code == 2 and json.loads(out)['result']['deltas'] == []


def test_run_exit_codes_partial_nothing_runnable_and_invalid(tmp_path, capsys):
    root, mapping = make_project(tmp_path, 'capa-api')
    exe = fake_capa(tmp_path, mapping)
    code, out, _err = invoke(capsys, 'run', str(root), '--profile', 'context', '--capa', str(exe),
                             '--capa-accept-untested', '--json')
    assert code == 3 and json.loads(out)['status'] == 'partial'          # capa ok, FLOSS absent
    assert invoke(capsys, 'run', str(root), '--json')[0] == 2             # nothing configured: nothing runnable
    assert invoke(capsys, 'run', str(root), '--engines', 'floss', '--capa', str(exe), '--json')[0] == 2
    assert invoke(capsys, 'run', str(root), '--engines', 'bogus', '--json')[0] == 2


def test_exit_code_table():
    def result(status, evidence=0):
        return SimpleNamespace(run=SimpleNamespace(status=status, evidence_count=evidence))
    assert tools_cli._run_exit([result('ok', 3), result('ok', 1)], False)[0] == 0
    assert tools_cli._run_exit([result('none-found'), result('none-found')], False)[0] == 4
    assert tools_cli._run_exit([result('ok', 3), result('failed')], False)[0] == 3
    assert tools_cli._run_exit([result('absent'), result('unsupported')], False)[0] == 2
    assert tools_cli._run_exit([result('ok', 3), result('cancelled')], False)[0] == 5
    assert tools_cli._run_exit([result('ok', 3)], True)[0] == 5


def test_hook_in_cli_is_registered():
    assert 'intel-tools' in cli.COMMANDS and cli.HANDLERS['intel-tools'] is tools_cli.dispatch
