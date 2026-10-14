"""SPEC-10b §3 CLI: `secondary binexport-check` (user-facing) and the hidden `_binexport-worker` hook."""
from __future__ import annotations

import json

from binexport_builder import SHA, mutated, raw, valid

from patchtrace import cli


def run(capsys, *argv):
    code = cli.main(['secondary', *argv])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_binexport_check_json_success(tmp_path, capsys):
    p = tmp_path / 'a.BinExport'
    p.write_bytes(raw(valid()))
    code, out, err = run(capsys, 'binexport-check', str(p), '--artifact-sha256', SHA.upper(), '--role', 'older',
                         '--json')
    assert code == 0, err
    doc = json.loads(out)
    assert doc['status'] == 'complete' and doc['command'] == 'secondary binexport-check'
    result = doc['result']
    assert result['functions'] == 2 and result['id_binding'] == 'sha256' and result['protobuf_version'] == '7.36.2'
    assert 'function_addresses' not in result and result['vertex_types'] == {'0': 2}


def test_binexport_check_rejections_exit_codes(tmp_path, capsys):
    bad = tmp_path / 'b.BinExport'
    bad.write_bytes(raw(mutated('expression_cycle')))
    code, out, err = run(capsys, 'binexport-check', str(bad), '--artifact-sha256', SHA, '--role', 'newer')
    assert code == 2 and '[expression_cycle]' in err and 'Traceback' not in err
    unbound = valid()
    unbound.meta_information.executable_id = 'f' * 32
    p = tmp_path / 'c.BinExport'
    p.write_bytes(raw(unbound))
    code, out, err = run(capsys, 'binexport-check', str(p), '--artifact-sha256', SHA, '--role', 'older', '--json')
    assert code == 2 and json.loads(out)['status'] == 'failed' and 'executable_id_md5' in err
    code, out, _ = run(capsys, 'binexport-check', str(p), '--artifact-sha256', SHA, '--role', 'older',
                       '--accept-unbound', '--json')
    assert code == 0 and json.loads(out)['result']['id_binding'] == 'md5'
    code, _, err = run(capsys, 'binexport-check', str(p), '--artifact-sha256', 'xyz', '--role', 'older')
    assert code == 2 and '64 hex' in err


def test_worker_subcommand_is_hidden_and_wired(capsys, tmp_path):
    code, out, _ = run(capsys, 'binexport-check', '--help')
    assert code == 0 and 'Subtract Imagebase' in out
    code, out, _ = run(capsys, '--help')
    assert code == 0 and 'validate a user-supplied .BinExport' in out  # worker has no help line
    code, _, err = run(capsys, '_binexport-worker', '--request', str(tmp_path / 'missing.json'))
    assert code == 2 and 'unusable request' in err
