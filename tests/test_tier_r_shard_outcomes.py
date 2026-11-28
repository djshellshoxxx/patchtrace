"""Constructed shard outcomes and real CLI retention-failure plumbing; no native engine runs."""
from __future__ import annotations

import json

import pytest
from test_tier_r_output_persistence import provider, store_labels

from tools.calibration.tier_r import cli
from tools.calibration.tier_r import report_schemas as RS
from tools.calibration.tier_r import shard as S


def one_case_plan(case_id='suite:_template/tiny'):
    plan = {'contract': S.PLAN_CONTRACT, 'seed': 7, 'subset': 'full', 'engines': ['rz-diff'], 'of': 1,
            'cases_total': 1, 'shards': [{'shard': 0, 'cases': [case_id]}]}
    plan['plan_sha256'] = S.digest(plan, 'plan_sha256')
    return plan


@pytest.mark.parametrize(('case_id', 'command'), [
    ('card:zlib-v1-v2', 'fetch'),
    ('card:zlib-v1-v2', 'build-card'),
    ('suite:_template/tiny', 'build-suite'),
    ('mutate:_template/tiny:cmp-flip:7000', 'mutate'),
    ('aa:_template/tiny', 'aa'),
    ('noise:_template/tiny', 'noise'),
    ('suite:_template/tiny', 'evaluate'),
])
@pytest.mark.parametrize('reported', ['failed', 'error'])
@pytest.mark.parametrize('rc', [0, 1])
def test_explicit_command_failure_remains_nonpassing(case_id, command, reported, rc, monkeypatch):
    monkeypatch.delenv('PATCHTRACE_TIER_R_NO_EVAL', raising=False)

    def runner(argv, timeout, env):
        if argv[3] == command:
            return rc, json.dumps({'command': command, 'status': reported, 'error': 'authored command failure'}), None
        return 0, '{"status":"ok"}', None

    doc = S.run_shard(one_case_plan(case_id), 0, runner=runner, log=lambda _: None)
    failed_id = 'evaluate:rz-diff' if command == 'evaluate' else case_id
    result = next(case for case in doc['cases'] if case['id'] == failed_id)
    assert result['status'] == 'failed'
    assert 'authored command failure' in result['reason']
    assert S.merge([doc])[1]['failing_cases'] == [failed_id]


@pytest.mark.parametrize(('rc', 'reported', 'status', 'exit_code'), [
    (0, 'failed', 'failed', S.FINDINGS),
    (1, 'failed', 'failed', S.FINDINGS),
    (0, 'error', 'failed', S.FINDINGS),
    (1, 'error', 'failed', S.FINDINGS),
    (3, 'blocked', 'blocked', S.BLOCKED),
    (3, 'failed', 'blocked', S.BLOCKED),
    (None, 'failed', 'timeout', S.FINDINGS),
])
def test_evaluation_failure_reaches_shard_and_merge_cli(tmp_path, monkeypatch, capsys, rc, reported,
                                                       status, exit_code):
    monkeypatch.delenv('PATCHTRACE_TIER_R_NO_EVAL', raising=False)
    plan_path = tmp_path / 'plan.json'
    plan_path.write_text(json.dumps(one_case_plan()), encoding='utf-8')

    def runner(argv, timeout, env):
        if argv[3] == 'evaluate':
            return rc, json.dumps({'command': 'evaluate', 'status': reported,
                                   'error': 'authored evaluation failure'}), 'timeout' if rc is None else None
        return 0, '{"status":"ok"}', None

    monkeypatch.setattr(S, 'default_runner', runner)
    assert S.main(['run-shard', '--plan', str(plan_path), '--shard', '0', '--out', str(tmp_path / 'shards')]) == exit_code
    emitted = json.loads(capsys.readouterr().out)
    assert emitted['blocked' if status == 'blocked' else 'failed'] == ['evaluate:rz-diff']
    shard = json.loads((tmp_path / 'shards/shard-0.json').read_text())
    assert next(case for case in shard['cases'] if case['id'] == 'evaluate:rz-diff')['status'] == status
    assert S.main(['merge', '--in', str(tmp_path / 'shards'), '--plan', str(plan_path),
                   '--out', str(tmp_path / 'merge')]) == S.FINDINGS
    assert json.loads(capsys.readouterr().out)['failing_cases'] == 1
    provenance = json.loads((tmp_path / 'merge/tier-r-merge.json').read_text())
    assert provenance['failing_cases'] == ['evaluate:rz-diff']


@pytest.mark.parametrize(('case_id', 'command'), [
    ('card:zlib-v1-v2', 'build-card'),
    ('suite:_template/tiny', 'build-suite'),
    ('mutate:_template/tiny:cmp-flip:7000', 'mutate'),
])
def test_ordinary_findings_still_pass_shard_and_merge_cli(tmp_path, monkeypatch, capsys, case_id, command):
    monkeypatch.setenv('PATCHTRACE_TIER_R_NO_EVAL', '1')
    plan_path = tmp_path / 'plan.json'
    plan_path.write_text(json.dumps(one_case_plan(case_id)), encoding='utf-8')

    def runner(argv, timeout, env):
        if argv[3] == command:
            return 1, json.dumps({'command': command, 'status': 'findings', 'disagreements': 1}), None
        return 0, '{"status":"ok"}', None

    monkeypatch.setattr(S, 'default_runner', runner)
    assert S.main(['run-shard', '--plan', str(plan_path), '--shard', '0', '--out', str(tmp_path / 'shards')]) == S.OK
    assert json.loads(capsys.readouterr().out)['failed'] == []
    shard = json.loads((tmp_path / 'shards/shard-0.json').read_text())
    assert shard['cases'][0]['status'] == 'findings'
    assert S.main(['merge', '--in', str(tmp_path / 'shards'), '--plan', str(plan_path),
                   '--out', str(tmp_path / 'merge')]) == S.OK
    assert json.loads(capsys.readouterr().out)['failing_cases'] == 0


def test_real_evaluation_retention_failure_reaches_shard_and_merge(tmp_path, monkeypatch, capsys):
    store = store_labels(tmp_path)
    monkeypatch.setattr(cli.E, 'default_providers', lambda *args, **kwargs: [provider()])
    monkeypatch.setattr(RS, 'MAX_CREDIT_BYTES', 1)
    code = cli.main(['evaluate', '--store', str(store), '--engines', 'rz-diff'])
    output = capsys.readouterr().out
    emitted = json.loads(output)
    assert code == cli.FINDINGS and emitted['status'] == 'failed' and emitted['credited'] is False
    assert 'evaluation output completion failed' in emitted['error']
    monkeypatch.delenv('PATCHTRACE_TIER_R_NO_EVAL', raising=False)

    def runner(argv, timeout, env):
        if argv[3] == 'evaluate':
            return code, output, None
        return 0, '{"status":"ok"}', None

    doc = S.run_shard(one_case_plan(), 0, runner=runner, log=lambda _: None)
    evaluation = next(case for case in doc['cases'] if case['id'] == 'evaluate:rz-diff')
    assert evaluation['status'] == 'failed'
    assert 'evaluation output completion failed' in evaluation['reason']
    assert S.merge([doc])[1]['failing_cases'] == ['evaluate:rz-diff']
