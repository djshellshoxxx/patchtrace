"""SPEC-32 A/A reporting across the existing shard/store/merge/CLI boundary.

Every runner is authored. No compiler, analyzer, target or network is executed.
"""
from __future__ import annotations

import json

import pytest
from test_tier_r_shard import fake_runner, write_tree

from tools.calibration.tier_r import shard as S


def producer(command, returncode, differences, *, summary_command=None, summary_status=None):
    def run(argv, timeout, env):
        if argv[3] != command:
            return fake_runner(argv, timeout, env)
        summary = {'command': summary_command or command,
                   'status': summary_status or ('findings' if differences else 'ok'),
                   'not_byte_identical': differences, 'written': []}
        return returncode, json.dumps(summary), 'authored timeout' if returncode is None else None, 'authored diagnostic'
    return run


@pytest.mark.parametrize('command,rc,differences,expected', [
    ('aa', 0, ['pair-a'], 'failed'), ('aa', 1, ['pair-a'], 'failed'),
    ('aa', 0, [], 'ok'), ('aa', 1, [], 'findings'),
    ('aa', None, ['pair-a'], 'timeout'), ('aa', 3, ['pair-a'], 'blocked'),
    ('aa', 2, ['pair-a'], 'failed'),
    ('noise', 1, ['pair-a'], 'findings'), ('mutate', 1, ['pair-a'], 'findings'),
    ('evaluate', 1, ['pair-a'], 'findings'), ('build-suite', 1, ['pair-a'], 'findings'),
])
def test_rebuild_failure_and_other_statuses_survive_storage_and_merge(tmp_path, command, rc, differences, expected):
    plan = S.make_plan(write_tree(tmp_path), seed=4, shards=1, subset='full')
    doc = S.run_shard(plan, 0, runner=producer(command, rc, differences), log=lambda text: None)
    S.write_shard(doc, tmp_path / 'out')
    [restored] = S.load_shards(tmp_path / 'out', plan=plan)
    aggregate, provenance = S.merge([restored])
    prefix = {'build-suite': 'suite', 'evaluate': 'evaluate'}.get(command, command) + ':'
    cases = [case for case in restored['cases'] if case['id'].startswith(prefix)]
    assert cases and all(case['status'] == expected for case in cases)
    for case in cases:
        merged = next(row for row in provenance['cases'] if row['id'] == case['id'])
        assert merged == {key: case[key] for key in ('id', 'status', 'reason')}
        assert (case['id'] in provenance['failing_cases']) == (expected in {'failed', 'timeout', 'blocked'})
        if command == 'aa' and differences and rc in (0, 1):
            assert 'A/A' in case['reason'] and 'not byte-identical' in case['reason']
            assert case['id'] in S.render_markdown(aggregate, provenance)
        elif rc in (None, 2, 3):
            assert 'authored' in case['reason']


@pytest.mark.parametrize('rc', [0, 1])
def test_command_mismatch_does_not_promote_generic_findings(tmp_path, rc):
    plan = S.make_plan(write_tree(tmp_path), seed=5, shards=1, subset='suites')
    result = S.run_shard(plan, 0, runner=producer('aa', rc, ['pair-a'], summary_command='noise'))
    assert all(row['status'] == ('ok' if rc == 0 else 'findings')
               for row in result['cases'] if row['id'].startswith('aa:'))


def test_nonidentical_aa_cannot_claim_skipped_or_run_later_case_steps(tmp_path, monkeypatch):
    plan = S.make_plan(write_tree(tmp_path), seed=6, shards=1, subset='suites')
    original = S.case_steps
    monkeypatch.setattr(S, 'case_steps', lambda case: original(case) + (
        [['noise', '--after-aa']] if case.startswith('aa:') else []))
    calls = []
    run = producer('aa', 0, ['pair-a'], summary_status='skipped')

    def runner(argv, timeout, env):
        calls.append(argv[3:])
        return run(argv, timeout, env)

    doc = S.run_shard(plan, 0, runner=runner, log=lambda text: None)
    assert all(case['status'] == 'failed' for case in doc['cases'] if case['id'].startswith('aa:'))
    assert ['noise', '--after-aa'] not in calls


@pytest.mark.parametrize('rc', [0, 1])
def test_cli_run_and_merge_report_aa_failure(tmp_path, monkeypatch, capsys, rc):
    plan = S.make_plan(write_tree(tmp_path), seed=7, shards=1, subset='suites')
    plan_path = tmp_path / 'plan.json'
    plan_path.write_text(json.dumps(plan), encoding='utf-8')
    out, merged = tmp_path / 'out', tmp_path / 'merged'
    monkeypatch.setattr(S, 'default_runner', producer('aa', rc, ['pair-a']))
    monkeypatch.setenv('PATCHTRACE_TIER_R_NO_EVAL', '1')
    code = S.main(['run-shard', '--plan', str(plan_path), '--shard', '0', '--out', str(out)])
    summary = json.loads(capsys.readouterr().out)
    expected = {case for entry in plan['shards'] for case in entry['cases'] if case.startswith('aa:')}
    assert expected and code == S.FINDINGS and set(summary['failed']) == expected
    assert S.main(['merge', '--in', str(out), '--out', str(merged)]) == S.FINDINGS
    summary = json.loads(capsys.readouterr().out)
    provenance = json.loads((merged / 'tier-r-merge.json').read_text(encoding='utf-8'))
    assert summary['failing_cases'] == len(expected) and set(provenance['failing_cases']) == expected
    assert all('not byte-identical' in row['reason'] for row in provenance['cases'] if row['id'] in expected)
