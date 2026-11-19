"""SPEC-32 exit-1 reporting using only authored injected runner tuples."""
from __future__ import annotations

import json

import pytest

from tools.calibration.tier_r import shard as S


@pytest.fixture(autouse=True)
def evaluation_is_present(monkeypatch):
    monkeypatch.delenv('PATCHTRACE_TIER_R_NO_EVAL', raising=False)


def plan(case='suite:_template/tiny'):
    value = {'contract': S.PLAN_CONTRACT, 'seed': 7, 'subset': 'smoke', 'engines': ['rz-diff'],
             'of': 1, 'cases_total': 1, 'shards': [{'shard': 0, 'cases': [case]}]}
    value['plan_sha256'] = S.digest(value, 'plan_sha256')
    return value


def both_lanes(stdout, *, rc=1, stderr='authored final diagnostic', reason=None):
    calls, logs = [], []

    def injected(argv, timeout, env):
        calls.append(argv[3:])
        return rc, stdout, reason, stderr

    result = S.run_shard(plan(), 0, runner=injected, log=logs.append)
    assert [call[0] for call in calls] == ['build-suite', 'evaluate']
    assert [row['id'] for row in result['cases']] == ['suite:_template/tiny', 'evaluate:rz-diff']
    return result, logs


BAD_SUMMARIES = [
    '', 'not JSON', '{invalid-json', '[]', 'null', 'true', '1', '"suite"', '{}',
    '{"message":"incidental object"}', '{"status":"findings"}', '{"command":"suite"}',
    *[json.dumps({'command': command, 'status': 'findings'}) for command in
      (None, True, 1, [], {}, '', 'unknown', 'suite ', 'Suite', 'catalogue-check')],
    *[json.dumps({'command': 'suite', 'status': status, 'disagreements': 1}) for status in
      (None, False, 1, [], {}, '', 'blocked', 'skipped', 'error', 'proposals')],
    *[json.dumps({'command': 'suite', 'disagreements': count}) for count in
      (None, True, False, -1, 1.5, '1', [], {})],
]


@pytest.mark.parametrize('stdout', BAD_SUMMARIES)
def test_unrecognized_exit1_is_failed_and_logs_each_lane_diagnostic(stdout):
    result, logs = both_lanes(stdout)
    assert all(row['status'] == 'failed' for row in result['cases'])
    assert all(row['reason'] == 'exit 1: authored final diagnostic' for row in result['cases'])
    assert sum('stderr (last lines):' in line for line in logs) == 2
    assert any('[FAILED] suite:_template/tiny:' in line for line in logs)
    assert any('[FAILED] evaluate:rz-diff:' in line for line in logs)


@pytest.mark.parametrize('command', ['fetch', 'build-suite', 'build-card', 'aa', 'noise', 'mutate', 'evaluate', 'suite'])
@pytest.mark.parametrize('status', ['ok', 'findings', 'failed'])
def test_recognized_status_keeps_existing_exit1_semantics(command, status):
    result, logs = both_lanes(json.dumps({'command': command, 'status': status}))
    assert all(row['status'] == 'findings' and row['reason'] == 'exit 1' for row in result['cases'])
    assert logs == []


@pytest.mark.parametrize('count', [0, 1, 20])
def test_legacy_suite_integer_disagreements_remains_recognized(count):
    result, logs = both_lanes(json.dumps({'command': 'suite', 'disagreements': count}))
    assert all(row['status'] == 'findings' for row in result['cases'])
    assert logs == []


@pytest.mark.parametrize('summary', [
    {'command': 'fetch', 'status': 'failed', 'fetched': [], 'errors': ['authored fetch failure']},
    {'command': 'evaluate', 'status': 'failed', 'report': 'absent.json', 'engines': {'rz-diff': 'failed'}, 'blocked': {}},
    {'command': 'evaluate', 'status': 'failed', 'credited': False, 'error': 'authored retention failure', 'diagnostics': {}},
])
def test_actual_cli_failed_status_shapes_do_not_get_redefined(summary):
    result, logs = both_lanes(json.dumps(summary))
    assert all(row['status'] == 'findings' for row in result['cases'])
    assert logs == []


@pytest.mark.parametrize('rc,stdout,expected', [
    (None, '', 'timeout'), (3, '', 'blocked'), (2, '', 'failed'), (127, '', 'failed'),
    (0, '', 'ok'), (0, '{}', 'ok'), (0, '{"status":"skipped","reason":"authored skip"}', 'skipped'),
])
def test_other_exit_precedence_stays_unchanged(rc, stdout, expected):
    result, _logs = both_lanes(stdout, rc=rc)
    assert all(row['status'] == expected for row in result['cases'])


@pytest.mark.parametrize('rc', [0, 1])
def test_nonidentical_aa_keeps_failure_precedence_and_reason(rc):
    summary = {'command': 'aa', 'status': 'skipped', 'not_byte_identical': ['authored-pair']}
    result, logs = both_lanes(json.dumps(summary), rc=rc)
    assert all(row['status'] == 'failed' and 'A/A rebuild is not byte-identical' in row['reason']
               for row in result['cases'])
    assert sum('stderr (last lines):' in line for line in logs) == 2


def test_exit1_failure_reason_and_raw_stderr_tail_remain_bounded():
    stderr = 'discarded-prefix-marker\n' + '\n'.join(f'line {index}' for index in range(60)) + '\n' + 'z' * 5000
    result, logs = both_lanes('{}', stderr=stderr)
    assert all(row['status'] == 'failed' and len(row['reason']) == S.REASON_CHARS and '\n' not in row['reason']
               for row in result['cases'])
    assert all(len(line) <= S.STDERR_CHARS + 500 for line in logs)
    serialized = json.dumps(result)
    assert 'discarded-prefix-marker' not in serialized and 'z' * (S.REASON_CHARS + 1) not in serialized
    assert 'discarded-prefix-marker' not in '\n'.join(logs)


def test_runner_reason_stays_primary_and_missing_diagnostic_is_explicit():
    result, logs = both_lanes('', reason='authored runner reason\nwith whitespace')
    assert all(row['reason'] == 'authored runner reason with whitespace' for row in result['cases'])
    assert any('authored final diagnostic' in line for line in logs)
    empty, _logs = both_lanes('', stderr='')
    assert all(row['reason'] == 'exit 1: no diagnostic output' for row in empty['cases'])


def test_failed_fetch_stops_later_case_steps_but_keeps_independent_evaluation():
    calls = []

    def injected(argv, timeout, env):
        calls.append(argv[3])
        return (1, '', None, 'authored fetch traceback') if argv[3] == 'fetch' else (
            0, '{"command":"evaluate","status":"ok"}', None, '')

    result = S.run_shard(plan('card:zlib-a'), 0, runner=injected, log=lambda text: None)
    assert calls == ['fetch', 'evaluate']
    assert [row['status'] for row in result['cases']] == ['failed', 'ok']


def test_recognition_does_not_replace_existing_pretty_json_extraction():
    summary = {'command': 'suite', 'disagreements': 1}
    for stdout in (json.dumps(summary), 'authored progress\n' + json.dumps(summary),
                   'authored progress\n' + json.dumps(summary, indent=1)):
        assert S._summary(stdout) == summary
        result, _logs = both_lanes(stdout)
        assert all(row['status'] == 'findings' for row in result['cases'])
    assert S._summary('authored progress\n{"incidental":true}') == {'incidental': True}


def test_new_failed_status_survives_shard_storage_and_merge(tmp_path):
    result, _logs = both_lanes('{invalid-json')
    S.write_shard(result, tmp_path / 'shards')
    [restored] = S.load_shards(tmp_path / 'shards', plan=plan())
    _report, provenance = S.merge([restored])
    assert set(provenance['failing_cases']) == {'suite:_template/tiny', 'evaluate:rz-diff'}
    assert all(row['status'] == 'failed' and row['reason'] == 'exit 1: authored final diagnostic'
               for row in provenance['cases'])
