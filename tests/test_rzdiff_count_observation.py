"""Synthetic retained-capture decoding, never native Rizin compatibility evidence."""
from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools' / 'research'))
from rzdiff_count_observation import Capture, observation, query_argv  # noqa: E402


def capture():
    return Capture(query_argv('/approved/rz-diff', '/private/input.dll'), '1' * 64, '2' * 64)


def output(count='1\n'):
    return json.dumps({'from': '/private/input.dll', 'to': '/private/input.dll', 'diff': [
        {'from': [1, 1], 'to': [1, 1], 'ops': [
            {'op': 'delete', 'value': count}, {'op': 'insert', 'value': '-1\n'}]}]}).encode()


@pytest.mark.parametrize('count', [0, 1, 2, 123456, (1 << 64) - 1])
def test_counts_are_observations_only_and_bind_capture(count):
    raw = output(f'{count}\n')
    result = observation(capture(), raw, b'')
    assert result['recovered_count'] == count
    assert result['orientation_authorized'] is False
    assert result['capture_binding_verified'] is False
    assert result['stdout_sha256'] == hashlib.sha256(raw).hexdigest()
    assert result['stderr_sha256'] == hashlib.sha256(b'').hexdigest()
    assert result['artifact_sha256'] == '1' * 64
    assert result['runtime_config_sha256'] == '2' * 64
    assert result['argv'] == list(capture().argv)


def test_argv_contains_only_source_proven_fixed_commands():
    assert query_argv('tool', 'input') == (
        'tool', '-C', '-j', '-B', '-t', 'command', '-0', 'aflc', '-1', '%vi -1', 'input', 'input')


@pytest.mark.parametrize('count', ['-1\n', '01\n', '+1\n', '1', ' 1\n', '1\n2\n', '١\n',
                                 '9' * 21 + '\n', f'{1 << 64}\n'])
def test_noncanonical_or_unbounded_count_rejected(count):
    with pytest.raises(ValueError):
        observation(capture(), output(count), b'')


@pytest.mark.parametrize('mutation', [
    lambda d: d.update(timestamp='ignored'),
    lambda d: d.update(to='/other/input.dll'),
    lambda d: d.update(diff=[]),
    lambda d: d['diff'][0].update(extra=True),
    lambda d: d['diff'][0].update(**{'from': [True, 1]}),
    lambda d: d['diff'][0]['ops'].reverse(),
    lambda d: d['diff'][0]['ops'][1].update(value='-2\n'),
    lambda d: d['diff'][0]['ops'].append({'op': 'equal', 'value': ''}),
])
def test_shape_or_reference_drift_rejected(mutation):
    data = json.loads(output())
    mutation(data)
    with pytest.raises(ValueError):
        observation(capture(), json.dumps(data).encode(), b'')


@pytest.mark.parametrize('raw', [b'', b'[]', b'\xff', b'{' * 1000,
                                 b'{"from":1,"from":2}', b'x' * 65537])
def test_strict_bounded_json(raw):
    with pytest.raises(ValueError):
        observation(capture(), raw, b'')


@pytest.mark.parametrize('changes', [
    {'returncode': 1}, {'returncode': False}, {'reason': 'timeout'},
    {'artifact_sha256': 'x' * 64}, {'runtime_config_sha256': ''},
    {'executable_sha256': '0' * 64}, {'archive_sha256': '0' * 64},
    {'argv': (*capture().argv[:-1], '/other')},
    {'argv': ('evil', *capture().argv[1:6], '-0', 'aflj', *capture().argv[8:])},
])
def test_unverified_or_anomalous_capture_rejected(changes):
    with pytest.raises(ValueError):
        observation(replace(capture(), **changes), output(), b'')


def test_diagnostic_means_abstention_even_when_exit_is_zero():
    with pytest.raises(ValueError):
        observation(capture(), output(), b'cannot analyze binary\n')


@pytest.mark.parametrize('path', ['', '-eanalysis.timeout=0', 'a\x00b', 'a' * 4097])
def test_artifact_path_is_bounded_and_cannot_inject_tool_options(path):
    with pytest.raises(ValueError):
        query_argv('rz-diff', path)
