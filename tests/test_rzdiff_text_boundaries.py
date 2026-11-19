"""The rz-diff process interpreter keeps malformed fallback text inside typed failures."""
from __future__ import annotations

import hashlib
import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from patchtrace.secondary import rzdiff
from patchtrace.secondary.contracts import SecondaryError

OLD, NEW = 'a' * 64, 'b' * 64


def _interpret(output: str | bytes, *, code: int = 0, stderr: str = ''):
    return rzdiff.interpret(code, output, stderr, '0.9.1', OLD, NEW)


@pytest.mark.parametrize('output', ['\ud800', '\udfff', '["\ud800"]', '[]\udc80'],
                         ids=['high-surrogate', 'low-surrogate', 'in-json', 'after-json'])
def test_successful_exit_with_invalid_fallback_utf8_is_a_typed_input_error(output):
    with pytest.raises(SecondaryError) as info:
        _interpret(output)
    assert info.value.code == 'PT-SECONDARY-INPUT'
    assert 'UTF-8' in info.value.message


@pytest.mark.parametrize('stdout, stderr', [
    ('\ud800', ''), ('', '\ud800'), (b'\xff', '\udfff'), ('\udc80', 'explicit failure'),
], ids=['fallback-stdout', 'stderr', 'bytes-with-bad-stderr', 'stderr-preferred'])
def test_nonzero_exit_keeps_run_failure_and_encodable_diagnostics(stdout, stderr):
    with pytest.raises(SecondaryError) as info:
        _interpret(stdout, code=7, stderr=stderr)
    assert info.value.code == 'PT-SECONDARY-RUN'
    assert 'exited with 7' in info.value.message
    info.value.message.encode('utf-8')
    if stderr == 'explicit failure':
        assert info.value.message.endswith(stderr)


def test_invalid_diagnostic_tail_stays_bounded(monkeypatch):
    monkeypatch.setattr(rzdiff, 'STDERR_TAIL', 64)
    with pytest.raises(SecondaryError) as info:
        _interpret('', code=1, stderr='discarded-prefix' + '\ud800' * 100)
    assert info.value.code == 'PT-SECONDARY-RUN'
    assert info.value.message.startswith('rz-diff exited with 1: ')
    tail = info.value.message.removeprefix('rz-diff exited with 1: ')
    assert len(tail.encode('utf-8')) <= 64
    assert 'discarded-prefix' not in tail


@settings(max_examples=100, deadline=None, database=None)
@given(st.integers(0xD800, 0xDFFF), st.text(max_size=32), st.text(max_size=32))
def test_any_raw_surrogate_in_successful_fallback_output_is_a_typed_input_error(codepoint, before, after):
    with pytest.raises(SecondaryError) as info:
        _interpret(before + chr(codepoint) + after)
    assert info.value.code == 'PT-SECONDARY-INPUT'


@pytest.mark.parametrize('as_bytes', [False, True], ids=['fallback-text', 'exact-bytes'])
def test_valid_unicode_and_original_output_digest_are_preserved(as_bytes):
    entries = [
        {'similarity': 1, 'type': 'COMPLETE',
         'original': {'addr': address, 'name': '\U0001f600\u00e9', 'size': 1},
         'modified': {'addr': address + 2, 'name': '\u51fd\u6570', 'size': 1}}
        for address in (1, 2)
    ]
    text = json.dumps(entries, ensure_ascii=False)
    encoded = text.encode('utf-8')
    result = _interpret(encoded if as_bytes else text)
    assert result.file_sha256 == hashlib.sha256(encoded).hexdigest()
    assert [match.older_name for match in result.matches] == ['\U0001f600\u00e9'] * 2
    assert [match.newer_name for match in result.matches] == ['\u51fd\u6570'] * 2

