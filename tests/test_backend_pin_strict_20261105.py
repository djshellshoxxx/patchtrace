"""Offline pin qualification must have one interpretation before any downloads."""
import json

import pytest
from test_backend_pin import PIN_PATH, checker
from test_build_backend_bundle import tool


@pytest.mark.parametrize('endpoint', ['checker', 'producer'])
@pytest.mark.parametrize('where', ['schema', 'sha256', 'owner_approved'])
def test_ambiguous_pin_refused_by_checker_and_producer(tmp_path, capsys, where, endpoint):
    raw = PIN_PATH.read_bytes()
    if where == 'schema':
        raw = b'{"schema":"forged",' + raw[1:]
    elif where == 'sha256':
        doc = json.loads(raw)
        digest = doc['components']['ghidra']['sha256'].encode()
        raw = raw.replace(b'"sha256": "' + digest + b'"',
                          b'"sha256":"' + b'0' * 64 + b'", "sha256": "' + digest + b'"', 1)
    else:
        raw = raw.replace(b'"owner_approved": true', b'"owner_approved":false,"owner_approved": true', 1)
    pin = tmp_path / 'pin.json'
    pin.write_bytes(raw)
    if endpoint == 'checker':
        assert checker.main(['--pin', str(pin)]) == 1
        assert 'cannot read pin' in capsys.readouterr().err
    else:
        with pytest.raises(tool.BundleBuildError, match='PT-BUNDLE-PIN'):
            tool.gate_pin(raw)


@pytest.mark.parametrize('value', [b'NaN', b'Infinity', b'1e9999', b'"\\ud800"'])
def test_invalid_json_metadata_cannot_bypass_gates(tmp_path, capsys, value):
    raw = b'{"qualification_note":' + value + b',' + PIN_PATH.read_bytes()[1:]
    pin = tmp_path / 'pin.json'
    pin.write_bytes(raw)
    assert checker.main(['--pin', str(pin), '--release']) == 1
    assert 'cannot read pin' in capsys.readouterr().err
    with pytest.raises(tool.BundleBuildError, match='PT-BUNDLE-PIN'):
        tool.gate_pin(raw)


def test_ambiguous_pin_refused_before_output_cache_download_or_runner(tmp_path):
    pin = tmp_path / 'pin.json'
    pin.write_bytes(b'{"schema":"forged",' + PIN_PATH.read_bytes()[1:])
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError('pin gate must run before external work')

    with pytest.raises(tool.BundleBuildError, match='PT-BUNDLE-PIN'):
        tool.build_backend(pin, 'windows', tmp_path / 'out', cache_dir=tmp_path / 'cache',
                           fetcher=forbidden, runner=forbidden, compile_bytecode=False)
    assert calls == []
    assert not (tmp_path / 'out').exists()
    assert not (tmp_path / 'cache').exists()


def test_committed_pin_round_trip_preserves_every_value():
    assert checker.parse_pin(PIN_PATH.read_bytes()) == json.loads(PIN_PATH.read_bytes())
    assert tool.gate_pin(PIN_PATH.read_bytes()) == checker.parse_pin(PIN_PATH.read_bytes())
