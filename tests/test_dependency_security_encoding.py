"""Unicode producer controls; no pip, installer or network audit is executed.

The CP1252 branch is authored simulation. With explicit UTF-8 the child retains
its real interpreter stream; this is not native pip/Rich qualification.
"""
from __future__ import annotations

import json
import sys

import pytest
from test_dependency_security import project as project

from tools import dependency_security as scan

PAYLOAD = '\U0001f44b / \u4fee\u590d / caf\u00e9'
BODY = (
    'import json,sys; '
    '(sys.stdout.reconfigure(encoding="cp1252") if sys._xoptions.get("utf8") not in (True,"1") else None); '
    'print(json.dumps({"text":' + repr(PAYLOAD) + ',"utf8_mode":sys.flags.utf8_mode,'
    '"isolated":sys.flags.isolated,"ignore_environment":sys.flags.ignore_environment},ensure_ascii=False))'
)


def inspection_prefix(tmp_path, project):
    plan = scan.commands(tmp_path / 'out', tmp_path / 'repo', project, 'runtime')['scanner-inspect']
    return [sys.executable, *plan[1:plan.index('-m')]]


@pytest.mark.parametrize('profile', ['runtime', 'packaging', 'static'])
def test_every_direct_python_command_has_one_isolated_utf8_prefix(tmp_path, project, profile):
    for name, argv in scan.commands(tmp_path / 'out', tmp_path / 'repo', project, profile).items():
        mode = min(argv.index(option) for option in ('-c', '-m') if option in argv)
        assert argv[1:mode] == ['-I', '-X', 'utf8'], (name, argv)


def test_canonical_prefix_preserves_unicode_through_bounded_binary_capture(tmp_path, project):
    argv = [*inspection_prefix(tmp_path, project), '-c', BODY]
    scan.run_logged(argv, tmp_path, 'authored-unicode', timeout=10, limit=8192)
    scan.process_receipt(tmp_path, 'authored-unicode', argv)
    raw = (tmp_path / 'authored-unicode.stdout').read_bytes()
    assert PAYLOAD.encode('utf-8') in raw
    assert json.loads(raw) == {'text': PAYLOAD, 'utf8_mode': 1, 'isolated': 1, 'ignore_environment': 1}


def test_caller_python_settings_cannot_override_encoding_or_isolation(tmp_path, monkeypatch, project):
    settings = {'PYTHONUTF8': '0', 'PYTHONIOENCODING': 'ascii',
                'PYTHONPATH': str(tmp_path / 'foreign'), 'PYTHONHOME': str(tmp_path / 'missing')}
    for key, value in settings.items():
        monkeypatch.setenv(key, value)
    code = ('import json,os,sys; print(json.dumps({"utf8":sys.flags.utf8_mode,'
            '"isolated":sys.flags.isolated,"ignored":sys.flags.ignore_environment,'
            '"encoding":sys.stdout.encoding,"environment":{k:os.environ.get(k) for k in '
            + repr(list(settings)) + '}}))')
    argv = [*inspection_prefix(tmp_path, project), '-c', code]
    scan.run_logged(argv, tmp_path, 'authored-environment', timeout=10, limit=8192)
    scan.process_receipt(tmp_path, 'authored-environment', argv)
    result = scan.read_json(tmp_path / 'authored-environment.stdout')
    assert result == {'utf8': 1, 'isolated': 1, 'ignored': 1, 'encoding': 'utf-8',
                      'environment': dict.fromkeys(settings)}


@pytest.mark.parametrize('alteration', ['missing', 'disabled'])
def test_successful_utf8_receipt_refuses_missing_or_disabled_mode(tmp_path, alteration):
    argv = [sys.executable, '-I', '-X', 'utf8', '-c', BODY]
    scan.run_logged(argv, tmp_path, 'authored-provenance', timeout=10, limit=8192)
    scan.process_receipt(tmp_path, 'authored-provenance', argv)
    changed = list(argv)
    if alteration == 'missing':
        del changed[2:4]
    else:
        changed[3] = 'utf8=0'
    with pytest.raises(scan.EvidenceError, match='provenance'):
        scan.process_receipt(tmp_path, 'authored-provenance', changed)


def test_encoding_failure_remains_failed_with_original_raw_output(tmp_path):
    code = 'import sys; sys.stdout.reconfigure(encoding="cp1252"); print(' + repr(PAYLOAD) + ')'
    argv = [sys.executable, '-I', '-c', code]
    record = scan.run_logged(argv, tmp_path, 'authored-failure', timeout=10, limit=8192)
    assert record['exit_code'] != 0 and not record['timed_out'] and not record['output_limited']
    assert b'UnicodeEncodeError' in (tmp_path / 'authored-failure.stderr').read_bytes()
    assert scan.read_json(tmp_path / 'authored-failure.process.json')['argv'] == argv
    with pytest.raises(scan.EvidenceError):
        scan.successful(record)
