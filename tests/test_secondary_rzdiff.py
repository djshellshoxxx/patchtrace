"""SPEC-11: rz-diff probe, supervised run via fake executables, and strict parser."""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

from patchtrace.jobs import ProcessResult
from patchtrace.secondary.contracts import Capability, SecondaryError
from patchtrace.secondary.rzdiff import parse_output, parse_version, probe, run_rzdiff

OLD, NEW = 'a' * 64, 'b' * 64
FIXTURE = Path(__file__).parent / 'fixtures' / 'secondary' / 'rzdiff-functions.json'
posix = pytest.mark.skipif(os.name == 'nt', reason='shebang fake executables are POSIX-only')


def fake(tmp_path, body: str) -> Path:
    path = tmp_path / 'rz-diff'
    path.write_text(f'#!{Path(sys.executable).resolve()}\nimport sys, time, os\n{body}\n')
    path.chmod(0o755)
    return path


def cap(path='/opt/rz-diff', version='0.9.1'):
    return Capability(engine='rz-diff', supported=True, version=version, path=str(path), supports_json=True)


def artifacts(tmp_path):
    older, newer = tmp_path / 'old.sys', tmp_path / 'new.sys'
    older.write_bytes(b'MZ1')
    newer.write_bytes(b'MZ2')
    return older, newer


def test_fixture_parses_with_one_sided_records():
    result = parse_output(FIXTURE.read_text(), '0.9.1', OLD, NEW)
    assert result.engine == 'rz-diff' and len(result.matches) == 4
    full, partial, removed, added = result.matches
    assert (full.similarity_milli, full.match_type) == (1000, 'COMPLETE')
    assert (partial.similarity_milli, partial.similarity_text) == (963, '0.962963')
    assert partial.older_address == 0x140001008 and partial.algorithm == 'levenshtein-bytes'
    assert partial.confidence_milli is None and partial.flags == ()
    assert removed.newer_address is None and removed.older_address == 0x140002000
    assert added.older_address is None and added.newer_name == 'fcn.140003000'
    assert any('Levenshtein' in text for text in result.limitations)


ENTRY = {'similarity': 0.5, 'type': 'PARTIAL', 'original': {'addr': 1, 'name': 'f', 'size': 1},
         'modified': {'addr': 2, 'name': 'g', 'size': 1}}


def variant(**over):
    entry = {**ENTRY, **over}
    return json.dumps([{k: v for k, v in entry.items() if v != '<drop>'}])


@pytest.mark.parametrize('text', [
    '', '   \n', 'not json', '{"a": 1}', '[1]', 'null',
    variant(similarity=1.01), variant(similarity=-0.1), variant(similarity='0.5'), variant(similarity=True),
    variant(type='OTHER'), variant(original='<drop>'), variant(extra=1),
    variant(original={'addr': -1, 'name': 'f', 'size': 1}),
    variant(original={'addr': 2**64, 'name': 'f', 'size': 1}),
    variant(original={'addr': '1', 'name': 'f', 'size': 1}),
    variant(original={'addr': 1.0, 'name': 'f', 'size': 1}),
    variant(original={'addr': 1, 'name': 5, 'size': 1}),
    variant(original={'addr': 1, 'name': 'f'}),
    variant(original=None, modified=None),
    '[{"similarity": NaN, "type": "UNLIKE", "original": null, "modified": {"addr":1,"name":"f","size":1}}]',
    '[{"similarity": 0.5, "similarity": 0.6, "type": "PARTIAL", "original": null, "modified": null}]',
    FIXTURE.read_text() + 'trailing',
])
def test_malformed_output_rejected(text):
    with pytest.raises(SecondaryError):
        parse_output(text, '0.9.1', OLD, NEW)


def test_empty_array_is_valid_but_empty():
    assert parse_output('[]', '0.9.1', OLD, NEW).matches == ()


@pytest.mark.parametrize('text, expected', [
    ('rz-diff 0.9.1 @ linux-x86-64\ncommit: c3a90e92', ('0.9.1', (0, 9, 1))),
    ('rz-diff 0.10.0 @ windows-x86-64', ('0.10.0', (0, 10, 0))),
    ('rizin 0.9.1', None), ('', None),
])
def test_parse_version(text, expected):
    assert parse_version(text) == expected


def runner_returning(log, code=0, reason=None, seen=None):
    def run(argv, **kwargs):
        if seen is not None:
            seen.append((argv, kwargs))
        return ProcessResult(code, log, reason)
    return run


@pytest.mark.parametrize('log, code, supported, version', [
    ('rz-diff 0.9.1 @ linux-x86-64\n', 0, True, '0.9.1'),
    ('rz-diff 0.9.0 @ linux-x86-64\n', 0, True, '0.9.0'),
    ('rz-diff 0.8.2 @ linux-x86-64\n', 0, False, '0.8.2'),
    ('garbage', 0, False, None),
    ('rz-diff 0.9.1', 1, False, None),
])
def test_probe(log, code, supported, version):
    seen = []
    result = probe(Path('/opt/rz-diff'), {}, runner=runner_returning(log, code, seen=seen))
    assert (result.supported, result.version, result.supports_json) == (supported, version, supported)
    assert seen[0][0] == [str(Path('/opt/rz-diff')), '-v']  # platform path spelling


def test_probe_relative_path_is_unsupported():
    assert probe(Path('rz-diff'), dict(os.environ)).supported is False


def test_run_uses_argv_list_private_cwd_and_limits(tmp_path):
    older, newer = artifacts(tmp_path)
    seen = []
    result = run_rzdiff(cap(), older, newer, OLD, NEW, env={}, cancel=threading.Event(),
                        runner=runner_returning(FIXTURE.read_text(), seen=seen))
    argv, kwargs = seen[0]
    assert argv == ['/opt/rz-diff', '-C', '-j', '-t', 'functions', str(older.resolve()), str(newer.resolve())]
    assert kwargs['timeout_seconds'] == 1800 and kwargs['log_limit'] == 64 * 1024 * 1024 + 1
    assert kwargs['cwd'].name.startswith('patchtrace-rzdiff-') and not kwargs['cwd'].exists()
    assert len(result.matches) == 4


@pytest.mark.parametrize('timeout', [59, 86_401, 60.5, True])
def test_timeout_range(tmp_path, timeout):
    older, newer = artifacts(tmp_path)
    with pytest.raises(SecondaryError, match='timeout'):
        run_rzdiff(cap(), older, newer, OLD, NEW, env={}, cancel=threading.Event(), timeout_seconds=timeout,
                   runner=runner_returning('[]'))


def test_unsupported_capability_refused(tmp_path):
    older, newer = artifacts(tmp_path)
    bad = Capability(engine='rz-diff', supported=False, version='0.8.2', path='/x', supports_json=False,
                     reason='old')
    with pytest.raises(SecondaryError) as info:
        run_rzdiff(bad, older, newer, OLD, NEW, env={}, cancel=threading.Event())
    assert info.value.code == 'PT-SECONDARY-UNSUPPORTED'


@pytest.mark.parametrize('log, code, reason, error', [
    ('', 0, None, 'PT-SECONDARY-INPUT'),
    ('ERROR: rz-diff: error, cannot open file', 1, None, 'PT-SECONDARY-RUN'),
    ('[]', 0, 'timeout', 'PT-SECONDARY-RUN'),
    ('[]', -1, 'cancelled', 'PT-SECONDARY-CANCEL'),
    ('x' * (64 * 1024 * 1024 + 1), 0, None, 'PT-SECONDARY-LIMIT'),
    ('[{"similarity":0.5,"type":"PARTIAL","original":null,"modified":{"addr":1,"name":"\ufffd","size":1}}]',
     0, None, 'PT-SECONDARY-INPUT'),
], ids=['empty', 'exit-1', 'timeout', 'cancelled', 'over-64MiB', 'invalid-utf8'])
# Explicit ids: pytest would otherwise build a 64 MiB test id from the oversized log and stall
# writing it to a Windows console.
def test_run_failures(tmp_path, log, code, reason, error):
    older, newer = artifacts(tmp_path)
    with pytest.raises(SecondaryError) as info:
        run_rzdiff(cap(), older, newer, OLD, NEW, env={}, cancel=threading.Event(),
                   runner=runner_returning(log, code, reason))
    assert info.value.code == error
    if code == 1:
        assert 'cannot open file' in info.value.message


@posix
def test_real_fake_executable_end_to_end(tmp_path):
    older, newer = artifacts(tmp_path)
    exe = fake(tmp_path, f'''
if sys.argv[1:] == ["-v"]:
    print("rz-diff 0.9.1 @ linux-x86-64")
    sys.exit(0)
assert sys.argv[1:5] == ["-C", "-j", "-t", "functions"], sys.argv
assert os.getcwd() != {str(tmp_path)!r}
sys.stdout.write(open({str(FIXTURE)!r}).read())
''')
    capability = probe(exe, dict(os.environ))
    assert capability.supported and capability.version == '0.9.1'
    result = run_rzdiff(capability, older, newer, OLD, NEW, env=dict(os.environ), cancel=threading.Event())
    assert len(result.matches) == 4


@posix
def test_fake_exit_zero_empty_stdout_is_error(tmp_path):
    older, newer = artifacts(tmp_path)
    exe = fake(tmp_path, 'sys.exit(0)')
    with pytest.raises(SecondaryError, match='no output'):
        run_rzdiff(cap(exe), older, newer, OLD, NEW, env=dict(os.environ), cancel=threading.Event())


@posix
def test_fake_cancel_kills_child(tmp_path):
    older, newer = artifacts(tmp_path)
    exe = fake(tmp_path, 'time.sleep(60)')
    cancel = threading.Event()
    threading.Timer(0.5, cancel.set).start()
    started = time.monotonic()
    with pytest.raises(SecondaryError) as info:
        run_rzdiff(cap(exe), older, newer, OLD, NEW, env=dict(os.environ), cancel=cancel)
    assert info.value.code == 'PT-SECONDARY-CANCEL'
    assert time.monotonic() - started < 10


@posix
def test_fake_timeout(tmp_path, monkeypatch):
    from patchtrace.secondary import rzdiff
    monkeypatch.setattr(rzdiff, 'TIMEOUT_RANGE', (1, 86_400))
    older, newer = artifacts(tmp_path)
    exe = fake(tmp_path, 'time.sleep(60)')
    with pytest.raises(SecondaryError, match='timeout'):
        run_rzdiff(cap(exe), older, newer, OLD, NEW, env=dict(os.environ), cancel=threading.Event(),
                   timeout_seconds=1)


@posix
def test_stderr_diagnostics_do_not_corrupt_json(tmp_path):
    older, newer = artifacts(tmp_path)
    exe = fake(tmp_path, f'''
sys.stderr.write("WARNING: rz-diff: symbol table missing\\n")
sys.stdout.write(open({str(FIXTURE)!r}).read())
sys.stderr.write("INFO: done\\n")
''')
    result = run_rzdiff(cap(exe), older, newer, OLD, NEW, env=dict(os.environ), cancel=threading.Event())
    assert len(result.matches) == 4


@posix
def test_nonzero_exit_reports_stderr_not_stdout(tmp_path):
    older, newer = artifacts(tmp_path)
    exe = fake(tmp_path, 'sys.stdout.write("partial"); sys.stderr.write("ERROR: cannot open file"); sys.exit(1)')
    with pytest.raises(SecondaryError) as info:
        run_rzdiff(cap(exe), older, newer, OLD, NEW, env=dict(os.environ), cancel=threading.Event())
    assert info.value.code == 'PT-SECONDARY-RUN' and 'cannot open file' in info.value.message


def test_run_requests_separate_streams(tmp_path):
    older, newer = artifacts(tmp_path)
    seen = []
    run_rzdiff(cap(), older, newer, OLD, NEW, env={}, cancel=threading.Event(),
               runner=runner_returning(FIXTURE.read_text(), seen=seen))
    assert seen[0][1]['separate_streams'] is True


@pytest.mark.parametrize('over', [{'type': ['COMPLETE']}, {'type': {'a': 1}}, {'similarity': 10 ** 400}],
                         ids=['type-array', 'type-object', 'huge-int'])
def test_malformed_entries_raise_structured_error(over):
    with pytest.raises(SecondaryError):
        parse_output(variant(**over), '0.9.1', OLD, NEW)
