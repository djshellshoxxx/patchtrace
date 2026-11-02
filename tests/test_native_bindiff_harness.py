"""Harness guard controls; no compiler, JVM, exporter or BinDiff executes here."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[1] / 'docs/qa/native-bindiff-harness-20261102.py'
SPEC = importlib.util.spec_from_file_location('native_bindiff_harness', PATH)
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)


def test_default_is_setup_only(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(H, 'setup', lambda *args: {'source_head': 'a' * 40})
    monkeypatch.setattr(H, 'exercise', lambda *args: pytest.fail('default executed native analysis'))
    assert H.main(['--tool-root', str(tmp_path), '--source-head', 'a' * 40]) == 0
    assert json.loads(capsys.readouterr().out)['native_executed'] is False
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('existing', ['empty_directory', 'file'])
def test_existing_session_is_never_adopted(tmp_path, existing):
    path = tmp_path / 'run'
    if existing == 'file':
        path.write_text('previous evidence')
    else:
        path.mkdir()
    with pytest.raises(FileExistsError):
        H.Session(path, {})
    if existing == 'file':
        assert path.read_text() == 'previous evidence'


def test_hash_guard_rejects_changed_bytes_and_links(tmp_path):
    path = tmp_path / 'tool'
    path.write_bytes(b'expected')
    digest = H.sha(path)
    assert H.require_hash(path, digest) == digest
    path.write_bytes(b'changed!')
    with pytest.raises(ValueError, match='digest'):
        H.require_hash(path, digest)
    link = tmp_path / 'linked'
    try:
        link.symlink_to(path)
    except OSError:
        pytest.skip('symlinks unavailable')
    with pytest.raises(ValueError, match='regular-file'):
        H.require_hash(link, H.sha(path))


def test_child_environment_drops_injection_and_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv('JAVA_TOOL_OPTIONS', 'injected')
    monkeypatch.setenv('OPENAI_API_KEY', 'private')
    monkeypatch.setenv('HTTPS_PROXY', 'private')
    monkeypatch.setenv('PYTHONPATH', 'foreign-repository')
    result = H.child_env(tmp_path, tmp_path / 'jdk/bin/java')
    assert not set(result) & {'JAVA_TOOL_OPTIONS', 'OPENAI_API_KEY', 'HTTPS_PROXY', 'PYTHONPATH'}
    assert result['HOME'] == str(tmp_path)


def test_headless_argv_keeps_paths_as_single_values_and_bounds_jvm(tmp_path):
    root = tmp_path / 'contains spaces'
    java = root / 'jdk/bin/java'
    args = H.headless_argv(java, root / 'ghidra', root / 'home', root / 'project', 'older')
    assert args[0] == str(java)
    assert '-Xmx2G' in args and '-XX:ActiveProcessorCount=2' in args
    assert str(root / 'project') in args and args[-2:] == ['-max-cpu', '1']
    assert 'ghidra.app.util.headless.AnalyzeHeadless' in args


def test_export_guard_detects_overflow_and_nonregular_entries(tmp_path, monkeypatch):
    monkeypatch.setattr(H, 'MAX_EXPORT', 4)
    assert H.export_guard(tmp_path) is None
    (tmp_path / 'output').write_bytes(b'12345')
    assert H.export_guard(tmp_path) == 'output-limit'
    (tmp_path / 'output').unlink()
    (tmp_path / 'folder').mkdir()
    assert H.export_guard(tmp_path) == 'output-unexpected'


def test_child_failure_retains_exact_logs_and_argv(tmp_path):
    session = H.Session(tmp_path / 'run', {})
    command = [sys.executable, '-c', 'import sys;print("out");print("err",file=sys.stderr);sys.exit(7)']
    result = session.run(command, cwd=tmp_path, env={}, cancel=session.cancel, timeout_seconds=5,
                         separate_streams=True, log_limit=4096, stderr_limit=4096)
    with pytest.raises(RuntimeError, match='exit=7'):
        H.require_clean(result, 'constructed child')
    receipt = json.loads((session.root / 'receipt.json').read_text())
    assert receipt['processes'][0]['argv'] == command
    assert (session.root / 'process-01.stdout').read_bytes().strip() == b'out'
    assert (session.root / 'process-01.stderr').read_bytes().strip() == b'err'


def test_failed_native_attempt_reports_failure_without_deleting_evidence(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(H, 'setup', lambda *args: {'source_head': 'a' * 40})

    def fail(session):
        (session.root / 'upstream.partial').write_bytes(b'preserve failed bytes')
        raise RuntimeError('injected native stage failure')

    monkeypatch.setattr(H, 'exercise', fail)
    run = tmp_path / 'run'
    assert H.main(['--tool-root', str(tmp_path), '--source-head', 'a' * 40,
                   '--run-dir', str(run), '--run']) == 1
    assert json.loads(capsys.readouterr().out)['status'] == 'failed'
    assert (run / 'upstream.partial').read_bytes() == b'preserve failed bytes'
    assert json.loads((run / 'receipt.json').read_text())['status'] == 'failed'


def test_reviewed_script_and_fixture_pins_are_current():
    pin = json.loads(H.PINS.read_text())
    assert H.sha(H.SCRIPT) == pin['script_sha256']
    for name, expected in pin['source_sha256'].items():
        assert H.sha(H.REPO / 'tests/fixtures' / name) == expected
    assert pin['binexport_signed'] is False and pin['bindiff_independent_trust_verified'] is False


def test_c3_logging_restores_the_production_runner_even_on_failure(tmp_path):
    session = H.Session(tmp_path / 'run', {})
    original = H.binexport_run.run_process
    with pytest.raises(RuntimeError, match='injected'):
        with H.record_c3(session):
            assert H.binexport_run.run_process == session.run
            raise RuntimeError('injected')
    assert H.binexport_run.run_process is original is H.run_process
