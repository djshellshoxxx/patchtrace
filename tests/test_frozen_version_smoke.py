"""Delivered-record acceptance controls with authored metadata and injected child output."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fake_exe import make_fake_exe

from patchtrace import __version__, buildinfo, jobs
from tools import frozen_smoke as smoke


@pytest.fixture
def delivered(tmp_path):
    package = tmp_path / 'Extracted package 研究'
    record_path = package / '_internal' / buildinfo.BUILD_INFO_RELATIVE
    record_path.parent.mkdir(parents=True)
    record = {'version': __version__, 'git_commit': 'a' * 40, 'git_describe': 'authored-test',
              'dirty': None, 'source_sha256': 'b' * 64, 'python': '3.12.0', 'pyinstaller': '6.22.3',
              'pyside6': '6.12.0', 'built_utc': '2026-11-27T23:00:00Z', 'frozen': True}
    raw = (json.dumps(record) + '\n').encode()
    record_path.write_bytes(raw)
    executable = package / 'PatchTrace.exe'
    executable.write_bytes(b'Authored placeholder: never executed by these injected-process tests.\n')
    return executable, record_path, record, raw


def response(record):
    return {'contract': 'enrichment-cli/1', 'command': 'version', 'status': 'complete', 'warnings': [],
            'result': {'contract': 'build-info/1', 'basis': 'packaged-record', **record}}


def process_result(body):
    raw = json.dumps(body).encode()
    return jobs.ProcessResult(returncode=0, log_tail='', log_bytes=raw, stdout_total=len(raw))


def test_version_only_checks_delivered_executable_and_reports_its_identity(delivered, monkeypatch, capsys):
    executable, record_path, record, raw = delivered
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return process_result(response(record))

    monkeypatch.setattr(jobs, 'run_process', run)
    monkeypatch.setattr(smoke, 'run', lambda *a, **k: pytest.fail('version-only ran another command'))
    monkeypatch.setattr(sys, 'argv', ['frozen_smoke.py', str(executable), '--version-only'])
    assert smoke.main() == 0
    assert len(calls) == 1 and calls[0][0] == [str(executable), 'version', '--json']
    assert calls[0][1]['cwd'] == executable.parent
    assert calls[0][1]['max_output_bytes'] == buildinfo.MAX_BUILD_BYTES
    out = capsys.readouterr()
    assert 'PASS V1' in out.out and record['git_commit'] in out.out and record['source_sha256'] in out.out
    assert not out.err and record_path.read_bytes() == raw


def test_missing_record_stops_full_smoke_before_executing_other_commands(delivered, monkeypatch):
    executable, record_path, _, _ = delivered
    record_path.unlink()
    monkeypatch.setattr(smoke, 'run', lambda *a, **k: pytest.fail('unverified package was executed'))
    monkeypatch.setattr(jobs, 'run_process', lambda *a, **k: pytest.fail('missing record reached child'))
    lines = []
    failures = smoke.run_checks([str(executable)], frozen=True, emit=lines.append)
    assert len(failures) == 1 and failures[0].startswith('V1 ')
    assert lines == ['FAIL V1 packaged version matches the delivered build record']


def test_version_only_fails_when_executable_reports_another_record(delivered, monkeypatch, capsys):
    executable, _, record, _ = delivered
    got = response(record | {'source_sha256': 'c' * 64})
    monkeypatch.setattr(jobs, 'run_process', lambda *a, **k: process_result(got))
    monkeypatch.setattr(sys, 'argv', ['frozen_smoke.py', str(executable), '--version-only'])
    assert smoke.main() == 1
    output = capsys.readouterr()
    assert 'FAIL V1' in output.out and 'differs' in output.err and 'PASS' not in output.out


def test_packaged_observation_needs_no_installed_host_dependencies(delivered, tmp_path):
    executable, record_path, record, _ = delivered
    # A real authored child prints only synthetic JSON; this is not a frozen application.
    authored = make_fake_exe(tmp_path / 'authored', 'consumer',
                             f'import json\nprint(json.dumps({response(record)!r}))\n')
    root = Path(__file__).resolve().parents[1]
    code = ('from pathlib import Path\n'
            'from tools.package_buildinfo import check_frozen_record\n'
            f'check_frozen_record(Path({str(authored)!r}), Path({str(record_path)!r}).read_bytes(), '
            f'cwd=Path({str(executable.parent)!r}))\n')
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(map(str, (root, root / 'src'))))
    result = subprocess.run([sys.executable, '-S', '-c', code], cwd=tmp_path, env=env,
                            capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('damage', ['utf8', 'duplicate', 'oversized', 'unknown-source', 'dirty', 'dependency'])
def test_invalid_record_never_launches_the_delivered_executable(delivered, monkeypatch, damage):
    executable, record_path, record, raw = delivered
    if damage == 'utf8':
        raw = b'\xff'
    elif damage == 'duplicate':
        raw = raw.rstrip()[:-1] + b', "frozen": true}'
    elif damage == 'oversized':
        raw += b' ' * buildinfo.MAX_BUILD_BYTES
    else:
        change = {'unknown-source': {'source_sha256': 'unknown'}, 'dirty': {'dirty': False},
                  'dependency': {'pyinstaller': None}}[damage]
        raw = json.dumps(record | change).encode()
    record_path.write_bytes(raw)
    monkeypatch.setattr(jobs, 'run_process', lambda *a, **k: pytest.fail('invalid metadata reached child'))
    failures = smoke.run_checks([str(executable)], frozen=True, version_only=True, emit=lambda line: None)
    assert len(failures) == 1 and failures[0].startswith('V1 ')
    assert record_path.read_bytes() == raw


@pytest.mark.parametrize('damage', ['frozen-int', 'dirty-int', 'float', 'overflow', 'nan', 'duplicate', 'warning'])
def test_invalid_child_version_response_cannot_pass_smoke(delivered, monkeypatch, damage):
    executable, _, record, _ = delivered
    got = response(record)
    if damage == 'frozen-int':
        got['result']['frozen'] = 1
    elif damage == 'dirty-int':
        got['result']['dirty'] = 0
    elif damage == 'warning':
        got['warnings'] = ['metadata unavailable']
    raw = json.dumps(got).encode()
    if damage in {'float', 'overflow', 'nan'}:
        raw = raw.replace(b'"frozen": true', b'"frozen": ' +
                          {'float': b'1.0', 'overflow': b'1e999', 'nan': b'NaN'}[damage])
    elif damage == 'duplicate':
        raw = raw.replace(b'"command": "version"', b'"command": "version", "command": "version"')
    result = jobs.ProcessResult(returncode=0, log_tail='', log_bytes=raw, stdout_total=len(raw))
    monkeypatch.setattr(jobs, 'run_process', lambda *a, **k: result)
    failures = smoke.run_checks([str(executable)], frozen=True, version_only=True, emit=lambda line: None)
    assert len(failures) == 1 and failures[0].startswith('V1 ')


@pytest.mark.parametrize('changed', ['record', 'package'])
def test_record_or_package_change_during_child_observation_fails(delivered, tmp_path, monkeypatch, changed):
    executable, record_path, record, raw = delivered

    def run(*args, **kwargs):
        if changed == 'package':
            executable.parent.rename(tmp_path / 'prior-package')
            record_path.parent.mkdir(parents=True)
            record_path.write_bytes(raw)
        else:
            record_path.write_bytes(json.dumps(record | {'source_sha256': 'c' * 64}).encode())
        return process_result(response(record))

    monkeypatch.setattr(jobs, 'run_process', run)
    failures = smoke.run_checks([str(executable)], frozen=True, version_only=True, emit=lambda line: None)
    assert len(failures) == 1 and 'changed' in failures[0]


@pytest.mark.parametrize('linked', ['package', 'internal', 'record'])
def test_linked_record_or_ancestor_is_not_resolved_away(delivered, tmp_path, monkeypatch, capsys, linked):
    executable, record_path, _, _ = delivered
    target = {'package': executable.parent, 'internal': executable.parent / '_internal',
              'record': record_path}[linked]
    external = tmp_path / f'original-{linked}'
    directory = target.is_dir()
    target.rename(external)
    try:
        target.symlink_to(external, target_is_directory=directory)
    except OSError:
        pytest.skip('host cannot create links')
    monkeypatch.setattr(jobs, 'run_process', lambda *a, **k: pytest.fail('linked package reached child'))
    monkeypatch.setattr(sys, 'argv', ['frozen_smoke.py', str(executable), '--version-only'])
    assert smoke.main() == 1
    output = capsys.readouterr()
    assert 'FAIL V1' in output.out and 'PASS' not in output.out


def test_actual_version_only_script_runs_without_site_packages_or_checkout_cwd(delivered, tmp_path):
    _, _, record, raw = delivered
    package = tmp_path / 'standalone-package'
    record_path = package / '_internal' / buildinfo.BUILD_INFO_RELATIVE
    record_path.parent.mkdir(parents=True)
    record_path.write_bytes(raw)
    # A real authored child, not a frozen application. It verifies host-only
    # source configuration and a synthetic secret cannot leak to the package.
    authored = make_fake_exe(package, 'consumer',
                             'import json, os, sys\n'
                             'assert sys.argv[1:] == ["version", "--json"]\n'
                             'assert "PYTHONPATH" not in os.environ\n'
                             'assert "OPENAI_API_KEY" not in os.environ\n'
                             f'print(json.dumps({response(record)!r}))\n')
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ, PYTHONPATH=str(root / 'src'), OPENAI_API_KEY='authored-test-sentinel')
    result = subprocess.run([sys.executable, '-S', str(root / 'tools' / 'frozen_smoke.py'),
                             str(authored), '--version-only'], cwd=tmp_path, env=env,
                            capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        'PASS V1 packaged version matches the delivered build record',
        f'VERSION git_commit={record["git_commit"]} source_sha256={record["source_sha256"]}',
    ]
    assert not result.stderr and record_path.read_bytes() == raw


def test_source_mode_cannot_claim_version_only_frozen_acceptance():
    with pytest.raises(ValueError, match='requires a frozen executable'):
        smoke.run_checks([sys.executable, '-m', 'patchtrace'], frozen=False, version_only=True)
