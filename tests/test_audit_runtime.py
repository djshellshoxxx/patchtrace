import json
import os
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

from patchtrace import backend
from patchtrace.backend import BackendConfig, _probe_backend, run_comparison
from patchtrace.diagnostics import redact_log
from patchtrace.runtime_discovery import MAX_CHILDREN_PER_ROOT, discover_local_runtimes
from tests import test_jobs

fake_runtime = test_jobs.fake_runtime
write_backend = test_jobs.write_backend


@pytest.mark.parametrize('text', [
    'proxy http://user:p@ss@proxy.example:8080/x',
    'proxy socks5://user:hunter2@proxy.example:1080',
    'url https://user:hunter2@host/path',
])
def test_url_credentials_fully_redacted(text):
    out = redact_log(text)
    assert 'hunter2' not in out and 'ss@proxy' not in out and 'user' not in out
    assert '[redacted]@' in out


def test_url_without_credentials_unchanged():
    assert redact_log('see https://example.com/a@b') == 'see https://example.com/a@b'


def _ghidra(path: Path) -> Path:
    (path / 'Ghidra').mkdir(parents=True)
    (path / 'Ghidra' / 'application.properties').write_text('application.version=11.0\n')
    return path


def test_discovery_finds_ghidra_in_crowded_root(tmp_path):
    root = tmp_path / 'Program Files'
    for index in range(MAX_CHILDREN_PER_ROOT * 30):
        (root / f'app{index:04}').mkdir(parents=True)
    expected = _ghidra(root / 'ghidra_11.0_PUBLIC')
    found = discover_local_runtimes(environ={}, search_roots=[root])
    assert expected.resolve() in found.ghidra_roots


@pytest.mark.skipif(os.name == 'nt', reason='POSIX shell script stands in for python')
def test_probe_tolerates_stderr_warning_before_json(tmp_path):
    payload = json.dumps({'python': '3.12.1', 'ghidriff': '1.0.0', 'pyghidra': '2.0',
                          'available': True})
    fake = tmp_path / 'python'
    fake.write_text('#!/bin/sh\necho "Could not find platform independent libraries <prefix>" >&2\n'
                    f"echo '{payload}'\n")
    fake.chmod(0o755)
    ghidra = _ghidra(tmp_path / 'ghidra')
    metadata = _probe_backend(BackendConfig(str(fake), str(ghidra)))
    assert metadata['ghidriff'] == '1.0.0'


@pytest.mark.parametrize('text,secret', [
    ('password="first second"', 'second'),
    ("secret: 'first second'", 'second'),
    ('token=abc123', 'abc123'),
    ('key ghp_' + 'A1' * 18, 'ghp_' + 'A1' * 18),
    ('id AKIAABCDEFGHIJKLMNOP here', 'AKIAABCDEFGHIJKLMNOP'),
    ('header Bearer eyJhbGciOi.payload.sig', 'eyJhbGciOi'),
    ('key sk-' + 'z' * 24, 'z' * 24),
])
def test_assignment_and_bare_tokens_redacted(text, secret):
    assert secret not in redact_log(text)


def test_redaction_keeps_ordinary_text():
    text = 'Analyzing function AKIA_helper at 0x1000; ghp_short; tokens processed 12'
    assert redact_log(text) == text


def test_scratch_cleanup_failure_keeps_completed_status(fake_runtime, monkeypatch):
    root, package, project, config = fake_runtime
    write_backend(package, '(out/"json"/"old-new.ghidriff.json").write_text('
                  'json.dumps({"functions":{"added":[],"deleted":[],"modified":[]}}))\n')
    calls = []

    def locked(path, *args, **kwargs):
        calls.append(Path(path))
        raise PermissionError('locked')

    monkeypatch.setattr(backend.shutil, 'rmtree', locked)
    monkeypatch.setattr(backend.time, 'sleep', lambda _: None)
    events = []
    path, run = run_comparison(config, project, root, threading.Event(), events.append)
    assert run.status == 'completed' and path.is_file()
    assert len(calls) == 5
    warnings = [e.message for e in events if e.stage == 'warning']
    assert warnings and str(calls[0]) in warnings[0]
    monkeypatch.undo()
    shutil.rmtree(calls[0])


def test_output_check_oserror_quarantines(fake_runtime, monkeypatch):
    root, package, project, config = fake_runtime
    write_backend(package, 'import time;time.sleep(30)\n')

    def boom(_directory):
        raise PermissionError('denied')

    monkeypatch.setattr(backend, '_output_scan', boom)
    path, run = run_comparison(config, project, root, threading.Event(), lambda _: None)
    assert run.status == 'failed' and run.error.startswith('PT-BACKEND: output directory')
    assert (path / 'failure.txt').is_file() and path.name.startswith('quarantine-')


@pytest.mark.skipif(os.name == 'nt', reason='POSIX wait path')
def test_post_kill_wait_timeout_becomes_pt_backend(fake_runtime, monkeypatch):
    root, package, project, config = fake_runtime
    write_backend(package, 'sys.exit(0)\n')
    real = subprocess.Popen.wait

    def stuck(self, timeout=None):
        real(self)
        raise subprocess.TimeoutExpired(self.args, timeout)

    monkeypatch.setattr(subprocess.Popen, 'wait', stuck)
    path, run = run_comparison(config, project, root, threading.Event(), lambda _: None)
    assert run.status == 'failed' and run.error == 'PT-BACKEND: terminated child did not exit'
    assert (path / 'failure.txt').is_file() and path.name.startswith('quarantine-')
