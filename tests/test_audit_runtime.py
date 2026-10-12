import json
import os
from pathlib import Path

import pytest

from patchtrace.backend import BackendConfig, _probe_backend
from patchtrace.diagnostics import redact_log
from patchtrace.runtime_discovery import MAX_CHILDREN_PER_ROOT, discover_local_runtimes


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
