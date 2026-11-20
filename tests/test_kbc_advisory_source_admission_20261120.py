"""Held local advisory-file admission. Synthetic files only; no target binary execution."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from patchtrace.kbcorrelation import cli_index
from patchtrace.kbcorrelation.sources.cvrf import SourceError


def test_advisory_regular_source_uses_held_nonblocking_descriptor(tmp_path, monkeypatch):
    source = tmp_path / 'advisory.json'
    raw = b'{"synthetic": true}\n'
    source.write_bytes(raw)
    observed = []
    original_open = os.open

    def recording_open(path, flags, *args, **kwargs):
        if os.fspath(path) == os.fspath(source):
            observed.append(flags)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(cli_index.os, 'open', recording_open)
    assert cli_index.read_input_file(source) == raw
    assert observed
    if hasattr(os, 'O_NONBLOCK'):
        assert all(flags & os.O_NONBLOCK for flags in observed)


def test_advisory_nonregular_directory_refused_as_input(tmp_path):
    with pytest.raises(SourceError) as exc:
        cli_index.read_input_file(tmp_path)
    assert exc.value.code == 'PT-KBC-INPUT'


def test_advisory_symlink_to_regular_file_remains_supported(tmp_path):
    actual = tmp_path / 'advisory.json'
    actual.write_bytes(b'original raw bytes')
    link = tmp_path / 'advisory-alias.json'
    try:
        link.symlink_to(actual)
    except (OSError, NotImplementedError):
        pytest.skip('source symlinks unavailable on this host')
    assert cli_index.read_input_file(link) == actual.read_bytes()


def test_advisory_bounded_read_still_rejects_oversize(tmp_path, monkeypatch):
    source = tmp_path / 'too-big.json'
    source.write_bytes(b'123456789')
    monkeypatch.setattr(cli_index, 'DEFAULT_LIMITS', SimpleNamespace(cvrf_doc_bytes=8))
    with pytest.raises(SourceError) as exc:
        cli_index.read_input_file(source)
    assert exc.value.code == 'PT-KBC-LIMIT'


@pytest.mark.skipif(
    os.name != 'posix' or not hasattr(os, 'mkfifo') or not hasattr(os, 'O_NONBLOCK'),
    reason='nonblocking FIFO admission needs a supported POSIX host',
)
def test_advisory_fifo_without_writer_refused_without_blocking(tmp_path):
    source = tmp_path / 'stalled-advisory.json'
    os.mkfifo(source)
    script = """
import sys
from pathlib import Path
from patchtrace.kbcorrelation.cli_index import read_input_file
from patchtrace.kbcorrelation.sources.cvrf import SourceError
try:
    read_input_file(Path(sys.argv[1]))
except SourceError as exc:
    print(exc.code)
else:
    print('UNEXPECTED_SUCCESS')
"""
    project_src = Path(__file__).resolve().parents[1] / 'src'
    env = os.environ.copy()
    env['PYTHONPATH'] = os.pathsep.join(filter(None, (str(project_src), env.get('PYTHONPATH', ''))))
    result = subprocess.run(
        [sys.executable, '-c', script, str(source)],
        capture_output=True, text=True, env=env, timeout=10, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'PT-KBC-INPUT'
