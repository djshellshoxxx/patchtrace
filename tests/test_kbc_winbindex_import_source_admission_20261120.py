"""Offline Winbindex import source admission, not binary/provider execution.

Synthetic fixed records; the FIFO control runs in a bounded child so an
implementation regression cannot wedge the hosted pytest process.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from patchtrace.kbcorrelation import wiring

NAME = "exampledrv.sys"
DATE = "2099-02-12"
FIXTURE = Path(__file__).parent / "fixtures/kbcorrelation/winbindex/exampledrv.sys.json"


def test_import_source_open_requests_nonblocking_and_preserves_exact_bytes(tmp_path, monkeypatch):
    source = tmp_path / "source.json"
    raw = FIXTURE.read_bytes()
    source.write_bytes(raw)
    original_open = os.open
    source_flags = []

    def recorded_open(path, flags, *args, **kwargs):
        if os.fspath(path) == os.fspath(source):
            source_flags.append(flags)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(wiring.os, "open", recorded_open)
    root = tmp_path / "workspace"
    receipt = wiring.save_winbindex_record(root, source, NAME, DATE)
    assert source_flags
    if hasattr(os, "O_NONBLOCK"):
        assert all(flags & os.O_NONBLOCK for flags in source_flags)
    assert (root / receipt["stored_as"]).read_bytes() == raw
    assert receipt["bytes"] == len(raw)


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK"),
    reason="named pipes and nonblocking source open require a supported POSIX host",
)
def test_named_pipe_source_refused_before_read_or_publication(tmp_path):
    source = tmp_path / "stream.json"
    os.mkfifo(source)
    root = tmp_path / "workspace"
    script = """
import sys
from pathlib import Path
from patchtrace.kbcorrelation.wiring import save_winbindex_record
from patchtrace.kbcorrelation.store import KbcStoreError
try:
    save_winbindex_record(Path(sys.argv[1]), Path(sys.argv[2]), 'exampledrv.sys', '2099-02-12')
except KbcStoreError as exc:
    print(exc.code)
else:
    print('UNEXPECTED_SUCCESS')
"""
    env = os.environ.copy()
    project_src = Path(__file__).resolve().parents[1] / "src"
    env["PYTHONPATH"] = os.pathsep.join(filter(None, (str(project_src), env.get("PYTHONPATH", ""))))
    # A failing old importer would wait forever on open(FIFO); bound the child.
    result = subprocess.run(
        [sys.executable, "-c", script, str(root), str(source)],
        capture_output=True, text=True, env=env, timeout=10, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "PT-KBC-INPUT"
    assert not (root / "winbindex").exists()


def test_symlink_to_regular_source_remains_compatible(tmp_path):
    original = tmp_path / "original.json"
    raw = FIXTURE.read_bytes()
    original.write_bytes(raw)
    source = tmp_path / "source-alias.json"
    try:
        source.symlink_to(original)
    except (OSError, NotImplementedError):
        pytest.skip("source symlinks are not available on this host")
    root = tmp_path / "workspace"
    receipt = wiring.save_winbindex_record(root, source, NAME, DATE)
    assert (root / receipt["stored_as"]).read_bytes() == raw
    assert original.read_bytes() == raw
