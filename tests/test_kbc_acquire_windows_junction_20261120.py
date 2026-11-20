"""Acquisition project destinations reject Windows junctions, not just symlinks."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from patchtrace.kbcorrelation.acquire import _check_directory
from patchtrace.kbcorrelation.store import KbcStoreError


def test_junction_predicate_refused_for_otherwise_empty_destination(tmp_path, monkeypatch):
    # Portable branch check, not a claim that Linux supports NTFS junctions.
    project = tmp_path / 'project'
    project.mkdir()
    original = Path.is_junction
    observed = []

    def mark_junction(path):
        if path == project:
            observed.append(True)
            return True
        return original(path)

    monkeypatch.setattr(Path, 'is_junction', mark_junction)
    with pytest.raises(KbcStoreError) as caught:
        _check_directory(str(project))
    assert caught.value.code == 'PT-KBC-INPUT' and observed
    assert list(project.iterdir()) == []


@pytest.mark.skipif(os.name != 'nt', reason='native NTFS junction support is Windows-only')
def test_real_windows_junction_to_empty_directory_is_refused(tmp_path):
    target = tmp_path / 'target'
    target.mkdir()
    junction = tmp_path / 'project'
    # "mklink" is a Windows shell builtin; no analyzed target binary is run.
    made = subprocess.run(
        ['cmd', '/d', '/c', f'mklink /J "{junction}" "{target}"'],
        capture_output=True, text=True, check=False,
    )
    if made.returncode:
        pytest.skip(f'junction creation unavailable: {made.returncode}')
    assert junction.is_junction()
    with pytest.raises(KbcStoreError) as caught:
        _check_directory(str(junction))
    assert caught.value.code == 'PT-KBC-INPUT'
    assert list(target.iterdir()) == []
