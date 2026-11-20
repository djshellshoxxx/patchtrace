"""Direct KB investigation project creation must not follow a Windows junction.

Portable predicate controls are separate from the native Windows junction case.
All tests use local empty directories; no analyzed binaries or network calls.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from patchtrace.kbcorrelation.investigation_service import InvestigationRequest, _new_destination
from patchtrace.kbcorrelation.store import KbcStoreError


def test_direct_create_refuses_final_junction_before_resolution(tmp_path, monkeypatch):
    destination = tmp_path / 'linked'
    destination.mkdir()
    genuine_junction = Path.is_junction

    def simulated_junction(path):
        return path == destination or genuine_junction(path)

    monkeypatch.setattr(Path, 'is_junction', simulated_junction)
    request = InvestigationRequest('create', tmp_path / 'workspace', destination=destination)
    with pytest.raises(KbcStoreError) as error:
        _new_destination(request)
    assert error.value.code == 'PT-KBC-INPUT'
    assert destination.is_dir() and list(destination.iterdir()) == []


def test_direct_create_still_accepts_real_empty_directory(tmp_path):
    destination = tmp_path / 'ordinary'
    destination.mkdir()
    request = InvestigationRequest('create', tmp_path / 'workspace', destination=destination)
    assert _new_destination(request) == destination.resolve()
    assert list(destination.iterdir()) == []


@pytest.mark.skipif(os.name != 'nt', reason='requires an actual Windows NTFS junction')
def test_direct_create_refuses_native_windows_junction(tmp_path):
    target = tmp_path / 'retained'
    # Empty is essential: a foreign file would cause the old availability
    # check to refuse too, hiding the missing junction admission guard.
    target.mkdir()
    junction = tmp_path / 'junction'
    result = subprocess.run(
        ['cmd.exe', '/c', 'mklink', '/J', str(junction), str(target)],
        capture_output=True, text=True, timeout=10, check=False,
    )
    if result.returncode != 0 or not junction.is_junction():
        pytest.skip('native junction creation unavailable on this Windows runner')
    request = InvestigationRequest('create', tmp_path / 'workspace', destination=junction)
    with pytest.raises(KbcStoreError) as error:
        _new_destination(request)
    assert error.value.code == 'PT-KBC-INPUT'
    assert list(target.iterdir()) == []
