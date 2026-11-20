"""Recheck project destination after a consented staged download; synthetic files only."""
from __future__ import annotations

import tempfile

import pytest
from test_acquisition_workflow import Importer, Server, run

from patchtrace.kbcorrelation.store import KbcStoreError


def test_link_inserted_during_stage_refuses_import_and_discards_downloads(tmp_path, monkeypatch):
    project = tmp_path / "proj"
    external = tmp_path / "external"
    external.mkdir()
    # Probe symlink privileges before the download callback; avoid hiding any
    # acquisition failure behind a platform-specific permission exception.
    probe = tmp_path / "probe"
    try:
        probe.symlink_to(external, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symbolic links unavailable on this host: {exc}")
    probe.unlink()

    stage_root = tmp_path / "staging"
    stage_root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(stage_root))
    inserted = []

    def swap_destination():
        if not inserted:
            project.symlink_to(external, target_is_directory=True)
            inserted.append(True)

    server = Server(on_blob=swap_destination)
    importer = Importer()
    _plan, _importer, result = run(tmp_path, server, importer=importer)

    assert inserted and server.calls
    assert isinstance(result, KbcStoreError) and result.code == "PT-KBC-INPUT"
    assert importer.seen == []
    assert project.is_symlink()
    assert list(external.iterdir()) == []
    assert list(stage_root.iterdir()) == []
