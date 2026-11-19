"""Windows read-only hard-link cleanup must precede raw evidence protection."""
from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

import pytest

from patchtrace.sample import sample_diff
from patchtrace.service import ProjectService


@pytest.mark.parametrize('apply', [False, True], ids=['discard', 'apply'])
def test_raw_staging_is_removed_before_shared_inode_becomes_readonly(tmp_path, monkeypatch, apply):
    original_unlink = Path.unlink
    stages = []

    def windows_stage_unlink(path, *args, **kwargs):
        if path.name.startswith('.raw-') and path.exists():
            stages.append(path)
            if not path.stat().st_mode & stat.S_IWRITE:
                raise PermissionError('Windows refuses deletion of a read-only hard link')
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'unlink', windows_stage_unlink)
    with ProjectService.sample(tmp_path / 'project') as service:
        prior_run = service.project.runs[0]
        prior_path = service.root / prior_run.raw_path
        prior_bytes = prior_path.read_bytes()
        source = tmp_path / 'import.json'
        raw_bytes = json.dumps(sample_diff(service.project)).encode('utf-8')
        source.write_bytes(raw_bytes)
        prepared = service.prepare_import(source)
        published = service.root / prepared.run.raw_path
        assert published.read_bytes() == raw_bytes
        assert prepared.run.raw_sha256 == hashlib.sha256(raw_bytes).hexdigest()
        assert not published.stat().st_mode & stat.S_IWRITE
        assert not list(published.parent.glob('.raw-*'))
        if apply:
            service.apply_import(prepared)
            assert published.read_bytes() == raw_bytes
            assert any(run.id == prepared.run.id for run in service.project.runs)
        else:
            service.discard_import(prepared)
            assert not published.exists()
            assert all(run.id != prepared.run.id for run in service.project.runs)
        assert source.read_bytes() == raw_bytes
        assert prior_path.read_bytes() == prior_bytes
        assert len(stages) == 2
        assert all(not stage.exists() for stage in stages)
