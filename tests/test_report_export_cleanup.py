"""Report outcomes survive an independent failure to remove a temporary file."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from patchtrace import reports
from patchtrace.reports import ExportError, export_project, previous_copy_path
from patchtrace.sample import create_sample


@pytest.fixture
def project(tmp_path):
    with create_sample(tmp_path / 'project') as service:
        return service.project


def _refuse_stage_cleanup(patch):
    original_unlink = Path.unlink
    attempted = []

    def refuse(path, *args, **kwargs):
        if path.name.startswith('.patchtrace-export-'):
            attempted.append(path)
            raise PermissionError('simulated staging cleanup denial')
        return original_unlink(path, *args, **kwargs)

    patch.setattr(Path, 'unlink', refuse)
    return attempted


def _stages(directory):
    return list(directory.glob('.patchtrace-export-*'))


@pytest.mark.parametrize('version', [1, 2])
def test_successful_publication_does_not_clean_up_a_consumed_stage(tmp_path, project, monkeypatch, version):
    destination = tmp_path / 'report.json'
    with monkeypatch.context() as patch:
        attempted = _refuse_stage_cleanup(patch)
        manifest = export_project(project, 'json', destination, report_version=version)
    assert hashlib.sha256(destination.read_bytes()).hexdigest() == manifest.sha256
    assert attempted == []
    assert _stages(tmp_path) == []


@pytest.mark.parametrize('version,code', [(1, 'PT-EXPORT:'), (2, 'PT-EXPORT-IO:')])
def test_cleanup_denial_preserves_typed_write_failure_and_previous_bytes(
        tmp_path, project, monkeypatch, version, code):
    destination = tmp_path / 'report.json'
    previous = b'previous analyst notes\n'
    destination.write_bytes(previous)

    def refuse_replace(*_args, **_kwargs):
        raise OSError('simulated publication failure')

    with monkeypatch.context() as patch:
        attempted = _refuse_stage_cleanup(patch)
        patch.setattr(reports.os, 'replace', refuse_replace)
        with pytest.raises(ExportError, match=f'^{code}') as failure:
            export_project(project, 'json', destination, report_version=version)
    assert destination.read_bytes() == previous
    assert previous_copy_path(destination, previous).read_bytes() == previous
    assert len(attempted) == 1 and _stages(tmp_path) == attempted
    assert failure.value.__notes__ == [
        'PT-EXPORT: temporary report cleanup failed; a staging file may remain beside the destination'
    ]


@pytest.mark.parametrize('version', [1, 2])
def test_cleanup_denial_preserves_backup_refusal(tmp_path, project, monkeypatch, version):
    destination = tmp_path / 'report.json'
    previous = b'previous analyst notes\n'
    destination.write_bytes(previous)
    backup = previous_copy_path(destination, previous)
    backup.write_bytes(b'pre-existing unrelated copy')

    with monkeypatch.context() as patch:
        attempted = _refuse_stage_cleanup(patch)
        with pytest.raises(ExportError, match='previous report backup does not match') as failure:
            export_project(project, 'json', destination, report_version=version)
    assert destination.read_bytes() == previous
    assert backup.read_bytes() == b'pre-existing unrelated copy'
    assert len(attempted) == 1 and _stages(tmp_path) == attempted
    assert len(failure.value.__notes__) == 1
    assert 'cleanup failed' in failure.value.__notes__[0]


def test_cleanup_denial_preserves_interruption(tmp_path, project, monkeypatch):
    destination = tmp_path / 'report.json'
    destination.write_bytes(b'keep previous report')
    interruption = KeyboardInterrupt()

    def interrupt(*_args, **_kwargs):
        raise interruption

    with monkeypatch.context() as patch:
        attempted = _refuse_stage_cleanup(patch)
        patch.setattr(reports.os, 'replace', interrupt)
        with pytest.raises(KeyboardInterrupt) as failure:
            export_project(project, 'json', destination)
    assert failure.value is interruption
    assert destination.read_bytes() == b'keep previous report'
    assert len(attempted) == 1 and _stages(tmp_path) == attempted
    assert len(interruption.__notes__) == 1
    assert 'cleanup failed' in interruption.__notes__[0]
