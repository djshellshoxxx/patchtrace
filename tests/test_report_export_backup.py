"""Exports never silently destroy an earlier file: differing bytes are kept as `<stem>.previous-<sha8><suffix>`."""
from __future__ import annotations

import hashlib
import os

import pytest

from patchtrace import reports
from patchtrace.reports import ExportError, export_project, previous_copy_path
from patchtrace.sample import create_sample


@pytest.fixture
def project(tmp_path):
    return create_sample(tmp_path / 'p').project


def backups(directory):
    return sorted(path.name for path in directory.iterdir() if '.previous-' in path.name)


def test_first_export_writes_no_backup(tmp_path, project):
    out = tmp_path / 'exports' / 'report.md'
    export_project(project, 'md', out)
    assert out.is_file() and backups(out.parent) == []


def test_identical_re_export_writes_no_backup(tmp_path, project):
    out = tmp_path / 'report.md'
    export_project(project, 'md', out)
    export_project(project, 'md', out)
    assert backups(tmp_path) == []


def test_a_differing_file_is_kept_before_it_is_replaced(tmp_path, project):
    out = tmp_path / 'report.md'
    out.write_bytes(b'my annotated notes\n')
    manifest = export_project(project, 'md', out)
    kept = previous_copy_path(out, b'my annotated notes\n')
    assert kept.name == f'report.previous-{hashlib.sha256(b"my annotated notes\n").hexdigest()[:8]}.md'
    assert kept.read_bytes() == b'my annotated notes\n'
    assert hashlib.sha256(out.read_bytes()).hexdigest() == manifest.sha256
    out.write_bytes(b'my annotated notes\n')  # the same earlier bytes again: the existing backup is reused
    export_project(project, 'md', out)
    assert backups(tmp_path) == [kept.name]


def test_a_failed_backup_leaves_the_old_file_and_no_staging_debris(tmp_path, project, monkeypatch):
    out = tmp_path / 'report.md'
    out.write_bytes(b'keep me\n')
    real_open = os.open

    def refuse_backup(path, flags, mode=0o777):
        if '.previous-' in str(path):
            raise PermissionError('read-only directory')
        return real_open(path, flags, mode)
    monkeypatch.setattr(reports.os, 'open', refuse_backup)
    with pytest.raises(ExportError, match='PT-EXPORT'):
        export_project(project, 'md', out)
    assert out.read_bytes() == b'keep me\n'
    assert sorted(path.name for path in tmp_path.iterdir()) == ['p', 'report.md']


def test_an_oversized_existing_file_is_refused_not_replaced(tmp_path, project, monkeypatch):
    probe = tmp_path / 'probe.md'
    export_project(project, 'md', probe)
    cap = probe.stat().st_size + 1  # the report itself fits under the cap; the file already at the path does not
    out = tmp_path / 'big.md'
    out.write_bytes(b'x' * (cap + 1))
    monkeypatch.setattr(reports, 'MAX_REPORT_BYTES', cap)
    with pytest.raises(ExportError, match='larger than any report'):
        export_project(project, 'md', out)
    assert out.read_bytes() == b'x' * (cap + 1) and backups(tmp_path) == []
