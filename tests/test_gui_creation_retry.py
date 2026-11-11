"""A failed local creation can be retried without unlinking the persistent writer lock."""
from __future__ import annotations

import pytest
from PySide6.QtWidgets import QDialog

from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService
from patchtrace.ui import NewProjectDialog


def test_new_wizard_retries_after_real_failed_creation(qtbot, tmp_path):
    older, newer = tmp_path / 'older.exe', tmp_path / 'newer.exe'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(b'invalid PE')
    root = tmp_path / 'project'
    with pytest.raises(ValueError):
        ProjectService.create(older, newer, 'first', root)
    assert [p.name for p in root.iterdir()] == ['.patchtrace.lock']
    lock = root / '.patchtrace.lock'
    identity = (lock.stat().st_dev, lock.stat().st_ino)
    newer.write_bytes(synthetic_pe(1))
    dialog = NewProjectDialog()
    qtbot.addWidget(dialog)
    dialog.older.setText(str(older))
    dialog.newer.setText(str(newer))
    dialog.root.setText(str(root))
    dialog.accept()
    assert dialog.result() == QDialog.DialogCode.Accepted, dialog.error.text()
    with ProjectService.create(older, newer, 'retry', root) as created:
        assert len(created.project.artifacts) == 2
    assert (lock.stat().st_dev, lock.stat().st_ino) == identity


@pytest.mark.parametrize('kind,expected', [('absent', True), ('empty', True), ('lock', True),
                                           ('foreign', False), ('lock-directory', False),
                                           ('lock-symlink', False), ('root-symlink', False), ('file', False)])
def test_destination_preflight_is_readonly_and_bounded(tmp_path, monkeypatch, kind, expected):
    from patchtrace import persistence

    root = tmp_path / 'destination'
    if kind != 'absent':
        root.mkdir()
    retained = tmp_path / 'retained.txt'
    retained.write_bytes(b'contributor data')
    if kind == 'lock':
        (root / '.patchtrace.lock').write_bytes(b'old metadata is not lock availability')
    elif kind == 'foreign':
        (root / 'notes.txt').write_bytes(b'contributor notes')
    elif kind == 'lock-directory':
        (root / '.patchtrace.lock').mkdir()
    elif kind == 'lock-symlink':
        try:
            (root / '.patchtrace.lock').symlink_to(retained)
        except OSError:
            pytest.skip('symlinks unavailable')
    elif kind == 'root-symlink':
        root.rmdir()
        try:
            root.symlink_to(tmp_path, target_is_directory=True)
        except OSError:
            pytest.skip('symlinks unavailable')
    elif kind == 'file':
        root.rmdir()
        root.write_bytes(b'contributor file')
    before = (root / '.patchtrace.lock').read_bytes() if kind == 'lock' else None

    def forbidden(*args, **kwargs):
        raise AssertionError('preflight must not acquire a lock or open SQLite')

    monkeypatch.setattr(persistence, 'ProjectLock', forbidden)
    monkeypatch.setattr(persistence.sqlite3, 'connect', forbidden)
    assert persistence.creation_directory_available(root) is expected
    assert retained.read_bytes() == b'contributor data'
    if before is not None:
        assert (root / '.patchtrace.lock').read_bytes() == before
    if kind == 'foreign':
        assert (root / 'notes.txt').read_bytes() == b'contributor notes'


def test_active_lock_preflight_does_not_bypass_actual_writer_lock(tmp_path):
    from patchtrace.persistence import ProjectLock, creation_directory_available

    older, newer = tmp_path / 'older.exe', tmp_path / 'newer.exe'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    root = tmp_path / 'case'
    root.mkdir()
    held = ProjectLock(root)
    lock = root / '.patchtrace.lock'
    identity = (lock.stat().st_dev, lock.stat().st_ino)
    try:
        assert creation_directory_available(root)
        with pytest.raises(ValueError, match='locked by another writer'):
            ProjectService.create(older, newer, 'blocked', root)
        assert (lock.stat().st_dev, lock.stat().st_ino) == identity
        assert not (root / 'project.sqlite3').exists()
    finally:
        held.close()
    with ProjectService.create(older, newer, 'retry', root):
        pass
    assert (lock.stat().st_dev, lock.stat().st_ino) == identity


def test_foreign_entry_still_blocks_new_wizard(qtbot, tmp_path):
    root = tmp_path / 'case'
    root.mkdir()
    retained = root / 'notes.txt'
    retained.write_bytes(b'contributor notes')
    binary = tmp_path / 'input.exe'
    binary.write_bytes(synthetic_pe(0))
    dialog = NewProjectDialog()
    qtbot.addWidget(dialog)
    dialog.older.setText(str(binary))
    dialog.newer.setText(str(binary))
    dialog.root.setText(str(root))
    dialog.accept()
    assert dialog.result() == QDialog.DialogCode.Rejected
    assert retained.read_bytes() == b'contributor notes'
    assert sorted(p.name for p in root.iterdir()) == ['notes.txt']


def test_kb_destination_accepts_retained_lock_without_mutating_it(tmp_path):
    from patchtrace.kbcorrelation.investigation_service import InvestigationRequest, _new_destination
    from patchtrace.persistence import ProjectLock

    root = tmp_path / 'case'
    root.mkdir()
    held = ProjectLock(root)
    held.close()
    lock = root / '.patchtrace.lock'
    before = lock.read_bytes(), lock.stat().st_ino
    request = InvestigationRequest('create', tmp_path / 'workspace', destination=root)
    assert _new_destination(request) == root.resolve()
    assert (lock.read_bytes(), lock.stat().st_ino) == before


def test_destination_preflight_refuses_inspection_error(tmp_path, monkeypatch):
    import os

    from patchtrace.persistence import creation_directory_available

    root = tmp_path / 'case'
    root.mkdir()

    def denied(*args, **kwargs):
        raise PermissionError('synthetic unreadable directory')

    monkeypatch.setattr(os, 'scandir', denied)
    assert not creation_directory_available(root)


@pytest.mark.parametrize('fail_at', [1, 2])
def test_promotion_failure_retains_committed_snapshot_foreign_files_and_lock(tmp_path, monkeypatch, fail_at):
    from test_acquisition_hardening import _acquired

    from patchtrace.acquisition import quarantine
    from patchtrace.acquisition.contracts import AcquisitionError
    from patchtrace.persistence import ProjectLock

    older, newer = _acquired(tmp_path)
    root = tmp_path / 'project'
    root.mkdir()
    held = ProjectLock(root)
    held.close()
    lock = root / '.patchtrace.lock'
    identity = (lock.stat().st_dev, lock.stat().st_ino)

    actual, calls = ProjectService.annotate, []

    def failed_annotation(self, *args, **kwargs):
        calls.append(args)
        if len(calls) < fail_at:
            return actual(self, *args, **kwargs)
        (self.root / 'contributor.txt').write_bytes(b'concurrent contributor data')
        raise OSError('synthetic annotation failure')

    monkeypatch.setattr(ProjectService, 'annotate', failed_annotation)
    with pytest.raises((AcquisitionError, OSError)) as error:
        quarantine.promote(older, newer, 'retained comparison', root)
    assert (root / 'contributor.txt').read_bytes() == b'concurrent contributor data'
    assert isinstance(error.value, AcquisitionError)
    assert str(root.resolve()) in str(error.value)
    assert (lock.stat().st_dev, lock.stat().st_ino) == identity
    with ProjectService.open(root) as retained:
        assert retained.project.name == 'retained comparison'
        assert len(retained.project.artifacts) == 2
        assert len(retained.project.annotations) == fail_at - 1


def test_acquisition_wizard_accepts_lock_only_destination(qtbot, tmp_path):
    from test_ui_acquisition import Server, make, ready

    from patchtrace.persistence import ProjectLock

    dialog, _ = make(qtbot, Server())
    ready(qtbot, dialog, tmp_path)
    root = tmp_path / 'proj'
    root.mkdir()
    held = ProjectLock(root)
    held.close()
    lock = root / '.patchtrace.lock'
    identity = (lock.stat().st_dev, lock.stat().st_ino)
    dialog.download_button.click()
    qtbot.waitUntil(lambda: dialog.worker is None and dialog.service is not None, timeout=10000)
    try:
        assert dialog.result() == QDialog.DialogCode.Accepted
        assert (lock.stat().st_dev, lock.stat().st_ino) == identity
        assert any(a.text.startswith('acquisition/1 provenance: ') for a in dialog.service.project.annotations)
    finally:
        dialog.service.close()


def test_acquisition_wizard_reports_retained_project_on_postcreate_failure(qtbot, tmp_path, monkeypatch):
    from test_ui_acquisition import Server, make, ready

    from patchtrace.persistence import ProjectLock

    dialog, _ = make(qtbot, Server())
    ready(qtbot, dialog, tmp_path)
    root = tmp_path / 'proj'
    root.mkdir()
    held = ProjectLock(root)
    held.close()
    identity = (root / '.patchtrace.lock').stat().st_ino

    def fail(self, *args, **kwargs):
        (self.root / 'contributor.txt').write_bytes(b'contributor data')
        raise OSError('synthetic annotation failure')

    monkeypatch.setattr(ProjectService, 'annotate', fail)
    dialog.download_button.click()
    qtbot.waitUntil(lambda: dialog.worker is None, timeout=10000)
    assert dialog.service is None
    assert 'Project retained at ' + str(root.resolve()) in dialog.status.text()
    assert (root / 'contributor.txt').read_bytes() == b'contributor data'
    assert (root / '.patchtrace.lock').stat().st_ino == identity
    with ProjectService.open(root) as retained:
        assert len(retained.project.artifacts) == 2


def test_kb_creation_retries_into_retained_lock_directory(tmp_path):
    from test_kb_investigation_service import ready, run

    from patchtrace.kbcorrelation.investigation_service import InvestigationRequest
    from patchtrace.persistence import ProjectLock

    ws, inv, scope, older, newer = ready(tmp_path)
    preview = run(InvestigationRequest('preview', ws, investigation_id=inv, scope_id=scope,
                                       older=older, newer=newer))
    assert preview.success
    root = tmp_path / 'project'
    root.mkdir()
    held = ProjectLock(root)
    held.close()
    lock = root / '.patchtrace.lock'
    identity = lock.stat().st_ino
    result = run(InvestigationRequest('create', ws, investigation_id=inv, scope_id=scope,
                                      older=older, newer=newer, destination=root,
                                      expected_pair_id=preview.data['pair']['pair_id'],
                                      expected_revision=preview.data['investigation_revision']))
    assert result.success, result.text
    with ProjectService.open(root) as created:
        assert len(created.project.artifacts) == 2
    assert lock.stat().st_ino == identity


def test_acquisition_workflow_uses_same_lock_only_policy(tmp_path):
    from patchtrace.acquisition.contracts import AcquisitionError
    from patchtrace.acquisition.workflow import check_project_root
    from patchtrace.persistence import ProjectLock

    root = tmp_path / 'case'
    root.mkdir()
    held = ProjectLock(root)
    identity = (root / '.patchtrace.lock').stat().st_ino
    try:
        check_project_root(root)  # advisory only; actual create still refuses the active writer
        assert (root / '.patchtrace.lock').stat().st_ino == identity
        retained = root / 'contributor.txt'
        retained.write_bytes(b'contributor data')
        with pytest.raises(AcquisitionError, match='absent or empty'):
            check_project_root(root)
        assert retained.read_bytes() == b'contributor data'
    finally:
        held.close()
