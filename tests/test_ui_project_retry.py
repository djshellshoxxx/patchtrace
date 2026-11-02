"""Actual modal retry choice, background work and cancellation/stale adoption guards."""
from __future__ import annotations

import threading

import pytest
from PySide6.QtCore import QSettings, QTimer
from PySide6.QtWidgets import QDialog
from test_project_retry import contents, partial, unlocked

from patchtrace import project_retry
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow, NewProjectDialog


def fill(dialog, pair, root):
    dialog.name.setText('Retried project')
    dialog.older.setText(str(pair[0]))
    dialog.newer.setText(str(pair[1]))
    dialog.root.setText(str(root))


def test_ordinary_accept_still_refuses_occupied_root_and_retry_is_explicit(qtbot, tmp_path):
    pair, root = partial(tmp_path)
    dialog = NewProjectDialog()
    qtbot.addWidget(dialog)
    fill(dialog, pair, root)
    before = contents(root)
    dialog.accept()
    assert dialog.result() == QDialog.DialogCode.Rejected
    assert 'absent or empty' in dialog.error.text()
    QTimer.singleShot(0, dialog.retry_button.click)
    assert dialog.exec() == NewProjectDialog.RETRY_REQUESTED
    assert contents(root) == before


def test_retry_action_does_not_replace_ordinary_empty_root_creation(qtbot, tmp_path):
    pair, root = partial(tmp_path)
    empty = tmp_path / 'empty'
    empty.mkdir()
    dialog = NewProjectDialog()
    qtbot.addWidget(dialog)
    fill(dialog, pair, empty)
    dialog.retry_button.click()
    assert dialog.result() == QDialog.DialogCode.Rejected
    assert 'Use Create' in dialog.error.text()
    dialog.accept()
    assert dialog.result() == QDialog.DialogCode.Accepted
    assert list(empty.iterdir()) == []


@pytest.mark.parametrize('delivery', ['current', 'cancel-validation', 'cancel-committed', 'other-project', 'revision'])
def test_real_retry_worker_is_responsive_and_adopts_only_current_uncancelled_result(qtbot, tmp_path, monkeypatch, delivery):
    pair, root = partial(tmp_path)
    before = contents(root)
    origin = ProjectService.sample(tmp_path / 'origin')
    window = MainWindow(origin, QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(window)
    monkeypatch.setattr(window, 'start_inspection', lambda: None)
    errors = []
    monkeypatch.setattr(window, 'show_error', errors.append)
    entered, release = threading.Event(), threading.Event()
    worker_threads, heartbeat = [], []
    main_thread = threading.get_ident()
    real_exec = NewProjectDialog.exec
    def choose(dialog):
        fill(dialog, pair, root)
        QTimer.singleShot(0, dialog.retry_button.click)
        return real_exec(dialog)
    monkeypatch.setattr(NewProjectDialog, 'exec', choose)
    def pause():
        worker_threads.append(threading.get_ident())
        entered.set()
        if not release.wait(10):
            raise RuntimeError('test did not release retry worker')
    if delivery == 'cancel-validation':
        real_validate = project_retry.validate_retry
        def validate(*args):
            pause()
            return real_validate(*args)
        monkeypatch.setattr(project_retry, 'validate_retry', validate)
    else:
        real_retry = ProjectService.retry_create
        def retry(cls, *args, **kwargs):
            result = real_retry(*args, **kwargs)
            pause()
            return result
        monkeypatch.setattr(ProjectService, 'retry_create', classmethod(retry))
    selected = origin
    try:
        window.new_project()
        qtbot.waitUntil(entered.is_set, timeout=10000)
        QTimer.singleShot(0, lambda: heartbeat.append('responsive'))
        qtbot.waitUntil(lambda: bool(heartbeat), timeout=2000)
        assert worker_threads == [worker_threads[0]] and worker_threads[0] != main_thread
        if delivery.startswith('cancel'):
            window.cancel_job()
        elif delivery == 'other-project':
            selected = ProjectService.sample(tmp_path / 'other')
            window.set_service(selected)
        elif delivery == 'revision':
            origin.swap_orientation()
            window.refresh()
        release.set()
        qtbot.waitUntil(lambda: window.worker is None, timeout=10000)
        assert errors == []
        if delivery == 'current':
            assert window.service.root == root
            assert window.project.name == 'Retried project'
        else:
            assert window.service is selected
            if delivery == 'cancel-validation':
                assert contents(root) == before
                unlocked(root)
            else:
                assert 'retained without opening' in window.logs.toPlainText()
                with ProjectService.open(root) as retained:
                    assert retained.project.name == 'Retried project'
    finally:
        release.set()
        qtbot.waitUntil(lambda: window.worker is None, timeout=10000)
        window.close()


def test_explicit_unrelated_root_is_refused_by_worker_and_original_project_remains(qtbot, tmp_path, monkeypatch):
    pair, root = partial(tmp_path)
    (root / 'user-note.txt').write_bytes(b'preserve user content')
    before = contents(root)
    origin = ProjectService.sample(tmp_path / 'origin')
    window = MainWindow(origin, QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(window)
    errors = []
    monkeypatch.setattr(window, 'show_error', errors.append)
    real_exec = NewProjectDialog.exec
    def choose(dialog):
        fill(dialog, pair, root)
        QTimer.singleShot(0, dialog.retry_button.click)
        return real_exec(dialog)
    monkeypatch.setattr(NewProjectDialog, 'exec', choose)
    try:
        window.new_project()
        qtbot.waitUntil(lambda: window.worker is None, timeout=10000)
        assert len(errors) == 1 and 'PT-RETRY' in errors[0]
        assert window.service is origin
        assert contents(root) == before
        unlocked(root)
    finally:
        window.close()
