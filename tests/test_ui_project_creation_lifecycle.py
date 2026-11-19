"""Real worker/store creation; late delivery must respect cancellation and project context."""
from __future__ import annotations

import threading
from pathlib import Path

import pytest
from PySide6.QtCore import QSettings, QTimer

from patchtrace import service as core
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow, NewProjectDialog


@pytest.fixture
def scene(qtbot, tmp_path, monkeypatch):
    paths = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    for path, version in zip(paths, (0, 1), strict=True):
        path.write_bytes(synthetic_pe(version))
    root = tmp_path / 'created'
    origin = ProjectService.sample(tmp_path / 'origin')
    window = MainWindow(origin, QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(window)
    monkeypatch.setattr(window, 'start_inspection', lambda: None)
    errors = []
    monkeypatch.setattr(window, 'show_error', errors.append)
    real_exec = NewProjectDialog.exec

    def choose(dialog):
        dialog.name.setText('Created project')
        dialog.older.setText(str(paths[0]))
        dialog.newer.setText(str(paths[1]))
        dialog.root.setText(str(root))
        QTimer.singleShot(0, dialog.accept)
        return real_exec(dialog)

    monkeypatch.setattr(NewProjectDialog, 'exec', choose)
    yield window, origin, paths, root, errors
    if window.worker is not None:
        window.cancel_job()
        qtbot.waitUntil(lambda: window.worker is None, timeout=10000)
    window.close()


def test_creation_cancels_before_first_copy_and_preserves_current_project(scene, qtbot, monkeypatch):
    window, origin, _paths, root, errors = scene
    entered, release = threading.Event(), threading.Event()
    original = core.inspect_artifact
    threads, heartbeats = [], []

    def inspect(*args, **kwargs):
        if not entered.is_set():
            threads.append(threading.get_ident())
            entered.set()
            if not release.wait(10):
                raise RuntimeError('test did not release creator')
        return original(*args, **kwargs)

    monkeypatch.setattr(core, 'inspect_artifact', inspect)
    try:
        window.new_project()
        qtbot.waitUntil(entered.is_set, timeout=10000)
        QTimer.singleShot(0, lambda: heartbeats.append(True))
        qtbot.waitUntil(lambda: bool(heartbeats), timeout=2000)
        assert threads[0] != threading.get_ident()
        window.cancel_job()
        release.set()
        qtbot.waitUntil(lambda: window.worker is None, timeout=10000)
        assert errors == [] and window.service is origin
        assert not (root / 'project.sqlite3').exists() and not list(root.rglob('*.bin'))
        assert 'Cancelled' in window.job_label.text()
    finally:
        release.set()
        qtbot.waitUntil(lambda: window.worker is None, timeout=10000)


@pytest.mark.parametrize('delivery', ['current', 'cancelled', 'other-project', 'revision'])
def test_completed_creation_is_adopted_only_by_the_original_active_context(scene, qtbot, monkeypatch, tmp_path, delivery):
    window, origin, _paths, root, errors = scene
    entered, release = threading.Event(), threading.Event()
    original = ProjectService.create

    def create(cls, *args, **kwargs):
        result = original(*args, **kwargs)
        if Path(args[3]) == root:
            entered.set()
            if not release.wait(10):
                result.close()
                raise RuntimeError('test did not release creator')
        return result

    monkeypatch.setattr(ProjectService, 'create', classmethod(create))
    selected = origin
    try:
        window.new_project()
        qtbot.waitUntil(entered.is_set, timeout=10000)
        if delivery == 'cancelled':
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
            assert window.service.root == root and window.project.name == 'Created project'
        else:
            assert window.service is selected
            assert 'retained without opening' in window.logs.toPlainText() + window.job_label.text()
            with ProjectService.open(root) as retained:
                assert retained.project.name == 'Created project'
    finally:
        release.set()
        qtbot.waitUntil(lambda: window.worker is None, timeout=10000)


def test_new_project_does_not_open_a_modal_while_another_worker_is_active(scene, monkeypatch):
    window, _origin, _paths, _root, _errors = scene

    def unexpected(*args):
        raise AssertionError('busy window opened a new modal')

    monkeypatch.setattr(NewProjectDialog, 'exec', unexpected)
    window.worker = object()
    try:
        window.new_project()
    finally:
        window.worker = None
