"""The explicit retry action runs real recovery off-thread and preserves the active view."""
from __future__ import annotations

import threading

import pytest
from PySide6.QtCore import QSettings, QTimer
from PySide6.QtWidgets import QDialog

from patchtrace.ingestion import inspect_artifact
from patchtrace.persistence import ProjectStore
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow, NewProjectDialog


def partial(tmp_path):
    pair = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    for path, version in zip(pair, (0, 1), strict=True):
        path.write_bytes(synthetic_pe(version))
    root = tmp_path / 'incomplete'
    with ProjectStore(root, create=True):
        pass
    inspect_artifact(pair[0], 'older', root)
    return pair, root


def fill(dialog, pair, root):
    dialog.name.setText('Recovered project')
    dialog.older.setText(str(pair[0]))
    dialog.newer.setText(str(pair[1]))
    dialog.root.setText(str(root))


def test_explicit_retry_is_distinct_from_ordinary_create(qtbot, tmp_path):
    pair, root = partial(tmp_path)
    dialog = NewProjectDialog()
    qtbot.addWidget(dialog)
    fill(dialog, pair, root)
    dialog.accept()
    assert dialog.result() != QDialog.DialogCode.Accepted
    assert 'Retry' in dialog.retry_button.text() and dialog.retry_button.toolTip()
    dialog.retry_button.click()
    assert dialog.result() == 2


@pytest.mark.parametrize('outcome', ['completed', 'cancelled', 'invalid'])
def test_actual_retry_worker_is_responsive_and_preserves_original_on_failure(qtbot, tmp_path, monkeypatch, outcome):
    from patchtrace import project_retry as module

    pair, root = partial(tmp_path)
    if outcome == 'invalid':
        (root / 'contributor.txt').write_bytes(b'preserve contributor data')
    original_bytes = {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob('*') if path.is_file()}
    origin = ProjectService.sample(tmp_path / 'origin')
    window = MainWindow(origin, QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(window)
    errors = []
    monkeypatch.setattr(window, 'start_inspection', lambda: None)
    monkeypatch.setattr(window, 'show_error', errors.append)
    real_exec, original_verify = NewProjectDialog.exec, module.verify_artifact
    entered, release = threading.Event(), threading.Event()
    threads, heartbeats = [], []

    def choose(dialog):
        fill(dialog, pair, root)
        QTimer.singleShot(0, dialog.retry_button.click)
        return real_exec(dialog)

    def verify(*args, **kwargs):
        if not entered.is_set():
            threads.append(threading.get_ident())
            entered.set()
            if not release.wait(10):
                raise RuntimeError('test did not release retry validator')
        return original_verify(*args, **kwargs)

    monkeypatch.setattr(NewProjectDialog, 'exec', choose)
    monkeypatch.setattr(module, 'verify_artifact', verify)
    try:
        window.new_project()
        if outcome != 'invalid':
            qtbot.waitUntil(entered.is_set, timeout=10000)
            QTimer.singleShot(0, lambda: heartbeats.append(True))
            qtbot.waitUntil(lambda: bool(heartbeats), timeout=2000)
            assert threads[0] != threading.get_ident()
            if outcome == 'cancelled':
                window.cancel_job()
        release.set()
        qtbot.waitUntil(lambda: window.worker is None, timeout=10000)
        if outcome == 'completed':
            assert errors == [] and window.service.root == root
            assert window.project.name == 'Recovered project'
        else:
            assert window.service is origin
            assert bool(errors) is (outcome == 'invalid')
            after = {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob('*') if path.is_file()}
            assert after == original_bytes
    finally:
        release.set()
        qtbot.waitUntil(lambda: window.worker is None, timeout=10000)
        window.close()
