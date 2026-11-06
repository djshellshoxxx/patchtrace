"""Qt worker status controls; these do not establish native Ghidriff compatibility."""
from __future__ import annotations

import threading

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QSettings, QThread
from PySide6.QtWidgets import QApplication
from shiboken6 import isValid

from patchtrace.models import JobEvent
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow


@pytest.fixture
def view(qtbot, tmp_path):
    window = MainWindow(ProjectService.sample(tmp_path / 'sample'),
                        QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat))

    def finish_before_close(window):
        # pytest-qt schedules registered widgets for deletion before yield-fixture finalizers.
        # Join here while the window can still receive the worker's normal finished callback.
        assert isValid(window), 'window was destroyed before worker cleanup'
        worker = window.worker
        if worker is not None:
            window.cancel_job()
            assert worker.wait(5000), 'test worker did not stop after cancellation'
            assert worker.isFinished() and not worker.isRunning()
        QApplication.processEvents()
        assert isValid(window), 'window was destroyed before GUI completion was delivered'
        assert window.worker is None, 'finished worker was not cleared by the normal GUI callback'
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)

    qtbot.addWidget(window, before_close_func=finish_before_close)
    window.show()
    return window


def progress(message='Checking candidate pairs; 12 s elapsed / 7200 s limit', **kwargs):
    return JobEvent(run_id='test-run', stage='analysis-progress', message=message, **kwargs)


def hold_job(view, qtbot, *events):
    ready = threading.Event()
    def task(cancel, emit):
        for event in events:
            emit(event)
        ready.set()
        cancel.wait(4)
    view.start_job('Comparing artifacts', task, lambda _: None)
    qtbot.waitUntil(ready.is_set)
    return view.worker


def test_progress_is_live_on_gui_thread_without_log_growth_or_percent(view, qtbot, monkeypatch):
    threads, original = [], view.job_event
    def observe(event):
        threads.append(QThread.currentThread())
        original(event)
    monkeypatch.setattr(view, 'job_event', observe)
    before = view.logs.document().blockCount()
    hold_job(view, qtbot, *(progress(f'Checking pairs; {n} s / 7200 s limit', progress=1.0) for n in range(40)))
    qtbot.waitUntil(lambda: '39 s / 7200 s limit' in view.job_label.text())
    assert view.worker is not None and view.worker.isRunning()
    assert threads and all(thread == view.thread() for thread in threads)
    assert view.logs.document().blockCount() == before + 1
    assert view.progress.minimum() == view.progress.maximum() == 0
    view._elapsed()
    assert '7200 s limit' in view.job_label.text()


@pytest.mark.parametrize('terminal', ['Error · analysis timed out', 'Cancelled · previous results preserved'])
def test_heartbeat_and_elapsed_preserve_terminal_state(view, qtbot, terminal):
    hold_job(view, qtbot)
    view.job_label.setText(terminal)
    view.job_event(progress())
    view._elapsed()
    assert view.job_label.text() == terminal


def test_old_worker_cannot_update_replacement_job(view, qtbot, monkeypatch):
    first = hold_job(view, qtbot, progress())
    monkeypatch.setattr(first, 'deleteLater', lambda: None)
    view.cancel_job()
    qtbot.waitUntil(lambda: view.worker is None)
    hold_job(view, qtbot, progress('Current worker'))
    qtbot.waitUntil(lambda: view.job_label.text() == 'Current worker')
    before = view.logs.toPlainText()
    first.event_ready.emit(progress('Stale worker'))
    qtbot.wait(20)
    assert view.job_label.text() == 'Current worker'
    assert view.logs.toPlainText() == before


@pytest.mark.parametrize('stage', ['completed', 'failed', 'cancelled', 'identical', 'cache'])
def test_budget_clears_before_normalization_or_other_work(view, qtbot, stage):
    hold_job(view, qtbot, progress(), JobEvent(run_id='test-run', stage=stage, message='Subprocess ended'))
    qtbot.waitUntil(lambda: 'Subprocess ended' in view.logs.toPlainText())
    view._elapsed()
    assert '7200' not in view.job_label.text()


def test_cancel_takes_precedence_over_progress(view, qtbot):
    hold_job(view, qtbot, progress())
    qtbot.waitUntil(lambda: '7200 s limit' in view.job_label.text())
    view.cancel_job()
    view.job_event(progress('Late heartbeat'))
    view._elapsed()
    assert view.job_label.text().startswith('Cancelling')


def test_finished_job_ignores_progress_and_new_job_has_fresh_status(view, qtbot):
    hold_job(view, qtbot)
    view.cancel_job()
    qtbot.waitUntil(lambda: view.worker is None)
    before = (view.job_label.text(), view.logs.toPlainText())
    view.job_event(progress('Already stopped'))
    assert (view.job_label.text(), view.logs.toPlainText()) == before
    hold_job(view, qtbot)
    view._elapsed()
    assert '7200' not in view.job_label.text() and 'Already stopped' not in view.job_label.text()
