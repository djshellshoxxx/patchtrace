"""Run the packaged F8 control through actual desktop controllers and persisted data."""
from __future__ import annotations

import os
import socket
import threading

import pytest
from PySide6.QtCore import QThread, QTimer

from patchtrace.gui.qt import kb_selftest
from patchtrace.gui.qt.kb_selftest import run_journey


def test_packaged_offline_kb_journey(qtbot, qapp, tmp_path, monkeypatch):
    def no_network(*_args, **_kwargs):
        raise AssertionError('The offline self-test attempted a network connection')
    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'create_connection', no_network)
    before = os.environ.get('LOCALAPPDATA')
    result = run_journey(qapp, tmp_path)
    assert result['matches'] == 4 and result['candidate_leads'] >= 4
    assert result['stale_after_reopen'] is True and result['synthetic'] is True
    assert os.environ.get('LOCALAPPDATA') == before
    from patchtrace.gui.qt.tasks import CancelToken
    from patchtrace.kbcorrelation.adapters.panel_snapshot import capture, load_snapshot
    from patchtrace.kbcorrelation.panel_qt import load_report
    from patchtrace.service import ProjectService
    root = tmp_path / 'KB-Δ-調査'
    workspace, project = root / 'app-data' / 'PatchTrace' / 'kb', root / 'comparison-ε'
    standalone = load_report(workspace, str(project), CancelToken())
    service = ProjectService.open(project)
    try:
        captured = load_snapshot(capture(service), workspace, CancelToken())
    finally:
        service.close()
    assert standalone == captured


def test_runner_uses_one_application_loop_and_rejects_nested_or_wrong_thread_calls(qapp, tmp_path):
    before = qapp.quitOnLastWindowClosed()
    delivered = []

    def steps():
        assert QThread.currentThread().loopLevel() == 1
        with pytest.raises(RuntimeError, match='before its event loop'):
            run_journey(qapp, tmp_path / 'nested')
        QTimer.singleShot(0, lambda: delivered.append(True))
        yield kb_selftest._Wait(lambda: bool(delivered), 'normal timer delivery')
        return {'done': True}

    assert kb_selftest._run_steps(qapp, steps()) == {'done': True}
    assert qapp.quitOnLastWindowClosed() == before
    assert not (tmp_path / 'nested').exists()
    errors = []

    def off_thread():
        try:
            run_journey(qapp, tmp_path / 'wrong-thread')
        except RuntimeError as error:
            errors.append(str(error))

    thread = threading.Thread(target=off_thread)
    thread.start()
    thread.join(2)
    assert not thread.is_alive() and len(errors) == 1
    assert 'GUI thread' in errors[0] and not (tmp_path / 'wrong-thread').exists()


@pytest.mark.parametrize('timeout', [False, True], ids=['step-error', 'timeout'])
@pytest.mark.parametrize('cleanup_error', [False, True], ids=['normal-close', 'close-error'])
def test_journey_failures_restore_environment_quit_policy_and_live_ownership(
        qapp, tmp_path, monkeypatch, timeout, cleanup_error):
    from patchtrace.gui.qt.tasks import live_task_threads
    from patchtrace.service import ProjectService

    before = qapp.quitOnLastWindowClosed()
    qapp.setQuitOnLastWindowClosed(not before)
    expected_policy = qapp.quitOnLastWindowClosed()
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'original-environment'))
    environment = os.environ['LOCALAPPDATA']
    started, stopped = threading.Event(), threading.Event()

    def worker(cancel, _report):
        started.set()
        try:
            cancel.wait(3)
        finally:
            stopped.set()

    def fail_candidate(window):
        window.panels.tasks.submit('selftest-failure-control', worker)
        yield kb_selftest._Wait(started.is_set, 'failure worker startup', timeout=1)
        if timeout:
            yield kb_selftest._Wait(lambda: False, 'forced test wait', timeout=0.02)
        raise RuntimeError('forced test step error')

    monkeypatch.setattr(kb_selftest, '_candidate', fail_candidate)
    if cleanup_error:
        close = kb_selftest.MainWindow.close

        def close_then_fail(window):
            close(window)
            raise ValueError('forced cleanup error')

        monkeypatch.setattr(kb_selftest.MainWindow, 'close', close_then_fail)
    try:
        with pytest.raises(RuntimeError, match='timed out' if timeout else 'forced test step') as failure:
            run_journey(qapp, tmp_path)
        assert os.environ['LOCALAPPDATA'] == environment
        assert qapp.quitOnLastWindowClosed() == expected_policy
        assert stopped.is_set() and not live_task_threads()
        if cleanup_error:
            assert any('forced cleanup error' in note for note in failure.value.__notes__)
        with ProjectService.open(tmp_path / 'KB-Δ-調査' / 'comparison-ε') as reopened:
            assert reopened.project.matches
    finally:
        qapp.setQuitOnLastWindowClosed(before)


def test_premature_event_loop_exit_is_a_failure_with_generator_cleanup(qapp):
    cleaned = []
    before = qapp.quitOnLastWindowClosed()

    def steps():
        try:
            QTimer.singleShot(0, qapp.quit)
            yield kb_selftest._Wait(lambda: False, 'never completed')
        finally:
            cleaned.append(True)

    with pytest.raises(RuntimeError, match='exited before completion'):
        kb_selftest._run_steps(qapp, steps())
    assert cleaned == [True] and qapp.quitOnLastWindowClosed() == before
