# ruff: noqa: F811 - the main_window fixture is imported for its name, as in test_gui_host.py
"""Stress: teardown after errors (GUI plan 8.5, 8.10; to-do T15).

Factories, hooks, result callbacks and lanes that raise must cost one status line or one failed panel, never the
window, the other panels or the join at shutdown. After a failure storm the host still shuts down, a second
shutdown is a no-op, and no worker thread survives."""
from __future__ import annotations

import threading

import pytest
from host_support import Recorder, make_host, spec  # noqa: F401 - the autouse tooltip fixture is imported with it
from PySide6.QtWidgets import QApplication
from qt_support import join_gui_threads, main_window, settings, task_threads  # noqa: F401

from patchtrace.gui.qt.tasks import TaskRunner


class Exploding(Recorder):
    def __init__(self, ctx) -> None:
        raise RuntimeError(f'factory failed on {ctx.spec.id}')


class Angry(Recorder):
    """Every hook raises; the host must turn each into one status line."""

    def project_changed(self, key) -> None:
        raise ValueError('project hook')

    def theme_changed(self, tokens) -> None:
        raise KeyError('theme hook')

    def busy_changed(self, busy) -> None:
        raise OSError('busy hook')


def test_failing_factories_and_hooks_leave_the_other_panels_working(qtbot, settings):  # noqa: F811
    window, host = make_host(qtbot, settings, spec('boom', factory=Exploding), spec('angry', factory=Angry),
                             spec('calm'))
    window.show()
    qtbot.waitExposed(window)
    for panel_id in ('boom', 'angry', 'calm'):
        host.show_panel(panel_id)
    assert host.panels['boom'].failure == 'RuntimeError' and host.panels['boom'].controller is None
    assert host.panels['boom'].dock.view.kind == 'error'
    assert host.panels['calm'].controller is not None
    for _ in range(20):
        host.project_changed()
        host.update_controls()
    host._theme_changed(host.tokens)
    assert 'panel error' in window.statusBar().currentMessage()
    assert host.panels['calm'].controller.names()[0] == 'theme'


def test_a_result_callback_that_raises_becomes_one_status_line(qtbot, settings):  # noqa: F811
    window, host = make_host(qtbot, settings)
    window.show()
    done = threading.Event()

    def explode(value):
        done.set()
        raise MemoryError('callback failed')

    host.tasks.submit('apply', lambda token, report: 'value', explode)
    qtbot.waitUntil(done.is_set)
    qtbot.waitUntil(lambda: 'could not apply' in window.statusBar().currentMessage())
    assert host.tasks.busy() is False


class Counter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.value = 0

    def arrive(self) -> None:
        with self._lock:
            self.value += 1


def test_shutdown_with_a_hundred_blocked_tasks_joins_every_worker(qtbot):
    runner = TaskRunner(reraise=True)
    arrived = Counter()

    def blocked(token, report):
        arrived.arrive()
        while not token.wait(0.01):  # wakes at once when the runner cancels; the wait is a condition, not a sleep
            pass
        return 'never delivered'

    for index in range(100):
        runner.submit(f'b{index}', blocked, lambda value: None)
    qtbot.waitUntil(lambda: arrived.value == 100)
    assert runner.shutdown(timeout=5) == []
    assert task_threads() == []
    assert runner.shutdown(timeout=5) == []  # idempotent
    with pytest.raises(RuntimeError):
        runner.submit('late', lambda token, report: None)


def test_a_lane_whose_init_failed_fails_every_request_with_the_class_name(qtbot):
    runner = TaskRunner(reraise=True)
    failures = []

    def broken():
        raise ConnectionError('secret path C:\\users\\x')

    lane = runner.lane('db', broken)
    for _ in range(20):
        lane.submit(lambda state, token, report: state, None, failures.append)
    qtbot.waitUntil(lambda: len(failures) == 20)
    assert {failure.text for failure in failures} == {'PT-GUI-TASK: ConnectionError'}
    assert runner.shutdown(timeout=5) == []


@pytest.mark.parametrize('exc', [ValueError, KeyError, OSError, RecursionError, ZeroDivisionError],
                         ids=['value', 'key', 'os', 'recursion', 'zero'])
def test_every_worker_exception_crosses_as_its_class_name_only(qtbot, exc):
    runner = TaskRunner(reraise=True)
    failures = []

    def fails(token, report):
        raise exc('C:\\private\\token=abc')

    runner.submit('fails', fails, None, failures.append)
    qtbot.waitUntil(lambda: len(failures) == 1)
    assert failures[0].exception_class == exc.__name__
    assert 'private' not in repr(failures[0]) and 'token=abc' not in repr(failures[0])
    assert runner.shutdown(timeout=5) == []


def test_closing_a_window_with_floated_docks_and_running_tasks_is_clean(qtbot, main_window):
    window, host = main_window, main_window.panels
    window.show()
    qtbot.waitExposed(window)
    for panel_id, panel in list(host.panels.items()):
        if panel.dock is not None:
            host.float_panel(panel_id)
    def blocked(token, report):
        token.wait(10)  # returns the moment the window's shutdown cancels the token
        return token.is_set()

    for index in range(10):
        host.tasks.submit(f'close{index}', blocked)
    window.close()
    QApplication.processEvents()
    assert host.closed
    assert task_threads() == []
    window.close()  # a second close after teardown is a no-op
