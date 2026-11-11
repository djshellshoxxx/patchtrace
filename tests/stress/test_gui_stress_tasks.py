"""Stress: 100 tasks cancelled mid-flight, progress floods, and cancellation during a flood (GUI plan 8.5).

Every wait is on a condition (a gate, a counter, a thread that has ended), never on a fixed sleep. The autouse
fixture in qt_support fails the test if any worker thread survives it."""
from __future__ import annotations

import threading

import pytest
from PySide6.QtWidgets import QApplication
from qt_support import join_gui_threads, task_threads  # noqa: F401

from patchtrace.gui.qt.tasks import TaskRunner

TASKS = 100
FLOOD = 100_000


@pytest.fixture
def runner():
    made = TaskRunner(reraise=True)
    yield made
    assert made.shutdown(timeout=5) == []


class Counter:
    """Thread-safe arrival count for workers that report that they have started."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._count = 0

    def arrive(self) -> None:
        with self._lock:
            self._count += 1

    @property
    def value(self) -> int:
        with self._lock:
            return self._count


def drain_queued_events() -> None:
    """Deliver the queued wake-ups of workers that have already ended (their threads are joined first)."""
    QApplication.processEvents()


def test_a_hundred_tasks_cancelled_mid_flight_deliver_nothing(qtbot, runner):
    gate = threading.Event()
    arrived = Counter()
    results, errors = [], []

    def ignores_its_token(token, report):
        arrived.arrive()
        gate.wait(10)
        return 'late'  # the worker ignores cancellation on purpose: the runner must still drop the result

    for index in range(TASKS):
        runner.submit(f'c{index}', ignores_its_token, results.append, errors.append)
    qtbot.waitUntil(lambda: arrived.value == TASKS)
    for index in range(TASKS):
        runner.cancel(f'c{index}')
    assert not runner.busy()
    gate.set()
    qtbot.waitUntil(lambda: not task_threads())
    drain_queued_events()
    assert results == [] and errors == []


def test_cancelling_half_of_a_hundred_keeps_the_other_half_exact(qtbot, runner):
    gate = threading.Event()
    arrived = Counter()
    results, errors = [], []

    def value(index):
        def worker(token, report):
            arrived.arrive()
            gate.wait(10)
            token.raise_if_cancelled()
            return index
        return worker

    for index in range(TASKS):
        runner.submit(f'c{index}', value(index), results.append, errors.append)
    qtbot.waitUntil(lambda: arrived.value == TASKS)
    for index in range(0, TASKS, 2):
        runner.cancel(f'c{index}')
    gate.set()
    qtbot.waitUntil(lambda: not task_threads())
    drain_queued_events()
    assert sorted(results) == list(range(1, TASKS, 2))
    assert errors == []


def test_resubmitting_a_channel_a_hundred_times_delivers_only_the_last_result(qtbot, runner):
    gate = threading.Event()
    results = []

    def slow(token, report):
        gate.wait(10)
        return 'old'

    for _ in range(TASKS - 1):
        runner.submit('same', slow, results.append)
    runner.submit('same', lambda token, report: 'new', results.append)
    gate.set()
    qtbot.waitUntil(lambda: not task_threads())
    drain_queued_events()
    assert results == ['new']


def test_a_progress_flood_is_throttled_and_its_final_value_arrives_before_the_result(qtbot, runner):
    progress, results = [], []

    def flood(token, report):
        for index in range(FLOOD):
            report('scan', index, FLOOD)
        return 'done'

    runner.submit('flood', flood, results.append, None, progress.append)
    qtbot.waitUntil(lambda: results == ['done'])
    assert progress, 'the final progress never arrived'
    assert progress[-1].done == FLOOD - 1 and progress[-1].total == FLOOD
    assert [p.done for p in progress] == sorted(p.done for p in progress)  # latest wins, never backwards
    assert len(progress) <= 200, f'{len(progress)} progress deliveries for one flood (throttle is 10 Hz)'


def test_cancelling_during_a_flood_delivers_no_progress_and_no_result(qtbot, runner):
    midway, gate = threading.Event(), threading.Event()
    progress, results, errors = [], [], []

    def flood(token, report):
        for index in range(FLOOD):
            report('scan', index, FLOOD)
            if index == 1_000:
                midway.set()
                gate.wait(10)
            token.raise_if_cancelled()
        return 'done'

    runner.submit('flood', flood, results.append, errors.append, progress.append)
    qtbot.waitUntil(midway.is_set)
    runner.cancel('flood')
    frozen = len(progress)
    gate.set()
    qtbot.waitUntil(lambda: not task_threads())
    drain_queued_events()
    assert len(progress) == frozen, 'progress reached the GUI after cancel'
    assert results == [] and errors == []
