"""InspectionSession: the file inspection on the host TaskRunner never shows a stale result and never leaks an open
artifact reader (GUI plan 8.5, F-gui-3; audit #116 P3). Offscreen and hermetic: the inspector is a fake that records
close(), except the one real run over the synthetic sample project."""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest
from qt_support import join_gui_threads  # noqa: F401

from patchtrace import ui_inspection_session
from patchtrace.gui.qt import tasks
from patchtrace.gui.qt.tasks import TaskRunner
from patchtrace.service import ProjectService
from patchtrace.ui_inspection_session import InspectionSession

SUMMARY = 'OLDER: unavailable (fake) · NEWER: unavailable (fake)'


class FakeInspection:
    def __init__(self, name: str) -> None:
        self.name = name
        self.closes = 0
        side = SimpleNamespace(overview=None, error_code='fake', trust=None)
        self.sides = {'older': side, 'newer': side}

    def close(self) -> None:
        self.closes += 1


class Inspector:
    """Stands in for inspect_project_artifacts; each call blocks on its own gate when one is set."""

    def __init__(self) -> None:
        self.calls, self.made, self.gates, self.fail = [], [], {}, {}

    def __call__(self, project_id, artifacts, root, cancel):
        self.calls.append(project_id)
        gate = self.gates.get(project_id)
        if gate is not None:
            assert gate.wait(5)
        if project_id in self.fail:
            raise self.fail[project_id]
        made = FakeInspection(project_id)
        self.made.append(made)
        return made


class Window:
    """The window's side of the session: its current key, status line and log."""

    def __init__(self) -> None:
        self.key, self.status, self.logged, self.ready = 'a', [], [], 0

    def on_ready(self) -> None:
        self.ready += 1


@pytest.fixture
def inspector(monkeypatch):
    fake = Inspector()
    monkeypatch.setattr(ui_inspection_session, 'inspect_project_artifacts', fake)
    return fake


@pytest.fixture
def runner():
    made = TaskRunner(reraise=True)
    yield made
    assert made.shutdown(timeout=5) == []


@pytest.fixture
def window():
    return Window()


def session_for(runner, window) -> InspectionSession:
    return InspectionSession(runner, lambda: window.key, on_status=window.status.append, on_ready=window.on_ready,
                             log=window.logged.append)


def start(session, window, root) -> bool:
    return session.start(window.key, (), root)


def join_workers() -> None:
    """Let every worker post its outcome without delivering it (no Qt events are processed)."""
    for thread in tasks.live_task_threads():
        thread.join(5)


def test_no_start_without_a_key(runner, window, inspector, tmp_path):
    window.key = None
    assert start(session_for(runner, window), window, tmp_path) is False and inspector.calls == []


def test_the_same_key_does_not_start_a_second_run(runner, window, inspector, qtbot, tmp_path):
    session, gate = session_for(runner, window), threading.Event()
    inspector.gates['a'] = gate
    assert start(session, window, tmp_path) is True
    assert start(session, window, tmp_path) is False
    gate.set()
    qtbot.waitUntil(lambda: session.current() is not None, timeout=5000)
    assert start(session, window, tmp_path) is False
    assert inspector.calls == ['a'] and window.status == ['File inspection complete · ' + SUMMARY]
    assert window.ready == 1 and session.current().closes == 0


def test_a_superseding_start_closes_the_old_result_and_never_shows_it(runner, window, inspector, qtbot, tmp_path):
    session = session_for(runner, window)
    start(session, window, tmp_path)
    join_workers()               # the old result is posted but not delivered
    window.key = 'b'
    assert start(session, window, tmp_path) is True
    qtbot.waitUntil(lambda: session.current() is not None, timeout=5000)
    old, new = inspector.made
    assert old.closes == 1 and new.closes == 0 and session.current() is new
    assert window.status == ['File inspection complete · ' + SUMMARY] and window.ready == 1


def test_a_superseded_worker_closes_its_own_result(runner, window, inspector, qtbot, tmp_path):
    session, gate = session_for(runner, window), threading.Event()
    inspector.gates['a'] = gate
    start(session, window, tmp_path)
    window.key = 'b'
    start(session, window, tmp_path)
    gate.set()
    qtbot.waitUntil(lambda: len(inspector.made) == 2 and session.current() is not None, timeout=5000)
    join_workers()
    qtbot.waitUntil(lambda: bool(not runner._running), timeout=5000)
    old = next(made for made in inspector.made if made.name == 'a')
    assert old.closes == 1 and session.current().name == 'b' and window.ready == 1


def test_a_result_for_a_key_that_changed_is_closed_and_not_shown(runner, window, inspector, qtbot, tmp_path):
    session = session_for(runner, window)
    start(session, window, tmp_path)
    join_workers()
    window.key = 'b'             # the project changed but nothing asked for a new inspection yet
    qtbot.waitUntil(lambda: bool(inspector.made and inspector.made[0].closes), timeout=5000)
    assert inspector.made[0].closes == 1 and session.current() is None
    assert window.status == [] and window.ready == 0


def test_a_stale_failure_is_ignored(runner, window, inspector, qtbot, tmp_path):
    session = session_for(runner, window)
    inspector.fail['a'] = ValueError('C:/secret/path')
    start(session, window, tmp_path)
    join_workers()
    window.key = 'b'
    qtbot.waitUntil(lambda: bool(not runner._running), timeout=5000)
    assert window.status == [] and window.logged == [] and session.failure() is None


def test_a_current_failure_reports_the_class_only(runner, window, inspector, qtbot, tmp_path):
    session = session_for(runner, window)
    inspector.fail['a'] = ValueError('C:/secret/path')
    start(session, window, tmp_path)
    qtbot.waitUntil(lambda: bool(window.status), timeout=5000)
    assert window.status == window.logged == ['File inspection failed: ValueError']
    assert session.failure() == 'ValueError' and session.current() is None
    assert start(session, window, tmp_path) is True   # a failure is not a result: a later refresh retries
    window.key = 'b'
    assert session.failure() is None


def test_stop_closes_the_current_result(runner, window, inspector, qtbot, tmp_path):
    session = session_for(runner, window)
    start(session, window, tmp_path)
    qtbot.waitUntil(lambda: session.current() is not None, timeout=5000)
    result = session.current()
    session.stop()
    assert result.closes == 1 and session.current() is None
    assert start(session, window, tmp_path) is True   # stop is not terminal: the next project starts afresh


def test_clear_closes_the_result_and_forgets_a_failure(runner, window, inspector, qtbot, tmp_path):
    session = session_for(runner, window)
    start(session, window, tmp_path)
    qtbot.waitUntil(lambda: session.current() is not None, timeout=5000)
    result = session.current()
    session.clear()
    session.clear()
    assert result.closes == 1 and session.current() is None and session.failure() is None


def test_stop_cancels_a_running_inspection_and_no_thread_survives(runner, window, monkeypatch, qtbot, tmp_path):
    made, started = [], threading.Event()

    def until_cancelled(project_id, artifacts, root, cancel):
        started.set()
        while not cancel():
            threading.Event().wait(0.005)
        made.append(FakeInspection(project_id))
        return made[-1]
    monkeypatch.setattr(ui_inspection_session, 'inspect_project_artifacts', until_cancelled)
    session = session_for(runner, window)
    start(session, window, tmp_path)
    assert started.wait(5)
    session.stop()
    join_workers()
    assert tasks.live_task_threads() == []
    qtbot.waitUntil(lambda: bool(not runner._running), timeout=5000)
    assert [result.closes for result in made] == [1] and window.status == [] and session.current() is None


def test_shutting_the_runner_down_closes_a_finished_result_and_refuses_new_starts(window, inspector, qtbot,
                                                                                    tmp_path):
    local = TaskRunner(reraise=True)
    session = session_for(local, window)
    start(session, window, tmp_path)
    join_workers()
    assert local.shutdown(timeout=5) == []
    assert [result.closes for result in inspector.made] == [1]
    window.key = 'b'
    assert start(session, window, tmp_path) is False
    session.stop()
    assert inspector.calls == ['a']


def test_one_real_run_over_the_sample_project(runner, window, qtbot, tmp_path):
    service = ProjectService.sample(tmp_path / 'sample')
    try:
        project = service.project
        window.key = (str(service.root), project.id)
        session = session_for(runner, window)
        assert session.start(project.id, project.artifacts, service.root) is True
        qtbot.waitUntil(lambda: session.current() is not None or bool(window.status), timeout=10000)
        result = session.current()
        assert result is not None and result.project_id == project.id
        assert window.status[0].startswith('File inspection complete · OLDER: ')
        assert set(result.sides) == {'older', 'newer'}
        session.stop()
        assert result.readers == {} and session.current() is None
    finally:
        service.close()
