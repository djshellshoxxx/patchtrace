"""TaskRunner, Lane, CancelToken and legacy-thread adoption (GUI plan 8.5, slice F2). Offscreen, hermetic."""
from __future__ import annotations

import gc
import os
import statistics
import subprocess
import sys
import threading
import time
import types
import weakref
from pathlib import Path

import pytest
from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, Qt, QThread
from PySide6.QtWidgets import QApplication, QTableView
from qt_support import flush_deferred_deletes, join_gui_threads, slot_timer  # noqa: F401
from shiboken6 import delete as delete_qobject

from patchtrace.gui.qt import tasks
from patchtrace.gui.qt.tasks import CancelToken, Progress, TaskCancelled, TaskFailure, TaskRunner


@pytest.fixture
def runner():
    made = TaskRunner(reraise=True)
    yield made
    assert made.shutdown(timeout=5) == []


class Sink:
    """Collects callbacks and the thread each one ran on."""

    def __init__(self) -> None:
        self.results, self.errors, self.progress, self.threads = [], [], [], []

    def result(self, value) -> None:
        self.results.append(value)
        self.threads.append(threading.current_thread())

    def error(self, failure) -> None:
        self.errors.append(failure)

    def on_progress(self, progress) -> None:
        self.progress.append(progress)


def submit(runner, sink, fn, channel='c'):
    return runner.submit(channel, fn, sink.result, sink.error, sink.on_progress)


def test_result_is_applied_on_the_gui_thread_and_worker_is_not(runner, qtbot):
    sink, seen = Sink(), []

    def work(token, report):
        seen.append((threading.current_thread() is threading.main_thread(),
                     QThread.currentThread() is QApplication.instance().thread()))
        return 41 + 1
    submit(runner, sink, work)
    qtbot.waitUntil(lambda: bool(sink.results), timeout=5000)
    assert sink.results == [42] and seen == [(False, False)]
    assert sink.threads == [threading.main_thread()]


def test_worker_exception_crosses_as_class_name_only(runner, qtbot):
    sink = Sink()

    def work(token, report):
        raise ValueError('C:/secret/path token=abc')
    submit(runner, sink, work)
    qtbot.waitUntil(lambda: bool(sink.errors), timeout=5000)
    failure = sink.errors[0]
    assert failure == TaskFailure('ValueError') and failure.text == 'PT-GUI-TASK: ValueError'
    assert 'secret' not in repr(failure) and not sink.results


def test_new_submit_supersedes_the_channel_and_drops_the_old_result(runner, qtbot):
    sink, gate = Sink(), threading.Event()

    def slow(token, report):
        gate.wait(5)
        return 'old'
    first = submit(runner, sink, slow)
    submit(runner, sink, lambda token, report: 'new')
    assert first.is_set()
    qtbot.waitUntil(lambda: bool(sink.results), timeout=5000)
    gate.set()
    qtbot.waitUntil(lambda: bool(not runner.busy()), timeout=5000)
    qtbot.wait(50)
    assert sink.results == ['new']


def test_cancel_drops_a_result_the_worker_still_produces(runner, qtbot):
    sink, gate = Sink(), threading.Event()
    submit(runner, sink, lambda token, report: gate.wait(5) or 'late')
    runner.cancel('c')
    gate.set()
    qtbot.waitUntil(lambda: bool(not runner.busy() and not runner._running), timeout=5000)
    qtbot.wait(50)
    assert sink.results == [] and sink.errors == []


def test_raise_if_cancelled_is_a_silent_drop(runner, qtbot):
    sink = Sink()

    def work(token, report):
        raise TaskCancelled
    submit(runner, sink, work)
    qtbot.waitUntil(lambda: bool(not runner._running), timeout=5000)
    assert sink.results == [] and sink.errors == []


def test_channels_are_independent(runner, qtbot):
    sink = Sink()
    submit(runner, sink, lambda token, report: 'a', channel='a')
    submit(runner, sink, lambda token, report: 'b', channel='b')
    qtbot.waitUntil(lambda: bool(len(sink.results) == 2), timeout=5000)
    assert sorted(sink.results) == ['a', 'b']


def test_progress_is_throttled_latest_wins_and_final_arrives_before_the_result(runner, qtbot):
    sink, order = Sink(), []

    def work(token, report):
        for i in range(100_000):
            report('scan', i, 100_000, f'item {i}')
        return 'done'
    runner.submit('p', work, lambda value: order.append('result'), None,
                  lambda progress: (sink.progress.append(progress), order.append('progress')))
    start = time.monotonic()
    qtbot.waitUntil(lambda: bool('result' in order), timeout=10000)
    elapsed = time.monotonic() - start
    assert len(sink.progress) <= elapsed * 1000 / tasks.PROGRESS_INTERVAL_MS + 3
    assert sink.progress[-1] == Progress('scan', 99_999, 100_000, 'item 99999')
    assert order[-1] == 'result' and order[-2] == 'progress'


def test_progress_text_is_bounded_and_stripped():
    progress = Progress('s\x1b[31m' + 'x' * 200, 1, None, 'a\u202eb\x00' + 'y' * 500)
    assert len(progress.stage) == 80 and len(progress.message) == 200
    assert '\x1b' not in progress.stage and '\u202e' not in progress.message and '\x00' not in progress.message


def test_idle_runner_has_no_active_timer(runner, qtbot):
    sink = Sink()
    runner.submit('p', lambda token, report: report('s', 1, 1) or 1, sink.result, None, sink.on_progress)
    qtbot.waitUntil(lambda: bool(sink.results), timeout=5000)
    qtbot.waitUntil(lambda: bool(not runner._bridge.timer.isActive()), timeout=2000)


def test_callback_exception_becomes_a_status_line(qtbot):
    lines = []
    quiet = TaskRunner(status=lines.append)
    try:
        def boom(value):
            raise KeyError('hostile <b>text</b>')
        quiet.submit('boom', lambda token, report: 1, boom)
        qtbot.waitUntil(lambda: bool(lines), timeout=5000)
        assert lines == ['Background task boom could not apply its result (KeyError).']
    finally:
        quiet.shutdown()


def test_callback_exception_is_reraised_in_tests(runner, qtbot):
    def boom(value):
        raise KeyError('x')
    with qtbot.capture_exceptions() as caught:
        runner.submit('boom', lambda token, report: 1, boom)
        qtbot.waitUntil(lambda: bool(caught), timeout=5000)
    assert caught[0][0] is KeyError


def test_hidden_channel_applies_nothing_until_shown_then_replays_the_latest(runner, qtbot):
    sink = Sink()
    runner.set_applying('c', False)
    submit(runner, sink, lambda token, report: 'first')
    qtbot.waitUntil(lambda: bool(not runner._running), timeout=5000)
    qtbot.wait(30)
    assert sink.results == []
    runner.set_applying('c', True)
    assert sink.results == ['first']


def test_submit_off_the_gui_thread_is_refused(runner):
    errors = []

    def attempt():
        try:
            runner.submit('c', lambda token, report: 1)
        except RuntimeError as exc:
            errors.append(str(exc))
    thread = threading.Thread(target=attempt)
    thread.start()
    thread.join()
    assert errors == ['TaskRunner must be used on the GUI thread']


def test_submit_after_shutdown_is_refused():
    closed = TaskRunner()
    closed.shutdown()
    with pytest.raises(RuntimeError, match='shut down'):
        closed.submit('c', lambda token, report: 1)


# ---- teardown matrix ------------------------------------------------------------------------------


@pytest.mark.parametrize('round_', range(5), ids=[f'r{i}' for i in range(5)])
def test_close_while_loading_cancels_and_joins(qtbot, round_):
    local, sink, started = TaskRunner(reraise=True), Sink(), threading.Event()

    def work(token, report):
        started.set()
        token.wait(5)
        return 'unused'
    local.submit('load', work, sink.result, sink.error)
    assert started.wait(5)
    assert local.shutdown(timeout=5) == []
    qtbot.wait(20)
    assert sink.results == [] and tasks.live_task_threads() == []


def test_project_switch_mid_task_applies_only_the_new_project(runner, qtbot):
    sink, gate = Sink(), threading.Event()
    submit(runner, sink, lambda token, report: gate.wait(5) and 'project-1')
    submit(runner, sink, lambda token, report: 'project-2')
    gate.set()
    qtbot.waitUntil(lambda: bool(not runner._running), timeout=5000)
    qtbot.wait(30)
    assert sink.results == ['project-2']


def test_gc_of_a_runner_with_a_started_worker_does_not_abort(qtbot):
    sink, gate, started = Sink(), threading.Event(), threading.Event()
    local = TaskRunner()

    def work(token, report):
        started.set()
        gate.wait(5)
        return 1
    local.submit('c', work, sink.result)
    assert started.wait(5)
    del local
    gc.collect()
    gate.set()
    qtbot.waitUntil(lambda: bool(not tasks.live_task_threads() and sink.results == [1]), timeout=5000)


def test_bridge_deleted_while_the_worker_runs_is_harmless(qtbot):
    local, sink, gate, started = TaskRunner(), Sink(), threading.Event(), threading.Event()

    def work(token, report):
        started.set()
        gate.wait(5)
        return 1
    local.submit('c', work, sink.result)
    assert started.wait(5)
    delete_qobject(local._bridge)
    gate.set()
    qtbot.waitUntil(lambda: bool(not tasks.live_task_threads()), timeout=5000)
    assert sink.results == []


def test_shutdown_with_a_hung_worker_returns_in_time_and_names_it(qtbot):
    local, release, started = TaskRunner(), threading.Event(), threading.Event()

    def hung(token, report):
        started.set()
        release.wait(10)   # ignores the token on purpose
    local.submit('hung', hung)
    assert started.wait(5)
    start = time.monotonic()
    stuck = local.shutdown(timeout=0.2)
    assert stuck == ['pt-task-hung'] and time.monotonic() - start >= 0.2
    assert time.monotonic() - start < 3
    release.set()
    qtbot.waitUntil(lambda: bool(not tasks.live_task_threads()), timeout=5000)


# ---- CancelToken ----------------------------------------------------------------------------------


def test_cancel_token_surface():
    token = CancelToken()
    assert not token.is_set() and token() is False
    token.raise_if_cancelled()
    token.set()
    assert token() is True and isinstance(token, threading.Event)
    with pytest.raises(TaskCancelled):
        token.raise_if_cancelled()


def test_checkpoint_yields_after_two_milliseconds_of_work_and_reports_cancel():
    token = CancelToken()
    token._mark = time.perf_counter() - 0.01
    before = time.perf_counter()
    assert token.checkpoint() is False
    assert time.perf_counter() - before >= 0.001
    assert token._mark >= before
    token.set()
    assert token.checkpoint() is True


class _RowModel(QAbstractTableModel):
    def rowCount(self, parent=QModelIndex()):  # noqa: B008 - Qt override signature
        return 1218

    def columnCount(self, parent=QModelIndex()):  # noqa: B008
        return 4

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        return f'{index.row()}:{index.column()}' if role == Qt.ItemDataRole.DisplayRole else None


def _repaint_times(view, count=30) -> list[float]:
    times = []
    for _ in range(count):
        start = time.perf_counter()
        view.viewport().repaint()
        times.append(time.perf_counter() - start)
    return times


def test_repaint_under_a_checkpointing_cpu_worker_stays_responsive(runner, qtbot):
    view = QTableView()
    view.setModel(_RowModel())
    view.resize(900, 600)
    qtbot.addWidget(view)
    view.show()
    qtbot.waitExposed(view)
    _repaint_times(view, 5)
    idle = statistics.median(_repaint_times(view))

    def burn(token, report):
        total = 0
        while not token.checkpoint():
            total += sum(range(2000))
        return total
    token = runner.submit('burn', burn)
    time.sleep(0.05)
    loaded = sorted(_repaint_times(view, 40))
    token.set()
    assert loaded[int(len(loaded) * 0.95) - 1] <= idle * 5 + 0.020


def test_gui_callbacks_stay_within_budget_for_a_thousand_deliveries(runner, qtbot, slot_timer):  # noqa: F811
    lane = runner.lane('q', lambda: 7)
    sink = Sink()
    for i in range(1000):
        lane.submit(lambda state, token, report, i=i: state + i, slot_timer.wrap(sink.result))
    qtbot.waitUntil(lambda: bool(len(sink.results) == 1000), timeout=10000)
    assert sink.results == [7 + i for i in range(1000)]
    slot_timer.assert_budget()


# ---- lanes ----------------------------------------------------------------------------------------


def test_lane_state_is_opened_used_and_closed_on_the_lane_thread(qtbot):
    local, sink, log = TaskRunner(reraise=True), Sink(), []

    def init():
        log.append(('init', threading.get_ident()))
        return {'tid': threading.get_ident()}

    def close(state):
        log.append(('close', threading.get_ident()))

    lane = local.lane('reader', init, close)
    lane.submit(lambda state, token, report: (state['tid'], threading.get_ident()), sink.result)
    qtbot.waitUntil(lambda: bool(sink.results), timeout=5000)
    assert local.shutdown(timeout=5) == []
    init_tid, use_tid = log[0][1], sink.results[0]
    assert use_tid == (init_tid, init_tid) and init_tid != threading.get_ident()
    assert [name for name, _ in log] == ['init', 'close'] and log[1][1] == init_tid


def test_lane_is_fifo_and_delivers_every_result_in_order(runner, qtbot):
    lane, sink = runner.lane('fifo', lambda: None), Sink()
    for i in range(20):
        lane.submit(lambda state, token, report, i=i: i, sink.result)
    qtbot.waitUntil(lambda: bool(len(sink.results) == 20), timeout=5000)
    assert sink.results == list(range(20))


def test_lane_coalesce_keeps_only_the_latest_request(runner, qtbot):
    lane, sink, gate, started = runner.lane('latest', lambda: None), Sink(), threading.Event(), threading.Event()

    def first(state, token, report):
        started.set()
        gate.wait(5)
        return 'first'
    lane.submit(first, sink.result, coalesce=True)
    assert started.wait(5)
    for name in ('second', 'third'):
        lane.submit(lambda state, token, report, name=name: name, sink.result, coalesce=True)
    gate.set()
    qtbot.waitUntil(lambda: bool(sink.results and not runner._running), timeout=5000)
    qtbot.wait(30)
    assert sink.results == ['third']


def test_lane_init_failure_fails_every_request_with_the_class(runner, qtbot):
    def init():
        raise OSError('C:/secret')
    lane, sink = runner.lane('broken', init, lambda state: pytest.fail('close after failed init')), Sink()
    lane.submit(lambda state, token, report: 1, sink.result, sink.error)
    qtbot.waitUntil(lambda: bool(sink.errors), timeout=5000)
    assert sink.errors == [TaskFailure('OSError')]


def test_lane_names_are_unique(runner):
    runner.lane('one', lambda: None)
    with pytest.raises(ValueError, match='already exists'):
        runner.lane('one', lambda: None)


def test_shutdown_closes_lane_state_after_the_running_request(qtbot):
    local, log, started, gate = TaskRunner(), [], threading.Event(), threading.Event()
    lane = local.lane('r', lambda: log.append('init') or 'state', lambda state: log.append(f'close {state}'))

    def running(state, token, report):
        started.set()
        gate.wait(5)
        log.append('request done')
    lane.submit(running)
    assert started.wait(5)
    threading.Timer(0.1, gate.set).start()
    assert local.shutdown(timeout=5) == []
    assert log == ['init', 'request done', 'close state']


# ---- legacy QThread registries --------------------------------------------------------------------


class _LegacyThread(QThread):
    def __init__(self):
        super().__init__()
        self.cancel = threading.Event()

    def run(self):
        self.cancel.wait(5)


def test_legacy_registries_are_adopted_into_shutdown(monkeypatch, qtbot):
    thread = _LegacyThread()
    fake = types.SimpleNamespace(_LIVE_THREADS={thread})
    monkeypatch.setitem(sys.modules, 'patchtrace.ui_series', fake)
    thread.start()
    qtbot.waitUntil(thread.isRunning, timeout=5000)
    assert tasks.legacy_threads() == [thread]
    local = TaskRunner()
    assert local.shutdown(timeout=5) == []
    assert not thread.isRunning() and tasks.legacy_threads() == []


@pytest.mark.parametrize('module, attribute', [('ui', '_DISCOVERY_THREADS'), ('ui_bundle_setup', '_THREADS')],
                         ids=['ui-discovery', 'bundle-setup'])
def test_unlisted_legacy_registries_are_joined_at_shutdown(monkeypatch, qtbot, module, attribute):
    thread = _LegacyThread()
    monkeypatch.setitem(sys.modules, f'patchtrace.{module}', types.SimpleNamespace(**{attribute: {thread}}))
    thread.start()
    qtbot.waitUntil(thread.isRunning, timeout=5000)
    assert tasks.legacy_threads() == [thread]
    assert tasks.join_legacy_threads(timeout=5) == []
    assert not thread.isRunning()


# ---- tools/qt_gate.py -----------------------------------------------------------------------------


def _qt_gate():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
    try:
        import qt_gate
    finally:
        sys.path.pop(0)
    return qt_gate


def test_qt_gate_lists_the_files_repeat_times_in_one_session():
    gate = _qt_gate()
    command = gate.build_command(['tests/a.py', 'tests/b.py'], 3, python='py')
    assert command[:4] == ['py', '-m', 'pytest', '-q'] and '--keep-duplicates' in command
    assert command[-6:] == ['tests/a.py', 'tests/b.py'] * 3
    for bad in ((['tests/a.py'], 0), ([], 5)):
        with pytest.raises(ValueError):
            gate.build_command(*bad)


def test_qt_gate_environment_enables_faulthandler_and_offscreen():
    env = _qt_gate().environment({})
    assert env == {'QT_QPA_PLATFORM': 'offscreen', 'PYTHONFAULTHANDLER': '1'}
    assert _qt_gate().environment({'QT_QPA_PLATFORM': 'minimal'})['QT_QPA_PLATFORM'] == 'minimal'


def test_qt_gate_default_files_cover_the_gui_tests_and_this_file():
    files = _qt_gate().default_files()
    assert 'tests/test_gui_tasks.py' in files and 'tests/test_evidence_ui.py' in files
    assert 'tests/qt_support.py' not in files and files == sorted(files)


# ---- Qt objects are freed on the GUI thread only (to-do T15) ----------------------------------------


class Probe(QObject):
    """A Qt wrapper that records the thread that frees it."""
    freed_on: list[threading.Thread] = []

    def __del__(self) -> None:
        Probe.freed_on.append(threading.current_thread())


class WatchedRunner(TaskRunner):
    def __del__(self) -> None:
        Probe.freed_on.append(threading.current_thread())


def _collect_on_a_worker_thread() -> None:
    thread = threading.Thread(target=gc.collect)
    thread.start()
    thread.join()


def _off_gui_thread(threads: list[threading.Thread]) -> list[str]:
    return [t.name for t in threads if t is not threading.main_thread()]


@pytest.mark.parametrize('parented', [False, True], ids=['no-parent', 'parent'])
def test_dropping_runner_closure_and_result_frees_qt_objects_on_the_gui_thread(qtbot, parented):
    Probe.freed_on = []
    parent, gate, got, bridge_freed = QObject(), threading.Event(), [], []
    local = WatchedRunner(parent if parented else None)
    held = Probe()
    weakref.finalize(local._bridge, lambda: bridge_freed.append(threading.current_thread()))

    def work(token, report, held=held):
        gate.wait(5)
        return Probe()
    local.submit('c', work, got.append)
    del held, work, local
    gate.set()
    qtbot.waitUntil(lambda: bool(got) and not tasks.live_task_threads(), timeout=5000)
    got.clear()
    _collect_on_a_worker_thread()
    tasks.shutdown_live_runners()
    flush_deferred_deletes()
    gc.collect()
    assert _off_gui_thread(Probe.freed_on + bridge_freed) == []


def test_lane_dropped_without_shutdown_frees_qt_objects_on_the_gui_thread(qtbot):
    Probe.freed_on = []
    local, got = WatchedRunner(), []
    local.lane('db', lambda: 1).submit(lambda state, token, report: Probe(), got.append)
    qtbot.waitUntil(lambda: bool(got), timeout=5000)
    got.clear()
    del local
    _collect_on_a_worker_thread()
    tasks.shutdown_live_runners()
    flush_deferred_deletes()
    gc.collect()
    assert _off_gui_thread(Probe.freed_on) == []


def test_runner_is_kept_alive_until_shutdown_without_a_reference(qtbot):
    sink, gate = Sink(), threading.Event()
    local = TaskRunner()
    local.submit('c', lambda token, report: gate.wait(5) and 'kept', sink.result)
    del local
    gc.collect()
    gate.set()
    qtbot.waitUntil(lambda: sink.results == ['kept'], timeout=5000)
    assert tasks.shutdown_live_runners() == []
    assert tasks.live_task_threads() == []


STRESS = """
import gc, threading
from PySide6.QtCore import QObject
from PySide6.QtWidgets import QApplication
from patchtrace.gui.qt.tasks import TaskRunner, shutdown_live_runners

app, parent, got = QApplication([]), QObject(), []
for index in range(50):
    gate, held = threading.Event(), QObject()
    runner = TaskRunner(parent if index % 2 else None)

    def work(token, report, held=held):
        gate.wait(5)
        return QObject()
    runner.submit('c', work, got.append)
    del held, work, runner
    gate.set()
    collector = threading.Thread(target=gc.collect)
    collector.start()
    collector.join()
    for _ in range(10):
        app.processEvents()
        threading.Event().wait(0.002)
assert shutdown_live_runners() == []
print('ok')
"""


def test_dropping_runners_in_a_subprocess_never_aborts(tmp_path):
    script = tmp_path / 'stress.py'
    script.write_text(STRESS, encoding='utf-8', newline='\n')
    env = {**os.environ, 'QT_QPA_PLATFORM': 'offscreen', 'PYTHONFAULTHANDLER': '1'}
    done = subprocess.run([sys.executable, str(script)], env=env, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0 and done.stdout.strip() == 'ok', done.stderr[-2000:]


@pytest.mark.parametrize('char', ['؜', '‎', '‏', '‮', '⁦'], ids=['alm', 'lrm', 'rlm', 'rlo', 'lri'])
def test_task_text_drops_every_bidi_control(char):
    assert char not in tasks._clip(f'a{char}b', 10)
