"""Background tasks for the single main window (GUI plan 8.5).

``TaskRunner.submit(channel, fn, ...)`` runs ``fn(token, report)`` on a daemon Python thread; results, errors
and progress come back on the GUI thread through one queued bridge slot. The worker is pure with respect to Qt,
the project service and SQLite: it gets an immutable snapshot built on the GUI thread and returns a value.
``TaskRunner.lane`` is a long-lived worker whose state (for example read-only SQLite connections) is opened,
used and closed on that one thread. Legacy ``QThread`` registries (``_LIVE_THREADS``) are adopted into the same
shutdown until they are migrated."""
from __future__ import annotations

import queue
import re
import sys
import threading
import time
import weakref
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Any

from PySide6.QtCore import QObject, Qt, QThread, QTimer, Signal, Slot
from shiboken6 import isValid

CODE = 'PT-GUI-TASK'
PROGRESS_INTERVAL_MS = 100       # 10 Hz, latest wins; 100,000 unthrottled emits delayed a GUI timer by 98 ms
JOIN_SECONDS = 5.0
CHECKPOINT_WORK = 0.002          # sleep 1 ms after every 2 ms of CPU work (measured repaint p95 20 ms)
CHECKPOINT_SLEEP = 0.001
LEGACY_MODULES = ('ui_engine_setup', 'ui_series', 'ui_bundle_setup', 'ui_inspection')

_UNSAFE = re.compile('[\x00-\x1f\x7f-\x9f  ‪-‮⁦-⁩]')


def _clip(text: object, limit: int) -> str:
    return _UNSAFE.sub(' ', str(text))[:limit]


class TaskCancelled(Exception):
    """Raised by ``CancelToken.raise_if_cancelled``; the runner treats it as a silent drop."""


@dataclass(frozen=True, slots=True)
class Progress:
    stage: str
    done: int = 0
    total: int | None = None         # None = indeterminate
    message: str = ''

    def __post_init__(self) -> None:
        object.__setattr__(self, 'stage', _clip(self.stage, 80))
        object.__setattr__(self, 'message', _clip(self.message, 200))


@dataclass(frozen=True, slots=True)
class TaskFailure:
    """What crosses from a failed worker: the exception class only (messages may carry paths or tokens)."""
    exception_class: str
    code: str = CODE

    @property
    def text(self) -> str:
        return f'{self.code}: {self.exception_class}'


class CancelToken(threading.Event):
    """Cooperative cancellation. An ``Event``, so legacy code can pass it where it expects one."""

    def __init__(self) -> None:
        super().__init__()
        self._mark = time.perf_counter()

    def __call__(self) -> bool:
        return self.is_set()

    def raise_if_cancelled(self) -> None:
        if self.is_set():
            raise TaskCancelled

    def checkpoint(self) -> bool:
        """Yield the GIL after 2 ms of work so GUI repaints stay fast; returns whether cancel is set."""
        if time.perf_counter() - self._mark >= CHECKPOINT_WORK:
            time.sleep(CHECKPOINT_SLEEP)
            self._mark = time.perf_counter()
        return self.is_set()


@dataclass(eq=False, slots=True)
class _Task:
    channel: str
    generation: int | None           # None: FIFO lane request, never superseded
    token: CancelToken
    on_result: Callable[[Any], None] | None
    on_error: Callable[[TaskFailure], None] | None
    on_progress: Callable[[Progress], None] | None
    pending: tuple | None = None     # latest report() arguments, written by the worker, read by the GUI timer
    sent: tuple | None = None

    def report(self, stage: str, done: int = 0, total: int | None = None, message: str = '') -> None:
        self.pending = (stage, done, total, message)


@dataclass(slots=True)
class _Event:
    kind: str                        # result, error or drop
    task: _Task
    payload: Any = None


class _Bridge(QObject):
    """Lives on the GUI thread. The slots are bound methods on a queued connection, never lambdas."""
    delivered = Signal(object)

    def __init__(self, parent: QObject | None, deliver: Callable, tick: Callable) -> None:
        super().__init__(parent)
        self._deliver = deliver
        self.timer = QTimer(self)
        self.timer.setInterval(PROGRESS_INTERVAL_MS)
        self.timer.timeout.connect(tick)
        self.delivered.connect(self._receive, Qt.ConnectionType.QueuedConnection)

    @Slot(object)
    def _receive(self, event: _Event) -> None:
        self._deliver(event)

    def post(self, event: _Event) -> None:
        try:
            self.delivered.emit(event)
        except RuntimeError:         # the bridge was deleted while a worker was still running
            pass


_RUNNERS: weakref.WeakSet[TaskRunner] = weakref.WeakSet()


class TaskRunner:
    def __init__(self, parent: QObject | None = None, status: Callable[[str], None] | None = None,
                 reraise: bool = False) -> None:
        """``status`` receives a line when a result callback raises; with ``reraise`` (tests) it propagates."""
        self._bridge = _Bridge(parent, self._deliver, self._tick)
        self._status = status
        self._reraise = reraise
        self._generation: dict[str, int] = {}
        self._tokens: dict[str, CancelToken] = {}
        self._running: set[_Task] = set()
        self._held: set[str] = set()
        self._parked: dict[str, _Event] = {}
        self._lanes: dict[str, Lane] = {}
        self._threads: set[threading.Thread] = set()
        self._lock = threading.Lock()
        self._closed = False
        _RUNNERS.add(self)

    # ---- submitting ----------------------------------------------------------------------------

    def submit(self, channel: str, fn: Callable[[CancelToken, Callable], Any],
               on_result: Callable[[Any], None] | None = None, on_error: Callable[[TaskFailure], None] | None = None,
               on_progress: Callable[[Progress], None] | None = None) -> CancelToken:
        """Start ``fn(token, report)``; the previous task on ``channel`` is cancelled and its result dropped.
        ``report(stage, done=0, total=None, message='')`` is cheap and may be called in a tight loop."""
        self._require_open()
        token = self._supersede(channel)
        generation = self._generation[channel]
        task = _Task(channel, generation, token, on_result, on_error, on_progress)
        self._start(task, lambda: fn(token, task.report), f'pt-task-{channel}')
        return token

    def cancel(self, channel: str) -> None:
        """Cancel the channel's task; its result is dropped even if the worker ignores the token."""
        self._supersede(channel)

    def busy(self, channel: str | None = None) -> bool:
        return any(channel in (None, task.channel) and not task.token.is_set() for task in self._running)

    def set_applying(self, channel: str, applying: bool) -> None:
        """A hidden panel may let a task finish but applies nothing until shown; the latest outcome is replayed."""
        if applying:
            self._held.discard(channel)
            parked = self._parked.pop(channel, None)
            if parked:
                self._deliver(parked)
        else:
            self._held.add(channel)

    def lane(self, name: str, init: Callable[[], Any], close: Callable[[Any], None] | None = None) -> Lane:
        self._require_open()
        if name in self._lanes:
            raise ValueError(f'lane {name!r} already exists')
        self._lanes[name] = Lane(self, name, init, close)
        return self._lanes[name]

    # ---- shutdown ------------------------------------------------------------------------------

    def shutdown(self, timeout: float = JOIN_SECONDS) -> list[str]:
        """Cancel everything, join each thread for at most ``timeout`` seconds (shared deadline) and adopt the
        legacy registries. Returns the names of threads that did not stop (daemon: they cannot block exit)."""
        if not self._closed:
            self._closed = True
            if isValid(self._bridge):
                self._bridge.timer.stop()
            for task in list(self._running):
                task.token.set()
            for lane in self._lanes.values():
                lane.stop()
        deadline = time.monotonic() + timeout
        with self._lock:
            threads = list(self._threads)
        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        stuck = [t.name for t in threads if t.is_alive()]
        stuck += [type(t).__name__ for t in join_legacy_threads(max(0.0, deadline - time.monotonic()))]
        self._running.clear()
        self._parked.clear()
        if isValid(self._bridge):
            self._bridge.deleteLater()
        return stuck

    # ---- internals -----------------------------------------------------------------------------

    def _require_open(self) -> None:
        if QThread.currentThread() is not self._bridge.thread():
            raise RuntimeError('TaskRunner must be used on the GUI thread')
        if self._closed:
            raise RuntimeError('TaskRunner is shut down')

    def _supersede(self, channel: str) -> CancelToken:
        previous = self._tokens.get(channel)
        if previous:
            previous.set()
        self._generation[channel] = self._generation.get(channel, 0) + 1
        self._tokens[channel] = CancelToken()
        return self._tokens[channel]

    def _start(self, task: _Task, call: Callable[[], Any], name: str) -> None:
        self._running.add(task)
        if task.on_progress:
            self._bridge.timer.start()
        thread = threading.Thread(target=self._work, args=(task, call), name=name, daemon=True)
        with self._lock:
            self._threads.add(thread)
        thread.start()

    def _work(self, task: _Task, call: Callable[[], Any]) -> None:
        try:
            event = _Event('result', task, call())
        except TaskCancelled:
            event = _Event('drop', task)
        except Exception as exc:  # noqa: BLE001 - only the class crosses the thread boundary
            event = _Event('error', task, TaskFailure(type(exc).__name__))
        self._bridge.post(event)
        with self._lock:
            self._threads.discard(threading.current_thread())

    def _current(self, task: _Task) -> bool:
        return task.generation is None or self._generation.get(task.channel) == task.generation

    def _deliver(self, event: _Event) -> None:
        task = event.task
        self._running.discard(task)
        if self._closed or event.kind == 'drop' or not self._current(task):
            return
        if task.channel in self._held:
            self._parked[task.channel] = event
            return
        self._flush_progress(task)
        callback = task.on_result if event.kind == 'result' else task.on_error
        self._apply(task.channel, callback, event.payload)

    def _tick(self) -> None:
        pending = [t for t in self._running if t.on_progress]
        if not pending:
            self._bridge.timer.stop()
        for task in pending:
            if task.channel not in self._held and self._current(task):
                self._flush_progress(task)

    def _flush_progress(self, task: _Task) -> None:
        latest = task.pending
        if latest is None or latest is task.sent:
            return
        task.sent = latest
        if task.on_progress:
            self._apply(task.channel, task.on_progress, Progress(*latest))

    def _apply(self, channel: str, callback: Callable | None, payload: Any) -> None:
        if callback is None:
            return
        try:
            callback(payload)
        except Exception as exc:
            if self._reraise:
                raise
            if self._status:
                self._status(f'Background task {_clip(channel, 40)} could not apply its result '
                             f'({type(exc).__name__}).')


class Lane:
    """One daemon thread; ``init()`` runs on it, every request gets that state, ``close(state)`` runs on it
    after the running request at shutdown. FIFO by default; ``coalesce=True`` is latest-only (earlier coalesced
    requests are cancelled and their results dropped). An ``init`` failure fails every request with its class."""

    def __init__(self, runner: TaskRunner, name: str, init: Callable[[], Any],
                 close: Callable[[Any], None] | None) -> None:
        self._runner = runner
        self._channel = f'lane:{name}'
        self._init = init
        self._close = close
        self._queue: queue.Queue = queue.Queue()
        self._latest = CancelToken()
        self._thread = threading.Thread(target=self._loop, name=f'pt-lane-{name}', daemon=True)
        with runner._lock:
            runner._threads.add(self._thread)
        self._thread.start()

    def submit(self, fn: Callable[[Any, CancelToken, Callable], Any],
               on_result: Callable[[Any], None] | None = None, on_error: Callable[[TaskFailure], None] | None = None,
               on_progress: Callable[[Progress], None] | None = None, *, coalesce: bool = False) -> CancelToken:
        runner = self._runner
        runner._require_open()
        token = CancelToken()
        generation = None
        if coalesce:
            self._latest.set()
            self._latest = token
            generation = runner._generation[self._channel] = runner._generation.get(self._channel, 0) + 1
        task = _Task(self._channel, generation, token, on_result, on_error, on_progress)
        runner._running.add(task)
        if on_progress:
            runner._bridge.timer.start()
        self._queue.put((task, fn))
        return token

    def stop(self) -> None:
        self._queue.put(None)

    def _loop(self) -> None:
        state, failure = None, None
        try:
            state = self._init()
        except Exception as exc:  # noqa: BLE001
            failure = TaskFailure(type(exc).__name__)
        while (item := self._queue.get()) is not None:
            task, fn = item
            if task.token.is_set():
                event = _Event('drop', task)
            elif failure:
                event = _Event('error', task, failure)
            else:
                event = self._run(task, fn, state)
            self._runner._bridge.post(event)
        if failure is None and self._close:
            with suppress(Exception):
                self._close(state)
        with self._runner._lock:
            self._runner._threads.discard(threading.current_thread())

    @staticmethod
    def _run(task: _Task, fn: Callable, state: Any) -> _Event:
        try:
            return _Event('result', task, fn(state, task.token, task.report))
        except TaskCancelled:
            return _Event('drop', task)
        except Exception as exc:  # noqa: BLE001
            return _Event('error', task, TaskFailure(type(exc).__name__))


# ---- process-wide helpers (tests and the host) ------------------------------------------------------


def live_task_threads() -> list[threading.Thread]:
    """Alive worker and lane threads of every runner."""
    found = []
    for runner in list(_RUNNERS):
        with runner._lock:
            found += [t for t in runner._threads if t.is_alive()]
    return found


def shutdown_live_runners(timeout: float = JOIN_SECONDS) -> list[str]:
    stuck: list[str] = []
    for runner in list(_RUNNERS):
        stuck += runner.shutdown(timeout)
    return stuck


def legacy_threads() -> list[QThread]:
    """Alive QThreads held by the status-quo module registries; found through ``sys.modules`` (no import)."""
    found = []
    for name in LEGACY_MODULES:
        module = sys.modules.get(f'patchtrace.{name}')
        found += [t for t in list(getattr(module, '_LIVE_THREADS', ())) if isValid(t) and t.isRunning()]
    return found


def join_legacy_threads(timeout: float = JOIN_SECONDS) -> list[QThread]:
    """Cancel and join the legacy QThreads (destroying a running one aborts the process); returns survivors."""
    threads = legacy_threads()
    deadline = time.monotonic() + timeout
    for thread in threads:
        if hasattr(thread, 'cancel'):
            thread.cancel.set()
    for thread in threads:
        thread.wait(int(max(0.0, deadline - time.monotonic()) * 1000))
    return legacy_threads()


__all__ = ['CODE', 'CancelToken', 'Lane', 'Progress', 'TaskCancelled', 'TaskFailure', 'TaskRunner',
           'join_legacy_threads', 'legacy_threads', 'live_task_threads', 'shutdown_live_runners']
