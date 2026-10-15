"""Shared Qt test support for the GUI framework and every panel built on it (GUI plan 8.8, slice F2).

Import what you need (`from qt_support import settings, join_gui_threads  # noqa: F401`); nothing here is
autouse for modules that do not import it. Worker registries are found through ``sys.modules`` so this file
works before, and without importing, ``patchtrace.gui.qt.tasks``: a module that was never imported cannot own
a thread."""
from __future__ import annotations

import statistics
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import pytest
from PySide6.QtCore import QAbstractItemModel, QCoreApplication, QEvent, QSettings, Qt
from PySide6.QtWidgets import (
    QAbstractButton,
    QAbstractItemView,
    QApplication,
    QComboBox,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QTableView,
    QTextEdit,
    QWidget,
)

# The C6 list with short explicit ids (Windows limits PYTEST_CURRENT_TEST to 32767 characters).
HOSTILE = ['<b>pwn</b>', '<img src=x onerror=1>', '&lt;', '{0}', '%s', '\x1b[31m', '\u202erev', 'file:///C:/x',
           'a\x00b', 'l1\u2028l2']
HOSTILE_PARAMS = [pytest.param(text, id=f'h{index}') for index, text in enumerate(HOSTILE)]

_LEGACY_REGISTRIES = (('ui_engine_setup', '_LIVE_THREADS'), ('ui_series', '_LIVE_THREADS'),
                      ('ui_bundle_setup', '_LIVE_THREADS'), ('ui_inspection', '_LIVE_THREADS'),
                      ('ui', '_DISCOVERY_THREADS'), ('ui_bundle_setup', '_THREADS'))
JOIN_MS = 5000


def legacy_threads() -> list:
    """Alive QThreads held by the status-quo module registries."""
    found = []
    for name, registry in _LEGACY_REGISTRIES:
        module = sys.modules.get(f'patchtrace.{name}')
        found += [t for t in list(getattr(module, registry, ())) if _alive(t)]
    return found


def _alive(thread) -> bool:
    from shiboken6 import isValid
    return thread is not None and isValid(thread) and thread.isRunning()


def task_threads() -> list:
    """Alive Python threads started by any ``TaskRunner`` (empty while the module is not imported)."""
    tasks = sys.modules.get('patchtrace.gui.qt.tasks')
    return list(tasks.live_task_threads()) if tasks else []


def flush_deferred_deletes() -> None:
    QApplication.processEvents()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)  # processEvents skips these at loop level 0


@pytest.fixture(autouse=True)
def join_gui_threads():
    """Cancel and join every runner thread and legacy QThread after the test; fail if any survives."""
    yield
    tasks = sys.modules.get('patchtrace.gui.qt.tasks')
    if tasks:
        tasks.shutdown_live_runners(timeout=JOIN_MS / 1000)
    survivors = [t.name for t in task_threads()]
    for thread in legacy_threads():
        if hasattr(thread, 'cancel'):
            thread.cancel.set()
        if not thread.wait(JOIN_MS):
            survivors.append(type(thread).__name__)
    flush_deferred_deletes()
    assert not survivors, f'worker threads survived the test: {survivors}'


@pytest.fixture
def settings(tmp_path) -> QSettings:
    return QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat)


@pytest.fixture
def main_window(qtbot, tmp_path, settings):
    """A MainWindow over the synthetic sample project; closing it runs the real shutdown path."""
    from patchtrace.service import ProjectService
    from patchtrace.ui import MainWindow
    service = ProjectService.sample(tmp_path / 'sample')
    window = MainWindow(service, settings, tmp_path / 'profiles')
    qtbot.addWidget(window)
    yield window
    window.close()
    if window.service:
        window.service.close()
        window.service = None


class RecordingAnnouncer:
    """Test double with the StatusAnnouncer surface; PySide6 cannot install an accessibility update handler."""

    def __init__(self) -> None:
        self.messages: list[tuple[str, bool]] = []

    def announce(self, text: str, assertive: bool = False) -> None:
        self.messages.append((text, assertive))

    @property
    def texts(self) -> list[str]:
        return [text for text, _ in self.messages]


@dataclass(slots=True)
class SlotTimer:
    """Wraps GUI-thread callbacks and records their wall time (budgets: median <= 16 ms, max <= 50 ms)."""
    durations: list[float] = field(default_factory=list)

    def wrap(self, function: Callable) -> Callable:
        def timed(*args, **kwargs):
            start = time.perf_counter()
            try:
                return function(*args, **kwargs)
            finally:
                self.durations.append(time.perf_counter() - start)
        return timed

    @property
    def median(self) -> float:
        return statistics.median(self.durations) if self.durations else 0.0

    @property
    def maximum(self) -> float:
        return max(self.durations, default=0.0)

    def assert_budget(self, median: float = 0.016, maximum: float = 0.05) -> None:
        assert self.durations, 'no callback was timed'
        assert self.median <= median and self.maximum <= maximum, (self.median, self.maximum, len(self.durations))


@pytest.fixture
def slot_timer() -> SlotTimer:
    return SlotTimer()


def top_level_windows(app: QCoreApplication | None = None) -> list[QWidget]:
    """Visible top-level windows; a new dock or tab must never add one (one main window)."""
    app = app or QApplication.instance()
    return [w for w in app.topLevelWidgets() if w.isWindow() and w.isVisible()]


_INTERACTIVE = (QAbstractButton, QLineEdit, QComboBox, QAbstractItemView, QTextEdit, QPlainTextEdit)


def a11y_audit(root: QWidget) -> list[str]:
    """Problems found under ``root`` (empty = clean). Static-label status lines with an empty accessible name are
    intentional (read when focused) and not flagged; interactive controls must be named, focusable, plain text."""
    problems: list[str] = []
    for widget in [root, *root.findChildren(QWidget)]:
        if widget.objectName().startswith('qt_'):
            continue  # Qt-internal children (toolbar extension button, scroll bar lines)
        label = f'{type(widget).__name__}#{widget.objectName() or "?"}'
        if isinstance(widget, _INTERACTIVE) and widget.isEnabled():
            has_text = isinstance(widget, QAbstractButton) and widget.text().strip()
            if not (widget.accessibleName().strip() or has_text):
                problems.append(f'{label}: no accessible name')
            if widget.focusPolicy() == Qt.FocusPolicy.NoFocus and not widget.isHidden():
                problems.append(f'{label}: not keyboard focusable')
        if isinstance(widget, QLabel) and widget.textFormat() not in (Qt.TextFormat.PlainText,):
            problems.append(f'{label}: label is not PlainText')
        if isinstance(widget, QTableView) and widget.verticalHeader().isVisible():
            problems.append(f'{label}: vertical header exposes row headers')
    return problems


def assert_lazy_model(factory: Callable[[int], QAbstractItemModel], sizes: tuple[int, ...] = (10_000, 100_000),
                      calls_per_cell: int = 8, slack: float = 5.0) -> dict[int, int]:
    """A model must cost what it shows, not what it holds. For each size: build it, attach a table view, paint.
    ``data()`` calls may not exceed (visible rows + 2) x columns x ``calls_per_cell`` and may not grow with the
    size; build plus first paint may take at most ``slack`` x the smallest size's time (plus 50 ms). Returns the
    ``data()`` call count per size. The model type must be a Python class (its ``data`` is wrapped)."""
    calls: dict[int, int] = {}
    baseline = None
    for size in sizes:
        start = time.perf_counter()
        model = factory(size)
        calls[size], ceiling = _paint_counting_data(model, calls_per_cell)
        elapsed = time.perf_counter() - start
        baseline = elapsed if baseline is None else baseline
        assert model.rowCount() == size, f'rowCount {model.rowCount()} != {size}'
        assert calls[size] <= ceiling, f'{calls[size]} data() calls for {size} rows (ceiling {ceiling})'
        assert elapsed <= baseline * slack + 0.05, f'{size} rows took {elapsed:.3f}s (smallest {baseline:.3f}s)'
    first = calls[sizes[0]]
    assert all(count <= first + first // 5 + 8 for count in calls.values()), f'data() calls grow with size: {calls}'
    return calls


def _paint_counting_data(model: QAbstractItemModel, calls_per_cell: int) -> tuple[int, int]:
    view = QTableView()
    view.verticalHeader().hide()
    view.resize(800, 400)
    cls = type(model)
    original = cls.data
    count = 0

    def counted(self, index, role=Qt.ItemDataRole.DisplayRole):
        nonlocal count
        count += 1
        return original(self, index, role)
    cls.data = counted
    try:
        view.setModel(model)
        view.show()
        QApplication.processEvents()
    finally:
        cls.data = original
    visible = view.viewport().height() // max(1, view.verticalHeader().defaultSectionSize()) + 2
    ceiling = visible * max(1, model.columnCount()) * calls_per_cell
    view.setModel(None)
    view.hide()
    view.deleteLater()
    return count, ceiling
