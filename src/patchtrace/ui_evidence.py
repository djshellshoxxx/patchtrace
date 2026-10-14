"""Qt adapter for the multi-engine evidence panel (C6, docs/specs/multi-engine-evidence-panel.md §5-§8).

All evidence logic lives in ``secondary.evidence_view`` and ``secondary.evidence_panel_service``; this
module only moves immutable view-models into widgets and forwards intents. Rules enforced here:

* Workers (``QThread.run``) receive immutable request objects and emit signals only. They never
  touch widgets, ``QSettings``, the clipboard, the project service or SQLite. Persisting an engine
  result happens in a GUI-thread slot (queued bound-method connection).
* Threads have NO Qt parent: destroying a running QThread (parent deleted, or garbage collection of
  an unreferenced started thread) aborts the process. A module registry keeps every started thread
  alive until ``finished``; ``EvidenceController.shutdown`` cancels and joins them.
* Sorting and filtering are owned by the table model (an index list), not a sort/filter proxy model:
  a proxy sort calls ``data()`` per comparison (measured seconds at 10k rows on PySide6 6.12).
* Every launch captures a monotonically increasing generation; results of older generations are
  dropped.
* Strings from tools, files and function names are plain text: labels use ``Qt.PlainText``, the
  detail pane is a ``QPlainTextEdit`` filled with ``setPlainText``, delegates use ``drawText``, and
  item tooltips go through the escaping registry templates.
"""
from __future__ import annotations

import dataclasses
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import (
    QAbstractTableModel,
    QByteArray,
    QModelIndex,
    QObject,
    QRect,
    QSize,
    Qt,
    QThread,
    QTimer,
    Signal,
)
from PySide6.QtGui import QColor, QFont, QFontMetrics, QGuiApplication, QKeySequence, QPalette, QPen
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDockWidget,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QStyle,
    QStyledItemDelegate,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)
from shiboken6 import isValid

from .secondary import evidence_panel_service as service_api
from .secondary.evidence_panel_service import (
    DEFAULT_TIMEOUT,
    PARALLEL_RANGE,
    TIMEOUT_RANGE,
    Cancelled,
    EvidenceRequest,
    RunRequest,
    capability_view,
    load_evidence,
    outcome_view,
)
from .secondary.evidence_view import (
    ENGINE_COLUMNS,
    ENGINE_NAMES,
    ENGINE_STATE_TEXT,
    ENGINE_UNITS,
    FOOTER,
    LOG_LINES,
    SECONDARY_ENGINES,
    STATE_TEXT,
    VERDICT_GLYPHS,
    VERDICT_MEANING,
    VERDICT_PRIORITY,
    EngineOutcomeView,
    EvidenceRow,
    EvidenceViewModel,
    calibration_display_level,
    empty_model,
    filter_rows,
    format_cell_detail,
    format_provenance_blocks,
    format_row_detail,
    sanitize_text,
    state_text,
)
from .tooltips import apply_tooltip, template

ADDRESS_ROLE = Qt.ItemDataRole.UserRole + 2
SORT_ROLE = Qt.ItemDataRole.UserRole + 1
ROW_ROLE = Qt.ItemDataRole.UserRole
FILTERS: tuple[tuple[str, frozenset[str]], ...] = (
    ('All', frozenset({'agree', 'contested', 'single-engine', 'unknown'})),
    ('Contested', frozenset({'contested'})),
    ('Unknown', frozenset({'unknown'})),
    ('Single engine', frozenset({'single-engine'})),
    ('Agree', frozenset({'agree'})),
    ('Engine-only records', frozenset({'engine-only'})),
)
# Badge fills: >= 4.5:1 against the black badge text (WCAG 1.4.3) and >= 3:1 against the black 1 px
# border and the dark theme background (WCAG 1.4.11). Contested is amber, never red. Checked by tests.
BADGE_COLORS = {'agree': '#8fd19e', 'contested': '#f0b429', 'single-engine': '#a9c1de', 'unknown': '#cfcfcf',
                'engine-only': '#c9b8e6'}
BADGE_TEXT = '#000000'
BADGE_BORDER = '#000000'
THEME_BACKGROUND = '#161b22'  # ui.DARK_STYLE QWidget background
MUTED_KINDS = frozenset({'not-run', 'no-record', 'not-comparable', 'failed'})
COLUMN_EMS = {0: 28, 1: 16}
ENGINE_EMS = 18
RUN_NOTE = ('Engines read both stored artifact copies as data; the binaries themselves are never run. '
            'Nothing is uploaded.')
_LIVE_THREADS: set[QThread] = set()  # a running QThread must never be garbage collected


def contrast_ratio(first: str, second: str) -> float:
    """WCAG relative-luminance contrast ratio of two #rrggbb colours (pure; used by tests)."""
    def luminance(color: str) -> float:
        channels = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]
    high, low = sorted((luminance(first), luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


class PlainLabel(QLabel):
    """Untrusted names and messages are always text, never Qt rich text."""

    def __init__(self, text: str = '', parent=None):
        super().__init__(text, parent)
        self.setTextFormat(Qt.TextFormat.PlainText)
        self.setOpenExternalLinks(False)
        self.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)


def _bool_setting(settings, key: str, default: bool) -> bool:
    try:
        value = settings.value(key, default)
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in ('true', '1'):
            return True
        if text in ('false', '0'):
            return False
    except Exception:  # noqa: BLE001 - corrupted settings fall back to defaults
        pass
    return default


def _int_setting(settings, key: str, default: int, low: int, high: int) -> int:
    try:
        value = int(str(settings.value(key, default)).strip())
    except Exception:  # noqa: BLE001
        return default
    return value if low <= value <= high else default


# ---- models ---------------------------------------------------------------------------------------


class EvidenceTableModel(QAbstractTableModel):
    """Rows of one view-model plus an index view (filter + sort) computed in Python.

    The filtered/sorted view is a list of indices into the immutable rows, so filtering and sorting
    10k rows is one Python pass (no per-row proxy callbacks); ``data`` reads precomputed strings and
    formats tooltip detail lazily. ``data_calls`` counts calls for the performance gate.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.vm: EvidenceViewModel | None = None
        self.rows: tuple[EvidenceRow, ...] = ()
        self.view: list[int] = []
        self.verdicts: frozenset[str] = FILTERS[0][1]
        self.search = ''
        self.hide_agree = False
        self.sort_column = -1
        self.sort_order = Qt.SortOrder.AscendingOrder
        self.stale = False
        self.data_calls = 0

    # -- content --
    def set_view_model(self, vm: EvidenceViewModel | None) -> None:
        self.beginResetModel()
        self.vm = vm
        self.rows = (vm.rows + vm.engine_only) if vm else ()
        self.stale = bool(vm and vm.state == 'stale')
        self._recompute()
        self.endResetModel()

    def set_filter(self, verdicts: frozenset[str], search: str, hide_agree: bool) -> None:
        self.beginResetModel()
        self.verdicts, self.search, self.hide_agree = verdicts, search, hide_agree
        self._recompute()
        self.endResetModel()

    def sort(self, column: int, order=Qt.SortOrder.AscendingOrder) -> None:
        """Model-owned sort: one Python sort over precomputed keys, no per-comparison data() calls.

        Persistent indexes (selection, current index) follow their rows through the reorder.
        """
        self.layoutAboutToBeChanged.emit()
        persistent = self.persistentIndexList()
        anchors = [(self.view[p.row()] if 0 <= p.row() < len(self.view) else None, p.column()) for p in persistent]
        self.sort_column, self.sort_order = column, order
        self._recompute()
        position = {row_index: n for n, row_index in enumerate(self.view)}
        moved = [self.index(position[row_index], col) if row_index in position else QModelIndex()
                 for row_index, col in anchors]
        self.changePersistentIndexList(persistent, moved)
        self.layoutChanged.emit()

    def _recompute(self) -> None:
        rows = self.rows
        # Default order first (contested, unknown, single engine, agree; then Ghidriff order). Column sorts
        # are stable on top of it, so ties keep this order in both directions.
        indices = sorted(filter_rows(rows, self.verdicts, self.search, self.hide_agree),
                         key=lambda i: (VERDICT_PRIORITY[rows[i].verdict], rows[i].order))
        column = self.sort_column
        reverse = self.sort_order == Qt.SortOrder.DescendingOrder
        if column == 0:
            indices.sort(key=lambda i: rows[i].function_label.lower(), reverse=reverse)
        elif column == 1:
            indices.sort(key=lambda i: VERDICT_PRIORITY[rows[i].verdict], reverse=reverse)
        elif column >= 2:
            cell = column - 2
            if ENGINE_COLUMNS[cell] == 'ghidriff':  # no numeric match score exists: alphabetical by raw text
                indices.sort(key=lambda i: rows[i].cells[cell].text.lower(), reverse=reverse)
            else:  # that ONE engine's native milli; rows without a value last, by name/address (flag F8)
                have = [i for i in indices if rows[i].cells[cell].sort_key is not None]
                none = [i for i in indices if rows[i].cells[cell].sort_key is None]
                have.sort(key=lambda i: rows[i].cells[cell].sort_key, reverse=reverse)
                none.sort(key=lambda i: (rows[i].function_label.lower(), rows[i].address_label))
                indices = have + none
        self.view = indices

    def row_at(self, view_row: int) -> EvidenceRow | None:
        return self.rows[self.view[view_row]] if 0 <= view_row < len(self.view) else None

    def view_row_of(self, match_id: str) -> int:
        for position, index in enumerate(self.view):
            if self.rows[index].match_id == match_id:
                return position
        return -1

    # -- Qt model API --
    def rowCount(self, parent=None):
        return 0 if parent is not None and parent.isValid() else len(self.view)

    def columnCount(self, parent=None):
        return 0 if parent is not None and parent.isValid() else 2 + len(ENGINE_COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation != Qt.Orientation.Horizontal:
            return None
        if section == 0:
            title, unit = 'Match / function', 'name, older > newer address'
        elif section == 1:
            title, unit = 'Verdict', 'function pairing only'
        else:
            engine = ENGINE_COLUMNS[section - 2]
            info = self.vm.engine(engine) if self.vm else None
            title, unit = (info.label if info else ENGINE_NAMES[engine]), ENGINE_UNITS[engine]
        if role == Qt.ItemDataRole.DisplayRole:
            return f'{title}\n{unit}'
        if role in (Qt.ItemDataRole.ToolTipRole, Qt.ItemDataRole.AccessibleTextRole):
            return f'{title} ({unit})'
        return None

    def flags(self, index):
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        self.data_calls += 1
        if not index.isValid() or index.row() >= len(self.view):
            return None
        row = self.rows[self.view[index.row()]]
        column = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return row.function_label
            if column == 1:
                return row.verdict_text
            return row.cells[column - 2].text
        if role == ADDRESS_ROLE:
            return row.address_label
        if role == ROW_ROLE:
            return row
        if role == SORT_ROLE:
            return row.cells[column - 2].sort_key if column >= 2 else None
        if role == Qt.ItemDataRole.AccessibleTextRole:
            if column == 0:
                values = ', '.join(f'{ENGINE_NAMES[c.engine]} {c.text}' for c in row.cells)
                return f'{row.function_label}, verdict {row.verdict_text}, {values}'
            if column == 1:
                return f'Verdict: {row.verdict_text}'
            return row.cells[column - 2].accessible
        if role == Qt.ItemDataRole.ToolTipRole:
            return self._tooltip(row, column)
        return None

    def _tooltip(self, row: EvidenceRow, column: int) -> str:
        engines = ', '.join(info.label for info in self.vm.engines) if self.vm else ''
        if column == 0:
            return template('evidence.row', function=row.function_label, verdict=row.verdict_text,
                            engines=engines, reason=row.address_label)
        if column == 1:
            return template('evidence.badge', verdict=row.verdict_text, meaning=VERDICT_MEANING[row.verdict],
                            reason=row.reason)
        cell = row.cells[column - 2]
        info = self.vm.engine(cell.engine) if self.vm else None
        return template('evidence.cell', engine=ENGINE_NAMES[cell.engine], value=cell.text,
                        unit=ENGINE_UNITS[cell.engine], provenance=info.label if info else cell.engine,
                        reason=format_cell_detail(cell).replace('\n', ' | '))


@dataclass(frozen=True)
class EngineRowView:
    engine: str
    label: str
    state: str
    version: str
    detail: str
    hashes: str
    hashes_full: str = ''


class EngineStatusModel(QAbstractTableModel):
    COLUMNS = ('Engine', 'State', 'Version', 'Detail', 'Input hashes')

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows: tuple[EngineRowView, ...] = ()

    def set_rows(self, rows: Sequence[EngineRowView]) -> None:
        self.beginResetModel()
        self.rows = tuple(rows)
        self.endResetModel()

    def rowCount(self, parent=None):
        return 0 if parent is not None and parent.isValid() else len(self.rows)

    def columnCount(self, parent=None):
        return 0 if parent is not None and parent.isValid() else len(self.COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.COLUMNS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        values = (row.label, row.state, row.version, row.detail, row.hashes)
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.AccessibleTextRole):
            return values[index.column()]
        if role == Qt.ItemDataRole.ToolTipRole:
            return template('evidence.engine_row', engine=row.label, state=row.state,
                            detail=row.detail, hashes=row.hashes_full or row.hashes)
        return None


# ---- delegate -------------------------------------------------------------------------------------


class EvidenceDelegate(QStyledItemDelegate):
    """Badge + two-line match painting with drawText only (no rich text, no pixmaps)."""

    def sizeHint(self, option, index):
        metrics = option.fontMetrics
        height = max(2 * metrics.lineSpacing() + 6, 28)
        width = metrics.horizontalAdvance('M') * (COLUMN_EMS.get(index.column(), ENGINE_EMS))
        return QSize(width, height)

    def paint(self, painter, option, index):
        model = index.model()
        row = index.data(ROW_ROLE)
        if row is None:
            return super().paint(painter, option, index)
        stale = getattr(model, 'stale', False)
        palette = option.palette
        painter.save()
        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        if selected:
            painter.fillRect(option.rect, palette.highlight())
        # Muted and stale text keep the theme text colour (contrast) and use italics as the extra cue.
        text_color = palette.color(QPalette.ColorRole.HighlightedText if selected else QPalette.ColorRole.Text)
        base_font = QFont(option.font)
        muted_font = QFont(option.font)
        muted_font.setItalic(True)
        painter.setFont(muted_font if stale else base_font)
        rect = option.rect.adjusted(4, 2, -4, -2)
        metrics = QFontMetrics(painter.font())
        column = index.column()
        painter.setPen(text_color)
        if column == 0:
            top = QRect(rect.left(), rect.top(), rect.width(), metrics.lineSpacing())
            painter.drawText(top, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                             metrics.elidedText(row.function_label, Qt.TextElideMode.ElideMiddle, rect.width()))
            bottom = QRect(rect.left(), rect.top() + metrics.lineSpacing(), rect.width(), metrics.lineSpacing())
            painter.drawText(bottom, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                             metrics.elidedText(row.address_label, Qt.TextElideMode.ElideMiddle, rect.width()))
        elif column == 1:
            label = f'{VERDICT_GLYPHS[row.verdict]}  {row.verdict_text}'
            width = min(rect.width(), metrics.horizontalAdvance(label) + metrics.horizontalAdvance('M'))
            badge = QRect(rect.left(), rect.center().y() - metrics.height() // 2 - 2, width, metrics.height() + 4)
            painter.setRenderHint(painter.RenderHint.Antialiasing, True)
            painter.setBrush(QColor(BADGE_COLORS[row.verdict]))
            painter.setPen(QPen(QColor(BADGE_BORDER), 1))
            painter.drawRoundedRect(badge, 4, 4)
            painter.setPen(QColor(BADGE_TEXT))
            painter.drawText(badge, Qt.AlignmentFlag.AlignCenter,
                             metrics.elidedText(label, Qt.TextElideMode.ElideRight, badge.width()))
        else:
            cell = row.cells[column - 2]
            if cell.kind == 'pairs-elsewhere':
                painter.setPen(QPen(QColor(BADGE_COLORS['contested']), 1))
                painter.drawRect(rect.adjusted(0, 0, -1, -1))
                painter.setPen(text_color)
            if cell.kind in MUTED_KINDS:
                painter.setFont(muted_font)
                metrics = QFontMetrics(muted_font)
            painter.drawText(rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                             metrics.elidedText(cell.text, Qt.TextElideMode.ElideRight, rect.width()))
        if option.state & QStyle.StateFlag.State_HasFocus:
            # Focus ring in the theme text colour: >= 3:1 against the cell background (WCAG 1.4.11).
            painter.setPen(QPen(text_color, 2))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRect(option.rect.adjusted(1, 1, -1, -1))
        painter.restore()


class EvidenceTable(QTableView):
    """Keyboard: Enter activates, Ctrl+C copies provenance, Space moves focus to the detail pane."""
    activated_row = Signal()
    copy_requested = Signal()
    detail_requested = Signal()

    def keyPressEvent(self, event):
        if event.matches(QKeySequence.StandardKey.Copy):
            self.copy_requested.emit()
            return
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self.activated_row.emit()
            return
        if event.key() == Qt.Key.Key_Space:
            self.detail_requested.emit()
            return
        super().keyPressEvent(event)


# ---- worker threads -------------------------------------------------------------------------------


def thread_alive(thread) -> bool:
    return thread is not None and isValid(thread) and thread.isRunning()


class _WorkerThread(QThread):
    """No Qt parent (a parent deleting a running QThread aborts the process); the module registry keeps
    the object alive until ``finished``, then it is deleted later (same pattern as ``ui_series``)."""

    def __init__(self):
        super().__init__()
        self.cancel = threading.Event()
        _LIVE_THREADS.add(self)
        self.finished.connect(self._release)

    def _release(self) -> None:
        _LIVE_THREADS.discard(self)
        self.deleteLater()


class EvidenceLoadThread(_WorkerThread):
    """Runs the pure ``load_evidence`` on an immutable request; emits the view-model."""
    model_ready = Signal(object, int)
    load_failed = Signal(str, int)

    def __init__(self, request: EvidenceRequest, loader: Callable = load_evidence):
        super().__init__()
        self.request = request
        self.generation = request.generation
        self.loader = loader

    def run(self):
        try:
            vm = self.loader(self.request, self.cancel.is_set)
        except Cancelled:
            return
        except Exception as exc:  # noqa: BLE001 - surfaced as E5 text
            if not self.cancel.is_set():
                self.load_failed.emit(f'PT-EVIDENCE-ASSEMBLY: unexpected {type(exc).__name__}', self.generation)
            return
        if not self.cancel.is_set():
            self.model_ready.emit(vm, self.generation)


class EngineRunThread(_WorkerThread):
    """Wraps the SPEC-28 scheduler; emits per-engine outcome views. Never persists anything."""
    engine_started = Signal(str, int)
    engine_progress = Signal(str, int, int, int)  # engine, done, total (0 = indeterminate), generation
    engine_finished = Signal(object, int)
    all_finished = Signal(object, int)
    run_failed = Signal(str, int)

    def __init__(self, request: RunRequest, execute: Callable | None = None, **execute_kw):
        super().__init__()
        self.request = request
        self.generation = request.generation
        self.execute = execute or service_api.execute_run
        self.execute_kw = execute_kw

    def run(self):
        generation = self.generation

        def on_event(event):
            if event.phase == 'started':
                self.engine_started.emit(event.engine, generation)
                self.engine_progress.emit(event.engine, 0, 0, generation)

        def on_outcome(outcome):
            self.engine_finished.emit(outcome_view(outcome), generation)

        try:
            outcomes = self.execute(self.request, self.cancel, on_event=on_event, on_outcome=on_outcome,
                                    **self.execute_kw)
        except Exception as exc:  # noqa: BLE001 - class name only; messages may carry paths or tokens
            self.run_failed.emit(f'PT-SECONDARY-RUN: {type(exc).__name__}', generation)
            return
        self.all_finished.emit(tuple(outcome_view(o) for o in outcomes), generation)


class EngineProbeThread(_WorkerThread):
    probes_ready = Signal(object, int)

    def __init__(self, generation: int, probe: Callable | None = None):
        super().__init__()
        self.generation = generation
        self.probe = probe or service_api.probe_engines

    def run(self):
        try:
            found = self.probe(self.cancel)
        except Exception:  # noqa: BLE001
            found = {}
        if not self.cancel.is_set():
            self.probes_ready.emit(found, self.generation)


# ---- panel ------------------------------------------------------------------------------------------


class EvidencePanel(QWidget):
    """Dock content. Contains no project/service/scheduler logic; emits intents only."""
    match_activated = Signal(str)
    refresh_requested = Signal()
    run_requested = Signal(object)        # tuple(engines), parallel, timeout as a dict
    cancel_requested = Signal()
    import_bindiff_requested = Signal()
    probe_requested = Signal()
    status_message = Signal(str)

    def __init__(self, settings=None, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.vm: EvidenceViewModel = empty_model('no-project')
        self.loading = False
        self.has_project = False
        self.shown_table = False
        self.show_index = False
        self.run_active = False
        self.run_blocked_reason = 'Needs an open project.'
        self.capabilities: dict[str, object] = {}
        self.engine_logs: dict[str, str] = {}
        self.engine_errors: dict[str, str] = {}
        self._selected_id: str | None = None
        self.setObjectName('evidence_panel')
        self.setAccessibleName('Engine evidence panel')
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        self.tabs = QTabWidget()
        self.tabs.setObjectName('evidence_tabs')
        self.tabs.setAccessibleName('Engine evidence views')
        self.tabs.tabBar().setObjectName('evidence.tabs')  # Qt names it qt_tabwidget_tabbar by default
        apply_tooltip(self.tabs.tabBar(), 'evidence.tabs')
        self.tabs.tabBar().setAccessibleName('Engine evidence views')
        layout.addWidget(self.tabs, 1)
        self._build_evidence_tab()
        self._build_engines_tab()
        self.footer = PlainLabel(FOOTER)
        self.footer.setObjectName('evidence_footer')
        self.footer.setWordWrap(True)
        layout.addWidget(self.footer)
        metrics = self.fontMetrics()
        self.setMinimumSize(metrics.horizontalAdvance('M') * 40, metrics.lineSpacing() * 14)
        self._restore_settings()
        self.search_timer = QTimer(self)
        self.search_timer.setSingleShot(True)
        self.search_timer.setInterval(150)
        self.search_timer.timeout.connect(self._apply_filter)
        self.elapsed_timer = QTimer(self)
        self.elapsed_timer.setInterval(1000)
        self.elapsed_timer.timeout.connect(self._tick)
        self.run_started = 0.0
        self.running_engines: list[str] = []
        self._apply()

    # -- construction --
    def _build_evidence_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(2, 2, 2, 2)
        bar = QHBoxLayout()
        bar.addWidget(PlainLabel('Filter:'))
        self.filter = QComboBox()
        self.filter.addItems([name for name, _ in FILTERS])
        apply_tooltip(self.filter, 'evidence.filter')
        self.filter.setAccessibleName('Filter by verdict')
        self.filter.currentIndexChanged.connect(self._filter_changed)
        bar.addWidget(self.filter)
        self.search = QLineEdit()
        self.search.setPlaceholderText('search name/address...')
        apply_tooltip(self.search, 'evidence.search')
        self.search.setAccessibleName('Search matches by function name or address')
        self.search.textChanged.connect(lambda _text: self.search_timer.start())
        bar.addWidget(self.search, 1)
        self.hide_agreed = QCheckBox('Hide agreed')
        apply_tooltip(self.hide_agreed, 'evidence.hide_agreed')
        self.hide_agreed.setAccessibleName('Hide matches where engines agree')
        self.hide_agreed.toggled.connect(self._filter_changed)
        bar.addWidget(self.hide_agreed)
        self.show_index_box = QCheckBox('Show triage index')
        apply_tooltip(self.show_index_box, 'evidence.show_index')
        self.show_index_box.setAccessibleName('Show uncalibrated triage index in details')
        self.show_index_box.toggled.connect(self._show_index_changed)
        bar.addWidget(self.show_index_box)
        self.copy_button = QPushButton('Copy provenance')
        apply_tooltip(self.copy_button, 'evidence.copy')
        self.copy_button.setAccessibleName('Copy provenance of selected match')
        self.copy_button.clicked.connect(self.copy_provenance)
        bar.addWidget(self.copy_button)
        self.refresh_button = QPushButton('Refresh')
        apply_tooltip(self.refresh_button, 'evidence.refresh')
        self.refresh_button.setAccessibleName('Reload engine evidence')
        self.refresh_button.clicked.connect(self.refresh_requested)
        bar.addWidget(self.refresh_button)
        layout.addLayout(bar)
        self.engines_label = PlainLabel('')
        self.engines_label.setObjectName('evidence_engines')
        self.engines_label.setWordWrap(True)
        layout.addWidget(self.engines_label)
        self.status = PlainLabel('')
        self.status.setObjectName('evidence_status')
        # Accessible name intentionally empty: QLabel.setText only emits an accessibility NameChanged event
        # when no fixed name is set, so the status text itself is the announced name (WCAG 4.1.3 intent).
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.stale_banner = PlainLabel('')
        apply_tooltip(self.stale_banner, 'evidence.stale_banner')
        self.stale_banner.setWordWrap(True)
        self.stale_banner.setAccessibleName('Stale engine evidence warning')
        layout.addWidget(self.stale_banner)
        self.partial_banner = PlainLabel('')
        self.partial_banner.setObjectName('evidence_partial_banner')
        self.partial_banner.setWordWrap(True)
        layout.addWidget(self.partial_banner)
        self.stack = QStackedWidget()
        layout.addWidget(self.stack, 1)
        # Page 0: state message (E0, E1, E2, E5, E7, E8). Every control is constructed eagerly.
        message = QWidget()
        message_layout = QVBoxLayout(message)
        self.state_label = PlainLabel('')
        self.state_label.setObjectName('evidence_state_text')
        self.state_label.setWordWrap(True)
        self.state_label.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        message_layout.addWidget(self.state_label)
        self.loading_bar = QProgressBar()
        self.loading_bar.setObjectName('evidence_loading')
        self.loading_bar.setRange(0, 0)
        self.loading_bar.setAccessibleName('Loading engine evidence')
        message_layout.addWidget(self.loading_bar)
        buttons = QHBoxLayout()
        self.retry_button = QPushButton('Retry')
        apply_tooltip(self.retry_button, 'evidence.retry')
        self.retry_button.setAccessibleName('Retry assembling engine evidence')
        self.retry_button.clicked.connect(self.refresh_requested)
        buttons.addWidget(self.retry_button)
        self.copy_error_button = QPushButton('Copy details')
        apply_tooltip(self.copy_error_button, 'evidence.copy_error')
        self.copy_error_button.setAccessibleName('Copy engine evidence error details')
        self.copy_error_button.clicked.connect(self.copy_error)
        buttons.addWidget(self.copy_error_button)
        self.open_engines_button = QPushButton('Open Engines tab')
        apply_tooltip(self.open_engines_button, 'evidence.open_engines')
        self.open_engines_button.setAccessibleName('Open the Engines tab')
        self.open_engines_button.clicked.connect(lambda: self.tabs.setCurrentIndex(1))
        buttons.addWidget(self.open_engines_button)
        buttons.addStretch(1)
        message_layout.addLayout(buttons)
        message_layout.addStretch(1)
        self.stack.addWidget(message)
        # Page 1: table + detail.
        split = QSplitter(Qt.Orientation.Vertical)
        split.setObjectName('evidence_split')
        self.model = EvidenceTableModel(self)
        self.table = EvidenceTable()
        self.table.setModel(self.model)
        apply_tooltip(self.table, 'evidence.table')
        self.table.setAccessibleName('Per-match engine evidence table')
        self.table.setItemDelegate(EvidenceDelegate(self.table))
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(False)
        self.table.verticalHeader().setVisible(False)  # hidden: no per-row RowHeader accessibles
        self.table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        self.table.setWordWrap(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(False)
        header.setSectionsClickable(True)
        header.setSortIndicatorShown(True)
        header.sectionClicked.connect(self._header_clicked)
        self.table.selectionModel().selectionChanged.connect(self._selection_changed)
        self.table.doubleClicked.connect(lambda _index: self.activate_current())
        self.table.activated_row.connect(self.activate_current)
        self.table.copy_requested.connect(self.copy_provenance)
        self.table.detail_requested.connect(lambda: self.detail.setFocus())
        split.addWidget(self.table)
        lower = QWidget()
        lower_layout = QVBoxLayout(lower)
        lower_layout.setContentsMargins(0, 0, 0, 0)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        apply_tooltip(self.detail, 'evidence.detail')
        self.detail.setAccessibleName('Selected match engine evidence details')
        lower_layout.addWidget(self.detail, 1)
        actions = QHBoxLayout()
        self.goto_button = QPushButton('Go to match in navigator')
        apply_tooltip(self.goto_button, 'evidence.goto')
        self.goto_button.setAccessibleName('Go to selected match in navigator')
        self.goto_button.clicked.connect(self.activate_current)
        actions.addWidget(self.goto_button)
        actions.addStretch(1)
        lower_layout.addLayout(actions)
        split.addWidget(lower)
        self.stack.addWidget(split)
        self._apply_metrics()
        self.tabs.addTab(page, 'Evidence')

    def _build_engines_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(2, 2, 2, 2)
        self.engine_model = EngineStatusModel(self)
        self.engine_table = QTableView()
        self.engine_table.setModel(self.engine_model)
        apply_tooltip(self.engine_table, 'evidence.engine_table')
        self.engine_table.setAccessibleName('Engine run status table')
        self.engine_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.engine_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.engine_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.engine_table.verticalHeader().setVisible(False)
        self.engine_table.horizontalHeader().setStretchLastSection(True)
        self.engine_table.selectionModel().selectionChanged.connect(lambda *_: self._show_engine_log())
        layout.addWidget(self.engine_table, 1)
        options = QHBoxLayout()
        self.engine_checks: dict[str, QCheckBox] = {}
        for engine in SECONDARY_ENGINES:
            box = QCheckBox(ENGINE_NAMES[engine])
            apply_tooltip(box, 'evidence.engine_check')
            box.setAccessibleName(f'Include {ENGINE_NAMES[engine]} in the next run')
            box.toggled.connect(lambda _checked: self._update_run_controls())
            self.engine_checks[engine] = box
            options.addWidget(box)
        options.addWidget(PlainLabel('Parallel engines:'))
        self.parallel = QSpinBox()
        self.parallel.setRange(*PARALLEL_RANGE)
        self.parallel.setValue(1)
        apply_tooltip(self.parallel, 'evidence.parallel')
        self.parallel.setAccessibleName('Parallel engines')
        options.addWidget(self.parallel)
        options.addWidget(PlainLabel('Timeout (s):'))
        self.timeout = QSpinBox()
        self.timeout.setRange(*TIMEOUT_RANGE)
        self.timeout.setValue(DEFAULT_TIMEOUT)
        apply_tooltip(self.timeout, 'evidence.timeout')
        self.timeout.setAccessibleName('Timeout per engine in seconds')
        options.addWidget(self.timeout)
        options.addStretch(1)
        layout.addLayout(options)
        controls = QHBoxLayout()
        self.run_button = QPushButton('Run selected engines')
        apply_tooltip(self.run_button, 'evidence.run')
        self.run_button.setAccessibleName('Run selected engines')
        self.run_button.clicked.connect(self._request_run)
        controls.addWidget(self.run_button)
        self.cancel_button = QPushButton('Cancel')
        apply_tooltip(self.cancel_button, 'evidence.cancel')
        self.cancel_button.setAccessibleName('Cancel running engines')
        self.cancel_button.clicked.connect(self.cancel_requested)
        controls.addWidget(self.cancel_button)
        self.probe_button = QPushButton('Probe engines')
        apply_tooltip(self.probe_button, 'evidence.probe')
        self.probe_button.setAccessibleName('Probe installed engines')
        self.probe_button.clicked.connect(self.probe_requested)
        controls.addWidget(self.probe_button)
        self.import_button = QPushButton('Import .BinDiff...')
        apply_tooltip(self.import_button, 'evidence.import_bindiff')
        self.import_button.setAccessibleName('Import a BinDiff result file')
        self.import_button.clicked.connect(self.import_bindiff_requested)
        controls.addWidget(self.import_button)
        self.run_progress = QProgressBar()
        self.run_progress.setObjectName('evidence_run_progress')
        self.run_progress.setRange(0, 0)
        self.run_progress.setAccessibleName('Engine run progress')
        self.run_progress.setVisible(False)
        controls.addWidget(self.run_progress, 1)
        layout.addLayout(controls)
        self.run_status = PlainLabel('')
        self.run_status.setObjectName('evidence_run_status')
        self.run_status.setWordWrap(True)
        layout.addWidget(self.run_status)
        self.preview = PlainLabel('')
        self.preview.setObjectName('evidence_run_preview')
        self.preview.setWordWrap(True)
        layout.addWidget(self.preview)
        self.engine_log = QPlainTextEdit()
        self.engine_log.setReadOnly(True)
        self.engine_log.setMaximumBlockCount(LOG_LINES)
        apply_tooltip(self.engine_log, 'evidence.engine_log')
        self.engine_log.setAccessibleName('Selected engine output')
        layout.addWidget(self.engine_log, 1)
        log_actions = QHBoxLayout()
        self.copy_details_button = QPushButton('Copy details')
        apply_tooltip(self.copy_details_button, 'evidence.copy_details')
        self.copy_details_button.setAccessibleName('Copy selected engine failure details')
        self.copy_details_button.clicked.connect(self.copy_engine_details)
        log_actions.addWidget(self.copy_details_button)
        log_actions.addStretch(1)
        layout.addLayout(log_actions)
        note = PlainLabel(RUN_NOTE)
        note.setObjectName('evidence_run_note')
        note.setWordWrap(True)
        layout.addWidget(note)
        self.tabs.addTab(page, 'Engines')

    def _apply_metrics(self):
        """Column widths and row height from font metrics only (high-DPI rule §1.7)."""
        metrics = self.table.fontMetrics()
        em = metrics.horizontalAdvance('M')
        for column in range(self.model.columnCount()):
            self.table.setColumnWidth(column, em * COLUMN_EMS.get(column, ENGINE_EMS))
        self.table.verticalHeader().setDefaultSectionSize(max(2 * metrics.lineSpacing() + 6, 28))
        self.table.horizontalHeader().setMinimumHeight(2 * metrics.lineSpacing() + 6)

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() == event.Type.FontChange and hasattr(self, 'table'):
            self._apply_metrics()

    # -- settings --
    def _restore_settings(self):
        if self.settings is None:
            return
        self.filter.blockSignals(True)
        self.filter.setCurrentIndex(_int_setting(self.settings, 'evidence/filter', 0, 0, len(FILTERS) - 1))
        self.filter.blockSignals(False)
        self.hide_agreed.blockSignals(True)
        self.hide_agreed.setChecked(_bool_setting(self.settings, 'evidence/hide_agreed', False))
        self.hide_agreed.blockSignals(False)
        self.show_index_box.blockSignals(True)
        self.show_index = _bool_setting(self.settings, 'evidence/show_index', False)
        self.show_index_box.setChecked(self.show_index)
        self.show_index_box.blockSignals(False)
        self.model.set_filter(FILTERS[self.filter.currentIndex()][1], '', self.hide_agreed.isChecked())

    def _save(self, key, value):
        if self.settings is None:
            return
        try:
            self.settings.setValue(key, value)
        except Exception:  # noqa: BLE001
            pass

    # -- public API --
    def set_project(self, present: bool) -> None:
        self.has_project = present
        if not present:
            self.vm = empty_model('no-project')
            self.shown_table = False
            self.loading = False
            self.model.set_view_model(None)
        self._apply()

    def set_loading(self, loading: bool) -> None:
        self.loading = loading
        self._apply()

    def set_view_model(self, vm: EvidenceViewModel) -> None:
        self.vm = vm
        self.loading = False
        self.has_project = vm.state != 'no-project'
        keep = self._selected_id
        self.model.set_view_model(vm if vm.rows or vm.engine_only else None)
        self.shown_table = bool(vm.rows or vm.engine_only)
        self._apply()
        if keep:
            self.select_match(keep)

    def set_failed(self, message: str) -> None:
        vm = self.vm
        self.set_view_model(dataclasses.replace(vm, state='failed', error=sanitize_text(message, 400), rows=(),
                                                engine_only=()))

    def set_stale(self, reason: str) -> None:
        if self.vm.state in ('no-project', 'failed'):
            return
        self.vm = dataclasses.replace(self.vm, state='stale', stale_reason=reason)
        self.model.stale = True
        self.model.vm = self.vm
        self.table.viewport().update()
        self._apply()

    def select_match(self, match_id: str) -> bool:
        position = self.model.view_row_of(match_id)
        if position < 0:
            return False
        self.table.selectRow(position)
        self.table.scrollTo(self.model.index(position, 0))
        return True

    def selected_rows(self) -> list[EvidenceRow]:
        rows = sorted({index.row() for index in self.table.selectionModel().selectedRows()})
        return [r for r in (self.model.row_at(i) for i in rows) if r is not None]

    def current_row(self) -> EvidenceRow | None:
        index = self.table.currentIndex()
        if index.isValid() and self.table.selectionModel().isRowSelected(index.row(), QModelIndex()):
            return self.model.row_at(index.row())
        rows = self.selected_rows()
        return rows[0] if rows else None

    # -- evidence tab behaviour --
    def _filter_changed(self, *_):
        self._save('evidence/filter', self.filter.currentIndex())
        self._save('evidence/hide_agreed', self.hide_agreed.isChecked())
        self._apply_filter()

    def _apply_filter(self):
        keep = self._selected_id
        self.model.set_filter(FILTERS[self.filter.currentIndex()][1], self.search.text(),
                              self.hide_agreed.isChecked())
        if keep and not self.select_match(keep):
            self._render_detail()
        self._update_status()

    def _show_index_changed(self, checked):
        self.show_index = bool(checked)
        self._save('evidence/show_index', self.show_index)
        self._render_detail()

    def _header_clicked(self, section):
        header = self.table.horizontalHeader()
        if self.model.sort_column == section:
            order = (Qt.SortOrder.DescendingOrder if self.model.sort_order == Qt.SortOrder.AscendingOrder
                     else Qt.SortOrder.AscendingOrder)
        else:
            order = Qt.SortOrder.AscendingOrder if section < 2 else Qt.SortOrder.DescendingOrder
        keep = self._selected_id
        self.model.sort(section, order)
        header.setSortIndicator(section, order)
        if keep:
            self.select_match(keep)

    def _selection_changed(self, *_):
        row = self.current_row()
        if row is not None:
            self._selected_id = row.match_id
        self._render_detail()
        self._update_buttons()

    def _render_detail(self):
        row = self.current_row()
        if row is None:
            self.detail.setPlainText('Select a match to see per-engine native values.')
        else:
            self.detail.setPlainText(format_row_detail(self.vm, row, self.show_index))

    def activate_current(self):
        row = self.current_row()
        if row is None or self.vm.state == 'stale' or row.verdict == 'engine-only':
            return
        self.match_activated.emit(row.match_id)

    def copy_provenance(self):
        rows = self.selected_rows()
        if not rows:
            return
        QGuiApplication.clipboard().setText(format_provenance_blocks(self.vm, rows, self.show_index))
        self.status_message.emit(f'Copied provenance for {min(len(rows), 200)} match(es)')

    def copy_error(self):
        if self.vm.error:
            QGuiApplication.clipboard().setText(
                f'PatchTrace engine evidence error\nProject: {self.vm.project_id}\n{self.vm.error}')

    # -- engines tab behaviour --
    def set_engine_rows(self, rows: Sequence[EngineRowView]) -> None:
        self.engine_model.set_rows(rows)
        self._show_engine_log()

    def set_capabilities(self, capabilities: dict) -> None:
        self.capabilities = dict(capabilities)
        self._update_run_controls()

    def set_run_blocked(self, reason: str | None) -> None:
        self.run_blocked_reason = reason or ''
        self._update_run_controls()

    def set_run_active(self, active: bool, engines: Sequence[str] = ()) -> None:
        self.run_active = active
        self.running_engines = list(engines)
        self.run_progress.setVisible(active)
        if active:
            self.run_started = time.monotonic()
            self.elapsed_timer.start()
            self._tick()
        else:
            self.elapsed_timer.stop()
        self._update_run_controls()

    def set_run_status(self, text: str) -> None:
        self.run_status.setText(sanitize_text(text, 400))  # empty accessible name: QLabel emits NameChanged

    def set_engine_log(self, engine: str, text: str, error: str = '') -> None:
        self.engine_logs[engine] = text
        if error:
            self.engine_errors[engine] = error
        self._show_engine_log()

    def _selected_engine(self) -> str | None:
        rows = self.engine_table.selectionModel().selectedRows()
        if rows:
            return self.engine_model.rows[rows[0].row()].engine
        return next(iter(self.engine_logs), None)

    def _show_engine_log(self):
        engine = self._selected_engine()
        self.engine_log.setPlainText(self.engine_logs.get(engine, '') if engine else '')
        self.copy_details_button.setEnabled(bool(engine and self.engine_errors.get(engine)))

    def copy_engine_details(self):
        engine = self._selected_engine()
        if engine and self.engine_errors.get(engine):
            QGuiApplication.clipboard().setText(self.engine_errors[engine] + '\n' + self.engine_logs.get(engine, ''))

    def _tick(self):
        if not self.run_active:
            return
        seconds = int(time.monotonic() - self.run_started)
        names = ', '.join(ENGINE_NAMES.get(e, e) for e in self.running_engines) or 'engines'
        self.set_run_status(f'{names} running {seconds // 60}:{seconds % 60:02d} (indeterminate)')

    def selected_engines(self) -> tuple[str, ...]:
        return tuple(e for e, box in self.engine_checks.items() if box.isChecked() and box.isEnabled())

    def _request_run(self):
        engines = self.selected_engines()
        if engines and self.run_button.isEnabled():
            self.run_requested.emit({'engines': engines, 'max_parallel': self.parallel.value(),
                                     'timeout_s': self.timeout.value()})

    def set_preview(self, text: str) -> None:
        self.preview.setText(text)

    def _update_run_controls(self):
        for engine, box in self.engine_checks.items():
            cap = self.capabilities.get(engine)
            supported = bool(cap is not None and getattr(cap, 'supported', False))
            box.setEnabled(supported and not self.run_active)
            if not supported and box.isChecked():
                box.setChecked(False)
        idle = not self.run_active
        reason = self.run_blocked_reason
        can_run = idle and not reason and bool(self.selected_engines())
        self.run_button.setEnabled(can_run)
        self.cancel_button.setEnabled(self.run_active)
        self.parallel.setEnabled(idle)
        self.timeout.setEnabled(idle)
        self.probe_button.setEnabled(idle and self.has_project)
        self.import_button.setEnabled(idle and self.has_project and not reason)

    # -- state application --
    def _update_status(self):
        vm = self.vm
        if self.loading and self.shown_table:
            text = STATE_TEXT['refreshing']
        elif self.loading:
            text = STATE_TEXT['loading']
        elif vm.state in ('ready', 'partial', 'stale') and (vm.rows or vm.engine_only):
            c = vm.counts
            text = (f'Summary: {len(vm.rows):,} matches - {c.get("agree", 0):,} agree - '
                    f'{c.get("contested", 0):,} contested - {c.get("single-engine", 0):,} single-engine - '
                    f'{c.get("unknown", 0):,} unknown; showing {self.model.rowCount():,}')
        else:
            text = state_text(vm)
        if text != self.status.text():
            self.status.setText(text)  # accessible name left empty, so QLabel itself emits NameChanged

    def _update_buttons(self):
        has_selection = self.current_row() is not None
        self.copy_button.setEnabled(has_selection)
        self.goto_button.setEnabled(has_selection and self.vm.state != 'stale')

    def _apply(self):
        vm = self.vm
        state = 'no-project' if not self.has_project else vm.state
        table_state = state in ('ready', 'partial', 'stale') and self.shown_table
        loading_first = self.loading and not self.shown_table and self.has_project
        self.stack.setCurrentIndex(1 if table_state and not loading_first else 0)
        if loading_first:
            self.state_label.setText(STATE_TEXT['loading'])
        elif not table_state:
            self.state_label.setText(state_text(vm) if self.has_project else STATE_TEXT['no-project'])
        self.loading_bar.setVisible(loading_first)
        self.retry_button.setVisible(state == 'failed')
        self.copy_error_button.setVisible(state == 'failed')
        self.open_engines_button.setVisible(state in ('no-engines', 'unsupported'))
        self.open_engines_button.setEnabled(self.has_project)
        self.stale_banner.setVisible(state == 'stale')
        self.stale_banner.setText(state_text(vm) if state == 'stale' else '')
        self.partial_banner.setVisible(state == 'partial')
        self.partial_banner.setText(state_text(vm) if state == 'partial' else '')
        enabled = self.has_project and not loading_first
        for widget in (self.filter, self.search, self.hide_agreed, self.show_index_box, self.table, self.detail):
            widget.setEnabled(enabled and table_state)
        self.refresh_button.setEnabled(self.has_project and not self.loading)
        engines = ' | '.join(f'{info.label} ({ENGINE_STATE_TEXT[info.state]})' for info in vm.engines)
        self.engines_label.setText(f'Engines: {engines}' if engines else '')
        self.engines_label.setVisible(bool(engines))
        if vm.warnings:
            self.engines_label.setText(self.engines_label.text() + '\n' + '\n'.join(vm.warnings))
        self._update_status()
        self._render_detail()
        self._update_buttons()
        self._update_run_controls()


class EvidenceDock(QDockWidget):
    def __init__(self, panel: EvidencePanel, parent=None):
        super().__init__('Engine evidence', parent)
        self.setObjectName('evidence.dock')
        self.setAccessibleName('Engine evidence panel')
        apply_tooltip(self, 'evidence.dock')
        self.setFeatures(QDockWidget.DockWidgetFeature.DockWidgetClosable
                         | QDockWidget.DockWidgetFeature.DockWidgetMovable
                         | QDockWidget.DockWidgetFeature.DockWidgetFloatable)
        self.setWidget(panel)
        self.panel = panel


def create_evidence_dock(parent=None, settings=None) -> EvidenceDock:
    return EvidenceDock(EvidencePanel(settings), parent)


# ---- controller (MainWindow seam) -----------------------------------------------------------------


class WindowPort:
    """Narrow read/write access to the MainWindow's project (spec §8 ProjectPort). GUI thread only."""

    def __init__(self, window):
        self.window = window

    @property
    def service(self):
        return getattr(self.window, 'service', None)

    @property
    def project(self):
        service = self.service
        return service.project if service else None

    def busy(self) -> bool:
        return getattr(self.window, 'worker', None) is not None

    def key(self):
        project = self.project
        if project is None:
            return None
        run = service_api.latest_run(project)
        sides = {a.side: a.sha256 for a in project.artifacts}
        return (str(self.service.root), project.id, project.revision, run.id if run else None,
                sides.get('older'), sides.get('newer'))

    def identity(self):
        key = self.key()
        return None if key is None else key[:2]

    def artifact_paths(self) -> tuple[Path, Path, str, str]:
        project = self.project
        sides = {a.side: a for a in project.artifacts}
        root = Path(self.service.root)
        return ((root / sides['older'].relative_path).resolve(), (root / sides['newer'].relative_path).resolve(),
                sides['older'].sha256, sides['newer'].sha256)

    def select_match(self, match_id: str) -> bool:
        navigator = getattr(self.window, 'navigator', None)
        if navigator is None:
            return False
        for row in range(navigator.count()):
            item = navigator.item(row)
            if item.data(Qt.ItemDataRole.UserRole) == match_id:
                navigator.setCurrentItem(item)
                navigator.scrollToItem(item)
                return True
        return False


class EvidenceController(QObject):
    """Owns the dock, threads and the generation counter; reads the project through ``WindowPort``."""

    def __init__(self, window, *, loader: Callable = load_evidence, run_execute: Callable | None = None,
                 run_kw: dict | None = None, probe: Callable | None = None, auto_probe: bool = True):
        super().__init__(window)
        self.window = window
        self.port = WindowPort(window)
        self.settings = getattr(window, 'settings', None)
        self.loader = loader
        self.run_execute = run_execute
        self.run_kw = run_kw or {}
        self.probe = probe
        self.auto_probe = auto_probe
        self.generation = 0
        self.run_generation = 0
        # Threads are referenced here (and in the module registry) but never parented; their cancel
        # events are kept separately so cancelling never touches a possibly deleted QThread wrapper.
        self.load_thread: EvidenceLoadThread | None = None
        self.load_cancel: threading.Event | None = None
        self.run_thread: EngineRunThread | None = None
        self.run_cancel: threading.Event | None = None
        self.probe_thread: EngineProbeThread | None = None
        self.threads: list[tuple[QThread, threading.Event]] = []
        self.run_request: RunRequest | None = None
        self.loaded_key = None
        self.dirty = True
        self.probed = False
        self._following = False
        self.outcomes: dict[str, EngineOutcomeView] = {}
        self.capabilities: dict[str, object] = {}
        self.engine_states: dict[str, str] = {}
        self.dock = create_evidence_dock(window, self.settings)
        self.panel = self.dock.panel
        window.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.dock)
        self.dock.hide()
        self._restore_geometry()
        self.action = self.dock.toggleViewAction()
        self.action.setText('Engine evidence')
        apply_tooltip(self.action, 'evidence.action')
        self.action.setShortcut(QKeySequence('Ctrl+Shift+E'))
        self._install_menu()
        queued = Qt.ConnectionType.QueuedConnection
        self.dock.visibilityChanged.connect(self._visibility_changed, queued)
        self.panel.refresh_requested.connect(self.reload)
        self.panel.match_activated.connect(self._activate)
        self.panel.run_requested.connect(self.start_run)
        self.panel.cancel_requested.connect(self.cancel_run)
        self.panel.probe_requested.connect(self.start_probe)
        self.panel.import_bindiff_requested.connect(self.import_bindiff)
        self.panel.status_message.connect(self._status)
        self.project_changed()

    # -- setup --
    def _install_menu(self):
        bar = self.window.menuBar() if hasattr(self.window, 'menuBar') else None
        if bar is None:
            return
        for action in bar.actions():
            if action.menu() is not None and action.text() == 'Analysis':
                action.menu().addAction(self.action)
                return

    def _restore_geometry(self):
        if self.settings is None:
            return
        try:
            value = self.settings.value('evidence/geometry')
            if isinstance(value, (QByteArray, bytes)) and value:
                self.dock.restoreGeometry(QByteArray(value))
        except Exception:  # noqa: BLE001 - invalid geometry is ignored
            pass

    def _status(self, text: str) -> None:
        bar = self.window.statusBar() if hasattr(self.window, 'statusBar') else None
        if bar is not None:
            bar.showMessage(text, 5000)

    # -- lifecycle hooks (called from MainWindow) --
    def project_changed(self) -> None:
        key = self.port.key()
        if key is None:
            self._invalidate()
            self.loaded_key = None
            self.outcomes.clear()
            self.panel.set_project(False)
            self._refresh_engine_rows()
            self.update_controls()
            return
        if self.loaded_key is not None and key[:2] != self.loaded_key[:2]:
            self.cancel_run()  # project switched: never store a result into the wrong project
            self.run_generation += 1  # and drop any outcome still queued for the old project
            self.outcomes.clear()
            self.probed = False
        self.panel.has_project = True
        if key != self.loaded_key:
            self.dirty = True
            if self.dock.isVisible():
                self.reload()
            elif self.loaded_key is not None and key[:2] != self.loaded_key[:2]:
                self.panel.set_project(True)
        self.update_controls()

    matches_changed = project_changed

    def update_controls(self) -> None:
        project = self.port.project
        reason = None
        if project is None:
            reason = 'Needs an open project.'
        elif self.port.busy():
            reason = 'Disabled while a Ghidriff analysis job is running.'
        elif service_api.latest_run(project) is None:
            reason = 'Needs a completed Ghidriff run.'
        self.panel.set_run_blocked(reason)
        if project is not None and not self.panel.run_active:
            try:
                older, newer, osha, nsha = self.port.artifact_paths()
                names = ', '.join(f'{ENGINE_NAMES[e]} {getattr(self.capabilities.get(e), "version", "") or ""}'
                                  .strip() for e in self.panel.selected_engines()) or 'no engine selected'
                self.panel.set_preview(f'Will run: {names} on older/newer artifact copies (SHA-256 {osha[:12]}.., '
                                       f'{nsha[:12]}..). Timeout {self.panel.timeout.value()} s.')
            except Exception:  # noqa: BLE001
                self.panel.set_preview('')

    def follow_match(self, match) -> None:
        """Navigator selection -> panel highlight (no activation loop)."""
        if match is None or self._following or not self.dock.isVisible():
            return
        self.panel.select_match(match.id)

    def shutdown(self) -> None:
        """Cancel and join every worker: destroying a running QThread aborts the process."""
        if self.settings is not None:
            try:
                self.settings.setValue('evidence/geometry', self.dock.saveGeometry())
            except Exception:  # noqa: BLE001
                pass
        self._invalidate()
        self.run_generation += 1
        for _thread, cancel in self.threads:
            cancel.set()
        for thread, _cancel in self.threads:
            if isValid(thread):
                thread.wait()  # engine children are killed by the scheduler's cancel; no forced thread kill
        self.threads = []
        self.load_thread = self.run_thread = self.probe_thread = None
        self.run_cancel = self.load_cancel = None
        if isValid(self.panel):
            self.panel.elapsed_timer.stop()

    # -- loading --
    def _invalidate(self) -> None:
        self.generation += 1
        if self.load_cancel is not None:
            self.load_cancel.set()
        self.load_thread = self.load_cancel = None

    def _register(self, thread: QThread) -> None:
        self._reap()
        self.threads.append((thread, thread.cancel))

    def _visibility_changed(self, visible: bool) -> None:
        if not visible:
            return
        if self.dirty and self.port.project is not None:
            self.reload()
        if self.auto_probe and not self.probed and self.port.project is not None:
            self.start_probe()

    def reload(self) -> None:
        if self.port.project is None:
            self.panel.set_project(False)
            return
        self._invalidate()
        generation = self.generation
        outcomes = tuple(self.outcomes.values()) + tuple(
            view for engine, cap in self.capabilities.items() if engine not in self.outcomes
            for view in (capability_view(cap),) if view is not None)
        try:
            request = service_api.build_request(self.port.service, generation=generation, outcomes=outcomes,
                                                calibration_level=calibration_display_level())
        except Exception as exc:  # noqa: BLE001 - unreadable store rows become E5, never a crash
            self.panel.set_view_model(empty_model('failed', project_id=self.port.project.id,
                                                  error=sanitize_text(f'PT-EVIDENCE-ASSEMBLY: {exc}', 400)))
            return
        self.loaded_key = self.port.key()
        self.dirty = False
        thread = EvidenceLoadThread(request, self.loader)
        queued = Qt.ConnectionType.QueuedConnection
        thread.model_ready.connect(self._model_ready, queued)
        thread.load_failed.connect(self._load_failed, queued)
        thread.finished.connect(self._reap, queued)
        self._register(thread)
        self.load_thread, self.load_cancel = thread, thread.cancel
        self.panel.set_project(True)
        self.panel.set_loading(True)
        thread.start()

    def _model_ready(self, vm: EvidenceViewModel, generation: int) -> None:
        if generation != self.generation:
            return  # stale generation: dropped
        self.load_thread = self.load_cancel = None
        self.panel.set_view_model(vm)
        self._refresh_engine_rows()
        self.update_controls()

    def _load_failed(self, message: str, generation: int) -> None:
        if generation != self.generation:
            return
        self.load_thread = self.load_cancel = None
        self.panel.set_failed(message)

    def _reap(self) -> None:
        """Forget finished threads; their deletion is owned by the registry (``_WorkerThread._release``)."""
        self.threads = [(t, c) for t, c in self.threads if thread_alive(t)]

    def _activate(self, match_id: str) -> None:
        self._following = True
        try:
            if not self.port.select_match(match_id):
                self._status('That match is hidden by the navigator filters.')
        finally:
            self._following = False

    # -- probes --
    def start_probe(self) -> None:
        if thread_alive(self.probe_thread):
            return
        self.probed = True
        thread = EngineProbeThread(self.generation, self.probe)
        thread.probes_ready.connect(self._probes_ready, Qt.ConnectionType.QueuedConnection)
        thread.finished.connect(self._reap, Qt.ConnectionType.QueuedConnection)
        self._register(thread)
        self.probe_thread = thread
        self.panel.set_run_status('Probing engines (no binary is touched)...')
        thread.start()

    def _probes_ready(self, found: dict, _generation: int) -> None:
        self.probe_thread = None
        self.capabilities = dict(found)
        self.panel.set_capabilities(self.capabilities)
        self.panel.set_run_status('Engine probe finished.')
        self._refresh_engine_rows()
        self.update_controls()
        if self.panel.vm.state in ('no-engines', 'unsupported') and self.port.project is not None:
            self.reload()

    # -- runs --
    def start_run(self, options: dict) -> None:
        if self.run_thread is not None or self.port.project is None or self.port.busy():
            return
        project = self.port.project
        run = service_api.latest_run(project)
        try:
            older, newer, osha, nsha = self.port.artifact_paths()
            cache = service_api.run_cache(self.port.service, osha, nsha)
            self.run_generation += 1
            request = RunRequest(project.id, project.revision, self.run_generation, tuple(options['engines']),
                                 int(options['max_parallel']), int(options['timeout_s']), older, newer, osha, nsha,
                                 run.id if run else None, dict(self.capabilities), cache)
        except Exception as exc:  # noqa: BLE001
            self.panel.set_run_status(sanitize_text(f'Engine run not started: {exc}', 400))
            return
        self.run_request = request
        thread = EngineRunThread(request, self.run_execute, **self.run_kw)
        queued = Qt.ConnectionType.QueuedConnection
        thread.engine_started.connect(self._engine_started, queued)
        thread.engine_finished.connect(self._engine_finished, queued)
        thread.all_finished.connect(self._all_finished, queued)
        thread.run_failed.connect(self._run_failed, queued)
        thread.finished.connect(self._run_thread_finished, queued)
        self._register(thread)
        self.run_thread, self.run_cancel = thread, thread.cancel
        for engine in request.engines:
            self.engine_states[engine] = 'queued'
        self.panel.set_run_active(True, request.engines)
        self._refresh_engine_rows()
        thread.start()

    def cancel_run(self) -> None:
        if self.run_cancel is not None and self.run_thread is not None:
            self.run_cancel.set()
            self.panel.set_run_status('Cancelling engines...')

    def _engine_started(self, engine: str, generation: int) -> None:
        if generation != self.run_generation:
            return
        self.engine_states[engine] = 'running'
        self._refresh_engine_rows()

    def _engine_finished(self, view: EngineOutcomeView, generation: int) -> None:
        """GUI thread: the only place an engine result is persisted (guard checked first)."""
        if generation != self.run_generation or self.run_request is None:
            return
        self.engine_states.pop(view.engine, None)
        message = ''
        if view.status in ('ok', 'cached'):
            try:
                stale = service_api.persist_outcome(self.port.service, self.run_request, view)
            except Exception as exc:  # noqa: BLE001
                stale = f'could not store the result: {type(exc).__name__}'
            if stale:
                message = f'{ENGINE_NAMES.get(view.engine, view.engine)} result discarded: {stale}.'
                self.panel.set_stale(stale)
        else:
            try:  # failed/cancelled attempts keep their run record; no match set is stored
                service_api.persist_outcome(self.port.service, self.run_request, dataclasses.replace(
                    view, match_set=None))
            except Exception:  # noqa: BLE001
                pass
            first = f'{view.error_code or view.status}: {view.message}'.strip(': ')
            message = f'{ENGINE_NAMES.get(view.engine, view.engine)} {view.status} ({sanitize_text(first, 200)}).'
            kept = [ENGINE_NAMES.get(e, e) for e, o in self.outcomes.items() if o.status in ('ok', 'cached')
                    and e != view.engine]
            if kept:
                message += f' {", ".join(kept)} result kept.'
        self.outcomes[view.engine] = dataclasses.replace(view, match_set=None, run=None)
        error = ''
        if view.status not in ('ok', 'cached'):
            error = '\n'.join([f'Engine: {ENGINE_NAMES.get(view.engine, view.engine)}',
                               f'Status: {view.status}', f'Error code: {view.error_code or "-"}',
                               f'Message: {view.message or "-"}', f'Version: {view.version or "-"}',
                               f'Older SHA-256: {self.run_request.older_sha256}',
                               f'Newer SHA-256: {self.run_request.newer_sha256}',
                               f'Started: {view.started_utc or "-"}', f'Duration: {view.duration_ms} ms'])
        self.panel.set_engine_log(view.engine, view.stderr_tail, error)
        if message:
            self.panel.set_run_status(message)
        self._refresh_engine_rows()

    def _all_finished(self, views: tuple, generation: int) -> None:
        if generation != self.run_generation:
            return
        statuses = ', '.join(f'{ENGINE_NAMES.get(v.engine, v.engine)} {v.status}' for v in views)
        self.panel.set_run_status(f'Engine run finished: {statuses}.')

    def _run_failed(self, message: str, generation: int) -> None:
        if generation != self.run_generation:
            return
        self.panel.set_run_status(f'Engine run failed: {sanitize_text(message, 200)}')

    def _run_thread_finished(self) -> None:
        thread = self.run_thread
        if thread is not None and not thread_alive(thread):
            self.run_thread = self.run_cancel = None
            self.run_request = None
            self.engine_states.clear()
            self.panel.set_run_active(False)
            self._refresh_engine_rows()
            self.update_controls()
            if self.port.project is not None:
                self.reload()
        self._reap()

    # -- import --
    def import_bindiff(self, path: str | None = None) -> None:
        if self.port.project is None or self.port.busy():
            return
        if path is None:
            path, _ = QFileDialog.getOpenFileName(self.window, 'Import BinDiff result', '',
                                                  'BinDiff results (*.BinDiff);;All files (*)')
        if not path:
            return
        from .enrichment.storage import EnrichmentStore, Guard
        from .secondary.bindiff import import_bindiff
        from .secondary.cli_run import record_import
        project = self.port.project
        run = service_api.latest_run(project)
        if run is None:
            self.panel.set_run_status('Import needs a completed Ghidriff run.')
            return
        sides = {a.side: a.sha256 for a in project.artifacts}
        try:
            match_set = import_bindiff(Path(path), sides['older'], sides['newer'])
            guard = Guard(project.id, run.id, run.raw_sha256, match_set.file_sha256)
            record_import(EnrichmentStore(self.port.service.store), guard, project.revision, match_set)
        except Exception as exc:  # noqa: BLE001 - shown as plain text
            self.panel.set_run_status(sanitize_text(f'BinDiff import failed: {exc}', 400))
            return
        self.outcomes.pop('bindiff', None)
        self.panel.set_run_status(f'BinDiff: {len(match_set.matches)} matches imported.')
        self.reload()

    # -- engine rows --
    def _refresh_engine_rows(self) -> None:
        vm = self.panel.vm
        rows = []
        for engine in ENGINE_COLUMNS:
            info = vm.engine(engine)
            cap = self.capabilities.get(engine)
            live = self.engine_states.get(engine)
            if engine == 'ghidriff':
                project = self.port.project
                run = service_api.latest_run(project) if project else None
                rows.append(EngineRowView('ghidriff', 'Ghidriff', 'baseline' if run else 'not run',
                                          sanitize_text(run.backend_version if run else '-', 40),
                                          'Primary result in the project', '', ''))
                continue
            state = live or (ENGINE_STATE_TEXT[info.state] if info else 'not run')
            version = (info.version if info and info.version else None) or getattr(cap, 'version', None) or '-'
            detail = info.detail if info else ''
            if cap is not None and not getattr(cap, 'supported', True) and state == 'not run':
                state = 'unsupported'
                detail = sanitize_text(getattr(cap, 'reason', '') or 'unsupported', 200)
            hashes = full = ''
            if info and info.file_sha256:
                hashes = f'set {info.file_sha256[:12]}'
                full = f'set {info.file_sha256}; older {info.older_sha256}; newer {info.newer_sha256}'
            rows.append(EngineRowView(engine, ENGINE_NAMES[engine], state, sanitize_text(version, 40),
                                      sanitize_text(detail, 200), hashes, full))
        self.panel.set_engine_rows(rows)
