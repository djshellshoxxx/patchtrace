"""Qt presentation of the unified comparison (SPEC-31 07 s3-s9; GUI plan F5 panel `unified`).

Responsibility: move the Qt-free read model (`unified/read_model.py`) to widgets. The panel is a tab of the evidence
dock in the one main window; it holds no analysis state. Loading and running go through the host's `TaskRunner`:
requests are built on the GUI thread, workers return values, and results (and the pointer-row publish) are applied in
GUI-thread callbacks only. All text a person can read comes from the read model or is a fixed string here.
"""
from __future__ import annotations

import shutil
from collections.abc import Callable, Collection, Mapping, Sequence
from functools import partial

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLineEdit,
    QMenu,
    QPushButton,
    QSplitter,
    QTableView,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from .gui.qt.docks import ControllerBase
from .gui.qt.labels import PlainLabel, SafeTextView
from .gui.registry import PanelContext
from .tooltips import apply_tooltip, template, tooltip
from .unified import pipeline, read_model
from .unified.limits import UnifiedError
from .unified.pair_text import IrPairTexts
from .unified.read_model import (
    Cancelled,
    UnifiedLoadRequest,
    UnifiedRowView,
    UnifiedViewModel,
)
from .unified.read_text import CLASS_NAMES, DECISION_LABELS, DECISION_MEANING, FOOTER, MATERIALITY_LABELS
from .unified.registry import REGISTRY

ROW_ROLE = Qt.ItemDataRole.UserRole
SEARCH_DEBOUNCE_MS = 150
COLUMNS_DEBOUNCE_MS = 250
DEFAULT_CHANGES = ('material', 'review', 'unknown', 'not-applicable')   # 07 s7; cosmetic/unchanged are counted
CANCELLED_TEXT = 'Cancelled; earlier results unchanged.'
LOADING_DETAIL = 'Loading details...'
FLAG_OFF_REASON = 'Unified analysis is off: turn on the unified/enabled setting to run it.'
NO_PAIR_TEXT = ('Disassembly from ProgramIR is not stored for this pair, and decompiled code is unavailable. '
                'Nothing is shown rather than a guess.')
LOAD_CHANNEL, RUN_CHANNEL, DETAIL_CHANNEL = 'unified-load', 'unified-run', 'unified-detail'
PairTexts = Callable[[UnifiedViewModel, UnifiedRowView], 'tuple[str, str, str] | None']


# ---- table ----------------------------------------------------------------------------------------------------


class UnifiedTableModel(QAbstractTableModel):
    """Rows of one view model plus an index list (filter, then column sort) computed in Python over precomputed keys.

    `data()` is O(1): it reads stored strings; the verbose tooltip is formatted only when asked for. No
    `QSortFilterProxyModel` and no content-sized columns (the C6 measured approach)."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.vm: UnifiedViewModel | None = None
        self.view: list[int] = []
        self.filters: dict = {}
        self.sort_key = 'default'
        self.sort_order = Qt.SortOrder.AscendingOrder
        self.shown = 0
        self.data_calls = 0

    @property
    def rows(self) -> Sequence[UnifiedRowView]:
        return self.vm.rows if self.vm else ()

    def set_view_model(self, vm: UnifiedViewModel | None) -> None:
        self.beginResetModel()
        self.vm = vm
        self._recompute()
        self.endResetModel()

    def set_filter(self, **filters) -> None:
        self.beginResetModel()
        self.filters = filters
        self._recompute()
        self.endResetModel()

    def sort(self, column: int, order=Qt.SortOrder.AscendingOrder) -> None:
        self.layoutAboutToBeChanged.emit()
        persistent = self.persistentIndexList()
        anchors = [(self.view[p.row()] if 0 <= p.row() < len(self.view) else None, p.column()) for p in persistent]
        spec = read_model.columns(self.vm) if self.vm else ()
        self.sort_key = spec[column].key if 0 <= column < len(spec) else 'default'
        self.sort_order = order
        self._recompute()
        position = {row_index: n for n, row_index in enumerate(self.view)}
        moved = [self.index(position[i], col) if i in position else QModelIndex() for i, col in anchors]
        self.changePersistentIndexList(persistent, moved)
        self.layoutChanged.emit()

    def _recompute(self) -> None:
        rows = self.rows
        indices = read_model.filter_rows(rows, **self.filters) if rows else []
        self.shown = len(indices)
        if self.shown > read_model.DISPLAY_ROW_CAP:   # U8: too many to list; the view model keeps them for a narrower filter
            indices = []
        elif self.sort_key != 'default' and self.vm is not None:
            indices = read_model.sort_rows(rows, indices, read_model.column_sort_key(self.vm, self.sort_key),
                                           descending=self.sort_order == Qt.SortOrder.DescendingOrder)
        self.view = indices

    def row_at(self, view_row: int) -> UnifiedRowView | None:
        return self.rows[self.view[view_row]] if 0 <= view_row < len(self.view) else None

    def view_row_of_match(self, match_id: str) -> int:
        for position, index in enumerate(self.view):
            if self.rows[index].ghidriff_match_id == match_id:
                return position
        return -1

    def rowCount(self, parent=None):
        return 0 if parent is not None and parent.isValid() else len(self.view)

    def columnCount(self, parent=None):
        return 0 if parent is not None and parent.isValid() or self.vm is None else len(read_model.columns(self.vm))

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation != Qt.Orientation.Horizontal or self.vm is None:
            return None
        spec = read_model.columns(self.vm)[section]
        if role == Qt.ItemDataRole.DisplayRole:
            return f'{spec.title}\n{spec.unit}' if spec.unit else spec.title
        if role in (Qt.ItemDataRole.ToolTipRole, Qt.ItemDataRole.AccessibleTextRole):
            return f'{spec.title} ({spec.unit})' if spec.unit else spec.title
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
            return read_model.cell_text(row, column)
        if role == ROW_ROLE:
            return row
        if role == Qt.ItemDataRole.AccessibleTextRole:
            return read_model.cell_spoken(row, column)
        if role == Qt.ItemDataRole.ToolTipRole:
            return self._tooltip(row, column)
        return None

    def _tooltip(self, row: UnifiedRowView, column: int) -> str:
        vm = self.vm
        sources = ', '.join(s.display for s in vm.sources) if vm else ''
        if column == 0:
            return template('unified.row', function=row.function_label, decision=row.decision_text,
                            change=row.change_text, sources=sources, reason=row.address_label)
        if column == 1:
            return template('unified.badge', decision=row.decision_text, meaning=DECISION_MEANING[row.decision])
        if column == 2:
            return template('unified.delta', kind=row.change_text, provenance='Change facts of this result',
                            reason=', '.join(row.classes) or row.materiality_text)
        info, cell = vm.sources[column - 3], row.cells[column - 3]
        return template('unified.cell', source=info.display, value=cell.text, unit=info.unit_caption or 'native units',
                        provenance=f'{info.display} {info.version}'.strip(), reason=cell.kind)


class UnifiedTable(QTableView):
    """Keyboard: Enter shows the row in the code panes, Ctrl+C copies provenance."""
    activated_row = Signal()
    copy_requested = Signal()

    def keyPressEvent(self, event):
        if event.matches(QKeySequence.StandardKey.Copy):
            self.copy_requested.emit()
        elif event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self.activated_row.emit()
        else:
            super().keyPressEvent(event)


class CheckMenuButton(QToolButton):
    """A multi-select filter: a button with a menu of checkable entries. `checked()` is what is ticked."""
    changed = Signal()

    def __init__(self, title: str, entries: Sequence[tuple[str, str]], defaults: Collection[str], tip_id: str,
                 parent: QWidget | None = None, entry_tips: Mapping[str, str] | None = None) -> None:
        super().__init__(parent)
        self.title, self.defaults = title, frozenset(defaults)
        self.setText(title)
        self.setAccessibleName(title)
        self.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.setMenu(QMenu(self))
        self.actions_by_key: dict[str, QAction] = {}
        self.set_entries(entries, defaults, tip_id, entry_tips)
        apply_tooltip(self, tip_id)

    def set_entries(self, entries: Sequence[tuple[str, str]], checked: Collection[str], tip_id: str,
                    entry_tips: Mapping[str, str] | None = None) -> None:
        """`entry_tips` maps an entry to its own tip id (a source has one); the others share the button's tip."""
        keep = frozenset(checked)
        self.menu().clear()
        self.actions_by_key = {}
        for key, text in entries:
            action = self.menu().addAction(text)
            action.setCheckable(True)
            action.setChecked(key in keep)
            action.setObjectName(f'{tip_id}.{key}')
            action.setToolTip(tooltip((entry_tips or {}).get(key, tip_id)))
            action.setStatusTip(f'{self.title}: {text}')
            action.toggled.connect(self._toggled)
            self.actions_by_key[key] = action

    def _toggled(self, _checked: bool) -> None:
        self._summarise()
        self.changed.emit()

    def _summarise(self) -> None:
        count = len(self.checked())
        self.setText(self.title if count == len(self.actions_by_key) else f'{self.title} ({count})')

    def checked(self) -> frozenset[str]:
        return frozenset(key for key, action in self.actions_by_key.items() if action.isChecked())

    def set_checked(self, keys: Collection[str]) -> None:
        for key, action in self.actions_by_key.items():
            action.blockSignals(True)
            action.setChecked(key in keys)
            action.blockSignals(False)
        self._summarise()

    def is_default(self) -> bool:
        return self.checked() == self.defaults


# ---- panel ----------------------------------------------------------------------------------------------------


def _button(text: str, name: str, tip_id: str) -> QPushButton:
    button = QPushButton(text)
    button.setObjectName(name)
    apply_tooltip(button, tip_id)
    return button


class UnifiedPanel(QWidget):
    """Widgets only. Every control exists from the start (hidden when it does not apply) so the tooltip and
    accessibility enumerations find it. The controller owns what to load and when."""
    run_requested = Signal()
    cancel_requested = Signal()
    retry_requested = Signal()
    copy_error_requested = Signal()
    view_switch_requested = Signal()
    row_changed = Signal(object)        # UnifiedRowView | None
    goto_requested = Signal(object)
    correct_requested = Signal(object)
    copy_requested = Signal(object)     # list of rows
    explain_requested = Signal(object)
    filters_changed = Signal()
    columns_changed = Signal()          # a user resize settled (debounced); never emitted for our own sizing

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAccessibleName('Unified comparison')
        self._user_widths: dict[str, int] = {}
        self._column_keys: tuple[str, ...] = ()
        self._sizing = False
        self.model = UnifiedTableModel(self)
        self.header = PlainLabel(wrap=True, limit=600)
        self.status = PlainLabel(wrap=True, limit=600)
        self.status.setAccessibleName('')   # empty, so a setText announces itself (C6 s1.8)
        self.banner = SafeTextView('Unified result notices', wrap=True)
        self.banner.setMaximumHeight(72)
        apply_tooltip(self.banner, 'unified.stale_banner')
        self.run_button = _button('Run unified', 'unified.run', 'unified.run')
        self.cancel_button = _button('Cancel', 'unified.cancel', 'unified.cancel')
        self.retry_button = _button('Retry', 'unified.retry', 'unified.retry')
        self.copy_error_button = _button('Copy details', 'unified.copy_error', 'unified.copy_error')
        self.view_switch = _button('Engine evidence tab', 'unified.view_switch', 'unified.view_switch')
        self.decision_filter = CheckMenuButton(
            'Decision', [(d, DECISION_LABELS[d]) for d in DECISION_LABELS], DECISION_LABELS, 'unified.filter_decision')
        self.change_filter = CheckMenuButton(
            'Change', [(m, MATERIALITY_LABELS[m]) for m in MATERIALITY_LABELS], DEFAULT_CHANGES,
            'unified.filter_change')
        self.class_filter = CheckMenuButton(
            'Class', [(c, f'{c} {CLASS_NAMES[c]}') for c in CLASS_NAMES], CLASS_NAMES, 'unified.filter_class')
        self.source_filter = CheckMenuButton(
            'Source', [(s.id, s.display) for s in REGISTRY.sources], [s.id for s in REGISTRY.sources],
            'unified.filter_source', entry_tips={s.id: s.tooltip_id for s in REGISTRY.sources})
        self.search = QLineEdit()
        self.search.setObjectName('unified.search')
        self.search.setAccessibleName('Search functions')
        self.search.setPlaceholderText('Search name or address')
        self.search.setClearButtonEnabled(False)
        apply_tooltip(self.search, 'unified.search')
        self.show_hidden = QCheckBox('Show hidden')
        self.show_hidden.setObjectName('unified.show_hidden')
        apply_tooltip(self.show_hidden, 'unified.show_hidden')
        self.summary = PlainLabel(wrap=True, limit=600)
        self.table = UnifiedTable()
        self.table.setObjectName('unified.table')
        self.table.setAccessibleName('Unified rows')
        self.table.setModel(self.model)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setAccessibleName('Row numbers')
        self.table.horizontalHeader().setAccessibleName('Unified column headers')
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSortIndicatorShown(True)
        self.table.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        self.table.setSortingEnabled(True)
        apply_tooltip(self.table, 'unified.table')
        self.detail = SafeTextView('Unified row details', wrap=True)
        self.detail.setObjectName('unified.detail')
        apply_tooltip(self.detail, 'unified.detail')
        self.goto_button = _button('Go to match', 'unified.goto', 'unified.goto')
        self.correct_button = _button('Correct match...', 'unified.correct', 'unified.correct')
        self.copy_button = _button('Copy provenance', 'unified.copy', 'unified.copy')
        self.explain_button = _button('Explain...', 'unified.explain', 'unified.explain')
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(SEARCH_DEBOUNCE_MS)
        self._columns_timer = QTimer(self)
        self._columns_timer.setSingleShot(True)
        self._columns_timer.setInterval(COLUMNS_DEBOUNCE_MS)
        self._columns_timer.timeout.connect(self.columns_changed)
        self.table.horizontalHeader().sectionResized.connect(self._section_resized)
        self._layout_widgets()
        self._connect()
        for button in (self.cancel_button, self.retry_button, self.copy_error_button):
            button.hide()
        self.update_row_controls(None, correct_ok=False)

    def _layout_widgets(self) -> None:
        top = QHBoxLayout()
        for widget in (self.run_button, self.cancel_button, self.retry_button, self.copy_error_button,
                       self.view_switch):
            top.addWidget(widget)
        top.addStretch(1)
        filters = QHBoxLayout()
        for widget in (self.decision_filter, self.change_filter, self.class_filter, self.source_filter):
            filters.addWidget(widget)
        filters.addWidget(self.search, 1)
        filters.addWidget(self.show_hidden)
        actions = QHBoxLayout()
        for widget in (self.goto_button, self.correct_button, self.copy_button, self.explain_button):
            actions.addWidget(widget)
        actions.addStretch(1)
        lower = QWidget()
        lower_layout = QVBoxLayout(lower)
        lower_layout.setContentsMargins(0, 0, 0, 0)
        lower_layout.addWidget(self.detail, 1)
        lower_layout.addLayout(actions)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(lower)
        splitter.setStretchFactor(0, 2)
        layout = QVBoxLayout(self)
        layout.addWidget(self.header)
        layout.addLayout(top)
        layout.addWidget(self.status)
        layout.addWidget(self.banner)
        layout.addLayout(filters)
        layout.addWidget(self.summary)
        layout.addWidget(splitter, 1)
        layout.addWidget(PlainLabel(FOOTER, wrap=True, limit=400))

    def _connect(self) -> None:
        self.run_button.clicked.connect(self.run_requested)
        self.cancel_button.clicked.connect(self.cancel_requested)
        self.retry_button.clicked.connect(self.retry_requested)
        self.copy_error_button.clicked.connect(self.copy_error_requested)
        self.view_switch.clicked.connect(self.view_switch_requested)
        for button in (self.decision_filter, self.change_filter, self.class_filter, self.source_filter):
            button.changed.connect(self.apply_filters)
        self.show_hidden.toggled.connect(self.apply_filters)
        self.search.textChanged.connect(self._timer.start)
        self._timer.timeout.connect(self.apply_filters)
        self.table.selectionModel().currentRowChanged.connect(self._current_changed)
        self.table.activated_row.connect(self._goto)
        self.table.copy_requested.connect(self._copy)
        self.table.doubleClicked.connect(self._goto)
        self.goto_button.clicked.connect(self._goto)
        self.correct_button.clicked.connect(lambda: self.correct_requested.emit(self.current_row()))
        self.copy_button.clicked.connect(self._copy)
        self.explain_button.clicked.connect(lambda: self.explain_requested.emit(self.current_row()))

    # -- content --
    def current_row(self) -> UnifiedRowView | None:
        return self.model.row_at(self.table.currentIndex().row()) if self.table.currentIndex().isValid() else None

    def selected_rows(self) -> list[UnifiedRowView]:
        rows = [self.model.row_at(i.row()) for i in self.table.selectionModel().selectedRows()]
        return [row for row in rows if row is not None] or ([self.current_row()] if self.current_row() else [])

    def _current_changed(self, current: QModelIndex, _previous: QModelIndex) -> None:
        self.row_changed.emit(self.model.row_at(current.row()) if current.isValid() else None)

    def _goto(self, *_: object) -> None:
        if (row := self.current_row()) is not None:
            self.goto_requested.emit(row)

    def _copy(self, *_: object) -> None:
        if rows := self.selected_rows():
            self.copy_requested.emit(rows)

    def select_match(self, match_id: str) -> bool:
        position = self.model.view_row_of_match(match_id)
        if position < 0:
            return False
        self.table.blockSignals(True)
        self.table.selectRow(position)
        self.table.blockSignals(False)
        self.table.scrollTo(self.model.index(position, 0))
        return True

    def set_view_model(self, vm: UnifiedViewModel) -> None:
        """Show a view model: the state text, banners, summary and (U3/U4/U6/U8) the table."""
        self.header.setText(read_model.header_text(vm))
        self.banner.setPlainText('\n'.join(vm.banners[1:] if vm.state in ('U4', 'U6') else vm.banners))
        self.banner.setVisible(bool(self.banner.toPlainText()))
        self._set_sources(vm)
        self._sizing = True
        try:
            self.model.set_view_model(vm)
            self._size_columns(vm)
        finally:
            self._sizing = False
        self.apply_filters()
        self.retry_button.setVisible(vm.state == 'U5')
        self.copy_error_button.setVisible(vm.state == 'U5')
        self.cancel_button.setVisible(vm.state == 'U2')

    def set_column_widths(self, widths: Mapping[str, int]) -> None:
        """The remembered widths (already validated by the controller); they apply at the next view model."""
        self._user_widths = dict(widths)

    def user_widths(self) -> dict[str, int]:
        return dict(self._user_widths)

    def _size_columns(self, vm: UnifiedViewModel) -> None:
        spec = read_model.columns(vm)
        self._column_keys = tuple(c.key for c in spec)
        em = self.table.fontMetrics().averageCharWidth()
        header = self.table.horizontalHeader()
        for index, column in enumerate(spec):
            header.resizeSection(index, self._user_widths.get(column.key) or em * column.width_em)

    def _section_resized(self, index: int, _old: int, new: int) -> None:
        if self._sizing or not 0 <= index < len(self._column_keys):
            return
        self._user_widths[self._column_keys[index]] = new
        self._columns_timer.start()

    def _set_sources(self, vm: UnifiedViewModel) -> None:
        """Every registry source is listed (so the choice does not move between results); an id this build does not
        know is added with the generic tip. All are ticked: the filter then restricts nothing."""
        known = {s.id for s in REGISTRY.sources}
        extra = [(s.source, s.display) for s in vm.sources if s.source not in known]
        entries = [(s.id, s.display) for s in REGISTRY.sources] + extra
        tips = {s.id: s.tooltip_id for s in REGISTRY.sources} | {key: 'unified.source.unknown' for key, _ in extra}
        self.source_filter.set_entries(entries, [key for key, _ in entries], 'unified.filter_source', tips)
        self.source_filter.defaults = frozenset(key for key, _ in entries)

    def show_text_state(self, state: str, text: str) -> None:
        """U2 progress and the like: a status line without touching the table."""
        self.status.setText(text)
        self.cancel_button.setVisible(state == 'U2')

    def apply_filters(self) -> None:
        vm = self.model.vm
        change_default = self.change_filter.is_default()
        filters = {
            'decisions': None if self.decision_filter.checked() == self.decision_filter.defaults
            else self.decision_filter.checked(),
            'materialities': None if change_default else self.change_filter.checked(),
            'classes': None if self.class_filter.checked() == self.class_filter.defaults
            else self.class_filter.checked(),
            'sources': None if self.source_filter.is_default() else self.source_filter.checked(),
            'search': self.search.text(), 'show_collapsed': self.show_hidden.isChecked()}
        self.model.set_filter(**filters)
        self._show_counts(vm)
        self.row_changed.emit(self.current_row())
        self.filters_changed.emit()

    def _show_counts(self, vm: UnifiedViewModel | None) -> None:
        listing = bool(vm and vm.rows)
        if vm is None:
            self.table.setVisible(False)
            self.status.setText(read_model.STATE_TEXT['U0'])
            self.summary.setText('')
            return
        state, text = read_model.display_state(vm, self.model.shown)
        self.table.setVisible(listing and state != 'U8')
        if state == 'U8':
            self.status.setText(text)
        elif vm.state == 'U3':
            self.status.setText('')
        else:
            self.status.setText(vm.state_text)
        self.summary.setText(read_model.summary_text(vm, show_collapsed=self.show_hidden.isChecked())
                             if listing else '')

    def update_controls(self, run_enabled: bool, reason: str) -> None:
        self.run_button.setEnabled(run_enabled)
        base = tooltip('unified.run')
        self.run_button.setToolTip(base if run_enabled or not reason else f'{base}\nAvailability: {reason}')

    def update_row_controls(self, row: UnifiedRowView | None, *, correct_ok: bool) -> None:
        mapped = row is not None and row.ghidriff_match_id is not None
        self.goto_button.setEnabled(row is not None)
        self.correct_button.setEnabled(mapped and correct_ok)
        self.copy_button.setEnabled(row is not None)
        self.explain_button.setEnabled(row is not None)

    def set_detail(self, text: str) -> None:
        self.detail.setPlainText(text)


# ---- dialog ---------------------------------------------------------------------------------------------------


class ExplainDialog(QDialog):
    """The exact bounded text that describes one row; nothing is transmitted from this dialog."""

    def __init__(self, title: str, text: str, omitted: Sequence[str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle('Preview unified row context')
        self.resize(720, 420)
        layout = QVBoxLayout(self)
        layout.addWidget(PlainLabel(f'{title}. Nothing is sent from here.', wrap=True))
        view = SafeTextView('Exact row context', wrap=True)
        view.setPlainText(text + ('\n\nOmitted: ' + '; '.join(omitted) if omitted else ''))
        layout.addWidget(view, 1)
        close = QPushButton('Close')
        close.setObjectName('unified.explain_close')
        close.clicked.connect(self.accept)
        layout.addWidget(close)


# ---- controller -----------------------------------------------------------------------------------------------


class UnifiedController(ControllerBase):
    """Owns the load and run tasks; reads the project through the panel host's port. Every result is applied only if
    it still belongs to the project that asked (the key is compared on the GUI thread, 07 s9)."""

    def __init__(self, ctx: PanelContext, *, loader: Callable = read_model.load_unified,
                 pair_texts: PairTexts | None = None, engine_busy: Callable[[], bool] | None = None) -> None:
        panel = UnifiedPanel()
        super().__init__(panel)
        self.panel = panel
        self.port = ctx.project
        self.window = self.port.window
        self.tasks = ctx.tasks
        self.settings = ctx.settings
        self._status = ctx.shell.status
        self._announce = ctx.shell.announce
        self._copy_text = ctx.shell.copy_text
        self.nav = ctx.nav
        self.loader = loader
        self._ir_texts = IrPairTexts() if pair_texts is None else None
        self.pair_texts = pair_texts or self._ir_texts
        self.engine_busy = engine_busy or self._evidence_run_active
        self.vm: UnifiedViewModel | None = None
        self.dirty = True
        self.loaded_key = None
        self.last_error = ''
        self.detail_generation = 0
        self._restore_filters()
        self._restore_columns()
        panel.run_requested.connect(self.start_run)
        panel.retry_requested.connect(self.start_run)
        panel.cancel_requested.connect(self.cancel_run)
        panel.copy_error_requested.connect(self._copy_error)
        panel.view_switch_requested.connect(partial(self.nav.focus_panel, 'evidence'))
        panel.row_changed.connect(self._row_changed)
        panel.goto_requested.connect(self.show_row)
        panel.correct_requested.connect(self.correct)
        panel.copy_requested.connect(self.copy_provenance)
        panel.explain_requested.connect(self.explain)
        panel.filters_changed.connect(self._save_filters)
        panel.columns_changed.connect(self._save_columns)
        self.update_controls()

    # -- settings (each read validated; a bad value is the default) --
    def _restore_filters(self) -> None:
        panel = self.panel
        for button, key in ((panel.decision_filter, 'filters/decisions'), (panel.change_filter, 'filters/changes')):
            saved = frozenset(self.settings.get_list(key, ())) & frozenset(button.actions_by_key)
            if saved:
                button.set_checked(saved)
        panel.show_hidden.setChecked(self.settings.get_bool('view/show_hidden', False))

    def _restore_columns(self) -> None:
        self.panel.set_column_widths(read_model.parse_column_widths(self.settings.get_list('columns', ())))

    def _save_columns(self) -> None:
        self.settings.set('columns', read_model.format_column_widths(self.panel.user_widths()))

    def _save_filters(self) -> None:
        panel = self.panel
        self.settings.set('filters/decisions', sorted(panel.decision_filter.checked()))
        self.settings.set('filters/changes', sorted(panel.change_filter.checked()))
        self.settings.set('view/show_hidden', panel.show_hidden.isChecked())

    # -- host hooks --
    def focus_target(self) -> QWidget:
        return self.panel.table

    def project_changed(self, key) -> None:
        self.tasks.cancel(RUN_CHANNEL)
        self.tasks.cancel(DETAIL_CHANNEL)
        if key is None:
            self.loaded_key = None
            self._show(self.loader(UnifiedLoadRequest(None)))
        else:
            self.reload()
        self.update_controls()

    def busy_changed(self, busy: bool) -> None:
        """Also the host's "shown again" signal."""
        if self.dirty and self.port.project() is not None:
            self.reload()
        self.update_controls()

    def capabilities_changed(self) -> None:
        self.update_controls()

    def selection_changed(self, match_id: str | None) -> None:
        if match_id is not None:
            self.panel.select_match(match_id)

    def shutdown(self) -> None:
        for channel in (LOAD_CHANNEL, RUN_CHANNEL, DETAIL_CHANNEL):
            self.tasks.cancel(channel)
        if self._ir_texts is not None:
            self._ir_texts.close()

    # -- load --
    def _backend(self):
        try:
            return self.window.backend_config()
        except Exception:  # noqa: BLE001 - an unreadable setting means "not configured", never a crash
            return None

    def _extraction_configured(self) -> bool:
        backend = self._backend()
        return bool(backend and backend.python_executable and backend.ghidra_dir)

    def reload(self) -> None:
        service = self.window.service
        if service is None or self.port.project() is None:
            self._show(self.loader(UnifiedLoadRequest(None)))
            return
        key = self.port.key()
        request = read_model.request_from_service(service, extraction_configured=self._extraction_configured())
        self.loaded_key, self.dirty = key, False
        self.panel.show_text_state('load', read_model.progress_text('loading', 0, None))
        self.tasks.submit(LOAD_CHANNEL, lambda token, report: self.loader(request, token),
                          on_result=partial(self._loaded, key), on_error=self._load_failed)

    def _loaded(self, key, vm: UnifiedViewModel) -> None:
        if key != self.port.key():
            return   # the project moved on while the worker read; the newer load answers
        self._show(vm)

    def _load_failed(self, failure) -> None:
        if failure.exception_class == Cancelled.__name__:
            return
        self.panel.show_text_state('U5', f'The unified result could not be produced: {failure.text}. Earlier results '
                                         'and the primary Ghidriff results are unchanged.')

    def _show(self, vm: UnifiedViewModel) -> None:
        self.vm = vm
        self.last_error = vm.error or ''
        self.panel.set_view_model(vm)
        self.panel.set_detail('')
        self.update_controls()
        self._announce(vm.state_text if vm.state != 'U3' else read_model.summary_text(vm))

    # -- run --
    def run_availability(self) -> tuple[bool, str]:
        if self.port.project() is None:
            return False, 'Needs an open project.'
        if not self.settings.get_bool('enabled', False):
            return False, FLAG_OFF_REASON
        if self.port.busy() or self.engine_busy():
            return False, 'Disabled while a Ghidriff analysis or an engine run is active.'
        if self.tasks.busy(RUN_CHANNEL):
            return False, 'A unified analysis is already running.'
        return True, ''

    def update_controls(self) -> None:
        enabled, reason = self.run_availability()
        self.panel.update_controls(enabled, reason)
        row = self.panel.current_row()
        self.panel.update_row_controls(row, correct_ok=self._correct_ok())

    def _correct_ok(self) -> bool:
        button = getattr(self.window, 'correct_button', None)
        return bool(button is not None and button.isEnabled())

    def _evidence_run_active(self) -> bool:
        controller = self.window.panels.controller('evidence') if hasattr(self.window, 'panels') else None
        return getattr(controller, 'run_thread', None) is not None

    def start_run(self) -> None:
        enabled, reason = self.run_availability()
        if not enabled:
            self._status(reason)
            return
        service, key = self.window.service, self.port.key()
        try:
            request = pipeline.prepare(service, pipeline.UnifiedOptions(backend=self._backend()))
        except UnifiedError as error:
            self._run_error(read_model.error_text(error))
            return
        self.panel.show_text_state('U2', read_model.progress_text('prepare', 0, None))
        self.tasks.submit(
            RUN_CHANNEL, lambda token, report: pipeline.execute(
                request, token, lambda event: report(event.stage, event.done, event.total)),
            on_result=partial(self._run_finished, request, service, key), on_error=self._run_error_task,
            on_progress=self._progress)
        self.update_controls()

    def cancel_run(self) -> None:
        self.tasks.cancel(RUN_CHANNEL)
        self._status(CANCELLED_TEXT)
        self.reload()
        self.update_controls()

    def _progress(self, progress) -> None:
        self.panel.show_text_state('U2', read_model.progress_text(progress.stage, progress.done, progress.total))

    def _run_finished(self, request, service, key, output) -> None:
        if self.window.service is not service or self.port.key() != key:
            if output.staged is not None:   # the project changed under the run: never publish into another one
                shutil.rmtree(output.staged, ignore_errors=True)
            return
        try:
            report = pipeline.publish(service, request, output)
        except UnifiedError as error:
            if error.code == 'PT-UNIFIED-CANCEL':
                self._status(CANCELLED_TEXT)
                self.reload()
            else:
                self._run_error(read_model.error_text(error))
            return
        self._status(f'Unified analysis finished: {report.status}.')
        self.reload()

    def _run_error_task(self, failure) -> None:
        self._run_error(failure.text)

    def _run_error(self, text: str) -> None:
        self.last_error = read_model.STATE_TEXT['U5'].format(error=text)
        self.panel.show_text_state('U5', self.last_error)
        self.panel.retry_button.setVisible(True)
        self.panel.copy_error_button.setVisible(True)
        self.update_controls()

    def _copy_error(self) -> None:
        if self.last_error:
            self._copy_text(self.last_error)

    # -- rows --
    def _row_changed(self, row: UnifiedRowView | None) -> None:
        self.detail_generation += 1
        self.update_controls()
        if row is None or self.vm is None:
            self.panel.set_detail('')
            return
        vm = self.vm
        self.panel.set_detail(LOADING_DETAIL)
        self.tasks.submit(DETAIL_CHANNEL, lambda token, report: read_model.row_detail(vm, row),
                          on_result=partial(self._detail_ready, self.detail_generation),
                          on_error=lambda failure: self.panel.set_detail(f'Details could not be read: {failure.text}'))

    def _detail_ready(self, generation: int, text: str) -> None:
        if generation == self.detail_generation:
            self.panel.set_detail(text)

    def show_row(self, row: UnifiedRowView) -> None:
        """Rows that map to a Ghidriff match render exactly as today; other rows show stored pair text or say so."""
        if row.ghidriff_match_id is not None:
            if not self.nav.select_match(row.ghidriff_match_id, clear_filters=True):
                self._status('That Ghidriff match is not in the navigator.')
            return
        texts = self.pair_texts(self.vm, row) if self.pair_texts and self.vm else None
        older, newer, label = texts or (NO_PAIR_TEXT, NO_PAIR_TEXT, f'Unified row {row.function_label}: unavailable')
        self.nav.show_pair(older, newer, label)

    def correct(self, row: UnifiedRowView | None) -> None:
        if row is None or row.ghidriff_match_id is None or not self.nav.select_match(row.ghidriff_match_id, True):
            return
        self.window.correct_match()   # the existing dialog, over the match the navigator now holds

    def copy_provenance(self, rows: Sequence[UnifiedRowView]) -> None:
        if self.vm is None:
            return
        text = read_model.provenance_block(self.vm, rows)
        self._status('Provenance copied.' if text and self._copy_text(text) else 'Provenance could not be copied.')

    def explain(self, row: UnifiedRowView | None) -> None:
        fragment = read_model.explain_context(self.vm, row) if row is not None and self.vm else None
        if fragment is None:
            self._status('No context could be built for this row.')
            return
        if row.ghidriff_match_id is not None and self.nav.select_match(row.ghidriff_match_id, True):
            # D-30: the text reaches an AI only inside the existing, explicit context preview of the selected match
            self.window.preview_interpretation(notes=[(fragment.title, fragment.text, fragment.omitted)])
            return
        ExplainDialog(fragment.title, fragment.text, fragment.omitted, self.window).exec()

