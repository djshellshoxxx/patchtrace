"""VirtualTable: a flat table whose cost depends on what is visible, not on how many rows exist (GUI plan 8.4).

The worker runs `prepare_table` (`gui/table_spec.py`); `VirtualTableModel.set_prepared` swaps the pointer. The model
owns filter and sort over an index list (stable, None last), so there is no proxy model and no per-comparison
`data()` call. `data()` returns early for roles a table view asks for on every cell and never uses.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QItemSelection, QItemSelectionModel, QModelIndex, Qt, Signal
from PySide6.QtGui import QGuiApplication, QKeyEvent, QKeySequence
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableView, QWidget

from ..table_spec import PreparedTable, build_tsv, order_by
from .metrics import MetricsWatcher

KEY_ROLE = Qt.ItemDataRole.UserRole + 1    # row_key of the row
ROW_ROLE = Qt.ItemDataRole.UserRole + 2    # the source row object
CHIP_ROLE = Qt.ItemDataRole.UserRole + 3   # the column's chip value for the row (None without a chip)
SORT_ROLE = Qt.ItemDataRole.UserRole + 4   # the column's sort key for the row
KEEP_SELECTION_LIMIT = 5_000               # a larger selection is dropped on refresh; the current row is kept

_DISPLAY = Qt.ItemDataRole.DisplayRole
_ACCESSIBLE = Qt.ItemDataRole.AccessibleTextRole
_TOOLTIP = Qt.ItemDataRole.ToolTipRole
_EMPTY = PreparedTable((), (), (), (), (), (), (), 0)


class VirtualTableModel(QAbstractTableModel):
    """Read-only model over a `PreparedTable`. `data_calls` counts `data()` calls for the performance gates."""

    counts_changed = Signal(int, int)  # shown, total

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._p = _EMPTY
        self._terms: tuple[str, ...] = ()
        self._row_filter: Callable[[Any], bool] | None = None
        self._sort_key: str | None = None
        self._descending = False
        self._view: list[int] = list(_EMPTY.order)
        self._by_key: dict[str, int] | None = None
        self._positions: dict[int, int] | None = None
        self._text_keys: dict[int, list[str]] = {}
        self.data_calls = 0

    # -- content --
    @property
    def prepared(self) -> PreparedTable:
        return self._p

    @property
    def too_large(self) -> bool:
        return self._p.too_large

    @property
    def total(self) -> int:
        return self._p.total

    @property
    def sort_state(self) -> tuple[int, Qt.SortOrder]:
        """(column, order); column -1 = the default order."""
        column = self._sort_column()
        order = Qt.SortOrder.DescendingOrder if self._descending else Qt.SortOrder.AscendingOrder
        return column, order

    def set_prepared(self, prepared: PreparedTable) -> None:
        """Swap in new content; filter text and the sort column (by key, when it still exists) carry over."""
        self.beginResetModel()
        self._p = prepared
        if self._sort_column() < 0:
            self._sort_key = None
        self._text_keys.clear()
        self._rebuild()
        self.endResetModel()
        self.counts_changed.emit(len(self._view), prepared.total)

    def set_filter(self, text: str, row_filter: Callable[[Any], bool] | None = None) -> None:
        """Rows whose search text contains every whitespace-separated term (case-insensitive) and that pass
        `row_filter` (a predicate on the source row, for example a verdict set). Both are replaced together."""
        terms = tuple(text.casefold().split())
        if terms == self._terms and row_filter is self._row_filter:
            return
        self.beginResetModel()
        self._terms, self._row_filter = terms, row_filter
        self._rebuild()
        self.endResetModel()
        self.counts_changed.emit(len(self._view), self._p.total)

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        """Model-owned stable sort; persistent indexes (selection, current row) follow their rows."""
        self.layoutAboutToBeChanged.emit()
        persistent = self.persistentIndexList()
        anchors = [(self._view[p.row()] if 0 <= p.row() < len(self._view) else -1, p.column()) for p in persistent]
        columns = self._p.columns
        self._sort_key = columns[column].key if 0 <= column < len(columns) else None
        self._descending = order == Qt.SortOrder.DescendingOrder
        self._rebuild()
        wanted = {source for source, _ in anchors if source >= 0}
        where: dict[int, int] = {}
        for position, source in enumerate(self._view):
            if source in wanted:
                where[source] = position
                if len(where) == len(wanted):
                    break
        moved = [self.index(where[source], col) if source in where else QModelIndex() for source, col in anchors]
        self.changePersistentIndexList(persistent, moved)
        self.layoutChanged.emit()

    def _sort_column(self) -> int:
        for position, column in enumerate(self._p.columns):
            if column.key == self._sort_key:
                return position
        return -1

    def _rebuild(self) -> None:
        p = self._p
        indexes = p.order
        if self._terms:
            searches, terms = p.searches, self._terms
            indexes = [i for i in indexes if all(term in searches[i] for term in terms)]
        if self._row_filter is not None:
            rows, keep = p.rows, self._row_filter
            indexes = [i for i in indexes if keep(rows[i])]
        column = self._sort_column()
        if column >= 0:
            indexes = order_by(indexes, self._keys_of(column), self._descending)
        self._view = list(indexes)
        self._by_key = self._positions = None

    def _keys_of(self, column: int) -> list | tuple:
        keys = self._p.sort_keys[column]
        if keys is not None:
            return keys
        if column not in self._text_keys:  # no sort_key declared: the display text, case-folded
            self._text_keys[column] = [cells[column].casefold() for cells in self._p.texts]
        return self._text_keys[column]

    # -- lookups --
    def source_row(self, view_row: int) -> int:
        return self._view[view_row] if 0 <= view_row < len(self._view) else -1

    def row_at(self, view_row: int):
        source = self.source_row(view_row)
        return self._p.rows[source] if source >= 0 else None

    def key_at(self, view_row: int) -> str | None:
        source = self.source_row(view_row)
        return self._p.keys[source] if source >= 0 else None

    def texts_at(self, view_row: int) -> tuple[str, ...]:
        source = self.source_row(view_row)
        return self._p.texts[source] if source >= 0 else ()

    def view_row_of(self, key: str) -> int:
        """View row of the row with this key, or -1 when it is filtered out or gone."""
        if self._by_key is None:
            self._by_key = {}
            for source, row_key in enumerate(self._p.keys):
                self._by_key.setdefault(row_key, source)
        source = self._by_key.get(key, -1)
        if source < 0:
            return -1
        if self._positions is None:
            self._positions = {src: position for position, src in enumerate(self._view)}
        return self._positions.get(source, -1)

    # -- Qt model API --
    def rowCount(self, parent=None) -> int:
        return 0 if parent is not None and parent.isValid() else len(self._view)

    def columnCount(self, parent=None) -> int:
        return 0 if parent is not None and parent.isValid() else len(self._p.columns)

    def headerData(self, section, orientation, role=_DISPLAY):
        if orientation != Qt.Orientation.Horizontal or not 0 <= section < len(self._p.columns):
            return None
        column = self._p.columns[section]
        if role == _DISPLAY:
            return f'{column.title}\n{column.unit}' if column.unit else column.title
        if role in (_TOOLTIP, _ACCESSIBLE):
            return f'{column.title} ({column.unit})' if column.unit else column.title
        return None

    def flags(self, index):
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

    def data(self, index, role=_DISPLAY):
        self.data_calls += 1
        if role == _DISPLAY:
            return self._cell(index)
        if role not in (_ACCESSIBLE, _TOOLTIP, KEY_ROLE, ROW_ROLE, CHIP_ROLE, SORT_ROLE):
            return None  # Decoration, Font, Alignment, Foreground, Background, SizeHint, CheckState ...
        row, column = index.row(), index.column()
        if not (index.isValid() and row < len(self._view) and column < len(self._p.columns)):
            return None
        source, spec = self._view[row], self._p.columns[column]
        if role == KEY_ROLE:
            return self._p.keys[source]
        if role == ROW_ROLE:
            return self._p.rows[source]
        source_row = self._p.rows[source]
        if role == _TOOLTIP:
            return spec.tooltip(source_row) if spec.tooltip else self._p.texts[source][column]
        if role == CHIP_ROLE:
            return spec.chip(source_row) if spec.chip else None
        if role == SORT_ROLE:
            return self._keys_of(column)[source] if spec.sort_key else self._p.texts[source][column]
        if spec.accessible:
            return spec.accessible(source_row)
        text = self._p.texts[source][column]
        return f'{spec.title}: {text}, {spec.unit}' if spec.unit else f'{spec.title}: {text}'

    def _cell(self, index) -> str | None:
        row, column = index.row(), index.column()
        if index.isValid() and row < len(self._view) and column < len(self._p.columns):
            return self._p.texts[self._view[row]][column]
        return None


class VirtualTable(QTableView):
    """The view: fixed row height from font metrics, hidden vertical header, sortable header, extended row
    selection kept by `row_key`, and the keyboard contract (Enter, Space, Ctrl+C).

    Signals: `activated_key(key)` for Enter or double-click, `detail_requested(key)` for Space,
    `copied(rows, truncated)` after Ctrl+C, `counts_changed(shown, total)` for the panel's status summary."""

    activated_key = Signal(str)
    detail_requested = Signal(str)
    copied = Signal(int, bool)
    counts_changed = Signal(int, int)

    def __init__(self, name: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAccessibleName(name)
        self.table_model = VirtualTableModel(self)
        self.setModel(self.table_model)
        self.table_model.counts_changed.connect(self.counts_changed)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self.setWordWrap(False)
        self.horizontalHeader().setAccessibleName(f'{name} column headers')
        self.verticalHeader().setAccessibleName(f'{name} row headers')
        self.verticalHeader().hide()  # row headers are exposed to UI Automation as accessibles
        self.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        header = self.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionsClickable(True)
        header.setSortIndicatorShown(True)
        if hasattr(header, 'setSortIndicatorClearable'):
            header.setSortIndicatorClearable(True)
        header.setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        header.sortIndicatorChanged.connect(self.table_model.sort)
        self.doubleClicked.connect(self._activate_index)
        self._watcher = MetricsWatcher(self)
        self._watcher.changed.connect(self._apply_metrics)
        self._apply_metrics()

    # -- content --
    @property
    def too_large(self) -> bool:
        return self.table_model.too_large

    def set_prepared(self, prepared: PreparedTable) -> None:
        """Pointer swap; selection and the current row follow their `row_key`s."""
        kept = self._remember()
        self.table_model.set_prepared(prepared)
        self._after_content_change(kept)

    def set_filter(self, text: str, row_filter: Callable[[Any], bool] | None = None) -> None:
        kept = self._remember()
        self.table_model.set_filter(text, row_filter)
        self._after_content_change(kept)

    def _after_content_change(self, kept: tuple[str | None, list[str]]) -> None:
        self._apply_columns()
        self._sync_indicator()
        self._restore(*kept)

    def _sync_indicator(self) -> None:
        column, order = self.table_model.sort_state
        header = self.horizontalHeader()
        header.blockSignals(True)
        header.setSortIndicator(column, order)
        header.blockSignals(False)

    def _apply_metrics(self, *_: object) -> None:
        self.verticalHeader().setDefaultSectionSize(self._watcher.metrics.row_height)
        self._apply_columns()

    def _apply_columns(self) -> None:
        em = self._watcher.metrics.em
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for position, column in enumerate(self.table_model.prepared.columns):
            self.setColumnWidth(position, max(em, round(column.width_em * em)))

    # -- selection by key --
    def selected_keys(self, limit: int = KEEP_SELECTION_LIMIT) -> list[str]:
        """Keys of the selected rows in view order, at most `limit`."""
        keys: list[str] = []
        for view_row in self._selected_rows():
            key = self.table_model.key_at(view_row)
            if key is not None:
                keys.append(key)
            if len(keys) >= limit:
                break
        return keys

    def current_key(self) -> str | None:
        return self.table_model.key_at(self.currentIndex().row()) if self.currentIndex().isValid() else None

    def _selected_rows(self):
        """Distinct selected view rows, ascending, produced lazily (a select-all of 100k rows costs nothing here)."""
        model = self.selectionModel()
        ranges = sorted(model.selection(), key=lambda r: r.top()) if model else []
        last = -1
        for selection_range in ranges:
            for row in range(max(selection_range.top(), last + 1), selection_range.bottom() + 1):
                yield row
                last = row

    def _remember(self) -> tuple[str | None, list[str]]:
        return self.current_key(), self.selected_keys(KEEP_SELECTION_LIMIT + 1)

    def _restore(self, current: str | None, selected: list[str]) -> None:
        model = self.table_model
        selection_model = self.selectionModel()
        if len(selected) <= KEEP_SELECTION_LIMIT and selected:
            last = max(0, model.columnCount() - 1)
            chosen = QItemSelection()
            for key in selected:
                row = model.view_row_of(key)
                if row >= 0:
                    chosen.select(model.index(row, 0), model.index(row, last))
            selection_model.select(chosen, QItemSelectionModel.SelectionFlag.ClearAndSelect)
        row = model.view_row_of(current) if current is not None else -1
        if row >= 0:
            selection_model.setCurrentIndex(model.index(row, 0), QItemSelectionModel.SelectionFlag.NoUpdate)

    # -- keyboard --
    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.matches(QKeySequence.StandardKey.Copy):
            self.copy_selection()
        elif event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self._activate_index(self.currentIndex())
        elif event.key() == Qt.Key.Key_Space and event.modifiers() == Qt.KeyboardModifier.NoModifier:
            key = self.current_key()
            if key is not None:
                self.detail_requested.emit(key)
        else:
            super().keyPressEvent(event)

    def _activate_index(self, index: QModelIndex) -> None:
        key = self.table_model.key_at(index.row()) if index.isValid() else None
        if key is not None:
            self.activated_key.emit(key)

    def copy_selection(self) -> tuple[int, bool]:
        """Put the header and the selected rows (the current row when nothing is selected) on the clipboard as TSV,
        at most 16 KiB. Returns (rows copied, truncated)."""
        model = self.table_model
        rows = self._selected_rows()
        if not self.selectionModel().hasSelection() and self.currentIndex().isValid():
            rows = iter([self.currentIndex().row()])
        header = [column.title for column in model.prepared.columns]
        text, copied, truncated = build_tsv(header, (model.texts_at(row) for row in rows))
        if copied:
            QGuiApplication.clipboard().setText(text)
            self.copied.emit(copied, truncated)
        return copied, truncated
