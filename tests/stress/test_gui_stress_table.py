"""Stress: a 100,000-row VirtualTable sorted, filtered and copied while it is resized (GUI plan 8.4).

Rows are prepared in the test thread (the pure `prepare_table` is the worker's job in the app). Expected values are
computed from the rows, so a wrong order, a wrong filter count or a copy over the clipboard limit fails the test."""
from __future__ import annotations

import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication
from qt_support import join_gui_threads, settings  # noqa: F401

from patchtrace.gui.qt.table import VirtualTable
from patchtrace.gui.table_spec import COPY_LIMIT, ColumnSpec, TableSpec, prepare_table

ROWS = 100_000
GROUPS = ('alpha', 'bravo', 'charlie', 'delta', 'echo')
COLUMNS = (
    ColumnSpec('id', 'Id', lambda row: f'{row[0]:06d}', width_em=8, sort_key=lambda row: row[0]),
    ColumnSpec('name', 'Name', lambda row: row[1], width_em=24),
    ColumnSpec('score', 'Score', lambda row: str(row[2]), unit='pts', width_em=8, sort_key=lambda row: row[2]),
    ColumnSpec('group', 'Group', lambda row: row[3], width_em=10),
)
SPEC = TableSpec(row_key=lambda row: str(row[0]), search_text=lambda row: f'{row[1]} {row[3]}')


def make_rows() -> list[tuple[int, str, int, str]]:
    return [(i, f'item {i:06d} {GROUPS[i % 5]}', (i * 7919) % 1000, GROUPS[i % 5]) for i in range(ROWS)]


@pytest.fixture(scope='module')
def prepared():
    return prepare_table(SPEC, COLUMNS, make_rows())


@pytest.fixture
def table(qtbot, prepared):
    view = VirtualTable('stress rows')
    qtbot.addWidget(view)
    view.resize(900, 500)
    view.show()
    view.set_prepared(prepared)
    QApplication.processEvents()
    return view


def sort_by(view: VirtualTable, column: int, order: Qt.SortOrder) -> None:
    """Through the header, as a user click does (the header's sortIndicatorChanged feeds the model)."""
    view.horizontalHeader().setSortIndicator(column, order)


def test_a_hundred_thousand_rows_sort_and_filter_with_exact_counts(table):
    model = table.table_model
    assert model.rowCount() == ROWS and not table.too_large
    sort_by(table, 2, Qt.SortOrder.AscendingOrder)
    assert model.row_at(0)[2] == 0 and model.row_at(model.rowCount() - 1)[2] == 999
    sort_by(table, 2, Qt.SortOrder.DescendingOrder)
    assert model.row_at(0)[2] == 999 and model.row_at(model.rowCount() - 1)[2] == 0
    table.set_filter('CHARLIE')  # case-insensitive, one term
    assert model.rowCount() == ROWS // 5
    assert all(model.row_at(row)[3] == 'charlie' for row in (0, 1, model.rowCount() - 1))
    table.set_filter('charlie item 000')  # every term is a substring match on the search text
    assert model.rowCount() == sum(1 for i in range(ROWS) if i % 5 == 2 and '000' in f'item {i:06d} charlie')
    table.set_filter('')
    assert model.rowCount() == ROWS


def test_sorting_a_filtered_hundred_thousand_rows_keeps_the_filter(table):
    table.set_filter('delta')
    sort_by(table, 1, Qt.SortOrder.DescendingOrder)
    names = [table.table_model.row_at(row)[1] for row in range(table.table_model.rowCount())]
    assert len(names) == ROWS // 5
    assert names == sorted(names, reverse=True)
    assert all(name.endswith('delta') for name in names[:50])


def test_one_row_past_the_maximum_shows_the_too_large_state_and_no_rows(qtbot):
    at_limit = prepare_table(SPEC, COLUMNS, make_rows())
    over = prepare_table(SPEC, COLUMNS, make_rows() + [(ROWS, 'extra', 1, 'echo')])
    view = VirtualTable('limit rows')
    qtbot.addWidget(view)
    view.set_prepared(at_limit)
    assert not view.too_large and view.table_model.rowCount() == ROWS
    counts = []
    view.counts_changed.connect(lambda shown, total: counts.append((shown, total)))
    view.set_prepared(over)
    assert view.too_large and view.table_model.rowCount() == 0
    assert counts[-1] == (0, ROWS + 1)
    view.selectAll()
    copied, _ = view.copy_selection()
    assert copied == 0


def test_copy_of_a_select_all_is_bounded_by_the_clipboard_limit(table, qtbot):
    table.selectAll()
    copied, truncated = table.copy_selection()
    text = QGuiApplication.clipboard().text()
    assert truncated and 0 < copied < ROWS
    assert len(text.encode('utf-8')) <= COPY_LIMIT
    assert text.splitlines()[0] == 'Id\tName\tScore\tGroup'
    assert text.splitlines()[-1] == '[truncated at 16 KiB]'


def test_copy_with_no_selection_takes_the_current_row(table):
    table.clearSelection()
    table.setCurrentIndex(table.table_model.index(7, 0))
    copied, truncated = table.copy_selection()
    assert (copied, truncated) == (1, False)
    assert QGuiApplication.clipboard().text().splitlines()[1].startswith(f'{table.table_model.row_at(7)[0]:06d}')


def test_sorting_filtering_and_resizing_in_turns_never_loses_the_selection_or_the_current_row(table, qtbot):
    table.set_filter('echo')
    table.selectRow(3)
    key = table.current_key()
    assert key is not None
    for step in range(12):
        table.resize(600 + 80 * step, 300 + 30 * step)
        QApplication.processEvents()
        sort_by(table, step % 4, Qt.SortOrder.AscendingOrder if step % 2 else Qt.SortOrder.DescendingOrder)
        table.set_filter('echo' if step % 3 else 'echo item 0000')
        QApplication.processEvents()
        assert table.table_model.rowCount() == (ROWS // 5 if step % 3 else sum(
            1 for i in range(ROWS) if i % 5 == 4 and '0000' in f'item {i:06d} echo'))
    table.set_filter('echo')
    QApplication.processEvents()
    assert table.current_key() == key and key in table.selected_keys()


RESIZES = [(1200, 700), (700, 400), (1600, 900), (500, 300), (1100, 650)]


def resize_cost(view: VirtualTable, prepared) -> int:
    """data() calls for one fixed resize sequence on a view holding `prepared`."""
    view.set_prepared(prepared)
    QApplication.processEvents()
    view.table_model.data_calls = 0
    for width, height in RESIZES:
        view.resize(width, height)
        QApplication.processEvents()
    return view.table_model.data_calls


def test_resizing_a_hundred_thousand_row_table_costs_the_same_as_a_thousand_rows(qtbot, prepared):
    """data() is called for visible cells only, so the call count may not depend on how many rows exist."""
    small_view, big_view = VirtualTable('small rows'), VirtualTable('big rows')
    for view in (small_view, big_view):
        qtbot.addWidget(view)
        view.resize(900, 500)
        view.show()
    small = resize_cost(small_view, prepare_table(SPEC, COLUMNS, make_rows()[:1_000]))
    big = resize_cost(big_view, prepared)
    assert big <= small + small // 10 + 8, f'{big} data() calls for 100k rows, {small} for 1k rows'
    per_resize_cells = (big_view.viewport().height() // 36 + 2) * big_view.table_model.columnCount()
    assert big <= per_resize_cells * 16 * len(RESIZES), f'{big} data() calls for {len(RESIZES)} resizes'
