"""VirtualTable: lazy data(), model-owned sort and filter, selection by key, keyboard, copy cap (GUI plan 8.4, F4)."""
from __future__ import annotations

import time
from pathlib import Path

import pytest
from PySide6.QtCore import QItemSelectionModel, QPersistentModelIndex, Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication
from qt_support import HOSTILE, a11y_audit, assert_lazy_model, join_gui_threads  # noqa: F401

from patchtrace.gui.qt.table import (
    CHIP_ROLE,
    KEY_ROLE,
    ROW_ROLE,
    SORT_ROLE,
    VirtualTable,
    VirtualTableModel,
)
from patchtrace.gui.table_spec import COPY_LIMIT, MAX_ROWS, ColumnSpec, TableSpec, prepare_table
from patchtrace.gui.text import sanitize_text

DISPLAY = Qt.ItemDataRole.DisplayRole
SPEC = TableSpec(row_key=lambda r: r[0], search_text=lambda r: f'{r[0]} {r[3]}')
COLUMNS = (
    ColumnSpec('name', 'Function', lambda r: r[0], width_em=18),
    ColumnSpec('score', 'Score', lambda r: '' if r[1] is None else r[1], unit='milli', sort_key=lambda r: r[1],
               chip=lambda r: 'chip-' + r[0]),
    ColumnSpec('group', 'Group', lambda r: r[2], accessible=lambda r: f'Group {r[2]}'),
    ColumnSpec('note', 'Note', lambda r: r[3], width_em=24),
    ColumnSpec('addr', 'Address', lambda r: f'{r[4]:#x}', width_em=10),
    ColumnSpec('flag', 'Flag', lambda r: r[5], width_em=6),
)
CELLS_PER_ROW = len(COLUMNS)


def make_rows(count: int, prefix: str = 'fn') -> tuple:
    return tuple((f'{prefix}{n:06d}', None if n % 7 == 0 else (n * 37) % 1000, f'g{n % 5}', f'note {n % 11}',
                  0x1000 + n * 16, '=' if n % 3 else '!') for n in range(count))


def prepare(count: int, columns=COLUMNS, prefix: str = 'fn'):
    return prepare_table(SPEC, columns, make_rows(count, prefix))


@pytest.fixture(scope='module')
def prepared_10k():
    return prepare(10_000)


@pytest.fixture(scope='module')
def prepared_100k():
    return prepare(100_000)


@pytest.fixture
def table(qtbot):
    widget = VirtualTable('Test table')
    qtbot.addWidget(widget)
    widget.resize(900, 420)
    widget.show()
    return widget


def names(model: VirtualTableModel, limit: int | None = None) -> list[str]:
    count = model.rowCount() if limit is None else min(limit, model.rowCount())
    return [model.index(row, 0).data() for row in range(count)]


def select_rows(table: VirtualTable, rows: list[int]) -> None:
    model = table.table_model
    for position, row in enumerate(rows):
        flag = QItemSelectionModel.SelectionFlag.ClearAndSelect if position == 0 else QItemSelectionModel.SelectionFlag.Select
        table.selectionModel().select(model.index(row, 0), flag | QItemSelectionModel.SelectionFlag.Rows)


# -- data() call gates --------------------------------------------------------------------------------------

def test_data_calls_are_independent_of_the_row_count(qapp, prepared_10k, prepared_100k):
    sources = {10_000: prepared_10k, 100_000: prepared_100k}

    def factory(size: int) -> VirtualTableModel:
        model = VirtualTableModel()
        model.set_prepared(sources[size])
        return model
    calls = assert_lazy_model(factory)
    assert max(calls.values()) <= 7 * 13 * CELLS_PER_ROW * 1.2 + 20 + 120


@pytest.mark.parametrize('size', [10_000, 100_000], ids=['10k', '100k'])
def test_first_paint_sort_and_filter_stay_inside_the_budget(table, prepared_10k, prepared_100k, size):
    prepared = prepared_10k if size == 10_000 else prepared_100k
    model = table.table_model
    visible = table.viewport().height() // table.verticalHeader().defaultSectionSize() + 2
    ceiling = 7 * visible * CELLS_PER_ROW * 1.2 + 20
    time_limit = 0.5 if size == 10_000 else 1.5  # >= the measured 29 ms and 235 ms by a wide margin; Windows CI re-measures

    for label, action in (('reset', lambda: table.set_prepared(prepared)),
                          ('sort', lambda: table.horizontalHeader().setSortIndicator(1, Qt.SortOrder.DescendingOrder)),
                          ('filter', lambda: table.set_filter('note 3'))):
        before = model.data_calls
        start = time.perf_counter()
        action()
        QApplication.processEvents()
        elapsed = time.perf_counter() - start
        assert model.data_calls - before <= ceiling, (label, model.data_calls - before, ceiling)
        assert elapsed <= time_limit, (label, elapsed)


def test_preparing_100k_rows_in_the_worker_is_bounded():
    start = time.perf_counter()
    prepare(100_000)
    assert time.perf_counter() - start <= 5.0


def test_ten_thousand_rows_stay_under_64_mib(qapp):
    import tracemalloc
    tracemalloc.start()
    table_data = prepare(10_000)
    model = VirtualTableModel()
    model.set_prepared(table_data)
    current, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert current <= 64 * 1024 * 1024


# -- model behaviour ----------------------------------------------------------------------------------------

def test_default_order_and_unused_roles_return_early(qapp):
    model = VirtualTableModel()
    model.set_prepared(prepare(5))
    index = model.index(0, 1)
    assert model.rowCount() == 5 and model.columnCount() == CELLS_PER_ROW
    assert index.data(DISPLAY) == ''  # row 0 has no score
    for role in (Qt.ItemDataRole.DecorationRole, Qt.ItemDataRole.FontRole, Qt.ItemDataRole.TextAlignmentRole,
                 Qt.ItemDataRole.ForegroundRole, Qt.ItemDataRole.CheckStateRole, Qt.ItemDataRole.SizeHintRole):
        assert index.data(role) is None
    assert index.data(KEY_ROLE) == 'fn000000' and index.data(ROW_ROLE)[0] == 'fn000000'
    assert model.index(1, 1).data(CHIP_ROLE) == 'chip-fn000001'
    assert model.index(1, 1).data(SORT_ROLE) == 37
    assert model.index(1, 0).data(CHIP_ROLE) is None
    assert model.index(9, 0).data(DISPLAY) is None and not model.index(9, 0).isValid()


def test_accessible_text_carries_title_value_and_unit(qapp):
    model = VirtualTableModel()
    model.set_prepared(prepare(3))
    assert model.index(1, 1).data(Qt.ItemDataRole.AccessibleTextRole) == 'Score: 37, milli'
    assert model.index(1, 0).data(Qt.ItemDataRole.AccessibleTextRole) == 'Function: fn000001'
    assert model.index(1, 2).data(Qt.ItemDataRole.AccessibleTextRole) == 'Group g1'
    assert model.headerData(1, Qt.Orientation.Horizontal, Qt.ItemDataRole.AccessibleTextRole) == 'Score (milli)'
    assert model.headerData(1, Qt.Orientation.Horizontal, DISPLAY) == 'Score\nmilli'
    assert model.headerData(0, Qt.Orientation.Vertical, DISPLAY) is None


@pytest.mark.parametrize('hostile', HOSTILE, ids=[f'h{n}' for n in range(len(HOSTILE))])
def test_hostile_cell_text_is_sanitized_and_never_markup(qapp, hostile):
    rows = ((hostile, 1, 'g', hostile, 1, '='),)
    model = VirtualTableModel()
    model.set_prepared(prepare_table(SPEC, COLUMNS, rows))
    shown = model.index(0, 0).data(DISPLAY)
    assert shown == sanitize_text(hostile)
    assert '\x00' not in shown and '‮' not in shown and ' ' not in shown


def test_sort_puts_missing_values_last_in_both_directions_and_is_stable(table):
    table.set_prepared(prepare(30))
    model = table.table_model
    header = table.horizontalHeader()
    header.setSortIndicator(1, Qt.SortOrder.AscendingOrder)
    scores = [model.index(r, 1).data(SORT_ROLE) for r in range(30)]
    present = [s for s in scores if s is not None]
    assert present == sorted(present) and scores[len(present):] == [None] * (30 - len(present))
    ties = [name for score, name in zip(scores, names(model), strict=True) if score is None]
    assert ties == sorted(ties)  # stable on the default (source) order
    header.setSortIndicator(1, Qt.SortOrder.DescendingOrder)
    scores = [model.index(r, 1).data(SORT_ROLE) for r in range(30)]
    present = [s for s in scores if s is not None]
    assert present == sorted(present, reverse=True) and scores[len(present):] == [None] * (30 - len(present))
    assert [n for s, n in zip(scores, names(model), strict=True) if s is None] == ties


def test_sort_without_a_sort_key_uses_the_case_folded_text(table):
    rows = (('b', 1, 'g', 'n', 1, '='), ('A', 1, 'g', 'n', 2, '='), ('c', 1, 'g', 'n', 3, '='))
    table.set_prepared(prepare_table(SPEC, COLUMNS, rows))
    table.horizontalHeader().setSortIndicator(0, Qt.SortOrder.AscendingOrder)
    assert names(table.table_model) == ['A', 'b', 'c']
    table.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
    assert names(table.table_model) == ['b', 'A', 'c']


def test_a_persistent_index_follows_its_row_through_a_sort(table):
    table.set_prepared(prepare(20))
    model = table.table_model
    tracked = QPersistentModelIndex(model.index(3, 0))
    assert tracked.data() == 'fn000003'
    table.horizontalHeader().setSortIndicator(1, Qt.SortOrder.DescendingOrder)
    assert tracked.isValid() and tracked.data() == 'fn000003' and tracked.row() != 3


def test_filter_needs_every_term_ignores_case_and_reports_counts(table):
    table.set_prepared(prepare(100))
    seen = []
    table.counts_changed.connect(lambda shown, total: seen.append((shown, total)))
    table.set_filter('NOTE 3')
    model = table.table_model
    expected = [r[0] for r in make_rows(100) if 'note' in f'{r[0]} {r[3]}' and '3' in f'{r[0]} {r[3]}']
    assert names(model) == sorted(expected) and 0 < len(expected) < 100
    assert seen[-1] == (model.rowCount(), 100)
    table.set_filter('note 3 fn000003')
    assert names(model) == ['fn000003']
    table.set_filter('no such text')
    assert model.rowCount() == 0 and seen[-1] == (0, 100)
    table.set_filter('')
    assert model.rowCount() == 100


def test_filter_and_sort_compose(table):
    table.set_prepared(prepare(100))
    table.set_filter('note 3')
    table.horizontalHeader().setSortIndicator(1, Qt.SortOrder.AscendingOrder)
    scores = [table.table_model.index(r, 1).data(SORT_ROLE) for r in range(table.table_model.rowCount())]
    present = [s for s in scores if s is not None]
    assert present == sorted(present)


def test_columns_may_change_with_every_prepared_table(table):
    table.set_prepared(prepare(10))
    table.horizontalHeader().setSortIndicator(1, Qt.SortOrder.DescendingOrder)
    narrow = prepare(10, columns=(COLUMNS[0], COLUMNS[3]))
    table.set_prepared(narrow)
    assert table.table_model.columnCount() == 2
    assert table.horizontalHeader().sortIndicatorSection() == -1  # the sorted column is gone: default order
    assert names(table.table_model) == [f'fn{n:06d}' for n in range(10)]
    table.set_prepared(prepare(10))
    assert table.table_model.columnCount() == CELLS_PER_ROW
    assert table.columnWidth(0) > table.columnWidth(5)


def test_the_sort_column_survives_a_refresh_when_it_still_exists(table):
    table.set_prepared(prepare(20))
    table.horizontalHeader().setSortIndicator(1, Qt.SortOrder.DescendingOrder)
    table.set_prepared(prepare(20))
    assert table.horizontalHeader().sortIndicatorSection() == 1
    scores = [table.table_model.index(r, 1).data(SORT_ROLE) for r in range(20)]
    present = [s for s in scores if s is not None]
    assert present == sorted(present, reverse=True)


def test_more_than_100k_rows_is_the_too_large_state(table):
    table.set_prepared(prepare_table(SPEC, COLUMNS, range(MAX_ROWS + 1)))
    assert table.too_large and table.table_model.rowCount() == 0 and table.table_model.total == MAX_ROWS + 1


# -- selection ----------------------------------------------------------------------------------------------

def test_selection_follows_the_rows_through_sort(table):
    table.set_prepared(prepare(20))
    select_rows(table, [2, 5])
    assert table.selected_keys() == ['fn000002', 'fn000005']
    table.horizontalHeader().setSortIndicator(1, Qt.SortOrder.DescendingOrder)
    assert sorted(table.selected_keys()) == ['fn000002', 'fn000005']


def test_selection_and_current_row_are_kept_by_key_across_a_refresh(table):
    table.set_prepared(prepare(20))
    select_rows(table, [4, 6])
    table.selectionModel().setCurrentIndex(table.table_model.index(6, 0), QItemSelectionModel.SelectionFlag.NoUpdate)
    reordered = tuple(reversed(make_rows(20)))
    table.set_prepared(prepare_table(SPEC, COLUMNS, reordered))
    assert sorted(table.selected_keys()) == ['fn000004', 'fn000006']
    assert table.current_key() == 'fn000006'
    table.set_prepared(prepare_table(SPEC, COLUMNS, make_rows(5)))  # fn000006 and later are gone
    assert table.selected_keys() == ['fn000004'] and table.current_key() is None


def test_selection_survives_a_filter_for_visible_rows(table):
    table.set_prepared(prepare(40))
    select_rows(table, [3, 14, 5])
    table.set_filter('note 3')  # fn000003 and fn000014 match (n % 11 == 3)
    assert table.selected_keys() == ['fn000003', 'fn000014']


# -- keyboard and copy --------------------------------------------------------------------------------------

def test_enter_space_and_double_click_report_the_key(table, qtbot):
    table.set_prepared(prepare(10))
    table.setFocus()
    table.setCurrentIndex(table.table_model.index(2, 0))
    with qtbot.waitSignal(table.activated_key) as enter:
        QTest.keyClick(table, Qt.Key.Key_Return)
    assert enter.args == ['fn000002']
    with qtbot.waitSignal(table.activated_key) as keypad:
        QTest.keyClick(table, Qt.Key.Key_Enter)
    assert keypad.args == ['fn000002']
    with qtbot.waitSignal(table.detail_requested) as space:
        QTest.keyClick(table, Qt.Key.Key_Space)
    assert space.args == ['fn000002']
    QApplication.processEvents()
    cell = table.visualRect(table.table_model.index(4, 0)).center()
    assert not cell.isNull()
    QTest.mouseClick(table.viewport(), Qt.MouseButton.LeftButton, pos=cell)
    with qtbot.waitSignal(table.activated_key) as double:
        QTest.mouseDClick(table.viewport(), Qt.MouseButton.LeftButton, pos=cell)
    assert double.args == ['fn000004']


def test_enter_and_space_without_a_current_row_do_nothing(table):
    table.set_prepared(prepare_table(SPEC, COLUMNS, ()))
    got = []
    table.activated_key.connect(got.append)
    table.detail_requested.connect(got.append)
    table.setFocus()
    QTest.keyClick(table, Qt.Key.Key_Return)
    QTest.keyClick(table, Qt.Key.Key_Space)
    assert got == []


def test_arrow_keys_move_the_current_row(table):
    table.set_prepared(prepare(10))
    table.setFocus()
    table.setCurrentIndex(table.table_model.index(0, 0))
    QTest.keyClick(table, Qt.Key.Key_Down)
    QTest.keyClick(table, Qt.Key.Key_Down)
    assert table.current_key() == 'fn000002'


def test_ctrl_c_copies_the_selection_as_tsv(table, qtbot):
    table.set_prepared(prepare(10))
    select_rows(table, [1, 2])
    table.setFocus()
    with qtbot.waitSignal(table.copied) as copied:
        QTest.keyClick(table, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
    assert copied.args == [2, False]
    lines = QGuiApplication.clipboard().text().split('\n')
    assert lines[0] == 'Function\tScore\tGroup\tNote\tAddress\tFlag'
    assert lines[1].split('\t')[:2] == ['fn000001', '37'] and len(lines) == 3


def test_ctrl_c_with_only_a_current_row_copies_that_row(table):
    table.set_prepared(prepare(10))
    table.selectionModel().clearSelection()
    table.setCurrentIndex(table.table_model.index(3, 0))
    table.selectionModel().clearSelection()
    assert table.copy_selection() == (1, False)
    assert QGuiApplication.clipboard().text().split('\n')[1].startswith('fn000003')


def test_copying_a_select_all_of_100k_rows_is_capped_and_quick(table, prepared_100k):
    table.set_prepared(prepared_100k)
    table.selectAll()
    start = time.perf_counter()
    copied, truncated = table.copy_selection()
    elapsed = time.perf_counter() - start
    text = QGuiApplication.clipboard().text()
    assert truncated and 0 < copied < 1_000
    assert len(text.encode()) <= COPY_LIMIT and text.endswith('[truncated at 16 KiB]')
    assert elapsed <= 1.0


def test_copy_with_nothing_to_copy_leaves_the_clipboard_alone(table):
    QGuiApplication.clipboard().setText('keep')
    table.set_prepared(prepare_table(SPEC, COLUMNS, ()))
    assert table.copy_selection() == (0, False)
    assert QGuiApplication.clipboard().text() == 'keep'


# -- layout and accessibility -------------------------------------------------------------------------------

def test_row_height_is_fixed_from_font_metrics_and_headers_follow_the_rules(table):
    table.set_prepared(prepare(3))
    metrics = table.fontMetrics()
    assert table.verticalHeader().defaultSectionSize() == max(2 * metrics.lineSpacing() + 6, 28)
    assert table.verticalHeader().isHidden()
    assert table.verticalHeader().sectionResizeMode(0) == table.verticalHeader().ResizeMode.Fixed
    assert table.horizontalHeader().sectionResizeMode(0) == table.horizontalHeader().ResizeMode.Interactive
    assert table.accessibleName() == 'Test table'
    assert not [problem for problem in a11y_audit(table) if 'QHeaderView#?: not keyboard focusable' != problem]


def test_the_row_height_follows_a_font_change(table):
    before = table.verticalHeader().defaultSectionSize()
    font = table.font()
    font.setPointSize(font.pointSize() + 12)
    table.setFont(font)
    QApplication.processEvents()
    assert table.verticalHeader().defaultSectionSize() > before


def test_the_table_uses_none_of_the_forbidden_apis():
    source = (Path(__file__).resolve().parents[1] / 'src' / 'patchtrace' / 'gui' / 'qt' / 'table.py').read_text(
        encoding='utf-8')
    for banned in ('QSortFilterProxyModel', 'lessThan', 'ResizeToContents', 'ToContents', 'setHtml', 'setMarkdown',
                   'RichText', 'processEvents(', 'QTableWidget', 'QStandardItemModel'):
        assert banned not in source, banned


def test_row_filter_composes_with_text_filter_and_clears_with_the_next_call(table):
    table.set_prepared(prepare(60))
    model = table.table_model
    table.set_filter('', lambda row: row[2] == 'g1')
    assert model.rowCount() == 12 and all(model.index(r, 2).data() == 'g1' for r in range(12))
    table.set_filter('fn00000', lambda row: row[2] == 'g1')  # fn000001 and fn000006 are g1; the rest fail the predicate
    assert names(model) == ['fn000001', 'fn000006']
    table.set_filter('')
    assert model.rowCount() == 60


def test_column_tooltip_replaces_the_cell_text_tooltip(table):
    columns = (ColumnSpec('name', 'Function', lambda r: r[0], tooltip=lambda r: f'<p>{r[0]}!</p>'),
               ColumnSpec('note', 'Note', lambda r: r[3]))
    table.set_prepared(prepare(3, columns))
    model = table.table_model
    assert model.index(0, 0).data(Qt.ItemDataRole.ToolTipRole) == '<p>fn000000!</p>'
    assert model.index(0, 1).data(Qt.ItemDataRole.ToolTipRole) == 'note 0'
