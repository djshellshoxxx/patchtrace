"""The lazy-model measurement owns one model even when other Qt work is pending."""
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QTableView
from qt_support import _paint_counting_data, join_gui_threads  # noqa: F401

from patchtrace.gui.qt.table import VirtualTableModel
from patchtrace.gui.table_spec import ColumnSpec, TableSpec, prepare_table


def test_paint_counter_excludes_other_instances_with_pending_qt_work(qtbot):
    rows = tuple((f'row_{index}',) for index in range(10_000))
    prepared = prepare_table(
        TableSpec(row_key=lambda row: row[0], search_text=lambda row: row[0]),
        (ColumnSpec('name', 'Name', lambda row: row[0]),), rows,
    )
    selected, unrelated = VirtualTableModel(), VirtualTableModel()
    selected.set_prepared(prepared)
    unrelated.set_prepared(prepared)
    other_view = QTableView()
    qtbot.addWidget(other_view)
    other_view.setModel(unrelated)
    other_view.resize(800, 400)
    other_view.show()
    # Queue an independent model request as well as its first paint. The timer
    # makes the ownership witness deterministic even if a platform occludes it.
    QTimer.singleShot(0, lambda: unrelated.index(0, 0).data())
    selected_before, unrelated_before = selected.data_calls, unrelated.data_calls

    try:
        counted, ceiling = _paint_counting_data(selected, 8)
    finally:
        other_view.setModel(None)
        other_view.hide()

    assert unrelated.data_calls > unrelated_before
    assert counted == selected.data_calls - selected_before
    assert counted <= ceiling
