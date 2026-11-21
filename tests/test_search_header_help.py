"""Search header help through the actual controller/model, without changing result presentation.

Injected search results exercise local Qt presentation only; native accessibility remains separate.
"""
from __future__ import annotations

import pytest
from PySide6.QtCore import Qt
from test_ui_search_panel import Rig

from patchtrace import tooltips

HEADERS = ('Side', 'Kind', 'Match', 'Where', 'Change', 'Why')
HORIZONTAL = Qt.Orientation.Horizontal
DISPLAY = Qt.ItemDataRole.DisplayRole
ACCESSIBLE = Qt.ItemDataRole.AccessibleTextRole
TOOLTIP = Qt.ItemDataRole.ToolTipRole


@pytest.mark.parametrize('state', ('no-project', 'idle', 'ready'))
def test_search_headers_explain_each_column_in_empty_and_result_states(qtbot, state):
    rig = Rig(qtbot, open_=state != 'no-project')
    try:
        if state == 'ready':
            rig.search()
        model = rig.panel.table.table_model
        before = (rig.rows(), tuple(rig.calls), rig.controller.generation)
        assert model.columnCount() == len(HEADERS)
        assert model.rowCount() == (1 if state == 'ready' else 0)
        rendered = []
        for column, title in enumerate(HEADERS):
            tip_id = f'search.col.{title.lower()}'
            header = model.headerData(column, HORIZONTAL, TOOLTIP)
            assert header != title, f'{title} still has only the plain-label fallback'
            assert header == tooltips.tooltip(tip_id)
            assert all(label in header for label in ('What:', 'Why:', 'Effect:', 'Source:', 'Availability:'))
            assert model.headerData(column, HORIZONTAL, DISPLAY) == title
            assert model.headerData(column, HORIZONTAL, ACCESSIBLE) == title
            rendered.append(header)
        assert len(set(rendered)) == len(HEADERS), 'each column needs its own explanation'
        assert (rig.rows(), tuple(rig.calls), rig.controller.generation) == before
        assert not rig.controller.tasks.busy(), 'reading help must not start work'
    finally:
        rig.controller.shutdown()
        rig.shell.tasks.shutdown()


def test_search_header_rich_text_does_not_change_cells_accessibility_or_navigation(qtbot, monkeypatch):
    rig = Rig(qtbot)
    try:
        rig.search()
        model = rig.panel.table.table_model
        cells = tuple((model.index(0, column).data(DISPLAY), model.index(0, column).data(ACCESSIBLE),
                       model.index(0, column).data(TOOLTIP)) for column in range(len(HEADERS)))
        row_key = model.key_at(0)
        rig.panel.table.selectRow(0)
        rig.controller.copy()
        before_copy = tuple(rig.shell.copied)
        before_calls = tuple(rig.calls)
        monkeypatch.setitem(tooltips.REGISTRY, 'search.col.match', tooltips.TooltipEntry(
            '<Match> & context', 'Explain the displayed text.', 'Read only.', 'Local evidence.', 'Prepared table.'))
        header = model.headerData(2, HORIZONTAL, TOOLTIP)
        assert '&lt;Match&gt; &amp; context' in header and '<Match>' not in header
        assert model.headerData(2, HORIZONTAL, DISPLAY) == 'Match'
        assert model.headerData(2, HORIZONTAL, ACCESSIBLE) == 'Match'
        assert tuple((model.index(0, column).data(DISPLAY), model.index(0, column).data(ACCESSIBLE),
                      model.index(0, column).data(TOOLTIP)) for column in range(len(HEADERS))) == cells
        assert model.key_at(0) == row_key
        rig.controller.copy()
        assert tuple(rig.shell.copied) == before_copy * 2
        assert tuple(rig.calls) == before_calls
        assert not rig.nav.anchors, 'reading help must not navigate'
        rig.controller.go()
        assert len(rig.nav.anchors) == 1
        assert rig.nav.anchors[0].key == 'f0'
    finally:
        rig.controller.shutdown()
        rig.shell.tasks.shutdown()
