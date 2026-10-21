"""Every interactive framework widget carries a tooltip and a short accessible description (GUI audit GUI-6)."""
from __future__ import annotations

import pytest
from PySide6.QtWidgets import QPushButton
from qt_support import join_gui_threads  # noqa: F401

from patchtrace.gui.qt.canvas import GraphCanvas
from patchtrace.gui.qt.codediff import CodeDiffView
from patchtrace.gui.qt.table import VirtualTable
from patchtrace.gui.registry import DESCRIPTION_LIMIT


def _table():
    return [VirtualTable('Test table')]


def _canvas():
    return [GraphCanvas()]


def _diff():
    view = CodeDiffView()
    return [*view.findChildren(QPushButton), *view.panes.values()]


@pytest.mark.parametrize('build', [_table, _canvas, _diff], ids=['table', 'graph', 'codediff'])
def test_framework_widgets_have_tooltips(qtbot, build):
    widgets = build()
    assert widgets
    for widget in widgets:
        qtbot.addWidget(widget) if widget.parent() is None else None
        assert widget.toolTip(), widget.accessibleName()
        assert 0 < len(widget.accessibleDescription()) <= DESCRIPTION_LIMIT
