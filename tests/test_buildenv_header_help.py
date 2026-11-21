# ruff: noqa: F811
"""Build environment header help through actual controllers and the application host.

Synthetic stored fingerprints supply rows; no native tool or target is executed.
"""
from __future__ import annotations

import dataclasses
import subprocess
import sys

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
from qt_support import main_window, settings  # noqa: F401 - shared fixtures
from test_buildenv_support import pair_fingerprints
from test_ui_build_env_panel import FakeProject, reading, settle, start

from patchtrace import tooltips
from patchtrace.buildenv import qt_panel
from patchtrace.buildenv.panel_model import Outcome

HEADERS = (
    (0, 'Fact', 'build_env.col.fact'),
    (1, 'OLDER', 'build_env.col.older'),
    (2, 'NEWER', 'build_env.col.newer'),
    (3, 'Status', 'build_env.col.status'),
    (4, 'Basis', 'build_env.col.basis'),
)
HORIZONTAL = Qt.Orientation.Horizontal
DISPLAY = Qt.ItemDataRole.DisplayRole
ACCESSIBLE = Qt.ItemDataRole.AccessibleTextRole
TOOLTIP = Qt.ItemDataRole.ToolTipRole


@pytest.fixture(scope='module')
def build_pair(tmp_path_factory):
    return pair_fingerprints(tmp_path_factory.mktemp('header-pair'), 'diec-toolchain', 'toolchain')


@pytest.fixture
def controller(qtbot, build_pair, request):
    populated = getattr(request, 'param', True)
    controller, shell, _ = start(qtbot, reading(Outcome(*build_pair)),
                                 project=FakeProject(is_open=populated))
    settle(qtbot, controller)
    assert (controller.table.table_model.rowCount() > 0) is populated
    yield controller
    controller.shutdown()
    shell.tasks.shutdown()


def assert_header_help(model, column, title, tip_id):
    shown = model.headerData(column, HORIZONTAL, TOOLTIP)
    assert shown and shown != title, f'{title} still has only the title fallback'
    assert tip_id in tooltips.REGISTRY
    assert shown == tooltips.tooltip(tip_id)
    assert model.headerData(column, HORIZONTAL, DISPLAY) == title
    assert model.headerData(column, HORIZONTAL, ACCESSIBLE) == title


@pytest.mark.parametrize('controller', [False, True], indirect=True, ids=['empty', 'populated'])
@pytest.mark.parametrize('column,title,tip_id', HEADERS)
def test_each_header_displays_registered_help(controller, column, title, tip_id):
    assert controller.table.horizontalHeader().count() == 5
    assert_header_help(controller.table.table_model, column, title, tip_id)


def test_real_host_registers_and_displays_all_five_header_tips(main_window, qtbot):
    assert main_window.panels.show_panel('build_env') is not None
    controller = main_window.panels.controller('build_env')
    qtbot.waitUntil(lambda: not controller.tasks.busy() and controller.progress is None, timeout=5000)
    assert controller.table.horizontalHeader().count() == 5
    for header in HEADERS:
        assert_header_help(controller.table.table_model, *header)


def test_header_help_does_not_replace_cells_or_copied_text(controller):
    model = controller.table.table_model
    row = controller.good.rows[0]
    values = (row.label, row.older, row.newer, row.status, row.basis)
    assert model.texts_at(0) == values
    for column, title, tip_id in HEADERS:
        index = model.index(0, column)
        assert model.data(index, DISPLAY) == values[column]
        assert model.data(index, TOOLTIP) == values[column]
        assert model.data(index, ACCESSIBLE) == f'{title}: {values[column]}'
        assert_header_help(model, column, title, tip_id)
    controller.table.selectRow(0)
    assert controller.table.copy_selection() == (1, False)
    copied = QApplication.clipboard().text()
    assert copied.splitlines()[0] == 'Fact\tOLDER\tNEWER\tStatus\tBasis'
    assert '<b>What:</b>' not in copied
    assert row.label in copied and row.basis in copied


def test_header_uses_registry_escaping_and_missing_id_fallback(controller, monkeypatch):
    model = controller.table.table_model
    tip_id = 'build_env.col.fact'
    before = model.texts_at(0)
    monkeypatch.setitem(tooltips.REGISTRY, tip_id, tooltips.TooltipEntry(
        'A <b>property</b> & value.', 'Read <only>.', 'No changes.'))
    shown = model.headerData(0, HORIZONTAL, TOOLTIP)
    assert '&lt;b&gt;property&lt;/b&gt; &amp; value' in shown
    assert '<b>property</b>' not in shown
    assert model.headerData(0, HORIZONTAL, DISPLAY) == 'Fact'
    assert model.headerData(0, HORIZONTAL, ACCESSIBLE) == 'Fact'
    assert model.texts_at(0) == before
    monkeypatch.delitem(tooltips.REGISTRY, tip_id)
    assert model.headerData(0, HORIZONTAL, TOOLTIP) == 'Fact'


def test_removed_mapping_is_detected_by_the_actual_header_check(controller, monkeypatch):
    assert_header_help(controller.table.table_model, *HEADERS[3])
    columns = tuple(dataclasses.replace(column, tip_id='') if index == 3 else column
                    for index, column in enumerate(qt_panel.COLUMNS))
    monkeypatch.setattr(qt_panel, 'COLUMNS', columns)
    controller._show_rows()
    with pytest.raises(AssertionError, match='Status still has only the title fallback'):
        assert_header_help(controller.table.table_model, *HEADERS[3])


def test_header_declaration_and_copy_import_without_qt():
    code = (
        'import sys; '
        'import patchtrace.buildenv.panel; '
        'import patchtrace.buildenv.panel_model; '
        'assert not any(name.startswith(("PySide6", "patchtrace.gui.qt", "patchtrace.ui")) '
        'for name in sys.modules)'
    )
    assert subprocess.run([sys.executable, '-I', '-c', code], check=False).returncode == 0
