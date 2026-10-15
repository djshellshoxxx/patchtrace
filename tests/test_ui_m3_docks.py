"""GUI plan 8.10 step M3: the Series window and the File overview dialog are docks of the one main window."""
from __future__ import annotations

import subprocess
import sys
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QDialog
from qt_support import top_level_windows
from test_nway_series import builds  # noqa: F401, F811  (fixture reuse)
from test_nway_view_model import series_file  # noqa: F401, F811

from patchtrace.nway.panel import PANEL as SERIES
from patchtrace.pe_overview.panel import PANEL as FILES
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow
from patchtrace.ui_inspection import RowsModel, pe_rows, recorded_rows
from patchtrace.ui_series import open_pair_in_main


@pytest.fixture
def window(qtbot, tmp_path):
    view = MainWindow(ProjectService.sample(tmp_path / 'sample'),
                      QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat), tmp_path / 'profiles')
    qtbot.addWidget(view)
    view.show()
    yield view
    view._stop_inspection()
    view.close()


# ---- pure specs ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize('module', ['patchtrace.nway.panel', 'patchtrace.pe_overview.panel'], ids=['series', 'files'])
def test_panel_specs_import_no_qt(module):
    code = f'import sys, {module}; sys.exit(any(name.startswith("PySide6") for name in sys.modules))'
    assert subprocess.run([sys.executable, '-I', '-c', code], check=False).returncode == 0


@pytest.mark.parametrize('spec, area, has_requires', [(SERIES, 'bottom', False), (FILES, 'bottom', True)],
                         ids=['series', 'files'])
def test_specs_declare_dock_tips_and_the_reserved_slot(spec, area, has_requires):
    assert spec.area == area and spec.tabify_with is None and spec.shortcut is None
    assert {f'{spec.id}.dock', f'{spec.id}.action'} <= set(spec.tips)
    assert bool(spec.requires) == has_requires


# ---- the series dock ----------------------------------------------------------------------------------------


def test_series_dock_has_one_tab_per_file_and_closes_them(window, qtbot, series_file):  # noqa: F811
    path, _ = series_file
    other = path.parent / 'copy' / 'series.json'
    other.parent.mkdir()
    other.write_bytes(path.read_bytes())
    assert window.panels.show_panel('series')
    series = window.panels.controller('series')
    assert series.hint.isVisibleTo(window) and not series.tabs.isVisibleTo(window)
    first = series.open_series(path)
    assert series.open_series(path) is first and series.tabs.count() == 1 and series.tabs.currentWidget() is first
    second = series.open_series(other)
    assert series.tabs.count() == 2 and series.tabs.currentWidget() is second
    qtbot.waitUntil(lambda: first.loaded is not None and second.loaded is not None, timeout=5000)
    series.close_tab(0)
    series.close_tab(0)
    assert series.tabs.count() == 0 and series.hint.isVisibleTo(window)
    assert [d for d in window.findChildren(QDialog) if d.windowTitle().startswith('Series')] == []


def test_file_menu_entry_asks_for_a_file_and_a_cancel_opens_nothing(window, series_file):  # noqa: F811
    path, _ = series_file
    series = window.panels.show_panel('series') and window.panels.controller('series')
    series._choose = lambda title, file_filter='': None
    window.open_series()
    assert series.tabs.count() == 0
    series._choose = lambda title, file_filter='': path
    window.open_series()
    assert series.tabs.count() == 1 and series.tabs.tabToolTip(0).endswith('series.json')


def test_opening_a_pair_selects_its_match_in_the_main_window(window):
    window.panels.show_panel('series')
    port = window.panels.controller('series').port
    target = window.navigator.item(window.navigator.count() - 1).data(Qt.ItemDataRole.UserRole)
    open_pair_in_main(port, str(window.service.root), target)
    assert window.current_match().id == target


def test_series_dock_shutdown_is_idempotent_and_leaves_no_thread(window, series_file):  # noqa: F811
    path, _ = series_file
    window.panels.show_panel('series')
    series = window.panels.controller('series')
    tab = series.open_series(path)
    series.shutdown()
    series.shutdown()
    assert tab.thread is None


# ---- the files dock -----------------------------------------------------------------------------------------


def test_files_dock_replaces_the_overview_dialog(window, qtbot):
    window.show_file_overview()
    window.show_file_overview()
    files = window.panels.controller('files')
    assert window.panels.is_shown('files')
    assert [row.values[0] for row in files.recorded.rows][:1] == ['File name']
    assert files.recorded.headerData(1, Qt.Orientation.Horizontal) == 'OLDER'
    qtbot.waitUntil(lambda: 'complete' in files.status.full_text(), timeout=10000)
    assert files.pe.rowCount() > 3
    assert not [d for d in window.findChildren(QDialog) if d.windowTitle() == 'Preliminary file comparison']
    assert top_level_windows() == [window]


def test_files_dock_follows_a_project_change_and_clears_without_one(window, qtbot):
    window.show_file_overview()
    files = window.panels.controller('files')
    qtbot.waitUntil(lambda: files.pe.rowCount() > 0, timeout=10000)
    window.service = None
    window.panels.project_changed()
    assert files.recorded.rowCount() == 0 and files.pe.rowCount() == 0
    assert files.status.full_text() == 'File inspection not started.'


def test_file_overview_without_a_project_opens_nothing(qtbot, tmp_path):
    empty = MainWindow(None, QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat), tmp_path / 'profiles')
    qtbot.addWidget(empty)
    empty.show_file_overview()
    assert not empty.panels.is_shown('files')


def test_pe_rows_explain_an_unavailable_comparison_and_mark_changed_rows_bold():
    unavailable = SimpleNamespace(comparisons=(), sides={
        side: SimpleNamespace(overview=None, error='not a PE file', error_code='PT-PE-FORMAT', trust=None)
        for side in ('older', 'newer')})
    (row,) = pe_rows(unavailable)
    assert row.values[0] == 'PE comparison unavailable' and 'older: not a PE file' in row.values[1]
    changed = SimpleNamespace(field='Machine', older='x86', newer='x64', status='changed', provenance='headers',
                              reason='')
    kept = SimpleNamespace(field='Subsystem', older='gui', newer='gui', status='unchanged', provenance='headers',
                           reason='')
    inspection = SimpleNamespace(comparisons=(changed, kept), sides={
        side: SimpleNamespace(trust=None) for side in ('older', 'newer')})
    model = RowsModel(('a', 'b', 'c', 'd', 'e'))
    model.set_rows(pe_rows(inspection))
    assert [model.data(model.index(i, 0), Qt.ItemDataRole.FontRole) is not None for i in range(2)] == [True, False]
    assert 'Machine' in model.data(model.index(0, 0), Qt.ItemDataRole.ToolTipRole)


def test_recorded_rows_are_plain_text_with_the_metadata_tip(window):
    rows = recorded_rows(window.project)
    assert rows and all(len(row.values) == 3 and row.tip.startswith('Saved project artifact') for row in rows)
