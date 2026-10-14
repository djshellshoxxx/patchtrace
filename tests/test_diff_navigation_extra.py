"""Regression tests for cross-function difference navigation."""
import os

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtCore import QSettings

from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow


def test_next_diff_advances_single_hunk(qtbot, tmp_path):
    view = MainWindow(ProjectService.sample(tmp_path / 'sample'), QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(view)
    view.navigator.setCurrentRow(0)
    assert view.navigator.count() > 1
    view._hunks = [(0, 1, 'replace')]
    view._hunk_index = 0
    view.navigate_hunk(1)
    assert view.navigator.currentRow() == 1
    view.close()
