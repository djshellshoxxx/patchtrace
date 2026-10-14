"""2026-10-14 audit P2 GUI items: dialog lifecycle, note target, setup dialog, raw go-to."""
from __future__ import annotations

import os

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QDialog

from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow


@pytest.fixture
def window(qtbot, tmp_path):
    service = ProjectService.sample(tmp_path / 'sample')
    settings = QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat)
    view = MainWindow(service, settings)
    qtbot.addWidget(view)
    view.show()
    yield view
    if view.worker:
        view.cancel_job()
        qtbot.waitUntil(lambda: view.worker is None, timeout=5000)
    view.close()


def test_file_overview_is_one_dock_not_an_accumulating_dialog(window, qtbot):
    window.show_file_overview()
    window.show_file_overview()
    files = window.panels.controller('files')
    assert files is not None and window.panels.is_shown('files')
    assert not [d for d in window.findChildren(QDialog) if d.windowTitle() == 'Preliminary file comparison']
    assert window.panels.controller('files') is files
    qtbot.waitUntil(lambda: window._current_inspection() is not None, timeout=10000)


def test_refresh_keeps_note_target_unless_finding_changes(window):
    window.findings_list.setCurrentRow(0)
    assert window.note_target.currentIndex() == 1
    window.note_target.setCurrentIndex(0)  # analyst deliberately annotates the match
    window.refresh()
    window.select_finding()
    assert window.note_target.currentIndex() == 0
    window.findings_list.clearSelection()
    window.findings_list.setCurrentRow(-1)
    window.select_finding()
    window.findings_list.setCurrentRow(0)  # a (re)selected finding resets the target
    assert window.note_target.currentIndex() == 1


def test_raw_page_clamp_is_reported_in_match_label(window, qtbot):
    window.mode.setCurrentIndex(3)
    qtbot.waitUntil(lambda: window._raw_sides.get('older') is not None, timeout=10000)
    window.raw_page.setMaximum(9)
    window.raw_page.setValue(5)  # e.g. a go-to offset computed against a larger side that cannot be read
    qtbot.waitUntil(lambda: 'requested page 5' in window.match_label.text(), timeout=5000)
    assert window.raw_page.value() == 1 and 'showing last page 1' in window.match_label.text()
    assert 'past the end of this side' not in window.views['older'].toPlainText()
    window.render_match()
    assert 'requested page' not in window.match_label.text()
