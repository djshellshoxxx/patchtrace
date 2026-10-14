"""2026-10-14 audit P2 GUI items: dialog lifecycle, note target, setup dialog, raw go-to."""
from __future__ import annotations

import os

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication, QDialog

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


def test_overview_dialogs_are_deleted_not_accumulated(window, qtbot):
    window.show_file_overview()
    first = window._preflight_dialog
    window.show_file_overview()
    second = window._preflight_dialog
    assert second is not first
    QApplication.sendPostedEvents(None, 0)  # DeferredDelete
    QApplication.processEvents()
    qtbot.waitUntil(lambda: len([d for d in window.findChildren(QDialog)
                                 if d.windowTitle() == 'Preliminary file comparison']) == 1)
    # the surviving dialog's refs must not have been nulled by the old dialog's destruction
    assert window._preflight_dialog is second and window._preflight_status is not None
    assert window._preflight_pe_table is not None
    second.close()
    qtbot.waitUntil(lambda: window._preflight_dialog is None)
    assert window._preflight_status is None and window._preflight_pe_table is None


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
