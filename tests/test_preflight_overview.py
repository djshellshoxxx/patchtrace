"""Regression contract for the lightweight, read-only alpha file overview."""
from __future__ import annotations

import os

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QTableWidget

from patchtrace.models import Artifact
from patchtrace.preflight import overview_rows
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow


def artifact(side: str, size: int, value: str) -> Artifact:
    return Artifact(side=side, name=f'{side}<test>.dll', size=size,
                    sha256=value * 64, relative_path=f'artifacts/{side}.dll')


def test_overview_discloses_recorded_fields_and_newer_size_delta():
    rows = overview_rows(artifact('older', 1024, 'a'), artifact('newer', 1280, 'b'))
    indexed = {row.field: (row.older, row.newer) for row in rows}
    assert indexed['File name'] == ('older<test>.dll', 'newer<test>.dll')
    assert indexed['File size'] == ('1,024 bytes', '1,280 bytes')
    assert indexed['SHA-256'] == ('a' * 64, 'b' * 64)
    assert indexed['Size change (newer - older)'][1] == '+256 bytes'
    assert indexed['Content hash comparison'][1] == 'Different'
    assert indexed['Architecture'] == ('x86-64', 'x86-64')


def test_overview_rejects_reversed_orientation():
    with pytest.raises(ValueError, match='older.*newer'):
        overview_rows(artifact('newer', 10, 'a'), artifact('older', 10, 'b'))


def test_overview_reports_identical_artifacts():
    rows = overview_rows(artifact('older', 100, 'a'), artifact('newer', 100, 'a'))
    indexed = {row.field: row.newer for row in rows}
    assert indexed['Content hash comparison'] == 'Identical'
    assert indexed['Size change (newer - older)'] == '+0 bytes'


def test_preliminary_dialog_renders_read_only_project_metadata(qtbot, tmp_path):
    service = ProjectService.sample(tmp_path / 'sample')
    window = MainWindow(service, QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(window)
    window.show_file_overview()
    dialog = window._preflight_dialog
    assert dialog is not None
    assert dialog.isVisible()
    assert not dialog.isModal()
    table = dialog.findChild(QTableWidget)
    assert table is not None
    assert table.columnCount() == 3
    labels = [table.item(i, 0).text() for i in range(table.rowCount())]
    assert 'SHA-256' in labels and 'File size' in labels
    assert 'PE' in [table.item(i, 1).text() for i in range(table.rowCount())]
    dialog.close()
    window.close()
