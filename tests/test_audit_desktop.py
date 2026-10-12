"""Audit regressions for the desktop UI and entry point."""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QSettings, Qt, QTimer
from PySide6.QtWidgets import QApplication, QMessageBox

from patchtrace import ui
from patchtrace.service import ProjectService

INJECTION = '<b>owned</b><img src="x">'


@pytest.fixture
def window(qtbot, tmp_path):
    service = ProjectService.sample(tmp_path / 'sample')
    settings = QSettings(str(tmp_path / 'settings.ini'), QSettings.Format.IniFormat)
    main = ui.MainWindow(service=service, settings=settings)
    qtbot.addWidget(main)
    yield main
    if main.service:
        main.service.close()
        main.service = None


def test_plain_tip_escapes_markup():
    tip = ui.plain_tip(INJECTION + '\nline')
    assert '<b>' not in tip and '<img' not in tip
    assert '&lt;b&gt;owned&lt;/b&gt;' in tip and '<br>' in tip


def test_artifact_name_tooltip_is_not_rich_text(window):
    artifact = next(a for a in window.project.artifacts if a.side == 'older')
    artifact.name = INJECTION + '.exe'
    window.refresh()
    tip = window.side_labels['older'].toolTip()
    assert '<b>owned' not in tip and '<img' not in tip
    assert '&lt;b&gt;owned' in tip


def test_finding_summary_tooltip_is_not_rich_text(window, monkeypatch):
    run = SimpleNamespace(findings=[SimpleNamespace(
        id='f1', summary=INJECTION, fix_purpose='', review='unreviewed', stale=False, category='other')])
    object.__setattr__(window.service.project, 'interpretations', [run])
    monkeypatch.setattr(window, 'select_finding', lambda *_: None)
    window.refresh_findings()
    tip = window.findings_list.item(0).toolTip()
    object.__setattr__(window.service.project, 'interpretations', [])
    assert '<b>owned' not in tip and '&lt;b&gt;owned' in tip


def test_offline_confirmation_renders_bundle_name_as_plain_text(qtbot, tmp_path, monkeypatch):
    settings = QSettings(str(tmp_path / 's.ini'), QSettings.Format.IniFormat)
    monkeypatch.setattr(ui, 'discover_local_runtimes',
                        lambda: SimpleNamespace(python_executables=[], ghidra_roots=[]))
    dialog = ui.SetupDialog(settings)
    qtbot.addWidget(dialog)
    dialog._pending_plan = SimpleNamespace(archive=Path(INJECTION + '.zip'), runtime_id=INJECTION,
                                           file_count=1, total_bytes=1, sha256='0' * 64)
    seen = {}

    def inspect():
        box = next(w for w in QApplication.topLevelWidgets() if isinstance(w, QMessageBox) and w.isVisible())
        seen['format'] = box.textFormat()
        box.button(QMessageBox.StandardButton.No).click()

    QTimer.singleShot(0, inspect)
    dialog._finish_offline_inspection()
    assert seen['format'] == Qt.TextFormat.PlainText
    assert 'not authorized' in dialog.diagnostics.toPlainText()


def test_export_format_change_with_empty_destination(window, monkeypatch):
    errors = []
    monkeypatch.setattr(sys, 'excepthook', lambda *args: errors.append(args))
    dialog = ui.ExportDialog(window.project, window.service.root, [], window)
    dialog.destination.setText('')
    dialog.format.setCurrentText('json')
    assert not errors
    assert dialog.destination.text() == ''
    dialog.destination.setText('out/report.json')
    dialog.format.setCurrentText('html')
    assert dialog.destination.text().endswith('report.html')
    dialog.close()


def test_self_test_failure_releases_project(monkeypatch):
    from patchtrace import __main__ as entry
    created = []
    real = ProjectService.sample

    def sample(root):
        service = real(root)
        service.project.sample = False  # forces the visible-sample check to fail
        created.append(service)
        return service

    monkeypatch.setattr(ProjectService, 'sample', staticmethod(sample))
    monkeypatch.setattr(sys, 'argv', ['patchtrace', '--self-test'])
    with pytest.raises(RuntimeError, match='self-test'):
        entry.main()
    assert created and created[0].store.closed


def test_corrupt_numeric_settings_fall_back_to_defaults(qtbot, tmp_path):
    settings = QSettings(str(tmp_path / 'bad.ini'), QSettings.Format.IniFormat)
    settings.setValue('desktop/font_size', 'huge')
    settings.setValue('backend/timeout', '-5')
    settings.setValue('provider/context_budget', 'abc')
    assert ui.setting_int(settings, 'desktop/font_size', 11, 8, 28) == 11
    assert ui.setting_int(settings, 'backend/timeout', 3600, 10, 86400) == 3600
    service = ui.ProjectService.sample(tmp_path / 'case')
    view = ui.MainWindow(service, settings)
    qtbot.addWidget(view)


def test_cancelled_ranking_is_not_published(tmp_path):
    import threading

    from patchtrace.enrichment import pipeline
    from patchtrace.enrichment.storage import EnrichmentStore
    service = ui.ProjectService.sample(tmp_path / 'case2')
    try:
        cancel = threading.Event()
        cancel.set()
        result = pipeline.run(service.project, None, cancel)
        assert result.status.status == 'cancelled'
        assert pipeline.publish(EnrichmentStore(service.store), service.project, result) == []
    finally:
        service.close()
