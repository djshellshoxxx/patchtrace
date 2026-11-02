"""Profile navigation and inspection delivery controls for #116.

The inspection race uses a queued Qt signal across actual project adoption.
No native backend or target binary is executed.
"""
from __future__ import annotations

import pytest
from PySide6.QtCore import QObject, QSettings, Qt, Signal
from PySide6.QtWidgets import QMessageBox

from patchtrace.enrichment.profiles import AnalysisProfile, ProfileStore
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow, ProfilesPanel


def test_dirty_profile_selection_offers_cancel_without_losing_editor(qtbot, tmp_path, monkeypatch):
    store = ProfileStore(tmp_path / 'profiles')
    store.save(AnalysisProfile(name='alpha'))
    store.save(AnalysisProfile(name='beta'))
    panel = ProfilesPanel(tmp_path / 'profiles', selected='alpha')
    qtbot.addWidget(panel)
    original = panel.weights['BND'].value()
    panel.weights['BND'].setValue(original + 1)
    assert panel.is_dirty()
    asked = []
    monkeypatch.setattr(QMessageBox, 'exec', lambda box: asked.append(box.windowTitle())
                        or QMessageBox.StandardButton.Cancel)
    beta = next(i for i in range(panel.list.count())
                if panel.list.item(i).data(Qt.ItemDataRole.UserRole) == 'beta')
    panel.list.setCurrentRow(beta)
    print({'prompts': asked, 'selected': panel.selected_name(), 'weight': panel.weights['BND'].value(),
           'expected_unsaved_weight': original + 1, 'dirty': panel.is_dirty()})
    assert asked, 'changing selection discarded an unsaved editor without a decision'
    assert panel.selected_name() == 'alpha'
    assert panel.weights['BND'].value() == original + 1
    assert panel.is_dirty()


class InspectionFailure(QObject):
    failed = Signal(str, object)


def test_queued_old_inspection_failure_does_not_update_new_project(qtbot, tmp_path, monkeypatch):
    first = ProjectService.sample(tmp_path / 'first')
    window = MainWindow(first, QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(window)
    monkeypatch.setattr(window, 'start_inspection', lambda: None)
    window.show_file_overview()
    files = window.panels.controller('files')
    emitter = InspectionFailure()
    emitter.failed.connect(window._inspection_failed, Qt.ConnectionType.QueuedConnection)
    old_key = window._project_inspection_key()
    emitter.failed.emit('OldProjectFailure', old_key)
    second = ProjectService.sample(tmp_path / 'second')
    try:
        window.set_service(second)
        assert window._project_inspection_key() != old_key
        qtbot.wait(10)
        print({'current_project': window.project.id, 'old_project': old_key,
               'files_status': files.status.text(), 'inspection_error': window._inspection_error})
        assert 'OldProjectFailure' not in files.status.text()
        assert 'OldProjectFailure' not in window.logs.toPlainText()
        assert window._inspection_error is None
    finally:
        window.close()


def make_dirty_panel(qtbot, tmp_path):
    store = ProfileStore(tmp_path / 'profiles')
    store.save(AnalysisProfile(name='alpha'))
    store.save(AnalysisProfile(name='beta'))
    panel = ProfilesPanel(tmp_path / 'profiles', selected='alpha')
    qtbot.addWidget(panel)
    panel.weights['BND'].setValue(31)
    return panel


def select_beta(panel):
    panel.list.setCurrentRow(next(i for i in range(panel.list.count())
                                 if panel.list.item(i).data(Qt.ItemDataRole.UserRole) == 'beta'))


@pytest.mark.parametrize('choice,expected', [(QMessageBox.StandardButton.Save, 31),
                                            (QMessageBox.StandardButton.Discard, 30)])
def test_profile_save_or_discard_then_navigate_once(qtbot, tmp_path, monkeypatch, choice, expected):
    panel = make_dirty_panel(qtbot, tmp_path)
    prompts = []
    monkeypatch.setattr(QMessageBox, 'exec', lambda box: prompts.append(box.windowTitle()) or choice)
    select_beta(panel)
    assert prompts == ['Unsaved profile changes']
    assert panel.store.get('alpha').weights['BND'] == expected
    assert panel.selected_name() == 'beta' and not panel.is_dirty()
    assert panel.weights['BND'].value() == 30


@pytest.mark.parametrize('failure', ['storage', 'validation'])
def test_profile_save_failure_keeps_original_selection_and_editor(qtbot, tmp_path, monkeypatch, failure):
    panel = make_dirty_panel(qtbot, tmp_path)
    monkeypatch.setattr(QMessageBox, 'exec', lambda box: QMessageBox.StandardButton.Save)
    if failure == 'storage':
        def fail_save(*args, **kwargs):
            raise OSError('constructed disk-full failure')
        monkeypatch.setattr(panel.store, 'save', fail_save)
    else:
        panel.feature_ids.setText('not-a-number')
    select_beta(panel)
    assert panel.selected_name() == 'alpha'
    assert panel.weights['BND'].value() == 31 and panel.is_dirty()
    assert 'Not saved' in panel.error.text()
    assert panel.store.get('alpha').weights['BND'] == 30
    if failure == 'validation':
        assert panel.feature_ids.text() == 'not-a-number'


def test_save_and_rename_before_switch_does_not_reuse_deleted_list_item(qtbot, tmp_path, monkeypatch):
    panel = make_dirty_panel(qtbot, tmp_path)
    panel.name.setText('renamed')
    monkeypatch.setattr(QMessageBox, 'exec', lambda box: QMessageBox.StandardButton.Save)
    select_beta(panel)
    assert panel.selected_name() == 'beta'
    assert panel.store.names() == ['beta', 'renamed']
    assert panel.store.get('renamed').weights['BND'] == 31


@pytest.mark.parametrize('action', ['new_profile', 'duplicate_profile'])
def test_cancel_new_or_duplicate_preserves_unsaved_profile(qtbot, tmp_path, monkeypatch, action):
    panel = make_dirty_panel(qtbot, tmp_path)
    monkeypatch.setattr(QMessageBox, 'exec', lambda box: QMessageBox.StandardButton.Cancel)
    getattr(panel, action)()
    assert panel.selected_name() == 'alpha' and panel.is_dirty()
    assert panel.weights['BND'].value() == 31
    assert panel.store.names() == ['alpha', 'beta']


def test_profile_navigation_prompt_defaults_to_cancel_and_has_tooltips(qtbot, tmp_path, monkeypatch):
    panel = make_dirty_panel(qtbot, tmp_path)
    def inspect_prompt(box):
        assert box.textFormat() == Qt.TextFormat.PlainText
        assert box.standardButton(box.defaultButton()) == QMessageBox.StandardButton.Cancel
        assert box.standardButton(box.escapeButton()) == QMessageBox.StandardButton.Cancel
        assert all(button.toolTip() and button.accessibleDescription() for button in box.buttons())
        return QMessageBox.StandardButton.Cancel
    monkeypatch.setattr(QMessageBox, 'exec', inspect_prompt)
    select_beta(panel)
    assert panel.selected_name() == 'alpha'


@pytest.mark.parametrize('cancelled', [False, True])
def test_inspection_exception_signal_suppressed_only_after_cancellation(tmp_path, monkeypatch, cancelled):
    from patchtrace import ui_inspection

    worker = ui_inspection.InspectionThread('constructed-project', (), tmp_path, key=('original',))
    received = []
    worker.inspection_failed.connect(lambda message, key: received.append((message, key)))
    def fail_inspection(*args):
        if cancelled:
            worker.cancel.set()
        raise OSError('constructed read failure')
    monkeypatch.setattr(ui_inspection, 'inspect_project_artifacts', fail_inspection)
    worker.run()
    assert received == ([] if cancelled else [('OSError', ('original',))])
