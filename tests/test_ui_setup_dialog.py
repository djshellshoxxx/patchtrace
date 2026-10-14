"""2026-10-14 audit P2: SetupDialog unsaved-profile prompt, background discovery, reject behavior."""
from __future__ import annotations

import os

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QDialog

from patchtrace.enrichment import profiles
from patchtrace.enrichment.profiles import ProfileStore
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow, SetupDialog


@pytest.fixture
def window(qtbot, tmp_path):
    service = ProjectService.sample(tmp_path / 'sample')
    settings = QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat)
    view = MainWindow(service, settings)
    qtbot.addWidget(view)
    view.show()
    yield view
    view.close()


def make_dialog(qtbot, window, tmp_path):
    store = ProfileStore(tmp_path / 'profiles')
    store.save(profiles.build({'name': 'triage', 'snapshot_max_age_days': 7}))
    dialog = SetupDialog(window.settings, window, tmp_path / 'profiles')
    qtbot.addWidget(dialog)
    dialog.profiles.reload('triage')
    return dialog, store


def test_accept_prompts_for_unsaved_profile_edits(qtbot, window, tmp_path, monkeypatch):
    dialog, store = make_dialog(qtbot, window, tmp_path)
    assert not dialog.profiles.is_dirty()
    dialog.profiles.max_age.setValue(30)
    assert dialog.profiles.is_dirty()
    asked = []
    monkeypatch.setattr(dialog.profiles, 'confirm_save', lambda name: asked.append(name) or False)
    dialog.accept()  # user chose to keep editing
    assert asked == ['triage'] and dialog.result() != QDialog.DialogCode.Accepted
    assert store.get('triage').snapshot_max_age_days == 7
    monkeypatch.setattr(dialog.profiles, 'confirm_save', lambda name: True)
    dialog.accept()
    assert dialog.result() == QDialog.DialogCode.Accepted
    assert store.get('triage').snapshot_max_age_days == 30


def test_accept_stays_open_when_profile_save_fails(qtbot, window, tmp_path, monkeypatch):
    dialog, _ = make_dialog(qtbot, window, tmp_path)
    dialog.profiles.feature_ids.setText('not-a-number')
    monkeypatch.setattr(dialog.profiles, 'confirm_save', lambda name: True)
    dialog.accept()
    assert dialog.result() != QDialog.DialogCode.Accepted
    assert dialog.tabs.currentWidget() is dialog.profiles and 'Not saved' in dialog.profiles.error.text()


def test_accept_without_edits_does_not_prompt(qtbot, window, tmp_path, monkeypatch):
    dialog, _ = make_dialog(qtbot, window, tmp_path)
    monkeypatch.setattr(dialog.profiles, 'confirm_save', lambda name: pytest.fail('prompted'))
    dialog.accept()
    assert dialog.result() == QDialog.DialogCode.Accepted


def test_discovery_runs_off_the_gui_thread(qtbot, window, tmp_path, monkeypatch):
    import threading

    from patchtrace.runtime_discovery import RuntimeCandidates
    release, seen = threading.Event(), {}
    python = tmp_path / 'py' / 'python.exe'

    def slow():
        seen['thread'] = threading.current_thread()
        release.wait(10)
        return RuntimeCandidates((python,), ())
    monkeypatch.setattr('patchtrace.ui.discover_local_runtimes', slow)
    dialog = SetupDialog(window.settings, window, tmp_path / 'profiles')
    qtbot.addWidget(dialog)
    assert dialog.python.text() == '' and 'search' in dialog.diagnostics.toPlainText().lower()
    assert not dialog.find.isEnabled()
    release.set()
    qtbot.waitUntil(lambda: dialog.python.text() == str(python), timeout=5000)
    qtbot.waitUntil(dialog.find.isEnabled, timeout=5000)
    assert seen['thread'] is not threading.main_thread()


def test_discovery_failure_is_reported_not_raised(qtbot, window, tmp_path, monkeypatch):
    def boom():
        raise OSError('disk gone')
    monkeypatch.setattr('patchtrace.ui.discover_local_runtimes', boom)
    dialog = SetupDialog(window.settings, window, tmp_path / 'profiles')
    qtbot.addWidget(dialog)
    qtbot.waitUntil(lambda: 'disk gone' in dialog.diagnostics.toPlainText(), timeout=5000)
    qtbot.waitUntil(dialog.find.isEnabled, timeout=5000)


def test_reject_during_offline_operation_cancels_it(qtbot, window, tmp_path):
    from patchtrace.ui import Worker
    dialog = SetupDialog(window.settings, window, tmp_path / 'profiles')
    qtbot.addWidget(dialog)
    qtbot.waitUntil(dialog.find.isEnabled, timeout=5000)
    dialog.show()
    dialog._busy_kind = 'offline'
    dialog.worker = Worker(lambda cancel, event: cancel.wait(10), dialog)
    dialog.worker.finished.connect(dialog._finish_offline_install)
    dialog._offline_busy(True)
    dialog.worker.start()
    dialog.reject()
    assert dialog.worker.cancel.is_set() and dialog.isVisible()
    text = dialog.diagnostics.toPlainText().lower()
    assert 'offline' in text and 'diagnosis' not in text
    qtbot.waitUntil(lambda: dialog.worker is None, timeout=5000)
    dialog.reject()
    assert not dialog.isVisible()


def test_reject_during_diagnosis_waits_with_accurate_message(qtbot, window, tmp_path):
    from patchtrace.ui import Worker
    dialog = SetupDialog(window.settings, window, tmp_path / 'profiles')
    qtbot.addWidget(dialog)
    qtbot.waitUntil(dialog.find.isEnabled, timeout=5000)
    dialog._busy_kind = 'diagnosis'
    dialog.worker = Worker(lambda cancel, event: cancel.wait(10), dialog)
    dialog.worker.finished.connect(dialog._finish_diagnosis)
    dialog.worker.start()
    dialog.reject()
    assert not dialog.worker.cancel.is_set()
    assert 'diagnosis' in dialog.diagnostics.toPlainText().lower()
    dialog.worker.cancel.set()
    qtbot.waitUntil(lambda: dialog.worker is None, timeout=5000)
