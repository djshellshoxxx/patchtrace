"""MainWindow entry integration for the local-only KB investigation workflow."""
from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QSettings

from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow


@pytest.fixture
def window(qtbot, tmp_path):
    view = MainWindow(settings=QSettings(str(tmp_path / 'entry.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(view)
    yield view
    view.worker = None
    view.close()


def test_offline_investigation_action_is_available_without_an_open_project(window, monkeypatch):
    called = []
    class Dialog:
        def exec(self):
            called.append(True)
    monkeypatch.setattr(window, 'investigation_dialog', lambda: Dialog(), raising=False)
    action = window.kb_investigation_action
    assert action.isEnabled() and 'local' in action.toolTip().lower()
    action.trigger()
    assert called == [True]


def test_investigation_entry_refuses_while_main_analysis_is_running(window, monkeypatch):
    def unexpected():
        pytest.fail('Dialog must not open while the parent analysis is running')
    monkeypatch.setattr(window, 'investigation_dialog', unexpected, raising=False)
    window.worker = object()
    try:
        window.investigate_kb()
    finally:
        window.worker = None


def _capture_dialog(window, monkeypatch):
    captured = {}
    class Dialog:
        def __init__(self, parent, **kwargs):
            captured.update(kwargs)
    monkeypatch.setitem(sys.modules, 'patchtrace.kbcorrelation.investigation_qt',
                        SimpleNamespace(InvestigationDialog=Dialog))
    window.investigation_dialog()
    return captured


def test_created_project_is_opened_on_the_gui_thread(window, monkeypatch, tmp_path):
    from PySide6.QtCore import QThread
    created = ProjectService.sample(tmp_path / 'new-comparison')
    ident = created.project.id
    created.close()
    captured = _capture_dialog(window, monkeypatch)
    assert captured['tasks'] is window.panels.tasks
    assert captured['current_project'] is None
    real_open = ProjectService.open
    def checked_open(path):
        assert QThread.currentThread() is window.thread()
        return real_open(path)
    monkeypatch.setattr(ProjectService, 'open', checked_open)
    captured['on_created'](tmp_path / 'new-comparison')
    assert window.project.id == ident


def test_late_created_project_does_not_replace_a_changed_parent(window, monkeypatch, tmp_path):
    original = ProjectService.sample(tmp_path / 'original')
    window.set_service(original)
    captured = _capture_dialog(window, monkeypatch)
    replacement = ProjectService.sample(tmp_path / 'replacement')
    window.set_service(replacement)
    captured['on_created'](tmp_path / 'retained-new-project')
    assert window.service is replacement
    assert 'retained without opening' in window.logs.toPlainText()
    reopened = ProjectService.open(tmp_path / 'original')
    reopened.close()


def test_failed_project_open_reaches_dialog_retention_handler(window, monkeypatch, tmp_path):
    captured = _capture_dialog(window, monkeypatch)
    def fail(_path):
        raise ValueError('PT-STORAGE: simulated open failure')
    monkeypatch.setattr(ProjectService, 'open', fail)
    with pytest.raises(ValueError, match='simulated open failure'):
        captured['on_created'](tmp_path / 'retained')
    assert window.service is None


def test_failed_render_restores_original_service_and_closes_candidate(window, monkeypatch, tmp_path):
    original = ProjectService.sample(tmp_path / 'original')
    window.set_service(original)
    candidate = ProjectService.sample(tmp_path / 'candidate')
    actual_refresh = window.refresh
    def refresh_then_fail():
        actual_refresh()
        if window.service is candidate:
            raise RuntimeError('simulated panel render failure')
    monkeypatch.setattr(window, 'refresh', refresh_then_fail)
    with pytest.raises(RuntimeError, match='panel render failure'):
        window.set_service(candidate)
    assert window.service is original
    assert original.store.load().id == original.project.id
    assert str(original.root) == window.settings.value('recent/project')
    with pytest.raises(ValueError, match='closed'):
        candidate.store._check_open()
    reopened = ProjectService.open(tmp_path / 'candidate')
    reopened.close()
