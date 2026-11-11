"""Real service ownership and preference rollback during desktop project adoption."""
from __future__ import annotations

import pytest
from PySide6.QtCore import QSettings

from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow


@pytest.fixture
def window(qtbot, tmp_path):
    view = MainWindow(settings=QSettings(str(tmp_path / 'adoption.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(view)
    yield view
    view.close()


def closed(service):
    with pytest.raises(ValueError, match='closed'):
        service.store._check_open()


@pytest.mark.parametrize('stage', ['render', 'recent'])
def test_failed_adoption_preserves_previous_service_and_preferences(window, monkeypatch, tmp_path, stage):
    previous = ProjectService.sample(tmp_path / 'previous')
    window.set_service(previous)
    window.settings.setValue('recent/projects', [str(previous.root), '/earlier/project'])
    before = {key: window.settings.value(key) for key in ('recent/project', 'recent/projects')}
    candidate = ProjectService.sample(tmp_path / 'candidate')
    method = 'refresh' if stage == 'render' else 'refresh_recent'
    actual = getattr(window, method)

    def refresh_then_fail():
        actual()
        if window.service is candidate:
            raise RuntimeError('incoming view failed')

    monkeypatch.setattr(window, method, refresh_then_fail)
    with pytest.raises(RuntimeError, match='incoming view failed'):
        window.set_service(candidate)
    assert window.service is previous
    assert previous.store.load().id == previous.project.id
    assert {key: window.settings.value(key) for key in before} == before
    closed(candidate)
    with ProjectService.open(candidate.root):
        pass  # rejected service released its project lock


def test_failed_first_adoption_restores_absent_preferences(window, monkeypatch, tmp_path):
    candidate = ProjectService.sample(tmp_path / 'candidate')
    actual = window.refresh_recent

    def fail_after_recent_update():
        actual()
        if window.service is candidate:
            raise RuntimeError('recent view failed')

    monkeypatch.setattr(window, 'refresh_recent', fail_after_recent_update)
    with pytest.raises(RuntimeError, match='recent view failed'):
        window.set_service(candidate)
    assert window.service is None
    assert not window.settings.contains('recent/project')
    assert not window.settings.contains('recent/projects')
    closed(candidate)


def test_success_keeps_previous_open_until_render_and_preferences_finish(window, monkeypatch, tmp_path):
    previous = ProjectService.sample(tmp_path / 'previous')
    window.set_service(previous)
    candidate = ProjectService.sample(tmp_path / 'candidate')
    actual = window.refresh_recent
    checked = []

    def check_before_commit():
        assert previous.store.load().id == previous.project.id
        assert window.service is candidate
        assert window.settings.value('recent/project') == str(candidate.root)
        actual()
        checked.append(True)

    monkeypatch.setattr(window, 'refresh_recent', check_before_commit)
    window.set_service(candidate)
    assert checked == [True]
    closed(previous)
    assert candidate.store.load().id == candidate.project.id


def test_readopting_same_service_never_closes_it(window, tmp_path):
    service = ProjectService.sample(tmp_path / 'project')
    window.set_service(service)
    window.set_service(service)
    assert service.store.load().id == service.project.id
    assert window.settings.value('recent/projects', type=list) == [str(service.root)]


def test_failed_rollback_render_retains_previous_service_and_reports_diagnostic(window, monkeypatch, tmp_path):
    previous = ProjectService.sample(tmp_path / 'previous')
    window.set_service(previous)
    candidate = ProjectService.sample(tmp_path / 'candidate')

    def fail_render():
        raise RuntimeError('view unavailable')

    monkeypatch.setattr(window, 'refresh', fail_render)
    with pytest.raises(RuntimeError, match='view unavailable'):
        window.set_service(candidate)
    assert window.service is previous
    assert previous.store.load().id == previous.project.id
    assert window.settings.value('recent/project') == str(previous.root)
    assert 'Previous project retained' in window.logs.toPlainText()
    closed(candidate)
