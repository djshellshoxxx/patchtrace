"""Actual saved-search stores under Qt: project ownership and no implicit query execution."""
from __future__ import annotations

from threading import Event
from types import SimpleNamespace

import pytest
from leads_support import FakeNav, FakeProject, FakeShell
from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QDialog

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.gui.qt.settings import PanelSettings
from patchtrace.gui.qt.tasks import TaskRunner
from patchtrace.gui.registry import PanelContext
from patchtrace.search.contracts import SearchResult
from patchtrace.search.panel import PANEL
from patchtrace.search.qt_panel import SearchController
from patchtrace.search.saved import EnrichmentSavedStore
from patchtrace.service import ProjectService


@pytest.fixture
def rig(qtbot, tmp_path):
    services = [ProjectService.sample(tmp_path / 'first')]
    port = FakeProject(services[0])
    shell = FakeShell(TaskRunner(reraise=True))
    shell.settings = PanelSettings(QSettings(str(tmp_path / 'settings.ini'), QSettings.Format.IniFormat), 'search')
    calls = []

    def search(_service, request, _cancel):
        calls.append(request)
        return SearchResult(status='no-results')

    controller = SearchController(PanelContext(PANEL, port, SimpleNamespace(), FakeNav(), shell),
                                  searcher=search, coverage=lambda _s: (),
                                  builder=lambda *_: pytest.fail('saved action built the index'))
    qtbot.addWidget(controller.panel)
    controller.panel.show()
    controller.project_changed(port.key())
    qtbot.waitUntil(lambda: not shell.tasks.busy())
    yield SimpleNamespace(controller=controller, port=port, shell=shell, calls=calls, services=services)
    controller.shutdown()
    shell.tasks.shutdown()
    for service in services:
        service.close()


def prepare(controller, text='read_item', mode='exact', side='older', scope='changed'):
    panel = controller.panel
    for widget in (panel.query, panel.mode, panel.side, panel.scope):
        widget.blockSignals(True)
    panel.query.setText(text)
    for widget, value in ((panel.mode, mode), (panel.side, side), (panel.scope, scope)):
        widget.setCurrentIndex(widget.findData(value))
    for widget in (panel.query, panel.mode, panel.side, panel.scope):
        widget.blockSignals(False)


def test_save_select_run_delete_and_recent_recall_are_explicit(rig, qtbot):
    c = rig.controller
    prepare(c)
    c.saved.save_current('My exact query')
    assert not rig.calls
    assert c.saved.widgets.saved.count() == 1
    item = EnrichmentSavedStore(EnrichmentStore(rig.port.service.store), rig.port.service.project.id).list().items[0]
    assert item.mode == 'exact'
    c.saved.refresh()
    assert not rig.calls
    c.saved.run_selected()
    qtbot.waitUntil(lambda: len(rig.calls) == 1 and not rig.shell.tasks.busy())
    plan = rig.calls[0].plan
    assert plan.mode == 'exact' and plan.sides == ('older',) and plan.scope == 'changed'
    c.saved.recall_recent(1)
    qtbot.wait(350)
    assert len(rig.calls) == 1 and c.panel.mode.currentData() == 'auto'
    c.saved.delete_selected()
    assert c.saved.widgets.saved.count() == 0 and len(rig.calls) == 1
    c.saved.clear_recent()
    assert c.saved.recent.items() == ()


def test_save_dialog_project_change_cannot_write_either_project(rig, tmp_path, monkeypatch):
    c = rig.controller
    prepare(c)
    first = rig.port.service

    def changed():
        replacement = ProjectService.sample(tmp_path / 'second')
        rig.services.append(replacement)
        rig.port.service = replacement
        c.project_changed(rig.port.key())
        c.saved.widgets.name_dialog.name.setText('Wrong project')
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(c.saved.widgets.name_dialog, 'exec', changed)
    c.saved.save_current()
    for service in (first, rig.port.service):
        assert EnrichmentSavedStore(EnrichmentStore(service.store), service.project.id).list().items == ()
    assert not rig.calls


def test_deleted_selection_cannot_execute_and_old_epoch_cannot_delete(rig):
    c = rig.controller
    prepare(c)
    c.saved.save_current('Query')
    token = c.saved.owner()
    saved_id = c.saved.widgets.saved.currentData()
    store = EnrichmentSavedStore(EnrichmentStore(rig.port.service.store), rig.port.service.project.id)
    assert store.delete(saved_id)
    c.saved.run_selected()
    assert not rig.calls
    c.saved.save_current('Replacement')
    c.project_changed(rig.port.key())
    c.saved.delete_selected(owner=token)
    assert len(store.list().items) == 1


def test_recent_settings_failures_do_not_break_a_query(rig, qtbot, monkeypatch):
    prepare(rig.controller)
    monkeypatch.setattr(rig.shell.settings, 'set', lambda *_: (_ for _ in ()).throw(OSError('settings unavailable')))
    rig.controller.submit()
    qtbot.waitUntil(lambda: len(rig.calls) == 1)
    assert rig.calls[0].plan.mode == 'exact'


def test_failed_recent_clear_does_not_claim_history_was_deleted(rig, monkeypatch):
    saved = rig.controller.saved
    saved.remember('read_item')
    monkeypatch.setattr(rig.shell.settings, 'set', lambda *_: (_ for _ in ()).throw(OSError('settings unavailable')))
    saved.clear_recent()
    assert saved.recent.items() == ('read_item',)
    assert 'could not' in saved.widgets.note.text().lower()


@pytest.mark.parametrize('recall', [False, True])
def test_delayed_build_only_submits_its_original_query_generation(rig, qtbot, recall):
    """Retained independent review race, with normal Build and explicit Enter controls."""
    c = rig.controller
    prepare(c, 'old_query')
    c.saved.remember('new_query')
    started, release = Event(), Event()
    coverage_calls = []

    def build(_service, _cancel, _progress):
        started.set()
        if not release.wait(5):
            raise RuntimeError('test build was not released')

    def coverage(_service):
        coverage_calls.append(True)
        return ()

    c.builder, c.coverage = build, coverage
    c.build()
    try:
        qtbot.waitUntil(started.is_set)
        if recall:
            c.saved.recall_recent(1)
            assert c.panel.query.text() == 'new_query'
        release.set()
        qtbot.waitUntil(lambda: not rig.shell.tasks.busy(), timeout=7000)
        qtbot.wait(350)
        assert coverage_calls == [True] and c.progress is None
        if recall:
            assert rig.calls == [], 'an older build executed recalled text without Enter'
            qtbot.keyClick(c.panel.query, Qt.Key.Key_Return)
            qtbot.waitUntil(lambda: len(rig.calls) == 1 and not rig.shell.tasks.busy())
            assert rig.calls[0].plan.text == 'new_query'
        else:
            assert len(rig.calls) == 1 and rig.calls[0].plan.terms[0].nfc == 'old_query'
    finally:
        release.set()


def test_real_default_search_build_save_run_and_reopen_without_extra_owner(qtbot, tmp_path, monkeypatch):
    from patchtrace.search import paths
    from patchtrace.ui import MainWindow

    cache = tmp_path / 'search-cache'
    monkeypatch.setattr(paths, 'default_cache_root', lambda: cache)
    service = ProjectService.sample(tmp_path / 'real-project')
    root = service.root
    window = MainWindow(service, QSettings(str(tmp_path / 'real.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(window)
    window.show()
    window.panels.show_panel('search')
    c = window.panels.controller('search')
    qtbot.waitUntil(lambda: not window.panels.tasks.busy())
    prepare(c, side='newer')
    before = tuple(sorted(path.relative_to(cache) for path in cache.rglob('*') if path.is_file()))
    original_open = ProjectService.open

    def forbidden(_path):
        pytest.fail('GUI saved action opened another project service')

    monkeypatch.setattr(ProjectService, 'open', forbidden)
    c.saved.save_current('Real exact query')
    assert c.result is None
    assert tuple(sorted(path.relative_to(cache) for path in cache.rglob('*') if path.is_file())) == before
    c.build()  # explicit normal search action; only this action may build the local index
    qtbot.waitUntil(lambda: c.result is not None and not window.panels.tasks.busy(), timeout=10000)
    c.saved.run_selected()
    qtbot.waitUntil(lambda: c.result is not None and not window.panels.tasks.busy(), timeout=10000)
    assert c.result.hits and c.request.plan.mode == 'exact' and c.request.plan.sides == ('newer',)
    assert all(evidence.side == 'newer' for hit in c.result.hits for evidence in hit.evidence)
    window.close()
    monkeypatch.setattr(ProjectService, 'open', original_open)
    reopened = ProjectService.open(root)
    try:
        items = EnrichmentSavedStore(EnrichmentStore(reopened.store), reopened.project.id).list().items
        assert len(items) == 1 and items[0].mode == 'exact'
    finally:
        reopened.close()
