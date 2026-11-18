"""Actual saved-search stores under Qt: project ownership and no implicit query execution."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from leads_support import FakeNav, FakeProject, FakeShell
from PySide6.QtCore import QSettings
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
