"""Owner-thread input capture and actual default Search panel integration."""
from __future__ import annotations

import dataclasses
import sqlite3
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from leads_support import FakeNav, FakeProject, FakeShell
from PySide6.QtWidgets import QApplication
from qt_support import join_gui_threads  # noqa: F401
from test_intel_tools_snapshot import captured as captured
from test_intel_tools_snapshot import entry, publish_tool

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.gui.qt.tasks import TaskRunner
from patchtrace.gui.registry import PanelContext
from patchtrace.intelligence.tools import store as TS
from patchtrace.intelligence.tools.common import RUN_KIND
from patchtrace.intelligence.tools.store import ToolStore
from patchtrace.persistence import ProjectStore
from patchtrace.search import paths, qt_panel, wiring
from patchtrace.search.errors import SearchError
from patchtrace.search.panel import PANEL
from patchtrace.service import ProjectService


def reachable(value, seen=None):
    seen = {} if seen is None else seen
    if id(value) in seen or isinstance(value, (str, bytes, int, float, Path, type(None))):
        return seen
    seen[id(value)] = value
    if isinstance(value, dict):
        children = (*value.keys(), *value.values())
    elif isinstance(value, (tuple, list, set, frozenset)):
        children = value
    elif dataclasses.is_dataclass(value):
        children = [getattr(value, field.name) for field in dataclasses.fields(value)]
    else:
        children = getattr(value, '__dict__', {}).values()
    for child in children:
        reachable(child, seen)
    return seen


@pytest.fixture
def rig(captured, tmp_path, qtbot, monkeypatch):
    service, store = captured
    monkeypatch.setattr(paths, 'default_cache_root', lambda: tmp_path / 'cache')
    port, shell, nav = FakeProject(service), FakeShell(TaskRunner(reraise=True)), FakeNav()
    controller = qt_panel.SearchController(PanelContext(PANEL, port, SimpleNamespace(), nav, shell))
    qtbot.addWidget(controller.panel)
    controller.panel.show()
    controller.project_changed(port.key())

    def settle():
        qtbot.waitUntil(lambda: not shell.tasks.busy(), timeout=10000)
        QApplication.processEvents()

    settle()
    yield SimpleNamespace(service=service, store=store, port=port, shell=shell, nav=nav, c=controller, settle=settle)
    controller.shutdown()
    shell.tasks.shutdown()


def query(rig, text='StoredCaptureNeedle'):
    rig.c.panel.query.setText(text)
    rig.c.submit()
    rig.settle()


def build(rig):
    rig.c.build()
    rig.settle()
    assert rig.c.failure is None


def test_normal_desktop_build_search_coverage_use_stored_sources(rig):
    build(rig)
    query(rig)
    assert rig.c.result is not None and rig.c.result.hits
    assert {e.group for hit in rig.c.result.hits for e in hit.evidence} == {'tool:floss:older', 'tool:floss:newer'}
    rig.c.show_coverage()
    assert 'tool:floss:newer | newer | indexed' in rig.c.panel.detail.toPlainText()


def test_default_desktop_query_reports_refused_retained_source_as_partial(rig):
    row = entry(rig.service, RUN_KIND, 'older')
    rig.service.store.connection.execute('UPDATE enrichment_entries SET stale=1 WHERE id=?', (row.id,))
    build(rig)
    query(rig, 'AbsentStoredNeedle')
    assert rig.c.result is not None and rig.c.result.status == 'partial' and not rig.c.result.hits


def test_capture_stays_on_owner_thread_and_worker_receives_no_stores(rig, monkeypatch):
    owner, captures, workers = threading.get_ident(), [], []
    original = wiring.snapshot_sources

    def capture(*args, **kw):
        captures.append(threading.get_ident())
        return original(*args, **kw)

    rig.c.sources = capture
    for field, call in (('searcher', qt_panel.default_search), ('builder', qt_panel.default_build),
                        ('coverage', qt_panel.default_coverage)):
        def wrap(bound, *args, original=call):
            workers.append((threading.get_ident(), bound))
            return original(bound, *args)
        setattr(rig.c, field, wrap)
    build(rig)
    query(rig)
    assert captures and set(captures) == {owner}
    assert workers and all(thread != owner for thread, _bound in workers)
    banned = (ProjectService, ProjectStore, sqlite3.Connection, EnrichmentStore, ToolStore)
    for _thread, bound in workers:
        assert isinstance(bound, wiring.BoundService)
        assert not any(isinstance(value, banned) for value in reachable(bound).values())
        assert bound.project is not rig.service.project


@pytest.mark.parametrize('damage', ['row', 'sidecar', 'project'])
def test_changed_input_while_search_is_pending_cannot_publish_old_completion(rig, monkeypatch, damage):
    if damage == 'sidecar':
        monkeypatch.setattr(TS, 'INLINE_LIMIT', 1)
        rig.store.publish_evidence(rig.store.latest('floss', 'newer')[1])
    build(rig)
    started, release = threading.Event(), threading.Event()

    def delayed(bound, request, cancel):
        result = qt_panel.default_search(bound, request, cancel)
        started.set()
        if not release.wait(5):
            raise RuntimeError('authored search gate was not released')
        return result

    rig.c.searcher = delayed
    rig.c.panel.query.setText('StoredCaptureNeedle')
    rig.c.submit()
    try:
        assert started.wait(5)
        if damage == 'row':
            row = entry(rig.service, RUN_KIND)
            rig.service.store.connection.execute('UPDATE enrichment_entries SET stale=1 WHERE id=?', (row.id,))
        elif damage == 'sidecar':
            row = entry(rig.service, 'tool-evidence')
            (rig.service.root / row.body['sidecar']).write_bytes(b'changed')
        else:
            rig.service.project.name = 'changed while pending'
    finally:
        release.set()
    rig.settle()
    assert rig.c.result is None
    assert rig.c.failure is not None and rig.c.failure.code == 'PT-SEARCH-STALE'


def test_same_revision_row_change_refreshes_next_default_search(rig):
    build(rig)
    query(rig)
    assert len(rig.c.result.hits) == 2
    publish_tool(rig.service, 'newer', run_id='replaced', label='ReplacementNeedle')
    build(rig)
    query(rig, 'ReplacementNeedle')
    assert len(rig.c.result.hits) == 1
    assert rig.c.result.hits[0].evidence[0].group == 'tool:floss:newer'


def test_visible_result_navigation_refuses_changed_stored_input(rig):
    build(rig)
    query(rig)
    rig.c.panel.table.selectRow(0)
    row = entry(rig.service, RUN_KIND)
    rig.service.store.connection.execute('UPDATE enrichment_entries SET stale=1 WHERE id=?', (row.id,))
    outcome = rig.c.go()
    assert outcome is not None and outcome.status != 'shown'
    assert not rig.nav.anchors and 'changed' in outcome.message.lower()


@pytest.mark.parametrize('completion', ['build', 'build-error', 'build-outcome-error', 'coverage', 'coverage-error'])
def test_late_operation_from_prior_inputs_does_not_replace_newer_search_state(rig, monkeypatch, completion):
    build(rig)
    pending = []
    submit = rig.shell.tasks.submit
    channel_name = 'search.coverage' if completion.startswith('coverage') else 'search.build'

    def defer(channel, fn, on_result, *args, **kw):
        if channel == channel_name:
            pending.append((on_result, args[0]))
            return None
        return submit(channel, fn, on_result, *args, **kw)

    monkeypatch.setattr(rig.shell.tasks, 'submit', defer)
    rig.c._probe_index() if channel_name == 'search.coverage' else rig.c.build()
    assert pending
    row = entry(rig.service, RUN_KIND, 'older')
    rig.service.store.connection.execute('UPDATE enrichment_entries SET stale=1 WHERE id=?', (row.id,))
    query(rig)
    assert rig.c.result is not None and rig.c.result.hits and rig.c.failure is None
    accepted = rig.c.result
    success, failure = pending[0]
    if completion.endswith('-error') and completion != 'build-outcome-error':
        failure(qt_panel.TaskFailure('AuthoredLateFailure'))
    elif completion == 'build-outcome-error':
        success(qt_panel.Outcome(code='PT-SEARCH-STORE', message='authored old failure'))
    else:
        success(()) if completion == 'coverage' else success(qt_panel.Outcome())
    assert rig.c.result is accepted and rig.c.failure is None and rig.c.progress is None


def test_old_visible_rows_remain_bound_to_their_own_inputs_during_refresh(rig):
    build(rig)
    query(rig)
    rig.c.panel.table.selectRow(0)
    started, release = threading.Event(), threading.Event()

    def delayed(bound, request, cancel):
        result = qt_panel.default_search(bound, request, cancel)
        started.set()
        if not release.wait(5):
            raise RuntimeError('authored refresh gate was not released')
        return result

    row = entry(rig.service, RUN_KIND)
    rig.service.store.connection.execute('UPDATE enrichment_entries SET stale=1 WHERE id=?', (row.id,))
    rig.c.searcher = delayed
    rig.c.submit()
    try:
        assert started.wait(5)
        outcome = rig.c.go()
        assert outcome is not None and outcome.status != 'shown' and not rig.nav.anchors
    finally:
        release.set()
    rig.settle()


@pytest.mark.parametrize('limit,value', [('PROJECT_NODES', 2), ('PROJECT_BYTES', 2), ('PROJECT_DEPTH', 1)])
def test_project_copy_budget_refuses_before_worker_submission(rig, monkeypatch, limit, value):
    monkeypatch.setattr(wiring, limit, value)
    rig.c.searcher = lambda *_args: pytest.fail('over-budget project reached worker')
    query(rig)
    assert rig.c.failure is not None and rig.c.failure.code == 'PT-SEARCH-LIMIT'


def test_copied_project_does_not_share_mutable_values(captured):
    service, _store = captured
    copied = wiring.copy_project(service.project)
    service.project.artifacts[0].name = 'owner changed'
    assert copied.artifacts[0].name != service.project.artifacts[0].name


def test_unsupported_project_values_refuse_capture():
    with pytest.raises(SearchError, match='unsupported snapshot value'):
        wiring.copy_project(SimpleNamespace(id='p', unknown=object()))
