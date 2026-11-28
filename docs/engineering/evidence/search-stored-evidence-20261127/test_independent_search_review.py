"""Independent local controls for frozen Search; no provider or analyzed file executes."""
from __future__ import annotations

import dataclasses
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication
from qt_support import join_gui_threads  # noqa: F401
from test_intel_tools_snapshot import captured as captured
from test_intel_tools_snapshot import entry, publish_tool
from test_search_wiring import add_advisory, add_cve

from patchtrace.cli import main as top_level_main
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.storage import FACTS_KIND
from patchtrace.intelligence.tools import snapshot
from patchtrace.intelligence.tools.common import RUN_KIND
from patchtrace.persistence import ProjectStore
from patchtrace.search import paths, qt_panel, wiring
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow


def invoke(capsys, root, cache, *options):
    capsys.readouterr()
    code = top_level_main(['search', str(root), '--cache-dir', str(cache), '--json', *options])
    output = capsys.readouterr()
    assert output.out.count('\n') == 1
    return code, json.loads(output.out)


def groups(doc):
    return {e['group'] for hit in doc['result']['hits'] for e in hit['evidence']}


@pytest.mark.parametrize('kind,needle,group', [
    ('string', 'StoredCaptureNeedle', 'tool:floss:newer'),
    ('advisory', 'CVE-2099-10001', 'adv'),
    ('cve', 'StoredSnapshotNeedle', 'cve'),
])
def test_top_level_dispatch_reads_stored_data_without_injected_ports(captured, tmp_path, capsys,
                                                                     kind, needle, group):
    service, _ = captured
    add_advisory(service)
    add_cve(service)
    root = service.root
    original = tuple(service.store.connection.iterdump())
    service.close()
    code, doc = invoke(capsys, root, tmp_path / 'cache', '--query', needle, '--kind', kind)
    assert code == 0 and group in groups(doc)
    with ProjectService.open(root) as reopened:
        assert tuple(reopened.store.connection.iterdump()) == original


@pytest.mark.parametrize('damage', ['advisory-file', 'cve-row', 'tool-side', 'global-budget'])
def test_default_query_cannot_certify_absence_after_known_capture_loss(captured, tmp_path, capsys,
                                                                      monkeypatch, damage):
    service, _ = captured
    if damage == 'advisory-file':
        add_advisory(service)
        row = EnrichmentStore(service.store).entries(FACTS_KIND)[0]
        (service.root / row.body['path']).write_bytes(b'authored unreadable advisory')
        expected_group = 'adv'
    elif damage == 'cve-row':
        add_cve(service)
        row = EnrichmentStore(service.store).entries('cve-snapshot')[0]
        service.store.connection.execute('UPDATE enrichment_entries SET body_sha256=? WHERE id=?',
                                         ('f' * 64, row.id))
        service.store.connection.commit()
        expected_group = 'cve'
    elif damage == 'tool-side':
        row = entry(service, RUN_KIND)
        service.store.connection.execute('UPDATE enrichment_entries SET stale=1 WHERE id=?', (row.id,))
        service.store.connection.commit()
        expected_group = 'tool:floss:newer'
    else:
        monkeypatch.setattr(snapshot, 'SNAPSHOT_ROWS', 1)
        expected_group = 'tool:floss:newer'
    root = service.root
    service.close()
    code, doc = invoke(capsys, root, tmp_path / 'cache', '--query', 'AuthoredAbsentNeedle')
    assert code == 3 and doc['status'] == 'partial' and not doc['result']['hits']
    coverage = {c['group']: c['status'] for c in doc['result']['coverage']}
    assert coverage[expected_group] == 'unavailable'


def test_optional_never_produced_tools_do_not_change_known_empty_scope(captured, tmp_path, capsys):
    service, _ = captured
    root = service.root
    service.close()
    code, doc = invoke(capsys, root, tmp_path / 'cache', '--query', 'AuthoredAbsentNeedle', '--kind', 'cve')
    assert code == 4 and doc['status'] == 'no-results'
    coverage = {c['group']: c['status'] for c in doc['result']['coverage']}
    assert coverage['tool:capa:older'] == 'unavailable' and coverage['cve'] == 'indexed'


def test_replaced_evidence_changes_default_cli_index_without_forced_rebuild(captured, tmp_path, capsys):
    service, _ = captured
    root = service.root
    service.close()
    cache = tmp_path / 'cache'
    code, original = invoke(capsys, root, cache, '--query', 'StoredCaptureNeedle', '--kind', 'string')
    assert code == 0 and groups(original) == {'tool:floss:older', 'tool:floss:newer'}
    with ProjectService.open(root) as reopened:
        publish_tool(reopened, 'newer', run_id='independent-replacement', label='IndependentReplacementNeedle')
    code, replaced = invoke(capsys, root, cache, '--query', 'IndependentReplacementNeedle', '--kind', 'string')
    assert code == 0 and groups(replaced) == {'tool:floss:newer'}
    code, old = invoke(capsys, root, cache, '--query', 'StoredCaptureNeedle', '--kind', 'string')
    assert code == 0 and groups(old) == {'tool:floss:older'}


def test_all_captured_ports_produce_documents_after_owner_close(captured, monkeypatch):
    service, _ = captured
    add_advisory(service)
    add_cve(service)
    captured_sources = wiring.snapshot_sources(service)
    service.close()

    def forbidden(*_args, **_kwargs):
        pytest.fail('value-only source unexpectedly reread a sidecar')
    monkeypatch.setattr(snapshot.ReadBudget, 'read', forbidden)

    def documents():
        return {s.group: tuple(s.documents()) for s in captured_sources.extra_specs() if s.buildable}
    with ThreadPoolExecutor(max_workers=1) as pool:
        result = pool.submit(documents).result(timeout=5)
    assert result['tool:floss:newer'] and result['adv'] and result['cve']


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
        children = [getattr(value, f.name) for f in dataclasses.fields(value)]
    else:
        children = getattr(value, '__dict__', {}).values()
    for child in children:
        reachable(child, seen)
    return seen


@pytest.fixture
def desktop(captured, tmp_path, qtbot, monkeypatch):
    service, _ = captured
    monkeypatch.setattr(paths, 'default_cache_root', lambda: tmp_path / 'cache')
    window = MainWindow(service, QSettings(str(tmp_path / 'window.ini'), QSettings.Format.IniFormat),
                        tmp_path / 'profiles')
    qtbot.addWidget(window)
    window.show()
    window.panels.show_panel('search')
    c = window.panels.controller('search')
    assert type(c) is qt_panel.SearchController

    def settle():
        qtbot.waitUntil(lambda: not window.panels.tasks.busy(), timeout=10000)
        QApplication.processEvents()
    settle()
    yield window, c, service, settle
    window.close()


def test_real_mainwindow_owner_capture_and_default_search_save_rerun(desktop, monkeypatch):
    _window, c, service, settle = desktop
    owner, captures, workers, sql_threads = threading.get_ident(), [], [], []
    capture, search_service = wiring.capture_rows, qt_panel._search_service
    service.store.connection.set_trace_callback(lambda _sql: sql_threads.append(threading.get_ident()))

    def observe_capture(*args, **kwargs):
        captures.append(threading.get_ident())
        return capture(*args, **kwargs)

    def observe_worker(bound):
        workers.append((threading.get_ident(), bound))
        return search_service(bound)

    def forbidden(*_args, **_kwargs):
        pytest.fail('desktop reopened the project store')
    monkeypatch.setattr(wiring, 'capture_rows', observe_capture)
    monkeypatch.setattr(qt_panel, '_search_service', observe_worker)
    monkeypatch.setattr(ProjectService, 'open', forbidden)
    c.source_snapshot = None
    c.panel.query.setText('StoredCaptureNeedle')
    c.debounce.stop()
    c.build()
    settle()
    assert c.result is not None and c.result.hits
    assert {e.group for h in c.result.hits for e in h.evidence} == {'tool:floss:older', 'tool:floss:newer'}
    c.saved.save_current('Independent retained strings')
    c.saved.run_selected()
    settle()
    assert c.result.hits and c.request.plan.text == 'StoredCaptureNeedle'
    assert captures and set(captures) == {owner}
    assert sql_threads and set(sql_threads) == {owner}
    assert workers and all(thread != owner for thread, _ in workers)
    for _, bound in workers:
        assert isinstance(bound, wiring.BoundService) and bound.project is not service.project
        assert not any(isinstance(item, (ProjectService, ProjectStore, sqlite3.Connection, EnrichmentStore))
                       for item in reachable(bound).values())
    service.store.connection.set_trace_callback(None)


def test_real_mainwindow_visible_rows_remain_pinned_during_changed_source_refresh(desktop, qtbot):
    _window, c, service, settle = desktop
    c.panel.query.setText('StoredCaptureNeedle')
    c.debounce.stop()
    c.build()
    settle()
    assert c.result is not None and c.result.hits
    c.panel.table.selectRow(0)
    accepted = c.result
    row = entry(service, RUN_KIND)
    service.store.connection.execute('UPDATE enrichment_entries SET stale=1 WHERE id=?', (row.id,))
    entered, release = threading.Event(), threading.Event()
    real_search = c.searcher

    def delayed(*args):
        result = real_search(*args)
        entered.set()
        assert release.wait(5)
        return result
    c.searcher = delayed
    c.submit()
    try:
        qtbot.waitUntil(entered.is_set, timeout=5000)
        assert c.result is accepted
        outcome = c.go()
        assert outcome is not None and outcome.status == 'blocked' and 'changed' in outcome.message
    finally:
        release.set()
    settle()
    assert c.result is not accepted and c.result.status == 'partial'
    assert {e.group for h in c.result.hits for e in h.evidence} == {'tool:floss:older'}


def test_real_mainwindow_pending_completion_rejected_after_unannounced_revision(desktop, qtbot):
    _window, c, service, settle = desktop
    c.build()
    settle()
    entered, release = threading.Event(), threading.Event()
    real_search = c.searcher

    def delayed(*args):
        result = real_search(*args)
        entered.set()
        assert release.wait(5)
        return result
    c.searcher = delayed
    c.panel.query.setText('StoredCaptureNeedle')
    c.submit()
    try:
        qtbot.waitUntil(entered.is_set, timeout=5000)
        service.project.revision += 1
    finally:
        release.set()
    settle()
    assert c.result is None and c.failure.code == 'PT-SEARCH-STALE'
