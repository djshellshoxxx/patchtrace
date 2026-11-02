"""Complete manual identity is computed in cancellable task work, never during Qt owner capture."""
from __future__ import annotations

import threading

import pytest
from qt_support import settings  # noqa: F401 (fixture)
from unified_s0_fixtures import make_project

from patchtrace.gui.tips import register_tips
from patchtrace.ui import MainWindow
from patchtrace.unified import keys, pipeline
from patchtrace.unified.panel import TEMPLATES, TIPS


@pytest.fixture
def manual_panel(qtbot, tmp_path, settings):  # noqa: F811
    register_tips(TIPS, TEMPLATES)
    service = make_project(tmp_path / 'project')
    removed = next(m for m in service.project.matches if m.category == 'removed')
    added = next(m for m in service.project.matches if m.category == 'added')
    service.correct_match(removed.id, [removed.older[0].id], [added.newer[0].id], 'modified', 'synthetic correction')
    window = MainWindow(service, settings, tmp_path / 'profiles')
    qtbot.addWidget(window)
    window.show()
    window.panels.show_panel('unified')
    controller = window.panels.controller('unified')
    controller.settings.set('enabled', True)
    controller.engine_busy = lambda: False
    qtbot.waitUntil(lambda: not controller.tasks.busy('unified-load'))
    yield controller, service
    window.close()
    if window.service:
        window.service.close()
        window.service = None


def watch_manual_hash(monkeypatch):
    calls = []
    original = keys.source_content_digest

    def hashing(source, snapshot, **kwargs):
        if source == 'manual':
            calls.append(threading.current_thread() is threading.main_thread())
        return original(source, snapshot, **kwargs)

    monkeypatch.setattr(keys, 'source_content_digest', hashing)
    return calls


def test_reload_never_hashes_manual_content_on_owner_thread(manual_panel, monkeypatch, qtbot):
    controller, service = manual_panel
    calls = watch_manual_hash(monkeypatch)
    manual = next(m for m in service.project.matches if m.manual)
    manual.older[0].code = 'return 57;'  # a fresh complete snapshot must be hashed, not served from the old cache
    controller.reload()
    assert True not in calls
    qtbot.waitUntil(lambda: not controller.tasks.busy('unified-load'))
    assert calls == [False] and controller.vm.state == 'U1'
    controller.reload()
    qtbot.waitUntil(lambda: not controller.tasks.busy('unified-load'))
    assert calls == [False]  # an unchanged repeat reuses the internally completed exact manual snapshot


def test_run_button_never_hashes_manual_content_on_owner_thread(manual_panel, monkeypatch, qtbot):
    controller, service = manual_panel
    calls = watch_manual_hash(monkeypatch)
    controller.start_run()
    assert True not in calls
    qtbot.waitUntil(lambda: not controller.tasks.busy('unified-run'), timeout=15000)
    assert True not in calls
    assert pipeline.recent_runs(service)[0].status == 'ok'


def test_project_close_discards_cached_snapshot_and_pending_load(manual_panel):
    controller, _service = manual_panel
    assert controller._resolved_plan is not None
    controller.project_changed(None)
    assert controller._resolved_plan is None and not controller.tasks.busy('unified-load')


def test_changed_manual_snapshot_is_stale_after_exact_key_lookup(manual_panel, qtbot):
    controller, service = manual_panel
    before = pipeline.run_unified(service, pipeline.UnifiedOptions(isolate=False, use_ir=False))
    controller.reload()
    qtbot.waitUntil(lambda: not controller.tasks.busy('unified-load'))
    assert controller.vm.result_id == before.result_id and controller.vm.state == 'U3'
    next(m for m in service.project.matches if m.manual).older[0].code = 'return 97;'
    controller.reload()
    qtbot.waitUntil(lambda: not controller.tasks.busy('unified-load'))
    assert controller.vm.state == 'U6' and controller.vm.result_id == before.result_id
    assert 'manual correction' in controller.vm.stale_reason


def test_cancel_during_run_identity_keeps_the_previous_result(manual_panel, monkeypatch, qtbot):
    controller, service = manual_panel
    baseline = pipeline.run_unified(service, pipeline.UnifiedOptions(isolate=False, use_ir=False))
    before = {p.name: p.read_bytes() for p in baseline.directory.iterdir()}
    next(m for m in service.project.matches if m.manual).older[0].code = 'return 101;'
    entered = threading.Event()
    original = keys.source_content_digest
    calls = []

    def hashing(source, snapshot, **kwargs):
        if source == 'manual':
            calls.append(source)
            if len(calls) == 1:
                entered.set()
                while not kwargs['budget'].cancel.wait(0.01):
                    kwargs['budget'].check()
        return original(source, snapshot, **kwargs)

    monkeypatch.setattr(keys, 'source_content_digest', hashing)
    controller.start_run()
    qtbot.waitUntil(entered.is_set)
    controller.cancel_run()
    qtbot.waitUntil(lambda: not controller.tasks.busy('unified-run') and not controller.tasks.busy('unified-load'))
    assert {p.name: p.read_bytes() for p in baseline.directory.iterdir()} == before
    assert [run.result_id for run in pipeline.recent_runs(service)] == [baseline.result_id]


def test_stale_plan_callback_never_reads_the_project_store(manual_panel, monkeypatch):
    controller, service = manual_panel
    from patchtrace.unified import read_model
    calls = []
    monkeypatch.setattr(read_model, 'request_from_plan', lambda *args, **kwargs: calls.append(args))
    controller._plan_loaded(service, controller.port.key(), controller._load_generation - 1,
                            False, controller._resolved_plan)
    assert calls == []
