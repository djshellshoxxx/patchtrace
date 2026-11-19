"""SPEC-28 §6.1: explicit unsaved attempts, using authored outcomes and real SQLite."""
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest
from PySide6.QtGui import QGuiApplication
from qt_support import join_gui_threads as join_gui_threads
from qt_support import main_window as main_window
from qt_support import settings as settings
from test_evidence_view import mset, rz

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.secondary import evidence_panel_service as service_api
from patchtrace.secondary.evidence_view import EngineOutcomeView
from patchtrace.secondary.runs import EngineRun
from patchtrace.secondary.store import current_sets
from patchtrace.service import ProjectService


def request(window):
    controller = window.panels.controller('evidence')
    controller.auto_probe = False
    project = window.service.project
    run = service_api.latest_run(project)
    sides = {a.side: a.sha256 for a in project.artifacts}
    controller.run_generation += 1
    controller.run_request = service_api.RunRequest(
        project.id, project.revision, controller.run_generation, ('rz-diff', 'bindiff'), 1, 60,
        Path('older'), Path('newer'), sides['older'], sides['newer'], run.id)
    return controller


def view(controller, status='failed', engine='rz-diff', suffix=''):
    req = controller.run_request
    success = status in ('ok', 'cached')
    match_set = mset('rz-diff', rz(16, 32), rz(48, 64), older=req.older_sha256, newer=req.newer_sha256)
    record = EngineRun(
        run_id=f'authored-{engine}-{status}{suffix}', engine=engine,
        engine_version='0.9.1' if engine == 'rz-diff' else '8', executable_path_sha256=None,
        argv_digest='a' * 64, older_sha256=req.older_sha256, newer_sha256=req.newer_sha256,
        orientation='older->newer', cache_key='b' * 64, status=status,
        error_code=None if success else 'PT-SECONDARY-RUN', returncode=0 if success else 3,
        started_utc='2026-11-18T12:00:00Z', duration_ms=7, stderr_tail='authored stderr',
        output_sha256=match_set.file_sha256 if success else None,
        match_set_id=match_set.entry_id if success else None)
    return EngineOutcomeView(
        engine, status, version=record.engine_version, error_code=record.error_code,
        message='' if success else 'authored engine failure', stderr_tail=record.stderr_tail,
        duration_ms=record.duration_ms, run=record, run_id=record.run_id, started_utc=record.started_utc,
        match_set=match_set if success else None)


def entries(window):
    return EnrichmentStore(window.service.store).entries(kind='engine-run')


def readonly_delivery(window, controller, outcome):
    connection = window.service.store.connection
    connection.execute('PRAGMA query_only=ON')
    try:
        controller._engine_finished(outcome, controller.run_generation)
    finally:
        connection.execute('PRAGMA query_only=OFF')


def row(controller, engine='rz-diff'):
    return next(r for r in controller.panel.engine_model.rows if r.engine == engine)


def copied(controller, engine='rz-diff'):
    panel = controller.panel
    index = next(i for i, r in enumerate(panel.engine_model.rows) if r.engine == engine)
    panel.engine_table.selectRow(index)
    panel.copy_engine_details()
    return QGuiApplication.clipboard().text()


def finish(controller, outcomes, qtbot):
    controller._all_finished(tuple(outcomes), controller.run_generation)
    controller._run_finished()
    qtbot.waitUntil(lambda: controller.load_token is None, timeout=5000)


@pytest.mark.parametrize('status', ['failed', 'cancelled', 'timeout'])
def test_unsaved_attempt_survives_final_summary_reload_and_copy(main_window, qtbot, status):
    controller = request(main_window)
    outcome = view(controller, status)
    readonly_delivery(main_window, controller, outcome)
    assert entries(main_window) == []
    assert current_sets(EnrichmentStore(main_window.service.store)) == []
    assert controller.outcomes['rz-diff'].status == status
    assert controller.outcomes['rz-diff'].run is None
    assert controller.outcomes['rz-diff'].match_set is None
    assert 'not saved' in controller.panel.run_status.text().lower()
    finish(controller, [outcome], qtbot)
    assert 'not saved' in controller.panel.run_status.text().lower()
    assert f'rz-diff {status}' in controller.panel.run_status.text()
    assert 'not saved' in row(controller).detail.lower()
    assert len(row(controller).detail) <= 200
    details = copied(controller)
    assert 'not saved' in details.lower() and 'OperationalError' in details
    assert f'Status: {status}' in details and 'authored engine failure' in details
    assert 'PT-SECONDARY-RUN' in details and outcome.run.older_sha256 in details
    assert 'authored stderr' in details
    assert entries(main_window) == []  # reload did not retry publication


@pytest.mark.parametrize('status', ['failed', 'cancelled', 'timeout'])
def test_healthy_unsuccessful_attempt_is_saved_without_warning(main_window, qtbot, status):
    controller = request(main_window)
    outcome = view(controller, status)
    controller._engine_finished(outcome, controller.run_generation)
    assert len(entries(main_window)) == 1
    finish(controller, [outcome], qtbot)
    assert 'not saved' not in controller.panel.run_status.text().lower()
    assert 'not saved' not in row(controller).detail.lower()
    assert f'Status: {status}' in copied(controller)


@pytest.mark.parametrize('change', [
    {'project_id': 'different-project'}, {'older_sha256': 'f' * 64}, {'run_id': 'different-run'},
], ids=['project', 'pair', 'run'])
def test_owner_refusal_is_an_unsaved_attempt(main_window, qtbot, change):
    controller = request(main_window)
    outcome = view(controller)
    controller.run_request = dataclasses.replace(controller.run_request, **change)
    controller._engine_finished(outcome, controller.run_generation)
    assert entries(main_window) == []
    finish(controller, [outcome], qtbot)
    assert 'not saved' in controller.panel.run_status.text().lower()
    assert 'not saved' in row(controller).detail.lower()
    assert 'authored engine failure' in copied(controller)


@pytest.mark.parametrize('stored', [False, True], ids=['unsaved-ok', 'saved-ok'])
def test_kept_result_means_successfully_persisted(main_window, stored):
    controller = request(main_window)
    success, failure = view(controller, 'ok'), view(controller, engine='bindiff')
    if stored:
        controller._engine_finished(success, controller.run_generation)
    else:
        readonly_delivery(main_window, controller, success)
    before = current_sets(EnrichmentStore(main_window.service.store))
    assert len(before) == int(stored)
    readonly_delivery(main_window, controller, failure)
    assert ('rz-diff result kept' in controller.panel.run_status.text()) is stored
    assert current_sets(EnrichmentStore(main_window.service.store)) == before
    assert controller.outcomes['bindiff'].status == 'failed'


def test_failed_attempt_never_replaces_a_trusted_set(main_window):
    controller = request(main_window)
    success = view(controller, 'ok')
    controller._engine_finished(success, controller.run_generation)
    before = current_sets(EnrichmentStore(main_window.service.store))
    assert len(before) == 1
    failure = dataclasses.replace(view(controller), match_set=success.match_set)
    readonly_delivery(main_window, controller, failure)
    assert current_sets(EnrichmentStore(main_window.service.store)) == before
    assert len(entries(main_window)) == 1
    assert controller.outcomes['rz-diff'].match_set is None


def test_exception_message_is_never_a_storage_diagnostic(main_window, qtbot, monkeypatch):
    controller = request(main_window)
    outcome = view(controller)
    secret = 'private-credential-' + '<b>secret</b>\u202e' * 1000

    def refuse(*args):
        raise RuntimeError(secret)

    monkeypatch.setattr(service_api, 'persist_outcome', refuse)
    controller._engine_finished(outcome, controller.run_generation)
    finish(controller, [outcome], qtbot)
    text = '\n'.join((controller.panel.run_status.text(), row(controller).detail, copied(controller)))
    assert 'not saved' in text.lower() and 'RuntimeError' in text
    assert 'private-credential' not in text and '<b>secret</b>' not in text
    assert len(row(controller).detail) <= 200 and len(copied(controller)) < 16 * 1024
    assert controller.outcomes['rz-diff'].message == 'authored engine failure'


def test_scheduler_failure_keeps_the_unsaved_diagnostic(main_window, qtbot):
    controller = request(main_window)
    readonly_delivery(main_window, controller, view(controller))
    controller._run_failed('PT-SECONDARY-RUN: scheduler stopped', controller.run_generation)
    controller._run_finished()
    qtbot.waitUntil(lambda: controller.load_token is None, timeout=5000)
    assert 'scheduler stopped' in controller.panel.run_status.text()
    assert 'not saved' in controller.panel.run_status.text().lower()
    assert 'not saved' in row(controller).detail.lower()


@pytest.mark.parametrize('inactive', ['generation', 'request'])
def test_inactive_delivery_does_not_publish_or_display_an_attempt(main_window, inactive):
    controller = request(main_window)
    outcome = view(controller)
    generation = controller.run_generation
    if inactive == 'generation':
        generation -= 1
    else:
        controller.run_request = None
    before = controller.panel.run_status.text()
    controller._engine_finished(outcome, generation)
    assert entries(main_window) == [] and controller.outcomes == {}
    assert controller.panel.run_status.text() == before


def test_a_new_run_clears_transient_unsaved_details(main_window, qtbot, monkeypatch):
    controller = request(main_window)
    outcome = view(controller)
    readonly_delivery(main_window, controller, outcome)
    finish(controller, [outcome], qtbot)
    assert 'not saved' in copied(controller).lower()
    submitted = []
    monkeypatch.setattr(controller, '_submit_run', submitted.append)
    controller.start_run({'engines': ('rz-diff',), 'max_parallel': 1, 'timeout_s': 60})
    assert len(submitted) == 1
    assert 'not saved' not in controller.panel.run_status.text().lower()
    assert 'not saved' not in row(controller).detail.lower()
    assert not controller.panel.engine_errors
    controller._run_finished()


@pytest.mark.parametrize('switch', [False, True], ids=['close', 'switch'])
def test_project_change_clears_unsaved_details(main_window, qtbot, tmp_path, switch):
    controller = request(main_window)
    outcome = view(controller)
    readonly_delivery(main_window, controller, outcome)
    finish(controller, [outcome], qtbot)
    assert 'not saved' in copied(controller).lower()
    if switch:
        main_window.set_service(ProjectService.sample(tmp_path / 'other'))
    else:
        main_window.service.close()
        main_window.service = None
    # Hidden panels defer host refresh; exercise the same lifecycle hook explicitly.
    controller.project_changed(controller.port.key())
    assert 'not saved' not in controller.panel.run_status.text().lower()
    assert all('not saved' not in r.detail.lower() for r in controller.panel.engine_model.rows)
    assert not controller.panel.engine_errors


def test_a_later_saved_attempt_replaces_its_unsaved_notice(main_window, qtbot):
    controller = request(main_window)
    first = view(controller)
    readonly_delivery(main_window, controller, first)
    second = view(controller, suffix='-retry')
    controller._engine_finished(second, controller.run_generation)
    finish(controller, [second], qtbot)
    assert len(entries(main_window)) == 1
    assert 'not saved' not in controller.panel.run_status.text().lower()
    assert 'not saved' not in row(controller).detail.lower()
    assert 'not saved' not in copied(controller).lower()
