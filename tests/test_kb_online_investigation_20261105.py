"""Consented online-advisory orchestration with authored responses; never live evidence."""
from __future__ import annotations

import json
import threading
from dataclasses import replace
from datetime import UTC, datetime
from functools import partial

import kbc_helpers as h
import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import BASELINE, FixedClock, write_pair
from test_kbc_cvrf_fetch import FEB, Opener, Resp

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.investigation_service import InvestigationRequest, execute_request
from patchtrace.kbcorrelation.sources.cvrf_fetch import fetch_months
from patchtrace.kbcorrelation.store import WorkspaceStore
from patchtrace.service import ProjectService

pytestmark = pytest.mark.usefixtures('no_sockets')
HOST = 'api.msrc.microsoft.com'
BODY = h.fixture_path(BASELINE).read_bytes()


def worker(opener):
    return partial(execute_request,
                   service_factory=lambda path: wiring.build_service(path, clock=FixedClock()),
                   source_fetcher=partial(fetch_months, opener=opener, sleep=lambda *_: None,
                                          now=lambda: datetime(2099, 2, 15, tzinfo=UTC)))


def plan_request(tmp_path, **changes):
    return replace(InvestigationRequest('plan_sources', tmp_path / 'workspace', lead='KB5099001',
                                       source_months='2099-02'), **changes)


def consent(request, result):
    return replace(request, operation='sync_sources', source_plan_json=result.data['plan_json'],
                   consent_hosts=tuple(result.data['hosts']), consent_plan=result.data['plan_sha'])


def test_preview_is_no_network_no_workspace_write_and_contains_exact_plan(tmp_path):
    opener = Opener({})
    request = plan_request(tmp_path)
    result = worker(opener)(request, threading.Event())
    assert result.success, result.text
    assert opener.calls == [] and not request.workspace.exists()
    plan = json.loads(result.data['plan_json'])
    assert FEB in result.text and HOST in result.text and result.data['plan_sha'] in result.text
    assert '\nHeader: User-Agent: PatchTrace\n' in result.text and 'Header: Accept: application/json' in result.text
    for cap in plan['caps']:
        assert cap in result.text
    assert 'unverified' in result.text


@pytest.mark.parametrize('lead', ['KB5099001', 'CVE-2099-20001'])
def test_consented_sync_returns_existing_search_scopes_and_source_provenance(tmp_path, lead):
    opener = Opener({FEB: Resp(200, BODY)})
    run, request = worker(opener), plan_request(tmp_path, lead=lead)
    preview = run(request, threading.Event())
    result = run(consent(request, preview), threading.Event())
    assert result.success and result.data['scopes'], result.text
    assert not result.data['source_partial']
    assert len(opener.calls) == 1 and opener.calls[0][1] == FEB
    assert lead not in opener.calls[0][1]
    with WorkspaceStore(request.workspace, create=False) as store:
        source, = store.sources()
        assert source.origin == 'https-fetch' and source.authenticity == 'tls-allowlisted-host'
        assert source.uri == FEB and store.read_object(source.sha256) == BODY


@pytest.mark.parametrize('change', ['no-consent', 'host', 'digest', 'months', 'duplicate-json', 'oversized-json', 'nan-json', 'unknown-field'])
def test_invalid_or_stale_consent_never_calls_transport(tmp_path, change):
    opener = Opener({})
    run, request = worker(opener), plan_request(tmp_path)
    preview = run(request, threading.Event())
    fetch = consent(request, preview)
    if change == 'no-consent':
        fetch = replace(fetch, consent_hosts=(), consent_plan='')
    elif change == 'host':
        fetch = replace(fetch, consent_hosts=(HOST, 'evil.invalid'))
    elif change == 'digest':
        fetch = replace(fetch, consent_plan='0' * 64)
    elif change == 'months':
        fetch = replace(fetch, source_months='2099-01')
    elif change == 'duplicate-json':
        fetch = replace(fetch, source_plan_json=preview.data['plan_json'][:-1] + ',"plan_sha":"' + '0' * 64 + '"}')
    elif change == 'nan-json':
        fetch = replace(fetch, source_plan_json=preview.data['plan_json'][:-1] + ',"extra":NaN}')
    elif change == 'unknown-field':
        fetch = replace(fetch, source_plan_json=preview.data['plan_json'][:-1] + ',"extra":true}')
    else:
        fetch = replace(fetch, source_plan_json=' ' * 65537)
    result = run(fetch, threading.Event())
    assert not result.success and result.error_code.startswith('PT-KBC-')
    assert opener.calls == [] and not request.workspace.exists()


def test_partial_network_failure_preserves_valid_document_and_search(tmp_path):
    opener = Opener({FEB: Resp(200, BODY)})
    run, request = worker(opener), plan_request(tmp_path, source_months='2099-01,2099-02')
    result = run(consent(request, run(request, threading.Event())), threading.Event())
    assert result.success and result.data['source_partial'] and result.data['scopes']
    assert [r['state'] for r in result.data['source_months']] == ['not-published', 'added']
    assert 'Partial advisory sync' in result.text
    with WorkspaceStore(request.workspace, create=False) as store:
        assert len(store.sources()) == 1


def test_cancel_preserves_committed_month_and_prevents_following_requests(tmp_path, monkeypatch):
    opener = Opener({FEB: Resp(200, BODY)})
    cancel = threading.Event()
    class MarchClock:
        def now_utc(self):
            return '2099-03-15T00:00:00Z'
    run = partial(execute_request,
                  service_factory=lambda p: wiring.build_service(p, clock=MarchClock()),
                  source_fetcher=partial(fetch_months, opener=opener))
    request = plan_request(tmp_path, source_months='2099-02,2099-03')
    preview = run(request, cancel)
    original = WorkspaceStore.add_document
    def add_then_cancel(store, *args):
        result = original(store, *args)
        cancel.set()
        return result
    monkeypatch.setattr(WorkspaceStore, 'add_document', add_then_cancel)
    result = run(consent(request, preview), cancel)
    assert not result.success and result.error_code == 'PT-KBC-CANCEL'
    assert len(opener.calls) == 1
    assert result.data['source_months'][0]['state'] == 'added'
    with WorkspaceStore(request.workspace, create=False) as store:
        assert len(store.sources()) == 1


def settled(qtbot, dialog):
    qtbot.waitUntil(lambda: dialog._pending is None, timeout=10000)


def test_real_dialog_explicit_preview_sync_product_pair_create_preserves_hashes(qtbot, tmp_path):
    from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
    opener, opened = Opener({FEB: Resp(200, BODY)}), []
    dialog = InvestigationDialog(workspace=tmp_path / 'workspace', execute=worker(opener), on_created=opened.append)
    qtbot.addWidget(dialog)
    try:
        dialog.fields['lead'].setText('KB5099001')
        dialog.fields['months'].setText('2099-02')
        dialog.buttons['plan_sources'].click()
        settled(qtbot, dialog)
        assert opener.calls == [] and FEB in dialog.details.toPlainText()
        assert dialog.buttons['sync_sources'].isEnabled()
        dialog.buttons['sync_sources'].click()
        settled(qtbot, dialog)
        assert len(opener.calls) == 1 and not dialog.buttons['sync_sources'].isEnabled()
        index = next(i for i in range(1, dialog.scope.count()) if 'amd64' in dialog.scope.itemText(i))
        dialog.scope.setCurrentIndex(index)
        settled(qtbot, dialog)
        old, new = write_pair(tmp_path / 'inputs')
        for key, value in (('older', old), ('newer', new), ('destination', tmp_path / 'new-project')):
            dialog.fields[key].setText(str(value))
        dialog.buttons['preview'].click()
        settled(qtbot, dialog)
        pair = dialog._preview[1].data['pair']
        dialog.buttons['create'].click()
        settled(qtbot, dialog)
        assert opened == [(tmp_path / 'new-project').resolve()]
        service = ProjectService.open(opened[0])
        try:
            assert [a.sha256 for a in service.project.artifacts] == [pair['older_sha256'], pair['newer_sha256']]
        finally:
            service.close()
        assert len(opener.calls) == 1
    finally:
        dialog.reject()


@pytest.mark.parametrize('edit', ['lead', 'months', 'workspace', 'older', 'mode', 'cancel', 'search'])
def test_dialog_edits_and_other_actions_revoke_source_plan(qtbot, tmp_path, edit):
    from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
    opener = Opener({})
    dialog = InvestigationDialog(workspace=tmp_path / 'workspace', execute=worker(opener))
    qtbot.addWidget(dialog)
    try:
        dialog.fields['lead'].setText('KB5099001')
        dialog.fields['months'].setText('2099-02')
        dialog.buttons['plan_sources'].click()
        settled(qtbot, dialog)
        assert dialog.buttons['sync_sources'].isEnabled()
        if edit == 'mode':
            dialog.manual_pair_start.setChecked(True)
        elif edit == 'cancel':
            dialog.cancel_operation()
        elif edit == 'search':
            dialog.buttons['search'].click()
            settled(qtbot, dialog)
        else:
            dialog.fields[edit].setText(dialog.fields[edit].text() + '-edited')
        assert dialog._online_plan is None and not dialog.buttons['sync_sources'].isEnabled()
        dialog.buttons['sync_sources'].click()
        assert opener.calls == []
    finally:
        dialog.reject()


@pytest.mark.parametrize('action', ['edit', 'cancel', 'close'])
def test_late_plan_cannot_restore_revoked_consent(qtbot, tmp_path, action):
    from patchtrace.gui.qt.tasks import TaskRunner
    from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
    opener = Opener({})
    run, request = worker(opener), plan_request(tmp_path)
    captured = run(request, threading.Event())
    gate, started = threading.Event(), threading.Event()
    runner = TaskRunner(reraise=True)
    def delayed(request, token):
        started.set()
        gate.wait(5)
        return captured  # Deliberately ignore cancellation to exercise the GUI generation guard.
    dialog = InvestigationDialog(workspace=request.workspace, execute=delayed, tasks=runner)
    qtbot.addWidget(dialog)
    try:
        dialog.fields['lead'].setText(request.lead)
        dialog.fields['months'].setText(request.source_months)
        dialog.buttons['plan_sources'].click()
        qtbot.waitUntil(started.is_set)
        if action == 'edit':
            dialog.fields['months'].setText('2099-01')
        elif action == 'cancel':
            dialog.cancel_operation()
        else:
            dialog.reject()
        gate.set()
        qtbot.waitUntil(lambda: not runner.busy())
        assert dialog._online_plan is None and not dialog.buttons['sync_sources'].isEnabled()
        assert opener.calls == []
    finally:
        gate.set()
        dialog.reject()
        runner.shutdown()


@pytest.mark.parametrize(('status', 'response_body'), [(200, BODY), (200, b'{"not":"an advisory"}'), (503, b'')])
def test_sync_keeps_previously_imported_source_bytes_and_authenticity(tmp_path, status, response_body):
    opener = Opener({FEB: Resp(status, response_body)})
    run, request = worker(opener), plan_request(tmp_path)
    imported = run(replace(request, operation='import', source=h.fixture_path(BASELINE)), threading.Event())
    assert imported.success
    with WorkspaceStore(request.workspace, create=False) as store:
        before = store.sources()
    result = run(consent(request, run(request, threading.Event())), threading.Event())
    assert result.success and result.data['scopes']
    assert result.data['source_partial'] == (response_body != BODY)
    with WorkspaceStore(request.workspace, create=False) as store:
        assert store.sources() == before
        assert store.read_object(before[0].sha256) == BODY
        assert before[0].authenticity == 'unverified-local-file'


@pytest.mark.parametrize('change', [
    {'lead': 'not-an-identifier'}, {'source_months': ''}, {'source_months': '2099-03'},
    {'source_months': 'x' * 4097}, {'manual_pair_start': True},
])
def test_invalid_source_scope_fails_before_network_or_workspace_creation(tmp_path, change):
    opener = Opener({})
    request = plan_request(tmp_path, **change)
    result = worker(opener)(request, threading.Event())
    assert not result.success and opener.calls == [] and not request.workspace.exists()


def test_month_plan_never_contains_project_paths_names_or_hashes(tmp_path):
    opener = Opener({FEB: Resp(200, BODY)})
    request = plan_request(tmp_path, older=tmp_path / 'sensitive-old.sys', newer=tmp_path / 'sensitive-new.sys',
                           current_project=tmp_path / 'private-project', name='private-project-name')
    run = worker(opener)
    preview = run(request, threading.Event())
    assert preview.success
    for value in (str(tmp_path), 'sensitive-old.sys', 'sensitive-new.sys', 'private-project-name', request.lead):
        assert value not in preview.text and value not in preview.data['plan_json']
    result = run(consent(request, preview), threading.Event())
    assert result.success and len(opener.calls) == 1
    assert opener.calls[0][2] == {'User-Agent': 'PatchTrace', 'Accept': 'application/json'}


def test_maximum_month_plan_remains_fully_visible_before_consent(qtbot, tmp_path):
    from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
    from patchtrace.kbcorrelation.sources.net_plan import months_since
    opener = Opener({})
    dialog = InvestigationDialog(workspace=tmp_path / 'workspace', execute=worker(opener))
    qtbot.addWidget(dialog)
    try:
        dialog.fields['lead'].setText('KB5099001')
        dialog.fields['months'].setText(','.join(months_since('2097-03', '2099-02')))
        dialog.buttons['plan_sources'].click()
        settled(qtbot, dialog)
        request, result = dialog._online_plan
        assert len(result.text) > 4000
        assert dialog.details.toPlainText() == result.text
        for item in json.loads(result.data['plan_json'])['requests']:
            assert item['url'] in dialog.details.toPlainText()
        assert dialog.buttons['sync_sources'].isEnabled() and opener.calls == []
    finally:
        dialog.reject()
