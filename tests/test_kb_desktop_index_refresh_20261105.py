"""Desktop metadata consent and real saved-index reuse with authored responses only."""
from __future__ import annotations

import gzip
import hashlib
import json
import threading
from dataclasses import replace
from datetime import UTC, datetime
from functools import partial

import kbc_helpers as h
import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import NOW, FixedClock
from kbc_k5_support import record
from test_acquisition_transport import Opener, Resp

from patchtrace.acquisition import transport as tr
from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.investigation_service import InvestigationRequest, execute_request
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.sources.winbindex_fetch import build_plan, refresh
from patchtrace.kbcorrelation.store import WorkspaceStore

pytestmark = pytest.mark.usefixtures('no_sockets')
NAME = 'examplenet.sys'
BODY = gzip.compress(json.dumps(record(NAME)).encode(), mtime=0)


def worker(opener, **options):
    transport = tr.Transport(opener=opener, now=lambda: datetime(2099, 2, 15, tzinfo=UTC), sleep=lambda *_: None)
    return partial(execute_request, service_factory=lambda p: wiring.build_service(p, clock=FixedClock()),
                   metadata_refresher=partial(refresh, transport=transport, **options))


def request(tmp_path, **updates):
    return replace(InvestigationRequest('plan_metadata', tmp_path / 'workspace', component_name=NAME), **updates)


def consenting(asked, preview):
    return replace(asked, operation='refresh_metadata', source_plan_json=preview.data['plan_json'],
                   consent_hosts=tuple(preview.data['hosts']), consent_plan=preview.data['plan_sha'])


def test_desktop_facade_metadata_preview_is_exact_and_offline(tmp_path):
    opener = Opener()
    asked = request(tmp_path, name='private-project', older=tmp_path / 'secret.sys', lead='KB5099001')
    result = worker(opener)(asked, threading.Event())
    assert result.success, result.text
    plan = build_plan(NAME)
    assert result.data['plan_json'] == plan.to_json()
    assert plan.url in result.text and plan.plan_sha in result.text
    for field in plan.as_dict():
        assert field in result.text
    for private in (str(tmp_path), asked.name, asked.lead, 'secret.sys'):
        assert private not in result.text
    assert opener.calls == [] and not asked.workspace.exists()


def test_desktop_facade_refresh_keeps_exact_raw_receipt_and_saved_index(tmp_path):
    opener = Opener(Resp(200, BODY, {'Last-Modified': 'Thu, 12 Feb 2099 00:00:00 GMT'}))
    run, asked = worker(opener), request(tmp_path)
    preview = run(asked, threading.Event())
    result = run(consenting(asked, preview), threading.Event())
    assert result.success, result.text
    receipt = result.data['metadata']
    assert receipt['raw_sha256'] == hashlib.sha256(BODY).hexdigest()
    assert receipt['date_basis'] == 'http-last-modified' and receipt['data_date'] == '2099-02-12'
    assert receipt['raw_sha256'] in result.text and receipt['source_kind'] == 'third-party-index'
    assert (asked.workspace / receipt['stored_as']).read_bytes() == BODY
    assert wiring.WorkspaceFileIndex(asked.workspace).rows(NAME, '11-24H2')[0]
    assert opener.calls == [('GET', build_plan(NAME).url, {'User-Agent': 'PatchTrace'})]


def settled(qtbot, dialog):
    qtbot.waitUntil(lambda: dialog._pending is None, timeout=10000)


def test_actual_dialog_metadata_preview_refresh_then_saved_candidate_journey(qtbot, tmp_path):
    from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
    root = tmp_path / 'workspace'
    raw = h.read_fixture_bytes('cvrf-2099-Feb.json').replace(
        b'Example OS 24H2 x64', b'Windows 11 Version 24H2 for x64-based Systems')
    with WorkspaceStore(root) as store:
        store.add_document(import_bytes(raw, now=NOW), raw)
    opener = Opener(Resp(200, BODY))
    dialog = InvestigationDialog(workspace=root, execute=worker(opener))
    qtbot.addWidget(dialog)
    try:
        dialog.fields['lead'].setText('KB5099001')
        dialog.buttons['search'].click()
        settled(qtbot, dialog)
        scope = next(i for i in range(1, dialog.scope.count()) if 'amd64' in dialog.scope.itemText(i))
        dialog.scope.setCurrentIndex(scope)
        settled(qtbot, dialog)
        dialog.fields['component'].setText(NAME)
        dialog.buttons['plan_metadata'].click()
        settled(qtbot, dialog)
        assert opener.calls == [] and build_plan(NAME).url in dialog.details.toPlainText()
        assert dialog.buttons['refresh_metadata'].isEnabled() and not dialog.buttons['sync_sources'].isEnabled()
        dialog.buttons['refresh_metadata'].click()
        settled(qtbot, dialog)
        assert len(opener.calls) == 1 and hashlib.sha256(BODY).hexdigest() in dialog.details.toPlainText()
        for field in ('date_basis', 'source_kind', 'authenticity', 'raw_bytes', 'stored_as'):
            assert field in dialog.details.toPlainText()
        assert not dialog.buttons['refresh_metadata'].isEnabled()
        dialog.buttons['candidate_pairs'].click()
        settled(qtbot, dialog)
        assert dialog.candidates.count() > 1 and dialog.candidates.currentData() is None
        dialog.candidates.setCurrentIndex(1)
        dialog.buttons['candidate_preview'].click()
        settled(qtbot, dialog)
        assert 'Saved-index claims' in dialog.details.toPlainText()
        assert not dialog.buttons['create'].isEnabled() and len(opener.calls) == 1
    finally:
        dialog.reject()


@pytest.mark.parametrize('change', ['empty-consent', 'wrong-host', 'wrong-digest', 'filename', 'monthly-plan'])
def test_metadata_facade_refuses_stale_or_crossed_consent_before_request(tmp_path, change):
    opener = Opener()
    run, asked = worker(opener), request(tmp_path)
    preview = run(asked, threading.Event())
    captured = consenting(asked, preview)
    if change == 'empty-consent':
        captured = replace(captured, consent_hosts=(), consent_plan='')
    elif change == 'wrong-host':
        captured = replace(captured, consent_hosts=('api.msrc.microsoft.com',))
    elif change == 'wrong-digest':
        captured = replace(captured, consent_plan='0' * 64)
    elif change == 'filename':
        captured = replace(captured, component_name='exampledrv.sys')
    else:
        monthly = run(replace(asked, operation='plan_sources', lead='KB5099001', source_months='2099-02'),
                      threading.Event())
        captured = replace(captured, source_plan_json=monthly.data['plan_json'],
                           consent_hosts=tuple(monthly.data['hosts']), consent_plan=monthly.data['plan_sha'])
    result = run(captured, threading.Event())
    assert not result.success and opener.calls == [] and not asked.workspace.exists()


def test_monthly_facade_refuses_metadata_plan_without_crossing_transport(tmp_path):
    opener = Opener()
    run, asked = worker(opener), request(tmp_path)
    preview = run(asked, threading.Event())
    crossed = replace(consenting(asked, preview), operation='sync_sources', lead='KB5099001', source_months='2099-02')
    result = run(crossed, threading.Event())
    assert not result.success and opener.calls == [] and not asked.workspace.exists()


@pytest.mark.parametrize('edit', ['workspace', 'lead', 'source', 'older', 'newer', 'destination', 'name', 'months',
                                 'component', 'mode', 'same-component', 'cancel', 'search'])
def test_any_input_or_operation_revokes_metadata_consent(qtbot, tmp_path, edit):
    from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
    opener = Opener()
    dialog = InvestigationDialog(workspace=tmp_path / 'workspace', execute=worker(opener))
    qtbot.addWidget(dialog)
    try:
        dialog.fields['component'].setText(NAME)
        dialog.buttons['plan_metadata'].click()
        settled(qtbot, dialog)
        assert dialog.buttons['refresh_metadata'].isEnabled()
        if edit == 'mode':
            dialog.manual_pair_start.setChecked(True)
        elif edit == 'same-component':
            dialog.same_component.setChecked(True)
        elif edit == 'cancel':
            dialog.cancel_operation()
        elif edit == 'search':
            dialog.buttons['search'].click()
            settled(qtbot, dialog)
        else:
            dialog.fields[edit].setText(dialog.fields[edit].text() + '-edited')
        assert dialog._metadata_plan is None and dialog._online_plan is None
        assert not dialog.buttons['refresh_metadata'].isEnabled()
        dialog.buttons['refresh_metadata'].click()
        assert opener.calls == []
    finally:
        dialog.reject()


def test_only_displayed_monthly_or_index_plan_can_receive_consent(qtbot, tmp_path):
    from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
    opener = Opener()
    dialog = InvestigationDialog(workspace=tmp_path / 'workspace', execute=worker(opener))
    qtbot.addWidget(dialog)
    try:
        dialog.fields['lead'].setText('KB5099001')
        dialog.fields['months'].setText('2099-02')
        dialog.fields['component'].setText(NAME)
        dialog.buttons['plan_metadata'].click()
        settled(qtbot, dialog)
        assert dialog.buttons['refresh_metadata'].isEnabled() and dialog._online_plan is None
        assert dialog.details.toPlainText() == dialog._metadata_plan[1].text
        dialog.buttons['plan_sources'].click()
        assert not dialog.buttons['refresh_metadata'].isEnabled()
        settled(qtbot, dialog)
        assert dialog.buttons['sync_sources'].isEnabled() and dialog._metadata_plan is None
        assert dialog.details.toPlainText() == dialog._online_plan[1].text
        dialog.buttons['plan_metadata'].click()
        assert not dialog.buttons['sync_sources'].isEnabled()
        settled(qtbot, dialog)
        assert dialog.buttons['refresh_metadata'].isEnabled() and dialog._online_plan is None
        assert dialog.details.toPlainText() == dialog._metadata_plan[1].text
        assert opener.calls == []
    finally:
        dialog.reject()


@pytest.mark.parametrize('action', ['edit', 'cancel', 'close'])
def test_late_committed_metadata_is_retained_without_stale_dialog_adoption(qtbot, tmp_path, action):
    from patchtrace.gui.qt.tasks import TaskRunner
    from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
    gate, started = threading.Event(), threading.Event()
    runner = TaskRunner(reraise=True)
    def publish_after_gate(*args):
        started.set()
        gate.wait(5)
        return wiring.save_winbindex_record(*args)
    opener = Opener(Resp(200, BODY))
    root = tmp_path / 'workspace'
    dialog = InvestigationDialog(workspace=root, execute=worker(opener, publish=publish_after_gate), tasks=runner)
    qtbot.addWidget(dialog)
    try:
        dialog.fields['component'].setText(NAME)
        dialog.buttons['plan_metadata'].click()
        settled(qtbot, dialog)
        before = dialog.details.toPlainText()
        dialog.buttons['refresh_metadata'].click()
        qtbot.waitUntil(started.is_set)
        if action == 'edit':
            dialog.fields['component'].setText('other.sys')
        elif action == 'cancel':
            dialog.cancel_operation()
        else:
            dialog.reject()
        gate.set()
        # busy() excludes cancelled tasks; wait for their queued completion/drop to be delivered.
        qtbot.waitUntil(lambda: not runner._running)
        assert (root / 'winbindex' / f'{NAME}@2099-02-15.json.gz').read_bytes() == BODY
        assert dialog.details.toPlainText() == before
        assert dialog._metadata_plan is None and dialog._candidate_result is None
        assert dialog._preview is None and not dialog.buttons['create'].isEnabled()
        assert len(opener.calls) == 1
    finally:
        gate.set()
        dialog.reject()
        runner.shutdown()


@pytest.mark.parametrize('action', ['edit', 'cancel', 'close'])
def test_late_metadata_preview_cannot_restore_discarded_consent(qtbot, tmp_path, action):
    from patchtrace.gui.qt.tasks import TaskRunner
    from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
    gate, started = threading.Event(), threading.Event()
    opener = Opener()
    run = worker(opener)
    runner = TaskRunner(reraise=True)
    def delayed(request, token):
        result = run(request, token)
        started.set()
        gate.wait(5)
        return result
    dialog = InvestigationDialog(workspace=tmp_path / 'workspace', execute=delayed, tasks=runner)
    qtbot.addWidget(dialog)
    try:
        dialog.fields['component'].setText(NAME)
        dialog.buttons['plan_metadata'].click()
        qtbot.waitUntil(started.is_set)
        if action == 'edit':
            dialog.fields['component'].setText('other.sys')
        elif action == 'cancel':
            dialog.cancel_operation()
        else:
            dialog.reject()
        gate.set()
        # busy() excludes cancelled tasks; wait for their queued completion/drop to be delivered.
        qtbot.waitUntil(lambda: not runner._running)
        assert dialog._metadata_plan is None and dialog._online_plan is None
        assert not dialog.buttons['refresh_metadata'].isEnabled() and opener.calls == []
    finally:
        gate.set()
        dialog.reject()
        runner.shutdown()


@pytest.mark.parametrize('change', [{'component_name': ''}, {'component_name': '../secret.sys'},
                                   {'component_name': 'unsupported.txt'}, {'manual_pair_start': True}])
def test_invalid_or_manual_metadata_start_never_requests_or_writes(tmp_path, change):
    opener = Opener()
    asked = request(tmp_path, **change)
    result = worker(opener)(asked, threading.Event())
    assert not result.success and opener.calls == [] and not asked.workspace.exists()
