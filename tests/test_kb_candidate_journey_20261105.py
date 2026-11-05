"""Saved-index candidate inspection, not live source or binary qualification."""
from __future__ import annotations

import json
import threading
from dataclasses import replace
from functools import partial

import kbc_helpers as h
import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import NOW, FixedClock, write_pair
from kbc_k5_support import record

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.investigation_service import InvestigationRequest, execute_request
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import WorkspaceStore
from patchtrace.service import ProjectService

pytestmark = pytest.mark.usefixtures('no_sockets')
NAME = 'examplenet.sys'


def worker():
    return partial(execute_request, service_factory=lambda p: wiring.build_service(p, clock=FixedClock()))


def seed(tmp_path, *, index=True):
    root = tmp_path / 'workspace'
    raw = h.read_fixture_bytes('cvrf-2099-Feb.json').replace(
        b'Example OS 24H2 x64', b'Windows 11 Version 24H2 for x64-based Systems')
    with WorkspaceStore(root, clock=FixedClock()) as store:
        store.add_document(import_bytes(raw, now=NOW), raw)
    if index:
        folder = root / 'winbindex'
        folder.mkdir()
        (folder / f'{NAME}@2099-02-12.json').write_text(json.dumps(record(NAME)), encoding='utf-8')
    run = worker()
    search = InvestigationRequest('search', root, lead='KB5099001')
    found = run(search, threading.Event())
    scope = next(s for s in found.data['scopes'] if s['family'] == 'windows-client' and s['architecture'] == 'amd64')
    selected = replace(search, investigation_id=found.data['investigation_id'], scope_id=scope['scope_id'])
    assert run(selected, threading.Event()).success
    return run, selected


def candidate_request(selected, **updates):
    return replace(selected, operation='candidate_pairs', component_name=NAME, **updates)


def selected_request(request, result):
    return replace(request, operation='candidate_preview', candidate_pair_id=result.data['pairs'][0]['pair_id'],
                   expected_revision=result.data['investigation_revision'],
                   expected_candidates_digest=result.data['candidates_digest'])


def test_real_saved_index_candidates_preserve_claims_and_zero_request_preview(tmp_path):
    run, selected = seed(tmp_path)
    request = candidate_request(selected)
    result = run(request, threading.Event())
    assert result.success and result.data['pairs'], result.text
    candidate = result.data['pairs'][0]
    assert candidate['bytes_state'] == 'pending' and candidate['grade'] == 'A'
    assert candidate['window'] and 'WINDOW_CONFOUNDED' in candidate['reason_codes']
    assert candidate['older_index']['architectures'] == ['amd64']
    assert candidate['older_index']['record_sha256']
    assert result.data['scope']['architecture'] == 'amd64'
    with WorkspaceStore(request.workspace, create=False) as store:
        before = store.current_revision(request.investigation_id).model_dump_json()
    preview = run(selected_request(request, result), threading.Event())
    assert preview.success, preview.text
    assert preview.data['pair']['pair_id'] == candidate['pair_id']
    assert preview.data['plan']['network_requests'] == 0
    assert preview.project_path is None and 'unverified' in preview.text.lower()
    assert candidate['older_sha256'] in preview.text and candidate['newer_sha256'] in preview.text
    assert result.data['scope']['scope_id'] in preview.text
    with WorkspaceStore(request.workspace, create=False) as store:
        assert store.current_revision(request.investigation_id).model_dump_json() == before


def test_dialog_requires_explicit_candidate_selection_and_keeps_local_hash_creation(qtbot, tmp_path):
    from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
    run, selected = seed(tmp_path)
    opened = []
    dialog = InvestigationDialog(workspace=selected.workspace, execute=run, on_created=opened.append)
    qtbot.addWidget(dialog)
    try:
        dialog.fields['lead'].setText(selected.lead)
        dialog.buttons['search'].click()
        qtbot.waitUntil(lambda: dialog._pending is None)
        dialog.scope.setCurrentIndex(dialog.scope.findData(selected.scope_id))
        qtbot.waitUntil(lambda: dialog._pending is None)
        dialog.fields['component'].setText(NAME)
        dialog.buttons['candidate_pairs'].click()
        qtbot.waitUntil(lambda: dialog._pending is None)
        assert dialog.candidates.currentData() is None
        assert not dialog.buttons['candidate_preview'].isEnabled()
        dialog.candidates.setCurrentIndex(1)
        dialog.buttons['candidate_preview'].click()
        qtbot.waitUntil(lambda: dialog._pending is None)
        assert 'Saved-index claims' in dialog.details.toPlainText()
        assert dialog._preview is None and not dialog.buttons['create'].isEnabled()
        older, newer = write_pair(tmp_path / 'inputs', older_name=NAME, newer_name=NAME)
        for key, value in (('older', older), ('newer', newer), ('destination', tmp_path / 'project')):
            dialog.fields[key].setText(str(value))
        assert dialog.candidates.currentData() is None
        dialog.buttons['preview'].click()
        qtbot.waitUntil(lambda: dialog._pending is None)
        pair = dialog._preview[1].data['pair']
        dialog.buttons['create'].click()
        qtbot.waitUntil(lambda: dialog._pending is None)
        assert opened
        project = ProjectService.open(opened[0])
        try:
            assert [a.sha256 for a in project.project.artifacts] == [pair['older_sha256'], pair['newer_sha256']]
        finally:
            project.close()
    finally:
        dialog.reject()


@pytest.mark.parametrize('change', ['record-claims', 'revision', 'advisory-source', 'filename', 'pair-prefix'])
def test_changed_candidate_context_cannot_be_adopted_as_current_preview(tmp_path, change):
    run, selected = seed(tmp_path)
    request = candidate_request(selected)
    listed = run(request, threading.Event())
    captured = selected_request(request, listed)
    record_path = selected.workspace / 'winbindex' / f'{NAME}@2099-02-12.json'
    if change == 'record-claims':
        doc = json.loads(record_path.read_text())
        doc['1' * 64]['fileInfo']['description'] = 'Changed source claim with unchanged file hash'
        record_path.write_text(json.dumps(doc), encoding='utf-8')
    elif change == 'revision':
        assert run(selected, threading.Event()).success
    elif change == 'advisory-source':
        raw = h.read_fixture_bytes('cvrf-2099-Feb.json').replace(
            b'Example OS 24H2 x64', b'Windows 11 Version 24H2 for x64-based Systems') + b'\n'
        with WorkspaceStore(selected.workspace) as store:
            store.add_document(import_bytes(raw, now=NOW), raw)
    elif change == 'filename':
        captured = replace(captured, component_name='missing.sys')
    else:
        captured = replace(captured, candidate_pair_id=captured.candidate_pair_id[:12])
    result = run(captured, threading.Event())
    assert not result.success and result.error_code == 'PT-KBC-STALE'
    assert result.project_path is None


def test_record_changed_during_domain_plan_is_detected_before_publishing_preview(tmp_path, monkeypatch):
    from patchtrace.kbcorrelation.service import KbService
    run, selected = seed(tmp_path)
    request = candidate_request(selected)
    listed = run(request, threading.Event())
    path = selected.workspace / 'winbindex' / f'{NAME}@2099-02-12.json'
    original = KbService.plan
    def plan_then_replace(service, *args, **kwargs):
        result = original(service, *args, **kwargs)
        doc = json.loads(path.read_text())
        doc['2' * 64]['fileInfo']['description'] = 'Changed during plan'
        path.write_text(json.dumps(doc), encoding='utf-8')
        return result
    monkeypatch.setattr(KbService, 'plan', plan_then_replace)
    result = run(selected_request(request, listed), threading.Event())
    assert not result.success and result.error_code == 'PT-KBC-STALE'


def test_missing_saved_index_is_explicit_and_never_an_empty_success_claim(tmp_path):
    run, selected = seed(tmp_path, index=False)
    result = run(candidate_request(selected), threading.Event())
    assert result.success and result.data['pairs'] == []
    assert 'not available offline' in result.data['reason']
    assert result.project_path is None


@pytest.mark.parametrize('scope_kind', ['arm64', 'windows-server'])
def test_unsupported_scopes_keep_explicit_domain_blockers(tmp_path, scope_kind):
    run, selected = seed(tmp_path)
    found = run(replace(selected, operation='search', lead='CVE-2099-20001',
                        investigation_id=None, scope_id=None), threading.Event())
    scope = next(s for s in found.data['scopes'] if s['architecture'] == scope_kind or s['family'] == scope_kind)
    changed = replace(selected, lead='CVE-2099-20001', investigation_id=found.data['investigation_id'],
                      scope_id=scope['scope_id'])
    assert run(changed, threading.Event()).success
    result = run(candidate_request(changed), threading.Event())
    assert result.success and not result.data['pairs']
    blockers = {item for resolution in result.data['resolutions'] for item in resolution['blockers']}
    assert ('ARCH' if scope_kind == 'arm64' else 'SERVER_NOT_COVERED') in blockers


@pytest.mark.parametrize('edit', ['component', 'workspace', 'scope', 'mode', 'cancel', 'search'])
def test_dialog_invalidates_candidate_list_after_context_changes(qtbot, tmp_path, edit):
    from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
    run, selected = seed(tmp_path)
    dialog = InvestigationDialog(workspace=selected.workspace, execute=run)
    qtbot.addWidget(dialog)
    try:
        dialog.fields['lead'].setText(selected.lead)
        dialog.buttons['search'].click()
        qtbot.waitUntil(lambda: dialog._pending is None)
        dialog.scope.setCurrentIndex(dialog.scope.findData(selected.scope_id))
        qtbot.waitUntil(lambda: dialog._pending is None)
        dialog.fields['component'].setText(NAME)
        dialog.buttons['candidate_pairs'].click()
        qtbot.waitUntil(lambda: dialog._pending is None)
        dialog.candidates.setCurrentIndex(1)
        assert dialog.buttons['candidate_preview'].isEnabled()
        if edit == 'scope':
            dialog.scope.setCurrentIndex(0)
        elif edit == 'mode':
            dialog.manual_pair_start.setChecked(True)
        elif edit == 'cancel':
            dialog.cancel_operation()
        elif edit == 'search':
            dialog.buttons['search'].click()
            qtbot.waitUntil(lambda: dialog._pending is None)
        else:
            dialog.fields[edit].setText(dialog.fields[edit].text() + '-changed')
        assert dialog._candidate_result is None and dialog.candidates.currentData() is None
        assert not dialog.buttons['candidate_preview'].isEnabled()
    finally:
        dialog.reject()


@pytest.mark.parametrize('change', [{'scope_id': None}, {'scope_id': 'unknown-scope'},
                                    {'component_name': '../private.sys'}, {'manual_pair_start': True}, {'lead': 'CVE-2099-20002'}])
def test_invalid_candidate_scope_cannot_change_the_investigation(tmp_path, change):
    run, selected = seed(tmp_path)
    with WorkspaceStore(selected.workspace, create=False) as store:
        before = store.current_revision(selected.investigation_id).model_dump_json()
    request = replace(candidate_request(selected), **change)
    result = run(request, threading.Event())
    assert not result.success and result.project_path is None
    with WorkspaceStore(selected.workspace, create=False) as store:
        assert store.current_revision(selected.investigation_id).model_dump_json() == before


@pytest.mark.parametrize('action', ['edit', 'cancel', 'close'])
def test_late_candidate_result_cannot_restore_changed_context(qtbot, tmp_path, action):
    from patchtrace.gui.qt.tasks import TaskRunner
    from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
    run, selected = seed(tmp_path)
    gate, started = threading.Event(), threading.Event()
    runner = TaskRunner(reraise=True)
    def delayed(request, token):
        result = run(request, token)
        if request.operation == 'candidate_pairs':
            started.set()
            gate.wait(5)
        return result  # Deliberately ignore later cancellation for the generation guard.
    dialog = InvestigationDialog(workspace=selected.workspace, execute=delayed, tasks=runner)
    qtbot.addWidget(dialog)
    try:
        dialog.fields['lead'].setText(selected.lead)
        dialog.buttons['search'].click()
        qtbot.waitUntil(lambda: dialog._pending is None)
        dialog.scope.setCurrentIndex(dialog.scope.findData(selected.scope_id))
        qtbot.waitUntil(lambda: dialog._pending is None)
        dialog.fields['component'].setText(NAME)
        dialog.buttons['candidate_pairs'].click()
        qtbot.waitUntil(started.is_set)
        if action == 'edit':
            dialog.fields['component'].setText('other.sys')
        elif action == 'cancel':
            dialog.cancel_operation()
        else:
            dialog.reject()
        gate.set()
        qtbot.waitUntil(lambda: not runner.busy())
        assert dialog._candidate_result is None and dialog.candidates.currentData() is None
        assert not dialog.buttons['candidate_preview'].isEnabled()
    finally:
        gate.set()
        dialog.reject()
        runner.shutdown()


def test_explicit_component_result_does_not_display_other_previously_entered_files(tmp_path):
    run, selected = seed(tmp_path)
    other = 'exampledrv.sys'
    (selected.workspace / 'winbindex' / f'{other}@2099-02-12.json').write_text(json.dumps(record(other)), encoding='utf-8')
    service = wiring.build_service(selected.workspace, clock=FixedClock())
    assert service.components(selected.investigation_id, product=selected.scope_id, files=(other,)).exit == 0
    result = run(candidate_request(selected), threading.Event())
    assert result.success and result.data['pairs']
    assert all(pair['file_name'] == NAME for pair in result.data['pairs'])
    assert other not in result.text


def test_selection_change_discards_late_preview_of_a_different_real_candidate(qtbot, tmp_path):
    from copy import deepcopy

    from patchtrace.gui.qt.tasks import TaskRunner
    from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
    run, selected = seed(tmp_path)
    path = selected.workspace / 'winbindex' / f'{NAME}@2099-02-12.json'
    doc = record(NAME)
    variant = deepcopy(doc['2' * 64])
    variant['fileInfo']['sha256'] = '3' * 64
    doc['3' * 64] = variant
    path.write_text(json.dumps(doc), encoding='utf-8')
    gate, started = threading.Event(), threading.Event()
    runner = TaskRunner(reraise=True)
    def delayed(request, token):
        result = run(request, token)
        if request.operation == 'candidate_preview':
            assert result.success
            started.set()
            gate.wait(5)
        return result
    dialog = InvestigationDialog(workspace=selected.workspace, execute=delayed, tasks=runner)
    qtbot.addWidget(dialog)
    try:
        dialog.fields['lead'].setText(selected.lead)
        dialog.buttons['search'].click()
        qtbot.waitUntil(lambda: dialog._pending is None)
        dialog.scope.setCurrentIndex(dialog.scope.findData(selected.scope_id))
        qtbot.waitUntil(lambda: dialog._pending is None)
        dialog.fields['component'].setText(NAME)
        dialog.buttons['candidate_pairs'].click()
        qtbot.waitUntil(lambda: dialog._pending is None)
        assert dialog.candidates.count() == 3 and dialog.candidates.currentData() is None
        dialog.candidates.setCurrentIndex(1)
        first = dialog.candidates.currentData()
        before = dialog.details.toPlainText()
        dialog.buttons['candidate_preview'].click()
        qtbot.waitUntil(started.is_set)
        dialog.candidates.setCurrentIndex(2)
        assert dialog.candidates.currentData() != first and dialog._pending is None
        gate.set()
        qtbot.waitUntil(lambda: not runner.busy())
        assert dialog.details.toPlainText() == before
        assert dialog._preview is None and not dialog.buttons['create'].isEnabled()
        assert dialog.buttons['candidate_preview'].isEnabled()
    finally:
        gate.set()
        dialog.reject()
        runner.shutdown()


@pytest.mark.parametrize('change', ['removed-older', 'metadata-only'])
def test_atomic_index_replacement_between_pair_resolution_and_claims_is_stale(tmp_path, monkeypatch, change):
    from patchtrace.kbcorrelation.service import KbService
    run, selected = seed(tmp_path)
    original = KbService.pairs
    replaced = []
    def pairs_then_publish(service, *args, **kwargs):
        result = original(service, *args, **kwargs)
        if not replaced:
            replacement = record(NAME)
            if change == 'removed-older':
                replacement.pop('1' * 64)
            else:
                replacement['1' * 64]['fileInfo']['description'] = 'Same binary hashes, new source metadata'
            source = tmp_path / 'replacement.json'
            source.write_text(json.dumps(replacement), encoding='utf-8')
            wiring.save_winbindex_record(selected.workspace, source, NAME, '2099-02-12')
            replaced.append(True)
        return result
    monkeypatch.setattr(KbService, 'pairs', pairs_then_publish)
    result = run(candidate_request(selected), threading.Event())
    assert replaced
    assert not result.success and result.error_code == 'PT-KBC-STALE'
    assert not result.data.get('pairs')


def test_pure_plan_reuses_captured_rows_during_transient_atomic_record_replacement(tmp_path, monkeypatch):
    from patchtrace.kbcorrelation.service import KbService
    run, selected = seed(tmp_path)
    request = candidate_request(selected)
    listed = run(request, threading.Event())
    original = KbService.plan
    source = tmp_path / 'transient.json'
    def transient_record_during_plan(service, *args, **kwargs):
        changed = record(NAME)
        changed.pop('1' * 64)
        source.write_text(json.dumps(changed), encoding='utf-8')
        wiring.save_winbindex_record(selected.workspace, source, NAME, '2099-02-12')
        try:
            # The existing pure domain planner must see its captured rows, never the transient record.
            return original(service, *args, **kwargs)
        finally:
            source.write_text(json.dumps(record(NAME)), encoding='utf-8')
            wiring.save_winbindex_record(selected.workspace, source, NAME, '2099-02-12')
    monkeypatch.setattr(KbService, 'plan', transient_record_during_plan)
    preview = run(selected_request(request, listed), threading.Event())
    assert preview.success, preview.text
    assert preview.data['selected_candidate'] == listed.data['pairs'][0]
    assert preview.data['plan']['network_requests'] == 0
