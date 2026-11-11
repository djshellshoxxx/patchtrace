"""Product-first local comparison journeys; real stores, authored documents/PEs, denied sockets."""
from __future__ import annotations

import base64
import gzip
import json
import threading
from dataclasses import replace
from functools import partial

import kbc_helpers as h
import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import BASELINE, NOW, FixedClock, write_pair
from test_kb_investigation_service import run
from test_ui_kb_investigation import settled

from patchtrace.kbcorrelation import service as domain
from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
from patchtrace.kbcorrelation.investigation_service import InvestigationRequest, execute_request
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService

pytestmark = pytest.mark.usefixtures('no_sockets')


@pytest.fixture
def loaded(tmp_path):
    root = tmp_path / 'workspace'
    raw = h.read_fixture_bytes(BASELINE)
    doc = import_bytes(raw, now=NOW)
    with WorkspaceStore(root) as store:
        store.add_document(doc, raw)
    return root, raw, doc


def catalogue(root, **kwargs):
    return run(InvestigationRequest('browse_products', root, product_start=True, **kwargs))


def chosen(loaded, tmp_path):
    root, _, _ = loaded
    listed = catalogue(root)
    assert listed.success, listed.text
    scope = next(s for s in listed.data['products'] if s['architecture'] == 'amd64')
    old, new = write_pair(tmp_path / 'inputs')
    return InvestigationRequest('preview', root, product_start=True, scope_id=scope['scope_id'],
                                product_scope_json=json.dumps(scope),
                                product_source_snapshot=tuple(listed.data['source_snapshot']), older=old, newer=new)


def create_request(asked, preview, tmp_path):
    return replace(asked, operation='create', destination=tmp_path / 'comparison',
                   expected_pair_id=preview.data['pair']['pair_id'])


def add_revision(loaded):
    root, raw, _ = loaded
    changed = json.loads(raw)
    changed['document']['current_release_date'] = '2099-02-14'
    body = json.dumps(changed).encode()
    doc = import_bytes(body, now=NOW)
    with WorkspaceStore(root) as store:
        assert store.add_document(doc, body)
    return doc


def test_catalogue_has_real_source_identity_and_does_not_create_investigation(loaded):
    root, raw, doc = loaded
    result = catalogue(root)
    assert result.success, result.text
    assert result.data['products'] and not result.data['truncated']
    assert result.data['total_matches'] == len(result.data['products'])
    assert {ref['doc_id'] for product in result.data['products'] for ref in product['source_product_ids']} == {
        doc.doc_id}
    assert result.data['source_snapshot'] == (doc.source.model_dump_json(),)
    assert 'no KB/CVE' in result.text
    with WorkspaceStore(root) as store:
        assert store.read_object(doc.source.sha256) == raw
        assert store.db.execute('SELECT COUNT(*) FROM investigations').fetchone()[0] == 0
        assert store.db.execute('SELECT COUNT(*) FROM coverage').fetchone()[0] == 0


def test_product_preview_and_create_preserve_scope_and_sources_without_attribution(loaded, tmp_path):
    asked = chosen(loaded, tmp_path)
    preview = run(asked)
    assert preview.success, preview.text
    assert preview.data['investigation_revision'] is None
    assert preview.data['selected_product']['scope_id'] == asked.scope_id
    with WorkspaceStore(asked.workspace) as store:
        assert store.db.execute('SELECT COUNT(*) FROM investigations').fetchone()[0] == 0
    create = create_request(asked, preview, tmp_path)
    made = run(create)
    assert made.success, made.text
    with ProjectService.open(made.project_path) as project:
        assert len(project.project.artifacts) == 2
        assert {a.sha256 for a in project.project.artifacts} == {
            preview.data['pair']['older_sha256'], preview.data['pair']['newer_sha256']}
    with WorkspaceStore(asked.workspace) as store:
        revision = store.current_revision(made.data['investigation_id'])
        assert revision.lead.kind == 'pair'
        assert revision.selected_scope_id == asked.scope_id and revision.scope_ids == (asked.scope_id,)
        assert revision.coverage_ids
        decision = next(d for d in store.decisions(revision.investigation_id) if d.op == 'product-selection')
        assert decision.next == asked.scope_id and 'analyst' in decision.reason.lower()
    service = wiring.build_service(asked.workspace, clock=FixedClock())
    bundle, = service._project_bundles(str(made.project_path))
    assert bundle.scope_id == asked.scope_id and bundle.lead.kind == 'pair'
    assert not bundle.context.cards and not bundle.cwe_profiles and not bundle.hypotheses and not bundle.card_facts
    assert bundle.context.coverage and 'No KB/CVE' in ' '.join(bundle.context.unknowns)
    assert {s.sha256 for s in bundle.sources} == {loaded[2].source.sha256}
    sidecar, = (made.project_path / 'kb' / 'sources').glob('*.json.gz')
    envelope = json.loads(gzip.decompress(sidecar.read_bytes()))
    assert base64.b64decode(envelope['bytes']) == loaded[1]
    assert envelope['source']['doc_id'] == loaded[2].doc_id


def pending_product_attach(loaded, tmp_path):
    asked = chosen(loaded, tmp_path)
    preview = run(asked)
    assert preview.success, preview.text

    def fail_row(point):
        if point == 'attach_before_row':
            raise KbcStoreError('PT-KBC-STORAGE', 'authored context-row interruption')

    result = execute_request(create_request(asked, preview, tmp_path), threading.Event(),
                             service_factory=lambda p: wiring.build_service(p, clock=FixedClock(), fault=fail_row))
    assert result.project_path is not None and result.data['project']['state'] == 'context-pending'
    return result


@pytest.mark.parametrize('newer_revision', [False, True])
def test_product_context_repair_preserves_original_sources(loaded, tmp_path, newer_revision):
    pending = pending_product_attach(loaded, tmp_path)
    if newer_revision:
        add_revision(loaded)
    service = wiring.build_service(loaded[0], clock=FixedClock())
    result = service.attach(str(pending.project_path), pending.data['investigation_id'], repair_it=True)
    assert result.exit == 0, result.text
    bundle, = service._project_bundles(str(pending.project_path))
    assert {source.doc_id for source in bundle.sources} == {loaded[2].doc_id}
    assert not bundle.context.cards
    for source in bundle.sources:
        sidecar = pending.project_path / 'kb' / 'sources' / f'{source.sha256}.json.gz'
        envelope = json.loads(gzip.decompress(sidecar.read_bytes()))
        assert envelope['source']['doc_id'] == source.doc_id
        assert base64.b64decode(envelope['bytes']) == loaded[1]
    assert service.attach(str(pending.project_path), pending.data['investigation_id'], repair_it=True).exit == 0
    assert service._project_bundles(str(pending.project_path)) == [bundle]


def test_product_context_repair_refuses_missing_original_sources(loaded, tmp_path):
    pending = pending_product_attach(loaded, tmp_path)
    add_revision(loaded)
    with WorkspaceStore(loaded[0]) as store:
        store.object_path(loaded[2].source.sha256).unlink()
        before = store.current_revision(pending.data['investigation_id'])
    service = wiring.build_service(loaded[0], clock=FixedClock())
    with pytest.raises(KbcStoreError) as raised:
        service.attach(str(pending.project_path), pending.data['investigation_id'], repair_it=True)
    assert raised.value.code == 'PT-KBC-STALE'
    assert service._project_bundles(str(pending.project_path)) == []
    with WorkspaceStore(loaded[0]) as store:
        assert store.current_revision(pending.data['investigation_id']) == before
    with ProjectService.open(pending.project_path) as project:
        assert len(project.project.artifacts) == 2


def test_product_context_repair_refuses_changed_alias_interpretation(loaded, tmp_path, monkeypatch):
    from patchtrace.kbcorrelation import alias_catalog

    pending = pending_product_attach(loaded, tmp_path)
    monkeypatch.setattr(alias_catalog, 'ALIAS_CATALOG_VERSION', alias_catalog.ALIAS_CATALOG_VERSION + 1)
    service = wiring.build_service(loaded[0], clock=FixedClock())
    with pytest.raises(KbcStoreError) as raised:
        service.attach(str(pending.project_path), pending.data['investigation_id'], repair_it=True)
    assert raised.value.code == 'PT-KBC-STALE'
    assert service._project_bundles(str(pending.project_path)) == []
    with WorkspaceStore(loaded[0]) as store:
        assert store.current_revision(pending.data['investigation_id']).state == 'CONTEXT_PENDING'


@pytest.mark.parametrize('damage', ['missing-snapshot', 'malformed-snapshot', 'missing-refs', 'missing-hashes',
                                    'null-hashes', 'invalid-hashes', 'changed-lead'])
def test_product_context_repair_refuses_incomplete_journal_provenance(loaded, tmp_path, damage):
    pending = pending_product_attach(loaded, tmp_path)
    with WorkspaceStore(loaded[0]) as store:
        op, state, body = store.journal_ops()[0]
        assert body['selected_product']['scope_id'] == body['revision']['selected_scope_id']
        if damage == 'missing-snapshot':
            body.pop('selected_product')
        elif damage == 'malformed-snapshot':
            body['selected_product'] = []
        elif damage == 'missing-refs':
            body['selected_product']['source_product_ids'] = []
        elif damage == 'missing-hashes':
            body['source_shas'] = []
        elif damage == 'null-hashes':
            body['source_shas'] = None
        elif damage == 'invalid-hashes':
            body['source_shas'] = [{}]
        else:
            body['revision']['lead'] = {'kind': 'cve', 'value': 'CVE-2099-20001', 'raw': 'CVE-2099-20001'}
        store.journal_put(op, state, body)
        before = store.current_revision(pending.data['investigation_id'])
    service = wiring.build_service(loaded[0], clock=FixedClock())
    with pytest.raises(KbcStoreError) as raised:
        service.attach(str(pending.project_path), pending.data['investigation_id'], repair_it=True)
    assert raised.value.code == 'PT-KBC-STALE'
    assert service._project_bundles(str(pending.project_path)) == []
    with WorkspaceStore(loaded[0]) as store:
        assert store.current_revision(pending.data['investigation_id']) == before
        assert store.journal_get(op) == (state, body)


def test_real_dialog_starts_from_product_without_kb_or_cve(qtbot, loaded, tmp_path):
    opened = []
    execute = partial(execute_request, service_factory=lambda p: wiring.build_service(p, clock=FixedClock()))
    dialog = InvestigationDialog(workspace=loaded[0], execute=execute, on_created=opened.append)
    qtbot.addWidget(dialog)
    try:
        dialog.product_start.setChecked(True)
        assert not dialog.fields['lead'].isEnabled()
        assert dialog.buttons['browse_products'].isEnabled()
        for key in ('plan_sources', 'sync_sources', 'plan_metadata', 'refresh_metadata', 'candidate_pairs'):
            assert not dialog.buttons[key].isEnabled()
        dialog.buttons['browse_products'].click()
        settled(qtbot, dialog)
        assert dialog.scope.count() > 1 and dialog.scope.currentData() is None
        assert not dialog.buttons['preview'].isEnabled()
        selected = next(i for i in range(1, dialog.scope.count()) if 'amd64' in dialog.scope.itemText(i))
        dialog.scope.setCurrentIndex(selected)
        assert dialog._investigation_id is None
        old, new = write_pair(tmp_path / 'inputs')
        for key, value in (('older', old), ('newer', new), ('destination', tmp_path / 'comparison')):
            dialog.fields[key].setText(str(value))
        dialog.buttons['preview'].click()
        settled(qtbot, dialog)
        assert dialog._preview is not None, dialog.status.full_text()
        assert 'no KB/CVE' in dialog.details.toPlainText()
        assert dialog.buttons['create'].isEnabled()
        dialog.buttons['create'].click()
        settled(qtbot, dialog)
        assert opened == [(tmp_path / 'comparison').resolve()]
        with ProjectService.open(opened[0]):
            pass
    finally:
        dialog.reject()


@pytest.mark.parametrize('updates', [{'scope_id': None}, {'product_scope_json': None},
                                   {'product_source_snapshot': None}, {'scope_id': 'f' * 64},
                                   {'investigation_id': 'earlier'}, {'expected_revision': 1},
                                   {'manual_pair_start': True}, {'product_start': False}])
def test_product_selection_cannot_be_missing_or_crossed_with_another_start(loaded, tmp_path, updates):
    asked = chosen(loaded, tmp_path)
    result = run(replace(asked, **updates))
    assert not result.success
    with WorkspaceStore(asked.workspace) as store:
        assert store.db.execute('SELECT COUNT(*) FROM investigations').fetchone()[0] == 0


@pytest.mark.parametrize('operation', ['search', 'candidate_pairs', 'candidate_preview',
                                    'plan_sources', 'sync_sources', 'plan_metadata', 'refresh_metadata'])
def test_product_start_cannot_use_advisory_or_download_routes(loaded, operation):
    result = run(InvestigationRequest(operation, loaded[0], product_start=True, lead='KB5099001',
                                      component_name='exampledrv.sys', source_months='2099-02'))
    assert not result.success and result.error_code == 'PT-KBC-INPUT'


def test_catalogue_filter_is_explicit_and_empty_results_preserve_workspace(loaded):
    all_rows = catalogue(loaded[0])
    scope = all_rows.data['products'][0]
    match = catalogue(loaded[0], product_query=scope['scope_id'])
    assert [row['scope_id'] for row in match.data['products']] == [scope['scope_id']]
    absent = catalogue(loaded[0], product_query='no matching product in this authored fixture')
    assert absent.success and absent.data['products'] == [] and absent.data['total_matches'] == 0
    assert 'no matching' in absent.text.lower()


@pytest.mark.parametrize('query', ['x' * 201, None, 3])
def test_invalid_product_filter_is_refused(loaded, query):
    result = catalogue(loaded[0], product_query=query)
    assert not result.success and result.error_code == 'PT-KBC-INPUT'


def test_catalogue_caps_real_imported_products_and_reports_truncation(tmp_path):
    body = h.cvrf_document([], products=[
        {'product_id': f'PT-{i:03}', 'name': f'Authored product {i:03} x64', 'architecture': 'amd64'}
        for i in range(205)])
    raw = json.dumps(body).encode()
    root = tmp_path / 'workspace'
    with WorkspaceStore(root) as store:
        store.add_document(import_bytes(raw, now=NOW), raw)
    result = catalogue(root)
    assert result.success and len(result.data['products']) == 200
    assert result.data['total_matches'] == 205 and result.data['truncated']
    assert 'Refine' in result.text
    last = catalogue(root, product_query='Authored product 204')
    assert last.success and len(last.data['products']) == 1 and not last.data['truncated']


def test_superseded_product_does_not_revive_after_newer_raw_source_becomes_unreadable(loaded):
    root, raw, doc = loaded
    removed = next(scope for scope in doc.scopes if scope.architecture == 'arm64')
    changed = json.loads(raw)
    changed['document']['current_release_date'] = '2099-02-14'
    changed['product_tree'] = [row for row in changed['product_tree'] if row['architecture'] != 'arm64']
    body = json.dumps(changed).encode()
    newer = import_bytes(body, now=NOW)
    with WorkspaceStore(root) as store:
        store.add_document(newer, body)
    before = catalogue(root)
    assert before.success and removed.scope_id not in {s['scope_id'] for s in before.data['products']}
    with WorkspaceStore(root) as store:
        store.object_path(newer.source.sha256).unlink()
    after = catalogue(root)
    assert not after.success and after.error_code == 'PT-KBC-VERIFY'


@pytest.mark.parametrize('zoned', [False, True], ids=['unknown-order', 'tied-instants'])
def test_unreadable_native_revision_never_yields_a_partial_product_catalogue(tmp_path, zoned):
    from test_kbc_msrc_review_findings import _snapshots

    root = tmp_path / 'workspace'
    docs = []
    with WorkspaceStore(root) as store:
        for body in _snapshots(zoned=zoned):
            raw = json.dumps(body).encode()
            doc = import_bytes(raw, now=NOW)
            docs.append(doc)
            store.add_document(doc, raw)
    before = catalogue(root)
    assert before.success
    assert {ref['doc_id'] for row in before.data['products'] for ref in row['source_product_ids']} == {
        doc.doc_id for doc in docs}
    with WorkspaceStore(root) as store:
        store.object_path(docs[1].source.sha256).unlink()
    after = catalogue(root)
    assert not after.success and after.error_code == 'PT-KBC-VERIFY'


def test_missing_workspace_is_not_created_by_product_browse(tmp_path):
    root = tmp_path / 'missing'
    result = catalogue(root)
    assert not result.success and not root.exists()


def test_product_admission_refuses_unreadable_unselected_source(loaded, tmp_path):
    root, raw, _ = loaded
    changed = json.loads(raw)
    changed['document'].update(release_id='2099-Jan', current_release_date='2099-01-10',
                               tracking_id='PT-CVRF-2099-Jan')
    changed['product_tree'] = [row for row in changed['product_tree'] if row['family'] == 'windows-server']
    body = json.dumps(changed).encode()
    extra = import_bytes(body, now=NOW)
    with WorkspaceStore(root) as store:
        store.add_document(extra, body)
    asked = chosen(loaded, tmp_path)
    assert extra.doc_id not in {ref['doc_id'] for ref in json.loads(asked.product_scope_json)['source_product_ids']}
    preview = run(asked)
    assert preview.success, preview.text
    with WorkspaceStore(root) as store:
        store.object_path(extra.source.sha256).unlink()
    create = create_request(asked, preview, tmp_path)
    result = run(create)
    assert not result.success and result.error_code == 'PT-KBC-STALE'
    assert not create.destination.exists()


def test_product_record_rejects_duplicate_json_keys(loaded, tmp_path):
    asked = chosen(loaded, tmp_path)
    duplicate = '{"scope_id":"' + asked.scope_id + '",' + asked.product_scope_json[1:]
    result = run(replace(asked, product_scope_json=duplicate))
    assert not result.success
    with WorkspaceStore(loaded[0]) as store:
        assert store.db.execute('SELECT COUNT(*) FROM investigations').fetchone()[0] == 0


def test_product_create_still_requires_exact_pair_preview(loaded, tmp_path):
    asked = chosen(loaded, tmp_path)
    result = run(replace(asked, operation='create', destination=tmp_path / 'comparison'))
    assert not result.success and not (tmp_path / 'comparison').exists()
    with WorkspaceStore(loaded[0]) as store:
        assert store.db.execute('SELECT COUNT(*) FROM investigations').fetchone()[0] == 0


@pytest.mark.parametrize('change', ['source-added', 'source-missing', 'scope-changed', 'file-changed'])
def test_product_create_rejects_stale_selection_or_bytes_without_project(loaded, tmp_path, change):
    asked = chosen(loaded, tmp_path)
    preview = run(asked)
    assert preview.success, preview.text
    create = create_request(asked, preview, tmp_path)
    if change == 'source-added':
        add_revision(loaded)
    elif change == 'source-missing':
        with WorkspaceStore(loaded[0]) as store:
            store.object_path(loaded[2].source.sha256).unlink()
    elif change == 'scope-changed':
        scope = json.loads(create.product_scope_json)
        scope['display_name'] = 'A different captured product description'
        create = replace(create, product_scope_json=json.dumps(scope))
    else:
        asked.newer.write_bytes(synthetic_pe(2))
    result = run(create)
    assert not result.success and result.error_code == 'PT-KBC-STALE'
    assert not create.destination.exists()
    with WorkspaceStore(loaded[0]) as store:
        assert store.db.execute('SELECT COUNT(*) FROM investigations').fetchone()[0] == 0


def test_product_architecture_must_match_local_files(loaded, tmp_path):
    asked = chosen(loaded, tmp_path)
    rows = catalogue(loaded[0]).data['products']
    arm = next(row for row in rows if row['architecture'] == 'arm64')
    result = run(replace(asked, scope_id=arm['scope_id'], product_scope_json=json.dumps(arm)))
    assert not result.success and result.error_code == 'PT-KBC-VERIFY'


def test_new_advisory_during_product_admission_is_refused(loaded, tmp_path, monkeypatch):
    asked = chosen(loaded, tmp_path)
    preview = run(asked)
    create = create_request(asked, preview, tmp_path)
    original = domain.load_index
    changed = []

    def load_then_commit(store, ports):
        result = original(store, ports)
        changed.append(add_revision(loaded))
        return result

    monkeypatch.setattr(domain, 'load_index', load_then_commit)
    result = run(create)
    assert not result.success and result.error_code == 'PT-KBC-STALE'
    assert len(changed) == 1 and not create.destination.exists()


def test_late_advisory_cannot_enter_product_context_after_admission(loaded, tmp_path, monkeypatch):
    asked = chosen(loaded, tmp_path)
    preview = run(asked)
    original = domain.KbService._approve_pair
    changed = []

    def approve_then_commit(service, *args, **kwargs):
        result = original(service, *args, **kwargs)
        changed.append(add_revision(loaded))
        return result

    monkeypatch.setattr(domain.KbService, '_approve_pair', approve_then_commit)
    result = run(create_request(asked, preview, tmp_path))
    assert result.success and len(changed) == 1
    bundle, = wiring.build_service(loaded[0], clock=FixedClock())._project_bundles(str(result.project_path))
    assert {source.doc_id for source in bundle.sources} == {loaded[2].doc_id}
    assert not bundle.context.cards
    with WorkspaceStore(loaded[0]) as store:
        assert changed[0].source in store.sources()


def test_cancelled_product_browse_does_not_create_workspace(tmp_path):
    token = threading.Event()
    token.set()
    root = tmp_path / 'workspace'
    result = run(InvestigationRequest('browse_products', root, product_start=True), token)
    assert not result.success and result.error_code == 'PT-KBC-CANCEL' and not root.exists()


def product_dialog(qtbot, loaded):
    execute = partial(execute_request, service_factory=lambda p: wiring.build_service(p, clock=FixedClock()))
    dialog = InvestigationDialog(workspace=loaded[0], execute=execute)
    qtbot.addWidget(dialog)
    dialog.product_start.setChecked(True)
    dialog.buttons['browse_products'].click()
    settled(qtbot, dialog)
    chosen_index = next(i for i in range(1, dialog.scope.count()) if 'amd64' in dialog.scope.itemText(i))
    dialog.scope.setCurrentIndex(chosen_index)
    return dialog


@pytest.mark.parametrize('change', ['workspace', 'product_query', 'source', 'mode'])
def test_product_listing_edits_discard_selection(qtbot, loaded, change):
    dialog = product_dialog(qtbot, loaded)
    try:
        assert dialog._product_result is not None and dialog.scope.currentData()
        if change == 'mode':
            dialog.manual_pair_start.setChecked(True)
            assert not dialog.product_start.isChecked()
        else:
            dialog.fields[change].setText(dialog.fields[change].text() + ' changed')
        assert dialog._product_result is None and dialog.scope.currentData() is None
        assert dialog._preview is None and not dialog.buttons['create'].isEnabled()
    finally:
        dialog.reject()


def test_local_file_edit_discards_preview_but_keeps_explicit_product_choice(qtbot, loaded, tmp_path):
    dialog = product_dialog(qtbot, loaded)
    try:
        scope = dialog.scope.currentData()
        old, new = write_pair(tmp_path / 'inputs')
        dialog.fields['older'].setText(str(old))
        dialog.fields['newer'].setText(str(new))
        dialog.buttons['preview'].click()
        settled(qtbot, dialog)
        assert dialog._preview is not None, dialog.status.full_text()
        dialog.fields['newer'].setText('changed.sys')
        assert dialog._preview is None and dialog.scope.currentData() == scope
        assert dialog._product_result is not None and not dialog.buttons['create'].isEnabled()
    finally:
        dialog.reject()


def test_product_mode_revokes_prior_metadata_grant(qtbot, loaded):
    execute = partial(execute_request, service_factory=lambda p: wiring.build_service(p, clock=FixedClock()))
    dialog = InvestigationDialog(workspace=loaded[0], execute=execute)
    qtbot.addWidget(dialog)
    try:
        dialog.fields['component'].setText('exampledrv.sys')
        dialog.buttons['plan_metadata'].click()
        settled(qtbot, dialog)
        assert dialog._metadata_plan is not None
        dialog.product_start.setChecked(True)
        assert dialog._metadata_plan is None and dialog._online_plan is None
        assert not dialog.buttons['refresh_metadata'].isEnabled()
        dialog.product_start.setChecked(False)
        assert dialog._metadata_plan is None and not dialog.buttons['refresh_metadata'].isEnabled()
    finally:
        dialog.reject()


@pytest.mark.parametrize('action', ['edit', 'cancel', 'close', 'mode'])
def test_late_product_catalogue_cannot_restore_selection(qtbot, loaded, action):
    from patchtrace.gui.qt.tasks import TaskRunner

    gate, started = threading.Event(), threading.Event()
    runner = TaskRunner(reraise=True)

    def delayed(request, token):
        result = run(request, token)
        started.set()
        gate.wait(5)
        return result

    dialog = InvestigationDialog(workspace=loaded[0], execute=delayed, tasks=runner)
    qtbot.addWidget(dialog)
    try:
        dialog.product_start.setChecked(True)
        dialog.buttons['browse_products'].click()
        qtbot.waitUntil(started.is_set)
        if action == 'edit':
            dialog.fields['product_query'].setText('a later query')
        elif action == 'cancel':
            dialog.cancel_operation()
        elif action == 'mode':
            dialog.manual_pair_start.setChecked(True)
        else:
            dialog.reject()
        gate.set()
        qtbot.waitUntil(lambda: not runner._running)
        assert dialog._product_result is None and dialog._preview is None
        assert dialog.scope.currentData() is None and not dialog.buttons['create'].isEnabled()
    finally:
        gate.set()
        dialog.reject()
        runner.shutdown()
