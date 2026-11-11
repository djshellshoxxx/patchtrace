"""Independent product-start regressions using real stores, authored inputs and denied sockets."""
from __future__ import annotations

import base64
import gzip
import json
import threading

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import NOW, FixedClock, write_pair
from test_kb_investigation_service import run
from test_kb_product_start_20261106 import catalogue, chosen, create_request, pending_product_attach
from test_kb_product_start_20261106 import loaded as loaded
from test_ui_kb_investigation import settled

from patchtrace.kbcorrelation import service as domain
from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.context import ContextBundle
from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import WorkspaceStore
from patchtrace.kbcorrelation.workflow import Event
from patchtrace.service import ProjectService

pytestmark = pytest.mark.usefixtures('no_sockets')


def test_competing_product_revision_is_not_overwritten_or_attached(loaded, tmp_path, monkeypatch):
    root = loaded[0]
    asked = chosen(loaded, tmp_path)
    preview = run(asked)
    assert preview.success, preview.text
    original = domain.KbService._step
    competing = []

    def step(service, ws, revision, kind, **fields):
        if kind == 'product_selected' and not competing:
            with WorkspaceStore(root) as writer:
                competing.append(writer.apply(revision, Event(kind, revision.revision, **fields)))
        return original(service, ws, revision, kind, **fields)

    monkeypatch.setattr(domain.KbService, '_step', step)
    create = create_request(asked, preview, tmp_path)
    refused = run(create)
    assert not refused.success and refused.error_code == 'PT-KBC-STALE'
    assert len(competing) == 1 and not create.destination.exists()
    with WorkspaceStore(root) as ws:
        assert ws.current_revision(competing[0].investigation_id) == competing[0]
        assert not ws.journal_ops()


def test_saved_product_context_exports_after_workspace_source_loss(loaded, tmp_path):
    root, raw, doc = loaded
    asked = chosen(loaded, tmp_path)
    preview = run(asked)
    assert preview.success, preview.text
    made = run(create_request(asked, preview, tmp_path))
    assert made.success, made.text
    with WorkspaceStore(root) as ws:
        ws.object_path(doc.source.sha256).unlink()
    service = wiring.build_service(root, clock=FixedClock())
    out = tmp_path / 'retained-context.json'
    result = service.export(str(made.project_path), str(out), overwrite=False)
    assert result.exit == 0, result.text
    bundle = ContextBundle.model_validate_json(out.read_bytes())
    assert bundle.lead.kind == 'pair' and bundle.scope_id == asked.scope_id
    assert not bundle.context.cards and not bundle.cwe_profiles and not bundle.hypotheses
    assert not bundle.card_facts
    assert {source.doc_id for source in bundle.sources} == {doc.doc_id}
    sidecar, = (made.project_path / 'kb' / 'sources').glob('*.json.gz')
    stored = json.loads(gzip.decompress(sidecar.read_bytes()))
    assert base64.b64decode(stored['bytes']) == raw
    with ProjectService.open(made.project_path) as reopened:
        assert {artifact.sha256 for artifact in reopened.project.artifacts} == {
            bundle.older_sha, bundle.newer_sha,
        }


def test_single_filtered_product_still_requires_an_explicit_selection(qtbot, loaded):
    dialog = InvestigationDialog(workspace=loaded[0], execute=run)
    qtbot.addWidget(dialog)
    try:
        dialog.product_start.setChecked(True)
        dialog.fields['product_query'].setText('PT-CLIENT')
        dialog.buttons['browse_products'].click()
        settled(qtbot, dialog)
        assert dialog.scope.count() == 2 and dialog.scope.currentData() is None
        dialog.scope.setCurrentIndex(1)
        assert dialog.scope.currentData() is not None
        dialog.buttons['browse_products'].click()
        settled(qtbot, dialog)
        assert dialog.scope.count() == 2 and dialog.scope.currentData() is None
        assert dialog._preview is None
    finally:
        dialog.reject()


def test_cancelled_product_create_retains_completed_project_without_adoption(qtbot, loaded, tmp_path):
    opened, notices = [], []
    committed, release = threading.Event(), threading.Event()

    def worker(request, token):
        result = run(request, token)
        if request.operation == 'create':
            committed.set()
            release.wait(30)
        return result

    dialog = InvestigationDialog(workspace=loaded[0], execute=worker, on_created=opened.append,
                                 notice=notices.append)
    qtbot.addWidget(dialog)
    destination = tmp_path / 'comparison'
    try:
        dialog.product_start.setChecked(True)
        dialog.buttons['browse_products'].click()
        settled(qtbot, dialog)
        selected = next(i for i in range(1, dialog.scope.count()) if 'amd64' in dialog.scope.itemText(i))
        dialog.scope.setCurrentIndex(selected)
        older, newer = write_pair(tmp_path / 'inputs')
        for key, value in (('older', older), ('newer', newer), ('destination', destination)):
            dialog.fields[key].setText(str(value))
        dialog.buttons['preview'].click()
        settled(qtbot, dialog)
        assert dialog.buttons['create'].isEnabled(), dialog.status.full_text()
        dialog.buttons['create'].click()
        qtbot.waitUntil(committed.is_set, timeout=10000)
        assert dialog._pending.operation == 'create'
        dialog.cancel_operation()
        release.set()
        settled(qtbot, dialog)
        assert opened == []
        assert any(str(destination.resolve()) in notice for notice in notices)
        assert dialog._preview is None and dialog._product_result is None
        assert not dialog.buttons['create'].isEnabled()
        with ProjectService.open(destination) as reopened:
            assert len(reopened.project.artifacts) == 2
    finally:
        release.set()
        dialog.reject()


@pytest.mark.parametrize('remove_selected_product', [False, True], ids=['retained-product', 'removed-product'])
def test_pending_product_repair_retains_original_source_after_newer_import(loaded, tmp_path,
                                                                         remove_selected_product):
    root, raw, original = loaded
    pending = pending_product_attach(loaded, tmp_path)
    changed = json.loads(raw)
    changed['document']['current_release_date'] = '2099-02-14'
    changed['document']['title'] += ' — subsequent revision'
    if remove_selected_product:
        changed['product_tree'] = []
        changed['vulnerabilities'] = []
    newer_raw = json.dumps(changed).encode()
    latest = import_bytes(newer_raw, now=NOW)
    assert original.doc_id != latest.doc_id
    with WorkspaceStore(root) as ws:
        selected_scope = ws.current_revision(pending.data['investigation_id']).selected_scope_id
        assert ws.add_document(latest, newer_raw)
    current = catalogue(root)
    assert current.success, current.text
    assert original.doc_id not in {
        ref['doc_id'] for scope in current.data['products'] for ref in scope['source_product_ids']}
    if remove_selected_product:
        assert current.data['products'] == []
    service = wiring.build_service(root, clock=FixedClock())
    repaired = service.attach(str(pending.project_path), pending.data['investigation_id'], repair_it=True)
    assert repaired.exit == 0, repaired.text
    bundle, = service._project_bundles(str(pending.project_path))
    assert bundle.scope_id == selected_scope and bundle.lead.kind == 'pair'
    assert {source.doc_id for source in bundle.sources} == {original.doc_id}
    assert {source.sha256 for source in bundle.sources} == {original.source.sha256}
    assert not bundle.context.cards and not bundle.cwe_profiles and not bundle.hypotheses
    sidecar, = (pending.project_path / 'kb' / 'sources').glob('*.json.gz')
    stored = json.loads(gzip.decompress(sidecar.read_bytes()))
    assert base64.b64decode(stored['bytes']) == raw
    repeated = service.attach(str(pending.project_path), pending.data['investigation_id'], repair_it=True)
    assert repeated.exit == 0
    assert service._project_bundles(str(pending.project_path)) == [bundle]
