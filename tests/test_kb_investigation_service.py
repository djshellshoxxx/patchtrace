"""Offline desktop backend journey; synthetic PE inputs are never executed."""
from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path

import kbc_helpers as h
from kbc_k3_support import BASELINE, FixedClock, write_pair

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.investigation_service import InvestigationRequest, execute_request
from patchtrace.kbcorrelation.store import WorkspaceStore
from patchtrace.service import ProjectService


def run(request, token=None):
    return execute_request(request, token or threading.Event(),
                           service_factory=lambda root: wiring.build_service(root, clock=FixedClock()))


def ready(tmp_path):
    ws = tmp_path / 'workspace'
    imported = run(InvestigationRequest('import', ws, source=h.fixture_path(BASELINE)))
    assert imported.success, imported.text
    found = run(InvestigationRequest('search', ws, lead='CVE-2099-20001'))
    assert found.success
    scope = next(s['scope_id'] for s in found.data['scopes'] if s['architecture'] == 'amd64')
    inv = found.data['investigation_id']
    chosen = run(InvestigationRequest('search', ws, lead='CVE-2099-20001', investigation_id=inv, scope_id=scope))
    assert chosen.success
    old, new = write_pair(tmp_path / 'inputs')
    return ws, inv, scope, old, new


def test_offline_import_search_preview_create_and_reopen(tmp_path):
    ws, inv, scope, old, new = ready(tmp_path)
    preview = run(InvestigationRequest('preview', ws, investigation_id=inv, scope_id=scope, older=old, newer=new))
    assert preview.success, preview.text
    assert isinstance(preview.data['investigation_revision'], int)
    project = tmp_path / 'comparison'
    made = run(InvestigationRequest('create', ws, investigation_id=inv, scope_id=scope, older=old, newer=new,
                                   destination=project, expected_pair_id=preview.data['pair']['pair_id'],
                                   expected_revision=preview.data['investigation_revision']))
    assert made.success, made.text
    assert made.project_path == project.resolve()
    reopened = ProjectService.open(project)
    try:
        assert len(reopened.project.artifacts) == 2
    finally:
        reopened.close()


def test_cancel_before_request_does_not_create_workspace(tmp_path):
    token = threading.Event()
    token.set()
    ws = tmp_path / 'workspace'
    result = run(InvestigationRequest('import', ws, source=h.fixture_path(BASELINE)), token)
    assert not result.success and result.error_code == 'PT-KBC-CANCEL'
    assert not ws.exists()


def test_failed_import_preserves_existing_sources(tmp_path):
    ws, *_ = ready(tmp_path)
    from patchtrace.kbcorrelation.store import WorkspaceStore
    with WorkspaceStore(ws) as store:
        before = [(s.doc_id, s.sha256) for s in store.sources()]
    bad = tmp_path / 'invalid.json'
    bad.write_text('{not json')
    result = run(InvestigationRequest('import', ws, source=bad))
    assert not result.success
    with WorkspaceStore(ws) as store:
        assert [(s.doc_id, s.sha256) for s in store.sources()] == before


def test_create_refuses_parent_or_existing_project_without_touching_it(tmp_path):
    ws, inv, scope, old, new = ready(tmp_path)
    parent = ProjectService.sample(tmp_path / 'open-project')
    database = parent.root / 'project.sqlite3'
    before = database.read_bytes()
    try:
        for destination in (parent.root, parent.root / 'nested'):
            result = run(InvestigationRequest('create', ws, investigation_id=inv, scope_id=scope, older=old,
                                             newer=new, destination=destination, current_project=parent.root,
                                             expected_pair_id='x', expected_revision=1))
            assert not result.success
        assert database.read_bytes() == before
    finally:
        parent.close()


def test_preview_requires_explicit_current_product(tmp_path):
    ws, inv, _, old, new = ready(tmp_path)
    result = run(InvestigationRequest('preview', ws, investigation_id=inv, older=old, newer=new))
    assert not result.success and 'product' in result.text.lower()


def test_changed_investigation_refuses_preview_commit_without_new_project(tmp_path):
    ws, inv, scope, old, new = ready(tmp_path)
    preview = run(InvestigationRequest('preview', ws, investigation_id=inv, scope_id=scope, older=old, newer=new))
    wiring.build_service(ws, clock=FixedClock()).search('CVE-2099-20001', product=scope, investigation=inv)
    with WorkspaceStore(ws) as store:
        revision = store.current_revision(inv).revision
    destination = tmp_path / 'stale-project'
    result = run(InvestigationRequest('create', ws, investigation_id=inv, scope_id=scope, older=old, newer=new,
                                     destination=destination, expected_pair_id=preview.data['pair']['pair_id'],
                                     expected_revision=preview.data['investigation_revision']))
    assert not result.success and result.error_code == 'PT-KBC-STALE'
    assert not destination.exists()
    with WorkspaceStore(ws) as store:
        assert store.current_revision(inv).revision == revision


def test_helper_imports_without_qt(tmp_path):
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'src'))
    code = 'import sys; import patchtrace.kbcorrelation.investigation_service; assert "PySide6" not in sys.modules'
    result = subprocess.run([sys.executable, '-c', code], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_changed_local_bytes_refuse_preview_commit(tmp_path):
    from patchtrace.sample import synthetic_pe
    ws, inv, scope, old, new = ready(tmp_path)
    preview = run(InvestigationRequest('preview', ws, investigation_id=inv, scope_id=scope, older=old, newer=new))
    new.write_bytes(synthetic_pe(2))
    destination = tmp_path / 'changed-input-project'
    result = run(InvestigationRequest('create', ws, investigation_id=inv, scope_id=scope, older=old, newer=new,
                                     destination=destination, expected_pair_id=preview.data['pair']['pair_id'],
                                     expected_revision=preview.data['investigation_revision']))
    assert not result.success and result.error_code == 'PT-KBC-STALE'
    assert not destination.exists()


def test_same_registered_bytes_create_fresh_project_without_opening_locked_original(tmp_path):
    ws, inv, scope, old, new = ready(tmp_path)
    first_preview = run(InvestigationRequest('preview', ws, investigation_id=inv, scope_id=scope,
                                           older=old, newer=new))
    first = run(InvestigationRequest('create', ws, investigation_id=inv, scope_id=scope, older=old, newer=new,
                                    destination=tmp_path / 'first',
                                    expected_pair_id=first_preview.data['pair']['pair_id'],
                                    expected_revision=first_preview.data['investigation_revision']))
    assert first.success
    locked = ProjectService.open(first.project_path)
    before = (locked.root / 'project.sqlite3').read_bytes()
    try:
        fresh = run(InvestigationRequest('search', ws, lead='CVE-2099-20001', scope_id=scope))
        inv = fresh.data['investigation_id']
        preview = run(InvestigationRequest('preview', ws, investigation_id=inv, scope_id=scope,
                                          older=old, newer=new))
        second = run(InvestigationRequest('create', ws, investigation_id=inv, scope_id=scope,
                                         older=old, newer=new, current_project=locked.root,
                                         destination=tmp_path / 'second',
                                         expected_pair_id=preview.data['pair']['pair_id'],
                                         expected_revision=preview.data['investigation_revision']))
        assert second.success, second.text
        reopened = ProjectService.open(second.project_path)
        try:
            assert reopened.project.id != locked.project.id
        finally:
            reopened.close()
        assert (locked.root / 'project.sqlite3').read_bytes() == before
    finally:
        locked.close()


def test_partial_context_attach_reports_retained_project_without_success(tmp_path):
    from patchtrace.kbcorrelation.store import KbcStoreError
    ws, inv, scope, old, new = ready(tmp_path)
    preview = run(InvestigationRequest('preview', ws, investigation_id=inv, scope_id=scope, older=old, newer=new))
    def fault(point):
        if point == 'after_sidecar_write':
            raise KbcStoreError('PT-KBC-STORAGE', 'synthetic row write failure')
    def factory(path):
        return wiring.KbService(path, wiring.build_env(clock=FixedClock(), fault=fault))
    destination = tmp_path / 'partial'
    result = execute_request(InvestigationRequest('create', ws, investigation_id=inv, scope_id=scope,
                                                older=old, newer=new, destination=destination,
                                                expected_pair_id=preview.data['pair']['pair_id'],
                                                expected_revision=preview.data['investigation_revision']),
                             threading.Event(), service_factory=factory)
    assert not result.success and result.project_path == destination.resolve()
    assert 'context' in result.text.lower()
    reopened = ProjectService.open(destination)
    reopened.close()


def test_arm64_advisory_scope_cannot_preview_amd64_binaries(tmp_path):
    ws, inv, _, old, new = ready(tmp_path)
    service = wiring.build_service(ws, clock=FixedClock())
    scopes = service.products(inv).result['products']
    arm64 = next(s['scope_id'] for s in scopes if s['architecture'] == 'arm64')
    service.search('CVE-2099-20001', product=arm64, investigation=inv)
    with WorkspaceStore(ws) as store:
        before = store.current_revision(inv).revision
    result = run(InvestigationRequest('preview', ws, investigation_id=inv, scope_id=arm64, older=old, newer=new))
    assert not result.success
    assert 'arch' in result.text.lower() or 'amd64' in result.text.lower()
    with WorkspaceStore(ws) as store:
        assert store.current_revision(inv).revision == before


def test_project_created_between_intent_and_port_call_is_never_reused(tmp_path, monkeypatch):
    from patchtrace.kbcorrelation.store import ProjectAttachment
    ws, inv, scope, old, new = ready(tmp_path)
    preview = run(InvestigationRequest('preview', ws, investigation_id=inv, scope_id=scope, older=old, newer=new))
    destination = tmp_path / 'raced-project'
    original = ProjectAttachment._create
    existing = {}
    def race(self, operation_id, body):
        other = ProjectService.create(old, new, 'Other legitimate project', destination)
        existing['id'] = other.project.id
        other.close()
        existing['bytes'] = (destination / 'project.sqlite3').read_bytes()
        return original(self, operation_id, body)
    monkeypatch.setattr(ProjectAttachment, '_create', race)
    result = run(InvestigationRequest('create', ws, investigation_id=inv, scope_id=scope, older=old, newer=new,
                                     destination=destination, expected_pair_id=preview.data['pair']['pair_id'],
                                     expected_revision=preview.data['investigation_revision']))
    assert not result.success and result.project_path == destination.resolve()
    assert (destination / 'project.sqlite3').read_bytes() == existing['bytes']
    reopened = ProjectService.open(destination)
    try:
        assert reopened.project.id == existing['id']
    finally:
        reopened.close()
