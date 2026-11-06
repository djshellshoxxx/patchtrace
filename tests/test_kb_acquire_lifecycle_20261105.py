"""Real local acquisition/import lifecycle over authored PE bytes and a fake socket-free transport."""
from __future__ import annotations

import json
import tempfile
import threading
from types import SimpleNamespace

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import NOW, FixedClock
from test_kbc_acquire_cli import HOSTS, NET

from patchtrace.kbcorrelation import service as service_module
from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.service import KbService
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore
from patchtrace.service import ProjectService

pytestmark = pytest.mark.usefixtures('no_sockets')


class HookedAcquirer:
    def __init__(self, delegate):
        self.delegate = delegate
        self.after_stage = None
        self.after_plan = None
        self.tokens = []

    def plan(self, older, newer):
        result = self.delegate.plan(older, newer)
        if self.after_plan:
            self.after_plan()
        return result

    def stage(self, older, newer, *, cancel, emit):
        self.tokens.append(cancel)
        staged = self.delegate.stage(older, newer, cancel=cancel, emit=emit)
        if self.after_stage:
            self.after_stage()
        return staged


@pytest.fixture
def ready(tmp_path, monkeypatch):
    from test_kbc_acquire_cli import NEWER, OLDER, URL_N, URL_O, Server, acquirer, cvrf, net_record

    stages = tmp_path / 'stages'
    stages.mkdir()
    monkeypatch.setattr(tempfile, 'tempdir', str(stages))
    root, destination = tmp_path / 'workspace', tmp_path / 'new-project'
    server = Server({URL_O: OLDER, URL_N: NEWER})
    port = HookedAcquirer(acquirer(server))
    service = wiring.build_service(root, clock=FixedClock(), acquirer=port)
    raw = cvrf()
    with WorkspaceStore(root) as store:
        store.add_document(import_bytes(raw, now=NOW), raw)
    source = tmp_path / 'index.json'
    source.write_text(json.dumps(net_record()), encoding='utf-8')
    wiring.save_winbindex_record(root, source, NET, '2099-02-12')
    found = service.search('CVE-2099-20001')
    scope = next(s['scope_id'] for s in found.result['scopes'] if s['architecture'] == 'amd64'
                 and s['family'] == 'windows-client')
    investigation = found.result['investigation_id']
    service.search('CVE-2099-20001', product=scope, investigation=investigation)
    with WorkspaceStore(root) as store:
        revision = store.current_revision(investigation).revision
    selection = {'product': scope, 'files': (NET,)}
    preview = service.acquire(investigation, str(destination), **selection)
    assert preview.exit == 2 and server.calls == []
    plan = preview.result['plan']

    def run(**options):
        return service.acquire(investigation, str(destination), **selection,
                               consent_hosts=(HOSTS,), consent_plan=plan['plan_sha'], **options)

    with ProjectService.sample(tmp_path / 'completed-project') as completed:
        previous_database = completed.root / 'project.sqlite3'
    previous_bytes = previous_database.read_bytes()
    yield SimpleNamespace(service=service, port=port, root=root, destination=destination, server=server,
                          stages=stages, investigation=investigation, scope=scope, revision=revision,
                          raw=raw, run=run)
    assert previous_database.read_bytes() == previous_bytes


def assert_refused_without_project(ready):
    assert not ready.destination.exists()
    assert list(ready.stages.iterdir()) == []


def test_pre_cancelled_acquire_never_stages_or_requests(ready):
    cancel = threading.Event()
    cancel.set()
    result = ready.run(cancel=cancel)
    assert result.exit == 5 and result.status == 'cancelled'
    assert ready.port.tokens == [] and ready.server.calls == []
    assert_refused_without_project(ready)


def test_cancel_token_reaches_stage_and_stops_import_after_verified_bytes(ready):
    cancel = threading.Event()
    ready.port.after_stage = cancel.set
    result = ready.run(cancel=cancel)
    assert result.exit == 5 and result.status == 'cancelled'
    assert ready.port.tokens == [cancel] and ready.server.calls
    assert_refused_without_project(ready)


def test_investigation_changed_during_stage_cannot_receive_old_plan(ready):
    ready.port.after_stage = lambda: ready.service.search(
        'CVE-2099-20001', product=ready.scope, investigation=ready.investigation)
    with pytest.raises(KbcStoreError) as caught:
        ready.run()
    assert caught.value.code == 'PT-KBC-STALE'
    assert ready.server.calls
    assert_refused_without_project(ready)


def test_explicit_stale_revision_is_refused_before_network(ready):
    with pytest.raises(KbcStoreError) as caught:
        ready.run(expected_revision=ready.revision - 1)
    assert caught.value.code == 'PT-KBC-STALE'
    assert ready.port.tokens == [] and ready.server.calls == []
    assert_refused_without_project(ready)


def add_source_without_changing_revision(ready):
    revised = ready.raw + b'\n'
    with WorkspaceStore(ready.root) as store:
        assert store.current_revision(ready.investigation).revision == ready.revision
        store.add_document(import_bytes(revised, now=NOW), revised)
        assert store.current_revision(ready.investigation).revision == ready.revision


def test_advisory_source_drift_without_revision_change_is_refused_after_stage(ready):
    ready.port.after_stage = lambda: add_source_without_changing_revision(ready)
    with pytest.raises(KbcStoreError) as caught:
        ready.run()
    assert caught.value.code == 'PT-KBC-STALE'
    assert_refused_without_project(ready)


def test_advisory_drift_during_pure_plan_is_refused_before_stage(ready):
    ready.port.after_plan = lambda: add_source_without_changing_revision(ready)
    with pytest.raises(KbcStoreError) as caught:
        ready.run()
    assert caught.value.code == 'PT-KBC-STALE'
    assert ready.port.tokens == [] and ready.server.calls == []
    assert_refused_without_project(ready)


def test_current_revision_acquire_preserves_verified_hashes_and_cleans_stage(ready):
    from test_kbc_acquire_cli import SHA_N, SHA_O

    result = ready.run(expected_revision=ready.revision)
    assert result.exit in (0, 3)
    with ProjectService.open(ready.destination) as project:
        assert [artifact.sha256 for artifact in project.project.artifacts] == [SHA_O, SHA_N]
    assert list(ready.stages.iterdir()) == []


def test_revision_is_rechecked_inside_import_after_acquire_guard(ready, monkeypatch):
    original = KbService.import_pair

    def change_then_import(service, *args, **kwargs):
        service.search('CVE-2099-20001', product=ready.scope, investigation=ready.investigation)
        return original(service, *args, **kwargs)

    monkeypatch.setattr(KbService, 'import_pair', change_then_import)
    with pytest.raises(KbcStoreError) as caught:
        ready.run()
    assert caught.value.code == 'PT-KBC-STALE'
    assert_refused_without_project(ready)


def test_source_snapshot_is_rechecked_inside_import_after_acquire_guard(ready, monkeypatch):
    original = KbService.import_pair

    def change_sources_then_import(service, *args, **kwargs):
        add_source_without_changing_revision(ready)
        return original(service, *args, **kwargs)

    monkeypatch.setattr(KbService, 'import_pair', change_sources_then_import)
    with pytest.raises(KbcStoreError) as caught:
        ready.run()
    assert caught.value.code == 'PT-KBC-STALE'
    with WorkspaceStore(ready.root) as store:
        assert store.current_revision(ready.investigation).revision == ready.revision
        assert len(store.sources()) == 2  # the legitimate concurrent import remains intact
    assert_refused_without_project(ready)


def add_newer_source_without_changing_revision(ready):
    revised = json.loads(ready.raw)
    revised['document']['current_release_date'] = '2099-02-14'
    raw = json.dumps(revised).encode()
    doc = import_bytes(raw, now=NOW)
    with WorkspaceStore(ready.root) as store:
        revision = store.current_revision(ready.investigation)
        assert store.add_document(doc, raw)
        assert store.current_revision(ready.investigation) == revision
    return doc.source


def test_source_added_during_import_index_build_is_refused_before_approval(ready, monkeypatch):
    original = service_module.load_index
    added = []

    def load_then_add_source(store, ports):
        result = original(store, ports)
        if ready.port.tokens and not added:  # the verified acquisition has reached import_pair
            assert not store.db.in_transaction
            added.append(add_newer_source_without_changing_revision(ready))
        return result

    monkeypatch.setattr(service_module, 'load_index', load_then_add_source)
    with pytest.raises(KbcStoreError) as caught:
        ready.run(expected_revision=ready.revision)
    assert caught.value.code == 'PT-KBC-STALE'
    assert len(added) == 1 and ready.server.calls
    with WorkspaceStore(ready.root) as store:
        assert store.current_revision(ready.investigation).revision == ready.revision
        assert len(store.sources()) == 2 and added[0] in store.sources()
    assert_refused_without_project(ready)


def test_source_added_after_admission_is_excluded_from_saved_context(ready, monkeypatch):
    from test_kbc_acquire_cli import SHA_N, SHA_O

    with WorkspaceStore(ready.root) as store:
        admitted_sources = store.sources()
        revision = store.current_revision(ready.investigation)
        coverage = tuple(store.get_coverage(key) for key in revision.coverage_ids)
        index, _ = service_module.load_index(store, ready.service.ports)
        edge_digest = index.edge_set_digest()
    original = KbService._approve_pair
    added = []

    def approve_then_add_source(service, store, *args, **kwargs):
        result = original(service, store, *args, **kwargs)
        assert not store.db.in_transaction
        added.append(add_newer_source_without_changing_revision(ready))
        return result

    monkeypatch.setattr(KbService, '_approve_pair', approve_then_add_source)
    result = ready.run(expected_revision=ready.revision)
    assert result.exit == 0 and result.status == 'complete'
    assert len(added) == 1 and ready.server.calls
    with WorkspaceStore(ready.root) as store:
        assert len(store.sources()) == 2 and added[0] in store.sources()
        assert store.read_object(added[0].sha256)
    bundles = ready.service._project_bundles(str(ready.destination))
    assert len(bundles) == 1
    bundle = bundles[0]
    assert bundle.context_key == result.result['context_key']
    assert {source.sha256 for source in bundle.sources} == {source.sha256 for source in admitted_sources}
    assert bundle.edge_set_digest == edge_digest and bundle.context.coverage == coverage
    assert bundle.card_facts and {fact.doc_id for fact in bundle.card_facts} == {
        source.doc_id for source in admitted_sources}
    assert {path.name for path in (ready.destination / 'kb' / 'sources').iterdir()} == {
        f'{source.sha256}.json.gz' for source in admitted_sources}
    with ProjectService.open(ready.destination) as project:
        assert [artifact.sha256 for artifact in project.project.artifacts] == [SHA_O, SHA_N]
    assert list(ready.stages.iterdir()) == []
