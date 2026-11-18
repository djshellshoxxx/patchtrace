"""PW-01 offline service journeys, scoped handoff and atomic failure preservation."""
from __future__ import annotations

import io
import json
import os
import threading
import weakref

import kbc_helpers as h
import pytest
from kbc_k1_support import import_fixture, no_sockets  # noqa: F401
from kbc_k3_support import FixedClock
from kbc_k5_support import FIXTURES, SHA

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.inventory_service import context_for, read_file
from patchtrace.kbcorrelation.sources.cvrf import SourceError
from patchtrace.kbcorrelation.sources.inventory_fetch import build_plan
from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore

pytestmark = pytest.mark.usefixtures('no_sockets')
CSV = b'File name,File version,File size,Architecture\r\nexampledrv.sys,1.2.3.4,128,x64\r\n'
PAGE = 'https://support.microsoft.com/help/5099001'
URL = 'https://download.microsoft.com/download/authored/files.csv'


@pytest.fixture
def service(tmp_path):
    svc = wiring.build_service(tmp_path / 'ws', clock=FixedClock())
    with WorkspaceStore(svc.root) as ws:
        ws.add_document(import_fixture('cvrf-2099-Feb.json'), h.read_fixture_bytes('cvrf-2099-Feb.json'))
    return svc


def imported(service, tmp_path, raw=CSV, **context):
    file = tmp_path / 'inventory.csv'
    file.write_bytes(raw)
    result = service.import_inventory(file, context_for(context.pop('kb', 'KB5099001'), **context))
    import_id = result.result['import_id']
    entries = service.inventory_details(import_id).result['entries']
    return result, import_id, entries


def investigation(service, **kwargs):
    result = service.search('KB5099001', **kwargs)
    scope = next(s['scope_id'] for s in result.result['scopes'] if s['architecture'] == 'amd64')
    return result.result['investigation_id'], scope, result.result['revision']


def snapshot(service, inv):
    with WorkspaceStore(service.root) as ws:
        return ws.current_revision(inv), ws.decisions(inv)


def select(service, inv, scope, revision, import_id, entry_id, **kwargs):
    return service.select_inventory(inv, import_id, entry_id, product=scope, expected_revision=revision,
                                    assert_scope=kwargs.pop('assert_scope', True), **kwargs)


def test_import_list_detail_preserve_local_origin_rows_and_idempotency(service, tmp_path):
    first, import_id, entries = imported(service, tmp_path)
    repeated, again, _ = imported(service, tmp_path)
    assert first.exit == repeated.exit == 0 and import_id == again
    assert not first.result['already_present'] and repeated.result['already_present']
    assert first.result['inventory']['source']['uri'] is None
    assert first.result['inventory']['source']['authenticity'] == 'unverified-local-file'
    listed = service.inventories()
    assert listed.result['total'] == 1 and listed.result['inventories'][0]['import_id'] == import_id
    detail = service.inventory_details(import_id, name='EXAMPLE', architecture='amd64')
    assert detail.result['entries'] == entries and detail.result['filtered_count'] == 1
    assert entries[0]['reference']['logical_record'] == 2
    assert service.inventory_details(import_id, architecture='arm64').exit == 4
    with WorkspaceStore(service.root) as ws:
        assert ws.unreferenced_objects() == ()


def test_empty_list_does_not_create_a_workspace(tmp_path):
    svc = wiring.build_service(tmp_path / 'absent', clock=FixedClock())
    assert svc.inventories().exit == 4
    assert not svc.root.exists()


@pytest.mark.parametrize('raw', [b'not an inventory', b'File name,File version\n"unfinished'])
def test_fatal_import_preserves_previous_source_and_revision(service, tmp_path, raw):
    _, import_id, _ = imported(service, tmp_path)
    inv, _, _ = investigation(service)
    before = snapshot(service, inv)
    path = tmp_path / 'broken.csv'
    path.write_bytes(raw)
    with pytest.raises(SourceError):
        service.import_inventory(path, context_for('KB5099001'))
    assert service.inventories().result['total'] == 1
    assert service.inventory_details(import_id).exit == 0 and snapshot(service, inv) == before


def test_partial_counts_and_diagnostics_are_visible(service, tmp_path):
    result, import_id, _ = imported(service, tmp_path, CSV + b'../bad.dll,1.2.3.4,128,x64\r\n')
    assert result.exit == 3 and result.result['inventory']['rejected_count'] == 1
    detail = service.inventory_details(import_id)
    assert detail.exit == 3 and detail.result['inventory']['diagnostics']


@pytest.mark.parametrize('kwargs', [{'limit': 0}, {'limit': 501}, {'offset': -1}, {'architecture': 'x64'},
                                  {'name': '\x1b[31m'}, {'state': 'verified'}])
def test_detail_filters_are_bounded_and_typed(service, tmp_path, kwargs):
    _, import_id, _ = imported(service, tmp_path)
    with pytest.raises(SourceError) as caught:
        service.inventory_details(import_id, **kwargs)
    assert caught.value.code == 'PT-KBC-INPUT'


def test_saved_csv_selection_reaches_existing_winbindex_candidates(service, tmp_path):
    # The generic Example OS fixture intentionally has no Winbindex key. Add an
    # authored explicit Windows client product so this journey tests real mapping.
    from patchtrace.kbcorrelation.sources.importer import import_bytes
    service = wiring.build_service(tmp_path / 'mapped', clock=FixedClock())
    raw = h.read_fixture_bytes('cvrf-2099-Feb.json').replace(b'Example OS 24H2', b'Windows 11 Version 24H2')
    with WorkspaceStore(service.root) as ws:
        ws.add_document(import_bytes(raw, now=service._now()), raw)
    _, import_id, entries = imported(service, tmp_path)
    searched = service.search('KB5099001')
    inv, revision = searched.result['investigation_id'], searched.result['revision']
    scope = next(s['scope_id'] for s in searched.result['scopes']
                 if s['architecture'] == 'amd64' and s['display_name'].startswith('Windows 11'))
    chosen = select(service, inv, scope, revision, import_id, entries[0]['entry_id'])
    assert chosen.result['revision'] == revision + 1 and chosen.result['state'] == 'COMPONENTS_READY'
    assert chosen.result['hint']['tier'] == 'E' and chosen.result['hint']['changed_in_kb'] == 'unknown'
    hints = service.components(inv, product=None, files=[]).result['hints']
    assert len(hints) == 1 and len(hints[0]['inventory_refs']) == 1
    assert hints[0]['inventory_refs'][0]['raw_sha256'] == entries[0]['reference']['raw_sha256']
    assert hints[0]['claim_refs'] == []
    wiring.save_winbindex_record(service.root, FIXTURES / 'exampledrv.sys.json', 'exampledrv.sys', '2099-02-12')
    pairs = service.pairs(inv)
    assert pairs.result['pairs']
    assert {p['newer_sha256'] for p in pairs.result['pairs']} == {SHA['Z']}
    assert entries[0]['reference']['raw_sha256'] not in {p['newer_sha256'] for p in pairs.result['pairs']}
    assert pairs.result['pairs'][0]['file_name'] == 'exampledrv.sys'


def test_selected_duplicate_rows_keep_both_claims_without_two_names(service, tmp_path):
    _, import_id, entries = imported(service, tmp_path, CSV + CSV.splitlines(keepends=True)[1])
    inv, scope, revision = investigation(service)
    for entry in entries:
        result = select(service, inv, scope, revision, import_id, entry['entry_id'])
        revision = result.result['revision']
    hints = service.components(inv, product=scope, files=['exampledrv.sys']).result['hints']
    assert len(hints) == 1 and len(hints[0]['inventory_refs']) == 2 and hints[0]['tier'] == 'E'
    assert {ref['logical_record'] for ref in hints[0]['inventory_refs']} == {2, 3}


def test_selection_replay_does_not_accumulate_full_inventory_models(service, tmp_path, monkeypatch):
    from patchtrace.kbcorrelation import inventory_selection

    inv, scope, revision = investigation(service)
    for n in range(4):
        raw = CSV.replace(b'exampledrv.sys', f'example{n}.sys'.encode())
        _, import_id, entries = imported(service, tmp_path, raw)
        revision = select(service, inv, scope, revision, import_id, entries[0]['entry_id']).result['revision']
    original, observed = inventory_selection.get_inventory, []

    def measured(*args, **kwargs):
        # A single inventory can retain thousands of rows. Before reading the
        # next one, only the immediately previous source may still be alive.
        assert sum(ref() is not None for ref in observed) <= 1
        record = original(*args, **kwargs)
        observed.append(weakref.ref(record))
        return record

    monkeypatch.setattr(inventory_selection, 'get_inventory', measured)
    hints = service.components(inv, product=scope, files=[]).result['hints']
    assert {hint['basename'] for hint in hints} == {f'example{n}.sys' for n in range(4)}
    assert len(observed) == 4 and all(ref() is None for ref in observed)


def test_selection_requires_explicit_mapping_and_exact_revision(service, tmp_path):
    _, import_id, entries = imported(service, tmp_path)
    inv, scope, revision = investigation(service)
    before = snapshot(service, inv)
    with pytest.raises(KbcStoreError, match='scope assertion'):
        select(service, inv, scope, revision, import_id, entries[0]['entry_id'], assert_scope=False)
    with pytest.raises(KbcStoreError) as stale:
        select(service, inv, scope, revision - 1, import_id, entries[0]['entry_id'])
    assert stale.value.code == 'PT-KBC-STALE' and snapshot(service, inv) == before
    result = select(service, inv, scope, revision, import_id, entries[0]['entry_id'])
    again = select(service, inv, scope, result.result['revision'], import_id, entries[0]['entry_id'])
    assert result.result['revision'] == again.result['revision']
    assert len(snapshot(service, inv)[1]) == 1


@pytest.mark.parametrize('context,raw', [
    ({'kb': 'KB5099009'}, CSV), ({'product_scope_id': 'a' * 64}, CSV),
    ({'product': 'Windows Server 2022'}, CSV), ({'release': '22H2'}, CSV),
    ({'build': '12345.9'}, CSV), ({}, CSV.replace(b'x64', b'arm64')),
    ({}, CSV.replace(b'1.2.3.4', b'unknown')), ({}, CSV + b'exampledrv.sys,2.0.0.0,128,x64\r\n'),
])
def test_scope_architecture_and_metadata_conflicts_cannot_be_overridden(service, tmp_path, context, raw):
    _, import_id, entries = imported(service, tmp_path, raw, **context)
    inv, scope, revision = investigation(service)
    before = snapshot(service, inv)
    with pytest.raises(KbcStoreError):
        select(service, inv, scope, revision, import_id, entries[0]['entry_id'])
    assert snapshot(service, inv) == before


def test_a_source_bound_to_the_exact_scope_needs_no_extra_assertion(service, tmp_path):
    inv, scope, revision = investigation(service)
    _, import_id, entries = imported(service, tmp_path, product_scope_id=scope)
    result = select(service, inv, scope, revision, import_id, entries[0]['entry_id'], assert_scope=False)
    assert result.exit == 0 and not result.result['selection']['asserted_scope']


@pytest.mark.parametrize('cancelled', [False, True])
def test_decision_and_revision_roll_back_together(service, tmp_path, cancelled):
    _, import_id, entries = imported(service, tmp_path)
    inv, scope, revision = investigation(service)
    before, token = snapshot(service, inv), threading.Event()

    def fault(point):
        if point == 'after_revision_decisions':
            if cancelled:
                token.set()
            else:
                raise RuntimeError('authored interruption')

    failing = wiring.build_service(service.root, clock=FixedClock(), fault=fault)
    with pytest.raises((RuntimeError, KbcStoreError)):
        select(failing, inv, scope, revision, import_id, entries[0]['entry_id'], cancel=token)
    assert snapshot(service, inv) == before


def test_changing_recorded_document_scope_does_not_reuse_the_selection(service, tmp_path):
    _, import_id, entries = imported(service, tmp_path)
    inv, scope, revision = investigation(service, months='2099-Feb')
    select(service, inv, scope, revision, import_id, entries[0]['entry_id'])
    # Existing workflow requires returning through product selection before a new search.
    service.components(inv, product=scope, files=[])
    with WorkspaceStore(service.root) as ws:
        rev = ws.current_revision(inv)
        from patchtrace.kbcorrelation.workflow import Event
        ws.apply(rev, Event('product_selected', rev.revision, scope_id=scope))
    service.search('KB5099001', months='2099-Feb,2099-Jan', product=scope, investigation=inv)
    assert service.components(inv, product=scope, files=[]).result['hints'] == []
    assert len(snapshot(service, inv)[1]) == 1


def test_support_saved_import_detail_and_orphan_accounting(service, tmp_path):
    file = tmp_path / 'page.html'
    file.write_text(f'<p><a href="{URL}">File information</a> for cumulative update.</p>')
    result = service.support_links(file, page_url=PAGE)
    assert result.exit == 0 and result.result['source']['uri'] is None
    assert result.result['extraction']['links'][0]['accepted']
    again = service.inventory_details(result.result['import_id'])
    assert again.result['extraction'] == result.result['extraction']
    assert service.inventories(kind='support-page').result['total'] == 1
    with WorkspaceStore(service.root) as ws:
        assert ws.unreferenced_objects() == ()


class Response:
    def __init__(self, body=CSV, status=200, headers=None):
        self.status, self.headers = status, headers or {}
        self.data, self.closed = io.BytesIO(body), False

    def read(self, amount):
        return self.data.read(amount)

    def close(self):
        self.closed = True


def test_exact_plan_envelope_and_fetched_receipt_are_preserved(service, tmp_path):
    preview = service.inventory_plan(URL)
    file = tmp_path / 'plan.json'
    file.write_text(json.dumps({'contract': 'enrichment-cli/1', 'command': 'kb inventory plan',
                                'result': preview.result}))
    plan = build_plan(URL)
    called = []

    def opener(method, url, headers, timeout):
        called.append((method, url))
        return Response()

    result = service.fetch_inventory(file, context=context_for('KB5099001'), consent_hosts=plan.hosts,
                                     consent_plan=plan.plan_sha, opener=opener)
    assert result.exit == 0 and called == [('GET', URL)]
    source = result.result['inventory']['source']
    assert source['authenticity'] == 'tls-allowlisted-host' and source['uri'] == URL
    assert result.result['inventory']['retrieval']['plan_sha'] == plan.plan_sha


def test_new_redirect_returns_reviewable_plan_without_following(service):
    plan = build_plan('https://go.microsoft.com/fwlink/?linkid=1234')
    called = []

    def opener(method, url, headers, timeout):
        called.append(url)
        return Response(b'', 302, {'Location': URL})

    result = service.fetch_inventory(plan, context=context_for('KB5099001'), consent_hosts=plan.hosts,
                                     consent_plan=plan.plan_sha, opener=opener)
    assert result.exit == 2 and result.status == 'failed'
    assert result.result['proposed_plan']['urls'] == [plan.urls[0], URL]
    assert URL in result.result['preview'] and called == [plan.urls[0]]
    assert service.inventories().result['total'] == 0


def test_offline_and_missing_consent_never_call_opener(service):
    plan = build_plan(URL)
    for kwargs in ({'offline': True}, {'consent_plan': '0' * 64}):
        values = {'context': context_for('KB5099001'), 'consent_hosts': plan.hosts, 'consent_plan': plan.plan_sha,
                  'opener': lambda *_: pytest.fail('unexpected request'), **kwargs}
        with pytest.raises(SourceError):
            service.fetch_inventory(plan, **values)


def test_regular_file_ingress_bounds_and_cancellation(tmp_path):
    file = tmp_path / 'source.csv'
    file.write_bytes(CSV)
    with pytest.raises(SourceError):
        read_file(file, len(CSV) - 1)
    with pytest.raises(SourceError):
        read_file(tmp_path, 100)
    token = threading.Event()
    token.set()
    with pytest.raises(SourceError) as caught:
        read_file(file, 1000, cancel=token)
    assert caught.value.code == 'PT-KBC-CANCEL'
    if os.name != 'nt':
        link = tmp_path / 'link.csv'
        link.symlink_to(file)
        with pytest.raises(SourceError):
            read_file(link, 1000)
