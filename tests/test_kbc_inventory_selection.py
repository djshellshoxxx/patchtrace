"""Independent PW-01 scope, atomicity and evidence-preservation regressions.

All fixtures are authored; these checks make no live request or target execution.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import socket
import threading

import kbc_helpers as h
import pytest
from kbc_k3_support import FixedClock

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.inventory_service import context_for
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore
from patchtrace.kbcorrelation.workflow import Event

NOW = '2099-02-15T00:00:00Z'
KB = 'KB5099001'
PRODUCT = 'WINDOWS-11-24H2-AMD64'
CSV = b'File name,File version,File size,Architecture\r\nreview.sys,1.2.3.4,128,x64\r\n'


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError('independent PW-01 review must stay offline')
    for name in ('socket', 'create_connection', 'getaddrinfo'):
        monkeypatch.setattr(socket, name, refuse)


def document(*, builds=('10.0.26100.9001',), release='2099-Feb', kb=KB, name='Windows 11 Version 24H2 x64'):
    products = ({'product_id': PRODUCT, 'name': name, 'family': 'windows-client', 'architecture': 'amd64'},)
    return h.cvrf_document([
        h.vulnerability(f'CVE-2099-{30000 + i}', 'Independent review component',
                        remediations=[h.remediation(2, kb[2:], [PRODUCT], build)],
                        product_statuses={'Fixed': [PRODUCT]})
        for i, build in enumerate(builds)
    ], release_id=release, products=products)


def service(tmp_path, *, doc=None, name='ws', fault=None):
    svc = wiring.build_service(tmp_path / name, clock=FixedClock(), fault=fault)
    raw = h.render_json(doc or document())
    with WorkspaceStore(svc.root) as ws:
        ws.add_document(import_bytes(raw, now=NOW), raw)
    return svc


def start(svc, *, lead=KB, **kwargs):
    result = svc.search(lead, **kwargs).result
    selected = next(scope for scope in result['scopes'] if scope['architecture'] == 'amd64')
    return result['investigation_id'], selected['scope_id'], result['revision']


def inventory(svc, tmp_path, *, raw=CSV, kb=KB, **context):
    path = tmp_path / 'review.csv'
    path.write_bytes(raw)
    output = svc.import_inventory(path, context_for(kb, **context))
    import_id = output.result['import_id']
    details = svc.inventory_details(import_id).result
    return import_id, details['entries'][0]['entry_id']


def snapshot(svc, investigation):
    with WorkspaceStore(svc.root) as ws:
        return (ws.current_revision(investigation), ws.decisions(investigation),
                ws.db.execute('SELECT count(*) FROM revisions WHERE investigation_id=?', (investigation,)).fetchone()[0])


def select(svc, state, identity, *, asserted=True, cancel=None):
    investigation, scope, revision = state
    return svc.select_inventory(investigation, *identity, product=scope, expected_revision=revision,
                                assert_scope=asserted, cancel=cancel)


@pytest.mark.parametrize('source_product', ['Windows 10', 'Windows 10 x64', 'Windows 10 Enterprise'])
@pytest.mark.parametrize('product_origin', ['csv-row', 'context'])
def test_known_client_generation_cannot_be_overridden_by_scope_assertion(tmp_path, source_product, product_origin):
    svc = service(tmp_path)
    state = start(svc)
    if product_origin == 'csv-row':
        raw = (f'File name,File version,File size,Architecture,Product\r\n'
               f'review.sys,1.2.3.4,128,x64,{source_product}\r\n').encode('ascii')
        identity = inventory(svc, tmp_path, raw=raw)
    else:
        identity = inventory(svc, tmp_path, product=source_product)
    before = snapshot(svc, state[0])
    with pytest.raises(KbcStoreError):
        select(svc, state, identity, asserted=True)
    assert snapshot(svc, state[0]) == before


def test_conflicting_advisory_builds_cannot_make_arbitrary_csv_build_eligible(tmp_path):
    svc = service(tmp_path, doc=document(builds=('10.0.26100.9001', '10.0.26100.9002')))
    state = start(svc)
    identity = inventory(svc, tmp_path, build='10.0.99999.1234')
    before = snapshot(svc, state[0])
    with pytest.raises(KbcStoreError):
        select(svc, state, identity, asserted=True)
    assert snapshot(svc, state[0]) == before


def test_explicit_wrong_client_generation_with_release_control(tmp_path):
    svc = service(tmp_path)
    state = start(svc)
    identity = inventory(svc, tmp_path, product='Windows 10 Version 24H2 x64')
    before = snapshot(svc, state[0])
    with pytest.raises(KbcStoreError):
        select(svc, state, identity)
    assert snapshot(svc, state[0]) == before


def test_unmapped_but_noncontradictory_product_assertion_control(tmp_path):
    svc = service(tmp_path)
    state = start(svc)
    identity = inventory(svc, tmp_path, product='Unmapped authored product')
    selected = select(svc, state, identity)
    assert selected.exit == 0
    assert selected.result['hint']['tier'] == 'E'
    assert selected.result['selection']['asserted_scope'] is True


def test_cas_competitor_cannot_publish_selection_decision_or_extra_revision(tmp_path):
    svc = service(tmp_path)
    state = start(svc)
    identity = inventory(svc, tmp_path)
    competing = []

    def fault(point):
        if point == 'before_cas':
            with WorkspaceStore(svc.root) as ws:
                current = ws.current_revision(state[0])
                ws.apply(current, Event('product_selected', current.revision, scope_id=state[1]))
            competing.append(snapshot(svc, state[0]))

    racing = wiring.build_service(svc.root, clock=FixedClock(), fault=fault)
    with pytest.raises(KbcStoreError) as raised:
        select(racing, state, identity)
    assert raised.value.code == 'PT-KBC-STALE'
    assert len(competing) == 1 and snapshot(svc, state[0]) == competing[0]
    assert snapshot(svc, state[0])[1] == ()


def test_sqlite_decision_insert_failure_rolls_back_cas_and_revision(tmp_path):
    svc = service(tmp_path)
    state = start(svc)
    identity = inventory(svc, tmp_path)
    before = snapshot(svc, state[0])
    with WorkspaceStore(svc.root) as ws:
        ws.db.execute("CREATE TRIGGER review_reject_decision BEFORE INSERT ON decisions "
                      "BEGIN SELECT RAISE(ABORT, 'independent review injected refusal'); END")
    with pytest.raises(KbcStoreError) as raised:
        select(svc, state, identity)
    assert raised.value.code == 'PT-KBC-STORAGE'
    assert snapshot(svc, state[0]) == before


@pytest.mark.parametrize('point', ['before_cas', 'after_revision_decisions'])
def test_cancellation_guards_preserve_decision_and_revision(tmp_path, point):
    svc = service(tmp_path)
    state = start(svc)
    identity = inventory(svc, tmp_path)
    before = snapshot(svc, state[0])
    token = threading.Event()

    def fault(observed):
        if observed == point:
            token.set()

    cancellable = wiring.build_service(svc.root, clock=FixedClock(), fault=fault)
    with pytest.raises(KbcStoreError) as raised:
        select(cancellable, state, identity, cancel=token)
    assert raised.value.code == 'PT-KBC-CANCEL'
    assert snapshot(svc, state[0]) == before


def test_baseexception_after_decision_insert_rolls_back_everything(tmp_path):
    svc = service(tmp_path)
    state = start(svc)
    identity = inventory(svc, tmp_path)
    before = snapshot(svc, state[0])

    def fault(point):
        if point == 'after_revision_decisions':
            raise KeyboardInterrupt('independent review interruption')

    interrupted = wiring.build_service(svc.root, clock=FixedClock(), fault=fault)
    with pytest.raises(KeyboardInterrupt):
        select(interrupted, state, identity)
    assert snapshot(svc, state[0]) == before


def corrupt_inventory(svc, identity):
    info = svc.inventory_details(identity[0]).result['inventory']['source']
    raw_sha = info['sha256']
    path = svc.root / 'objects' / raw_sha[:2] / (raw_sha + '.gz')
    path.write_bytes(gzip.compress(CSV.replace(b'review.sys', b'forged.sys')))


def test_inventory_raw_replay_refusal_is_atomic_for_selection(tmp_path):
    svc = service(tmp_path)
    state = start(svc)
    identity = inventory(svc, tmp_path)
    before = snapshot(svc, state[0])
    corrupt_inventory(svc, identity)
    with pytest.raises(KbcStoreError) as raised:
        select(svc, state, identity)
    assert raised.value.code == 'PT-KBC-VERIFY'
    assert snapshot(svc, state[0]) == before


def test_component_replay_failure_does_not_keep_new_manual_decisions(tmp_path):
    svc = service(tmp_path)
    state = start(svc)
    identity = inventory(svc, tmp_path)
    select(svc, state, identity)
    before = snapshot(svc, state[0])
    corrupt_inventory(svc, identity)
    with pytest.raises(KbcStoreError) as raised:
        svc.components(state[0], product=state[1], files=['other.sys'])
    assert raised.value.code == 'PT-KBC-VERIFY'
    assert snapshot(svc, state[0]) == before


def test_component_replay_failure_does_not_publish_product_change(tmp_path):
    doc = document()
    doc['product_tree'].append({'product_id': 'SECOND-PRODUCT', 'name': 'Windows 11 Version 23H2 x64',
                                'family': 'windows-client', 'architecture': 'amd64'})
    doc['vulnerabilities'][0]['remediations'][0]['product_ids'].append('SECOND-PRODUCT')
    doc['vulnerabilities'][0]['product_statuses']['Fixed'].append('SECOND-PRODUCT')
    svc = service(tmp_path, doc=doc)
    searched = svc.search(KB).result
    investigation = searched['investigation_id']
    scopes = {scope['release']: scope['scope_id'] for scope in searched['scopes']}
    state = investigation, scopes['24H2'], searched['revision']
    identity = inventory(svc, tmp_path, product_scope_id=scopes['24H2'])
    select(svc, state, identity, asserted=False)
    svc.components(investigation, product=scopes['23H2'], files=['other.sys'])
    before = snapshot(svc, investigation)
    corrupt_inventory(svc, identity)
    with pytest.raises(KbcStoreError) as raised:
        svc.components(investigation, product=scopes['24H2'], files=[])
    assert raised.value.code == 'PT-KBC-VERIFY'
    assert snapshot(svc, investigation) == before


@pytest.mark.parametrize('method,kwargs', [
    ('inventories', {'limit': True}), ('inventories', {'limit': 101}),
    ('inventories', {'offset': 1_000_001}), ('inventory_details', {'limit': 501}),
    ('inventory_details', {'offset': -1}), ('inventory_details', {'name': 'x' * 129}),
    ('inventory_details', {'name': '\x1b[2J'}), ('inventory_details', {'architecture': 'X64'}),
])
def test_facade_rejects_page_and_filter_bounds_without_mutation(tmp_path, method, kwargs):
    from patchtrace.kbcorrelation.sources.cvrf import SourceError
    svc = service(tmp_path)
    state = start(svc)
    identity = inventory(svc, tmp_path)
    before = snapshot(svc, state[0])
    with pytest.raises(SourceError) as raised:
        if method == 'inventory_details':
            svc.inventory_details(identity[0], **kwargs)
        else:
            svc.inventories(**kwargs)
    assert raised.value.code == 'PT-KBC-INPUT'
    assert snapshot(svc, state[0]) == before


def test_display_text_is_plain_while_json_preserves_raw_hostile_metadata(tmp_path):
    svc = service(tmp_path)
    raw = CSV.replace(b'1.2.3.4', b'1.2.3.4\x1b[2J')
    identity = inventory(svc, tmp_path, raw=raw)
    result = svc.inventory_details(identity[0])
    assert '\x1b' not in result.text
    assert '\x1b' in result.result['entries'][0]['original_version']
    encoded = json.dumps(result.result)
    assert '\x1b' not in encoded and '\\u001b' in encoded



def test_cve_lead_refuses_kb_outside_recorded_month_scope(tmp_path):
    svc = service(tmp_path)
    raw = h.render_json(document(kb='KB5099002', release='2099-Jan'))
    with WorkspaceStore(svc.root) as ws:
        ws.add_document(import_bytes(raw, now=NOW), raw)
    state = start(svc, lead='CVE-2099-30000', months='2099-Feb')
    identity = inventory(svc, tmp_path, kb='KB5099002')
    before = snapshot(svc, state[0])
    with pytest.raises(KbcStoreError) as raised:
        select(svc, state, identity)
    assert raised.value.code == 'PT-KBC-SCOPE'
    assert snapshot(svc, state[0]) == before


def test_csv_claim_provenance_is_exact_and_never_a_binary_hash_or_cve_claim(tmp_path):
    svc = service(tmp_path)
    state = start(svc)
    identity = inventory(svc, tmp_path)
    selected = select(svc, state, identity)
    hints = svc.components(state[0], product=state[1], files=[]).result['hints']
    assert len(hints) == 1
    hint = hints[0]
    assert hint['tier'] == 'E' and hint['changed_in_kb'] == 'unknown'
    assert hint['claim_refs'] == []
    assert hint['inventory_refs'] == [{
        'import_id': identity[0], 'entry_id': identity[1], 'raw_sha256': hashlib.sha256(CSV).hexdigest(),
        'logical_record': 2, 'line_start': 2, 'line_end': 2, 'section_index': 0,
    }]
    assert 'sha256' not in hint and 'cve' not in hint
    assert hint['inventory_refs'] == selected.result['hint']['inventory_refs']


