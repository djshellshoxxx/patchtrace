"""Existing coverage compatibility and current admission identity; authored offline controls."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import kbc_helpers as h
import pytest
from kbc_k1_support import NOW, no_sockets, valid_csaf  # noqa: F401
from kbc_k3_support import FixedClock
from kbc_saved_scope_support import add, bundle, document

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.contracts import domain_id
from patchtrace.kbcorrelation.index import ReverseIndex
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.sources.scope import build_coverage
from patchtrace.kbcorrelation.store import WorkspaceStore
from patchtrace.kbcorrelation.workflow import Event

pytestmark = pytest.mark.usefixtures('no_sockets')
NATIVE = Path(__file__).parent / 'fixtures/kbcve/msrc/2024-Aug-CVE-2024-38193.facts.json'


def csaf_add(service, value):
    raw = json.dumps(value).encode()
    doc = import_bytes(raw, now=NOW, advisory=service.env.advisory)
    with WorkspaceStore(service.root) as store:
        assert store.add_document(doc, raw)
    return doc


def legacy_csaf_search(tmp_path):
    service = wiring.build_service(tmp_path / 'workspace', clock=FixedClock())
    value = valid_csaf()
    for title in ('Authored first snapshot', 'Authored second snapshot'):
        value['document']['title'] = title
        csaf_add(service, value)
    investigation = service.search(h.KB_CLIENT).result['investigation_id']
    with WorkspaceStore(service.root) as store:
        index = store.load_index(service.env.advisory)
        active = index.active_ids()
        current, = (doc for doc in index.documents if doc.doc_id in active)
        # The original service's valid receipt counts the active logical CSAF
        # revision, while cached_scope retains both immutable source snapshots.
        recorded = build_coverage(source_kind='csaf', scope=index.cached_scope(),
            requested=(current.doc_id,), inspected=(current.doc_id,),
            watermark=current.source.current_release_date, retrieved_at=NOW)
        assert len(recorded.scope.doc_ids) == 2 and len(recorded.inspected_ids) == 1
        store.put_coverage(recorded)
        rev = store.current_revision(investigation)
        store.apply(rev, Event('search_done', rev.revision, outcome='METADATA_READY',
                              scope_ids=rev.scope_ids, coverage_ids=(recorded.coverage_id,)))
    return service, investigation, recorded


@pytest.mark.parametrize('grow', [False, True])
def test_existing_cached_csaf_receipt_remains_usable_without_rewriting_inspection_history(tmp_path, grow):
    service, investigation, coverage = legacy_csaf_search(tmp_path)
    before = bundle(service, investigation)
    if grow:
        add(service, document('2099-Mar', h.CVE_B, 'unrelated.sys flaw'))
    reopened = wiring.build_service(service.root, clock=FixedClock())
    assert reopened.products(investigation).exit == 0
    after = bundle(reopened, investigation)
    assert after == before and after.context.coverage == (coverage,)
    assert after.context.cards and len(after.sources) == 1


def test_historical_csaf_inspection_heads_never_restore_current_withdrawn_claims(tmp_path):
    service, investigation, coverage = legacy_csaf_search(tmp_path)
    value = valid_csaf()
    tracking = value['document']['tracking']
    tracking['current_release_date'] = '2099-03-01T00:00:00Z'
    tracking['version'] = '2'
    tracking['revision_history'].append({'date': tracking['current_release_date'],
                                          'number': '2', 'summary': 'Authored withdrawal'})
    value['vulnerabilities'] = [copy.deepcopy(value['vulnerabilities'][0])]
    value['vulnerabilities'][0]['cve'] = 'CVE-2099-29999'  # Original CVEs withdrawn; schema still requires one row.
    latest = csaf_add(service, value)
    with WorkspaceStore(service.root) as store:
        index = store.load_index(service.env.advisory)
        assert index.active_ids() == {latest.doc_id}
        found = index.lookup_kb(h.KB_CLIENT, scope=coverage.scope, now=NOW)
        assert not found.edges and found.superseded
    after = bundle(service, investigation)
    assert after.context.coverage == (coverage,)
    assert not after.context.cards and not after.sources
    assert after.edge_set_digest == ReverseIndex().edge_set_digest()


@pytest.mark.parametrize('scope_kind', ['cached', 'files'])
@pytest.mark.parametrize('zoned', [False, True])
def test_tied_or_unknown_counterevidence_changes_saved_cve_context_identity(tmp_path, scope_kind, zoned):
    positive = json.loads(NATIVE.read_bytes())
    positive['DocumentTracking']['CurrentReleaseDate'] = '2026-10-28T01:48:49' + ('Z' if zoned else '')
    negative = copy.deepcopy(positive)
    negative['Vulnerability'][0]['Remediations'] = []
    service = wiring.build_service(tmp_path / 'workspace', clock=FixedClock())
    selected = add(service, positive)
    options = {}
    if scope_kind == 'files':
        path = tmp_path / 'scope.json'
        path.write_text(json.dumps({'doc_ids': [selected.doc_id], 'months': []}), encoding='utf-8')
        options['scope_file'] = path
    investigation = service.search('CVE-2024-38193', **options).result['investigation_id']
    before = bundle(service, investigation)
    assert len(before.context.cards) == 1
    competitor = add(service, negative)
    after = bundle(wiring.build_service(service.root, clock=FixedClock()), investigation)
    assert not after.context.cards and before.context != after.context
    assert before.context_key != after.context_key
    assert before.edge_set_digest != after.edge_set_digest
    with WorkspaceStore(service.root) as store:
        index = store.load_index(service.env.advisory)
        assert index.active_ids() == {selected.doc_id, competitor.doc_id}
        scope = store.get_coverage(store.current_revision(investigation).coverage_ids[0]).scope
        found = index.lookup_cve('CVE-2024-38193', scope=scope, now=NOW)
        assert not found.edges and found.disputed
        assert after.edge_set_digest == domain_id('kbc.edgeset', 1, sorted(e.edge_id for e in found.disputed))
    add(service, document('2099-Mar', h.CVE_B, 'unrelated.sys flaw'))
    assert bundle(service, investigation) == after


def test_agreeing_tied_native_source_outside_finite_scope_keeps_the_same_admitted_context(tmp_path):
    positive = json.loads(NATIVE.read_bytes())
    positive['DocumentTracking']['CurrentReleaseDate'] = '2026-10-28T01:48:49Z'
    agreeing = copy.deepcopy(positive)
    agreeing['DocumentTracking']['RevisionHistory'][0]['Description'] = {'Value': 'Authored identical claim'}
    service = wiring.build_service(tmp_path / 'workspace', clock=FixedClock())
    add(service, positive)
    investigation = service.search('CVE-2024-38193').result['investigation_id']
    before = bundle(service, investigation)
    add(service, agreeing)
    after = bundle(service, investigation)
    assert after == before and len(after.context.cards) == 1
