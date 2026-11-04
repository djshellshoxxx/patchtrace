"""Issue #118 (KB/CVE/acquisition audit) dispositions, P1 scoped investigation and P1 CVE-card provenance.
Synthetic, offline."""
from __future__ import annotations

import kbc_helpers as h
import pytest
from kbc_k1_support import NOW, json_bytes, no_sockets  # noqa: F401
from kbc_k3_support import FixedClock

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import WorkspaceStore

pytestmark = pytest.mark.usefixtures('no_sockets')


def month(release_id, cve, date):
    doc = h.cvrf_document([h.vulnerability(
        cve, f'Synthetic {cve}', cwe=('CWE-125', 'Out-of-bounds Read'),
        remediations=[h.remediation(h.REMEDIATION_VENDOR_FIX, h.KB_CLIENT[2:], [h.PRODUCT_CLIENT], '10.0.26100.9001')],
        product_statuses={'Fixed': [h.PRODUCT_CLIENT]})], release_id=release_id)
    doc['document']['current_release_date'] = date
    return doc


@pytest.fixture
def two_months(tmp_path):
    svc = wiring.build_service(tmp_path / 'ws', clock=FixedClock())
    with WorkspaceStore(svc.root) as ws:
        for rid, cve, date in (('2099-Jan', 'CVE-2099-10001', '2099-01-13'),
                               ('2099-Feb', 'CVE-2099-10002', '2099-02-13')):
            doc = month(rid, cve, date)
            raw = json_bytes(doc)
            ws.add_document(import_bytes(raw, now=NOW), raw)
    return svc


def test_a118_scoped_search_keeps_its_scope_for_the_lead_cves(two_months):
    out = two_months.search(h.KB_CLIENT, months='2099-Jan')
    inv = out.result['investigation_id']
    with WorkspaceStore(two_months.root) as ws:
        rev = ws.current_revision(inv)
        from patchtrace.kbcorrelation.cli_index import load_index
        index, _ = load_index(ws, two_months.ports)
        cves, _, _ = two_months._lead_cves(index, rev, ws)
    assert cves == ('CVE-2099-10001',)


def test_a118_card_and_edge_come_from_the_same_document():
    """#118 P1: document A states CWE-79 but has no edge for the product; document B states CWE-89 with the edge."""
    from test_kbc_card_field_provenance import NOW as T
    from test_kbc_card_field_provenance import imported, index_of, native

    from patchtrace.kbcorrelation import context
    from patchtrace.kbcorrelation.contracts import Lead
    a_raw = native(cwe='CWE-79', edge=False)
    a_raw['DocumentTracking']['Identification']['ID']['Value'] = '2099-Jan'
    a, b = imported(a_raw), imported(native(cwe='CWE-89', edge=True))
    index = index_of(a, b)
    scope = next(s.scope_id for s in index.scopes())
    out = context.build_bundle(
        investigation_id='00000000-0000-4000-8000-000000000118', base_revision=1,
        lead=Lead(kind='cve', value=h.CVE_A, raw=h.CVE_A), cves=(h.CVE_A,), index=index,
        rules=wiring.IntelligenceRules(), now=T, coverage=(index.coverage(now=T),), scope_id=scope, pair_id=None,
        older_sha=None, newer_sha=None)
    # The conflicting CWE is withheld with a stated warning; neither document's CWE is paired with the other's hash.
    assert [c.stated_cwe for c in out.context.cards] == [None]
    assert any(w.startswith('CARD_FACT_CONFLICT:') and 'stated_cwe' in w for w in out.context.unknowns)
    assert not [r for r in out.card_facts if r.field == 'stated_cwe']
    assert {r.doc_id for r in out.card_facts} == {a.doc_id, b.doc_id}
    assert {s.doc_id for s in out.sources} == {a.doc_id, b.doc_id}
