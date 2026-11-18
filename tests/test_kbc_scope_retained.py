"""Issue #118 P1a: a document-scoped KB search keeps its scope for every later lead lookup.

Recovered from claude/ws-p-20261104 (commit 5984511c), which never reached main. Before the fix the recorded
search used the `--months` scope, but lead CVEs, lead KBs, cards and the context bundle were looked up across the
whole cached corpus, so an investigation silently widened. Synthetic and offline."""
from __future__ import annotations

import kbc_helpers as h
import pytest
from kbc_k1_support import NOW, json_bytes, no_sockets  # noqa: F401
from kbc_k3_support import FixedClock

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.cli_index import load_index
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
    """The same KB fixes one CVE in January and another in February."""
    svc = wiring.build_service(tmp_path / 'ws', clock=FixedClock())
    with WorkspaceStore(svc.root) as ws:
        for rid, cve, date in (('2099-Jan', 'CVE-2099-10001', '2099-01-13'),
                               ('2099-Feb', 'CVE-2099-10002', '2099-02-13')):
            raw = json_bytes(month(rid, cve, date))
            ws.add_document(import_bytes(raw, now=NOW), raw)
    return svc


def _lead(svc, **search):
    out = svc.search(h.KB_CLIENT, **search)
    with WorkspaceStore(svc.root) as ws:
        rev = ws.current_revision(out.result['investigation_id'])
        index, _ = load_index(ws, svc.ports)
        cves, _, _ = svc._lead_cves(index, rev, ws)
        cards, _ = svc._lead_cards(index, rev, ws)
        kbs = svc._lead_kbs(index, rev, svc._stored_scope(ws, rev))
    return cves, cards, kbs


def test_month_scoped_search_keeps_its_scope_for_lead_cves_and_cards(two_months):
    cves, cards, kbs = _lead(two_months, months='2099-Jan')
    assert cves == ('CVE-2099-10001',)
    assert [c.cve for c in cards] == ['CVE-2099-10001']
    assert set(kbs) == {h.KB_CLIENT}


def test_unscoped_search_still_reads_the_whole_cached_corpus(two_months):
    cves, cards, _ = _lead(two_months)
    assert cves == ('CVE-2099-10001', 'CVE-2099-10002')
    assert [c.cve for c in cards] == ['CVE-2099-10001', 'CVE-2099-10002']
