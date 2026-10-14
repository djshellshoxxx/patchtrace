"""K1: normalised CSAF facts -> `vendor-association` edges (SPEC-37 32A S05, S12-S14, S16; NEG-08). SYNTHETIC/mocked.

The facts come from the real, offline ``intelligence`` validator and normaliser (test-side port binding), so the bridge
is exercised against the production fact shape; nothing here is live evidence about Microsoft's CSAF layout (probe L4).
"""
from __future__ import annotations

import copy
import hashlib
import json

import kbc_helpers as h
import pytest
from kbc_k1_support import (
    CSAF_VALID,
    NOW,
    IntelligenceAdvisoryPort,
    csaf_valid_bytes,
    import_fixture,
    json_bytes,
    no_sockets,  # noqa: F401
)

from patchtrace.kbcorrelation.ports import AdvisoryPort
from patchtrace.kbcorrelation.sources import csaf_bridge
from patchtrace.kbcorrelation.sources.cvrf import SourceError
from patchtrace.kbcorrelation.sources.importer import import_bytes

pytestmark = pytest.mark.usefixtures('no_sockets')
DOC = 'c' * 64
PORT = IntelligenceAdvisoryPort()


def facts_of(doc: dict) -> dict:
    raw = json_bytes(doc)
    return PORT.parse_csaf(raw, source_sha256=hashlib.sha256(raw).hexdigest())


def bridge(doc: dict):
    return csaf_bridge.bridge_facts(facts_of(doc), DOC)


def names(result, edge) -> str:
    return next(s.display_name for s in result.scopes if s.scope_id == edge.scope_id)


def test_port_binding_is_an_advisory_port():
    assert isinstance(PORT, AdvisoryPort)


def test_committed_valid_fixture_matches_its_builder():
    assert h.read_fixture_bytes(CSAF_VALID) == csaf_valid_bytes()


def test_s13_group_expands_to_concrete_products_and_the_edge_is_an_association():
    """S13 + 7.2: KB5099001 comes from a vendor_fix detail through a product group; one edge per concrete product, and the
    relation is vendor-association, never vendor-remediation."""
    result = bridge(json.loads(h.read_fixture_bytes(CSAF_VALID)))
    assert {(e.kb, e.cve, names(result, e), e.relation) for e in result.edges} == {
        ('KB5099001', h.CVE_A, 'Example OS 24H2 x64', 'vendor-association'),
        ('KB5099001', h.CVE_A, 'Example OS 24H2 ARM64', 'vendor-association')}
    assert all(e.ref.pointer == '/vulnerabilities/0/remediations/0' and e.ref.assertion == 'advisory_fact'
               for e in result.edges)
    assert not [e for e in result.edges if e.relation == 'vendor-remediation']


def test_s12_vendor_fix_without_a_kb_makes_no_association():
    result = bridge(json.loads(csaf_valid_bytes()))
    assert not [e for e in result.edges if e.cve == h.CVE_B]
    problem = next(p for p in result.problems if p.code == 'VENDOR_FIX_NO_KB')
    assert problem.level == 'info' and problem.pointer == '/vulnerabilities/1/remediations/0'


def test_s14_neg08_known_not_affected_gets_no_affected_or_fixed_assertion():
    """S14, NEG-08: the legacy server (known_not_affected) never gets an association edge."""
    doc = json.loads(csaf_valid_bytes())
    result = bridge(doc)
    assert 'Example Server 2089 x64' not in {names(result, e) for e in result.edges}
    # and when a KB-bearing vendor_fix does cover it, the edge is disputed, citing the status
    doc['vulnerabilities'][1]['remediations'][0]['details'] = 'Install KB5099002 for Example Server.'
    doc['vulnerabilities'][1]['remediations'][0]['product_ids'] = [h.PRODUCT_SERVER_LEGACY]
    # (group PT-GRP-SERVER still names the two current server products)
    result = bridge(doc)
    edge = next(e for e in result.edges if names(result, e) == 'Example Server 2089 x64')
    assert edge.relation == 'disputed' and edge.product_status.value == 'known_not_affected'
    assert edge.product_status.pointer == '/vulnerabilities/1/product_status/known_not_affected/0'
    assert {names(result, e) for e in result.edges if e.relation == 'vendor-association' and e.cve == h.CVE_B} == {
        'Example Server 2099 x64', 'Example Server 2099 Core x64'}


def test_s05_duplicate_remediations_keep_separate_pointers():
    doc = json.loads(csaf_valid_bytes())
    doc['vulnerabilities'][0]['remediations'].append(copy.deepcopy(doc['vulnerabilities'][0]['remediations'][0]))
    result = bridge(doc)
    rows = [e for e in result.edges if names(result, e) == 'Example OS 24H2 x64']
    assert sorted(e.ref.pointer for e in rows) == ['/vulnerabilities/0/remediations/0',
                                                    '/vulnerabilities/0/remediations/1']


@pytest.mark.parametrize('details,url,kbs', [
    ('Install KB5099001.', None, ['KB5099001']),
    ('See KB5099001 and KB5099002', None, ['KB5099001', 'KB5099002']),
    ('kb5099001, XKB5099001, KB123', None, []),
    ('Update', 'https://support.microsoft.com/help/5099003', ['KB5099003']),
    ('Update', 'https://support.microsoft.com/en-us/help/5099003/some-title', ['KB5099003']),
    ('Update', 'https://support.example.invalid/help/5099003', []),
    ('Update', 'https://evilsupport.microsoft.com.example.invalid/help/5099003', []),
    ('Update', 'https://support.microsoft.com/help/12', []),
])
def test_kb_tokens_only_from_exact_forms(details, url, kbs):
    rem = {'details': details, 'url': url}
    assert list(csaf_bridge.kb_tokens_of(rem)) == kbs


def test_other_categories_are_mention_only_and_unknown_groups_are_reported():
    doc = json.loads(csaf_valid_bytes())
    doc['vulnerabilities'][1]['remediations'] = [{
        'category': 'workaround', 'details': 'Avoid KB5099009 until later.', 'product_ids': [h.PRODUCT_SERVER]}]
    result = bridge(doc)
    assert [(e.kb, e.relation) for e in result.edges if e.cve == h.CVE_B] == [('KB5099009', 'mention-only')]
    facts = facts_of(doc)
    facts['vulnerabilities'][0]['remediations'][0]['group_ids'] = ['NO-SUCH-GROUP']
    facts['vulnerabilities'][0]['remediations'][0]['product_ids'] = []
    out = csaf_bridge.bridge_facts(facts, DOC)
    assert [p.code for p in out.problems if p.code in ('UNKNOWN_GROUP', 'NO_PRODUCTS')] == ['NO_PRODUCTS', 'UNKNOWN_GROUP'] \
        or {p.code for p in out.problems} >= {'UNKNOWN_GROUP', 'NO_PRODUCTS'}
    assert not [e for e in out.edges if e.cve == h.CVE_A]


def test_unknown_product_and_duplicate_cve_rows():
    facts = facts_of(json.loads(csaf_valid_bytes()))
    facts['vulnerabilities'][0]['remediations'][0]['product_ids'] = ['PT-GHOST']
    out = csaf_bridge.bridge_facts(facts, DOC)
    assert any(p.code == 'UNKNOWN_PRODUCT_ID' for p in out.problems)
    twin = copy.deepcopy(facts)
    twin['vulnerabilities'].append(copy.deepcopy(twin['vulnerabilities'][0]))
    out = csaf_bridge.bridge_facts(twin, DOC)
    assert not [e for e in out.edges if e.cve == h.CVE_A] and any(p.code == 'CVE_DUPLICATE' for p in out.problems)


def test_cards_and_statuses():
    result = bridge(json.loads(csaf_valid_bytes()))
    assert [(c.cve, c.source_kind, c.stated_cwe) for c in result.cards] == [(h.CVE_A, 'csaf', 'CWE-125'),
                                                                           (h.CVE_B, 'csaf', 'CWE-190')]
    classes = {(s.cve, s.klass) for s in result.statuses}
    assert (h.CVE_B, 'not_affected') in classes and (h.CVE_A, 'fixed') in classes


def test_s16_forged_microsoft_publisher_never_becomes_verified():
    """S16: a local file whose publisher claims to be Microsoft is still unverified-local-file."""
    doc = json.loads(csaf_valid_bytes())
    doc['document']['publisher'] = {'category': 'vendor', 'name': 'Microsoft Corporation',
                                    'namespace': 'https://www.microsoft.com'}
    imported = import_bytes(json_bytes(doc), now=NOW, advisory=PORT)
    assert imported.source.authenticity == 'unverified-local-file' and imported.source.origin == 'local-import'
    assert imported.source.uri is None and imported.source.kind == 'csaf'


def test_import_through_the_real_validator_and_without_a_port():
    imported = import_fixture(CSAF_VALID)
    assert imported.counts()['edges'] == 2 and imported.source.dialect == 'csaf/2.0'
    assert imported.source.release_id is None and imported.tracking_id == 'PT-SYNTH-KB-2099-02-VALID'
    with pytest.raises(SourceError) as info:
        import_bytes(csaf_valid_bytes(), now=NOW)
    assert info.value.code == 'PT-KBC-UNSUPPORTED'


def test_a_document_the_validator_rejects_is_a_source_error():
    doc = json.loads(csaf_valid_bytes())
    doc['document']['csaf_version'] = '2.0'
    del doc['document']['title']
    with pytest.raises(SourceError) as info:
        import_bytes(json_bytes(doc), now=NOW, advisory=PORT)
    assert info.value.code == 'PT-KBC-SOURCE' and 'rejected' in info.value.message


def test_a_port_returning_facts_for_another_document_is_refused():
    class Liar:
        def parse_csaf(self, raw, *, source_sha256):
            facts = PORT.parse_csaf(raw, source_sha256=source_sha256)
            return {**facts, 'source_id': '0' * 64}

        def report_for(self, *a):
            raise NotImplementedError

    with pytest.raises(SourceError, match='different document'):
        import_bytes(csaf_valid_bytes(), now=NOW, advisory=Liar())
