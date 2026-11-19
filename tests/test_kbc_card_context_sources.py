"""Offline card-consensus dependencies through actual import, context identity and project raw copies."""
from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import json
from pathlib import Path

import pytest
from kbc_k1_support import IntelligenceAdvisoryPort, no_sockets, valid_csaf  # noqa: F401
from kbc_k3_support import FixedClock, write_pair

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.context import ContextBundle, build_bundle
from patchtrace.kbcorrelation.contracts import Lead, SearchScope, domain_id
from patchtrace.kbcorrelation.index import ReverseIndex
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import WorkspaceStore

FIXTURE = Path(__file__).parent / 'fixtures/kbcve/msrc/2024-Aug-CVE-2024-38193.facts.json'
NOW = '2026-11-02T00:00:00Z'
INV = '00000000-0000-4000-8000-000000000153'
CVE = 'CVE-2024-38193'
KB = 'KB5041571'
pytestmark = pytest.mark.usefixtures('no_sockets')


def _raw(value):
    return (json.dumps(value, ensure_ascii=True, indent=2) + '\n').encode()


def _snapshots(conflict=True):
    left = json.loads(FIXTURE.read_bytes())
    left['Vulnerability'][0]['Title'] = {'Value': 'Alpha title'}
    right = copy.deepcopy(left)
    right['DocumentTracking']['RevisionHistory'][0]['Description'] = {'Value': 'Distinct retained snapshot bytes'}
    if conflict:
        right['Vulnerability'][0]['Title'] = {'Value': 'Beta title'}
        right['Vulnerability'][0]['CWE'] = [{'ID': 'CWE-125'}]
    return left, right


def _doc(value):
    return import_bytes(_raw(value), now=NOW)


def _index(*docs):
    result = ReverseIndex()
    for doc in docs:
        result.add(doc)
    return result


def _bundle(index):
    return build_bundle(investigation_id=INV, base_revision=3, lead=Lead(kind='kb', value=KB, raw=KB),
                        cves=(CVE,), index=index, rules=wiring.IntelligenceRules(), now=NOW,
                        coverage=(index.coverage(now=NOW),), scope_id=None, pair_id=None,
                        older_sha=None, newer_sha=None)


@pytest.mark.parametrize('conflict', [False, True], ids=['agreement', 'conflict'])
def test_active_card_source_dependencies_are_bound_with_their_edges(conflict):
    a, b = map(_doc, _snapshots(conflict))
    assert b.edges and len(b.cards) == 1
    before, after = _bundle(_index(a)), _bundle(_index(a, b))
    assert before.edge_set_digest != after.edge_set_digest
    assert before.context_key != after.context_key
    assert {s.doc_id for s in after.sources} == {a.doc_id, b.doc_id}
    card, = after.context.cards
    assert card.stated_cwe == (None if conflict else 'CWE-416')
    assert any(w.startswith('CARD_FACT_CONFLICT:') for w in after.context.unknowns) == conflict


def test_new_active_source_bytes_change_key_even_when_card_consensus_is_unchanged():
    left, right = _snapshots()
    changed = copy.deepcopy(right)
    changed['DocumentTracking']['RevisionHistory'][0]['Description'] = {'Value': 'New raw revision note'}
    a, b, c = map(_doc, (left, right, changed))
    before, after = _bundle(_index(a, b)), _bundle(_index(a, c))
    assert before.context.cards == after.context.cards
    assert before.context.unknowns == after.context.unknowns
    assert before.edge_set_digest != after.edge_set_digest
    assert before.context_key != after.context_key
    assert {s.doc_id for s in after.sources} == {a.doc_id, c.doc_id}


def test_card_contributor_ids_and_context_are_independent_of_insertion_order():
    a, b = map(_doc, _snapshots())
    forward, reverse = _index(a, b), _index(b, a)
    assert forward.lookup_cve(CVE, now=NOW).card_doc_ids == tuple(sorted((a.doc_id, b.doc_id)))
    assert _bundle(forward) == _bundle(reverse)


def test_lookup_contributors_follow_selected_documents_and_cve():
    a, b = map(_doc, _snapshots())
    unrelated = valid_csaf()
    unrelated['vulnerabilities'][0]['cve'] = 'CVE-2024-39999'
    unrelated['vulnerabilities'][0]['product_status'].pop('fixed', None)
    unrelated['vulnerabilities'][0].pop('remediations', None)
    c = import_bytes(_raw(unrelated), now=NOW, advisory=IntelligenceAdvisoryPort())
    index = _index(a, b, c)
    selected = SearchScope(kind='provided_files', doc_ids=(a.doc_id,))
    assert index.lookup_cve(CVE, scope=selected, now=NOW).card_doc_ids == (a.doc_id,)
    assert index.lookup_kb(KB, scope=selected, now=NOW).card_doc_ids == (a.doc_id,)
    assert {s.doc_id for s in _bundle(index).sources} == {a.doc_id, b.doc_id}
    assert _bundle(_index(a, b)).context_key == _bundle(index).context_key


def test_superseded_card_only_snapshot_is_not_a_context_dependency():
    left, right = _snapshots()
    left['DocumentTracking']['CurrentReleaseDate'] = '2026-11-02T00:00:00Z'
    right['DocumentTracking']['CurrentReleaseDate'] = '2026-11-01T00:00:00Z'
    a, b = map(_doc, (left, right))
    index = _index(a, b)
    assert index.active_ids() == {a.doc_id}
    assert index.lookup_cve(CVE, now=NOW).card_doc_ids == (a.doc_id,)
    before, after = _bundle(_index(a)), _bundle(index)
    assert before.context_key == after.context_key
    assert {s.doc_id for s in after.sources} == {a.doc_id}


def test_other_source_kind_conflict_warning_keeps_its_own_raw_dependencies():
    native = _doc(_snapshots()[0])
    csafs = []
    for position, title in enumerate(('CSAF Alpha', 'CSAF Beta')):
        value = valid_csaf()
        value['document']['tracking']['id'] += str(position)
        value['vulnerabilities'] = [value['vulnerabilities'][0]]
        value['vulnerabilities'][0].update(cve=CVE, title=title)
        value['vulnerabilities'][0]['product_status'].pop('fixed')
        del value['vulnerabilities'][0]['remediations']
        csafs.append(import_bytes(_raw(value), now=NOW, advisory=IntelligenceAdvisoryPort()))
    assert all(not doc.edges for doc in csafs)
    bundle = _bundle(_index(native, *csafs))
    assert bundle.context.cards[0].source_kind == 'cvrf'
    assert bundle.context.cards[0].title == 'Alpha title'
    assert any('csaf active source cards disagree' in warning for warning in bundle.context.unknowns)
    assert {s.doc_id for s in bundle.sources} == {native.doc_id, *(doc.doc_id for doc in csafs)}
    assert {s.kind for s in bundle.sources} == {'cvrf-month', 'csaf'}


def test_unlocatable_xml_card_does_not_hide_locatable_csaf_card():
    from test_kbc_cvrf import XML_VULN, xml_doc

    xml_cve = 'CVE-2099-30002'
    xml = import_bytes(xml_doc(XML_VULN), now=NOW)
    value = valid_csaf()
    value['vulnerabilities'][0]['cve'] = xml_cve
    value['vulnerabilities'][0]['title'] = 'Located CSAF card'
    csaf = import_bytes(_raw(value), now=NOW, advisory=IntelligenceAdvisoryPort())
    index = _index(xml, csaf)
    bundle = build_bundle(investigation_id=INV, base_revision=3,
                          lead=Lead(kind='cve', value=xml_cve, raw=xml_cve), cves=(xml_cve,),
                          index=index, rules=wiring.IntelligenceRules(), now=NOW,
                          coverage=(index.coverage(now=NOW),), scope_id=None, pair_id=None,
                          older_sha=None, newer_sha=None)
    card, = bundle.context.cards
    assert card.source_kind == 'csaf' and card.title == 'Located CSAF card'
    assert {source.doc_id for source in bundle.sources} == {xml.doc_id, csaf.doc_id}
    assert not any('CARD_FACT_SOURCE_MISSING:' in warning for warning in bundle.context.unknowns)


def test_card_only_conflict_without_a_remediation_still_retains_warning_sources():
    left, right = _snapshots()
    left['Vulnerability'][0]['Remediations'] = []
    a, b = map(_doc, (left, right))
    bundle = _bundle(_index(a, b))
    assert not bundle.context.cards
    assert any(w.startswith('CARD_FACT_CONFLICT:') for w in bundle.context.unknowns)
    assert {s.doc_id for s in bundle.sources} == {a.doc_id, b.doc_id}


def test_actual_attachment_preserves_every_consensus_source_byte_and_persisted_identity(tmp_path):
    service = wiring.build_service(tmp_path / 'ws', clock=FixedClock())
    originals = {}
    with WorkspaceStore(service.root) as ws:
        for value in _snapshots():
            raw, doc = _raw(value), _doc(value)
            assert ws.add_document(doc, raw)
            originals[doc.source.sha256] = raw
    search = service.search(KB)
    old, new = write_pair(tmp_path)
    project = tmp_path / 'P'
    out = service.import_pair(search.result['investigation_id'], str(old), str(new), str(project))
    assert out.exit == 0
    exported = tmp_path / 'context.json'
    assert service.export(str(project), str(exported), overwrite=False).exit == 0
    bundle = ContextBundle.model_validate_json(exported.read_bytes())
    assert bundle.context_key == out.result['context_key']
    assert {s.sha256 for s in bundle.sources} == set(originals)
    assert {p.name for p in (project / 'kb/sources').glob('*.gz')} == {sha + '.json.gz' for sha in originals}
    for sha, expected in originals.items():
        stored = json.loads(gzip.decompress((project / 'kb/sources' / (sha + '.json.gz')).read_bytes()))
        raw = base64.b64decode(stored['bytes'], validate=True)
        assert raw == expected and hashlib.sha256(raw).hexdigest() == sha
    service = wiring.build_service(service.root, clock=FixedClock())
    assert any(w.startswith('CARD_FACT_CONFLICT:') for w in service.explain(str(project), None).result['unknowns'])


def test_original_key_policy_bundle_remains_readable_without_rekeying():
    doc = _doc(_snapshots()[0])
    new = _bundle(_index(doc))
    old_key = domain_id('kbc.context', 1, {
        'inv': INV, 'revision': 3, 'edge_set_digest': new.edge_set_digest, 'csaf_source_shas': [],
        'rules_digest': new.rules_digest, 'lexicon_digest': new.lexicon_digest,
        'kev_snapshot_sha': None, 'older': None, 'newer': None, 'scope_id': None,
        'versions': {'contract': 'kbcorrelation/1', 'bundle': 1}})
    old = new.model_dump(mode='json')
    old['context_key'] = old_key
    restored = ContextBundle.model_validate_json(json.dumps(old))
    assert restored.context_key == old_key != new.context_key
    assert restored.context == new.context and restored.sources == new.sources
