"""Fresh #153 review regressions; offline mutations of the pinned native factual projection."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
from kbc_k1_support import IntelligenceAdvisoryPort, no_sockets, valid_csaf  # noqa: F401
from kbc_k3_support import FixedClock, write_pair

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.index import ReverseIndex
from patchtrace.kbcorrelation.sources.cvrf import parse_cvrf
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import WorkspaceStore

FIXTURE = Path(__file__).parent / 'fixtures/kbcve/msrc/2024-Aug-CVE-2024-38193.facts.json'
NOW = '2026-11-02T00:00:00Z'
CVE = 'CVE-2024-38193'
KB = 'KB5041571'
pytestmark = pytest.mark.usefixtures('no_sockets')


def _data():
    return json.loads(FIXTURE.read_bytes())


def _raw(value):
    return (json.dumps(value, ensure_ascii=True, indent=2) + '\n').encode('utf-8')


def _import(value):
    return import_bytes(_raw(value), now=NOW)


def _snapshots(*, zoned=False):
    left = _data()
    left['Vulnerability'][0]['Title'] = {'Value': 'Alpha title in alpha.sys'}
    if zoned:
        left['DocumentTracking']['CurrentReleaseDate'] += 'Z'
    right = copy.deepcopy(left)
    right['Vulnerability'][0]['Title'] = {'Value': 'Beta title in beta.sys'}
    right['Vulnerability'][0]['CWE'] = [{'ID': 'CWE-125'}]
    return left, right


def _index(*docs):
    index = ReverseIndex()
    for doc in docs:
        index.add(doc)
    return index


def _conflicts(lookup):
    return tuple(w for w in lookup.warnings if w.startswith('CARD_FACT_CONFLICT:'))


@pytest.mark.parametrize('zoned', [False, True], ids=['unknown-order', 'tied-instants'])
def test_conflicting_active_card_fields_are_withheld_independently_of_insertion_order(zoned):
    a, b = map(_import, _snapshots(zoned=zoned))
    results = []
    for docs in ((a, b), (b, a)):
        index = _index(*docs)
        assert index.active_ids() == {a.doc_id, b.doc_id}
        lookup = index.lookup_cve(CVE, now=NOW)
        assert {e.ref.doc_id for e in lookup.edges} == {a.doc_id, b.doc_id}
        assert len(lookup.edges) == len(a.edges) + len(b.edges)
        card, = lookup.cards
        assert card.title is None and card.stated_cwe is None
        warning, = _conflicts(lookup)
        assert CVE in warning and 'cvrf' in warning and 'title' in warning and 'stated_cwe' in warning
        assert any(w.startswith('REVISION_ORDER_UNKNOWN:') for w in lookup.warnings)
        assert _conflicts(index.lookup_kb(KB, now=NOW)) == (warning,)
        results.append((lookup.cards, lookup.edges, lookup.warnings))
    assert results[0] == results[1]
    # The presentation must not mutate either original source card.
    assert (a.cards[0].title, a.cards[0].stated_cwe) == ('Alpha title in alpha.sys', 'CWE-416')
    assert (b.cards[0].title, b.cards[0].stated_cwe) == ('Beta title in beta.sys', 'CWE-125')


@pytest.mark.parametrize('field', ['Title', 'CWE'])
@pytest.mark.parametrize('missing', [False, True], ids=['different-value', 'absent-value'])
def test_only_disagreeing_fields_are_withheld_and_absence_is_not_agreement(field, missing):
    left, right = _snapshots()
    right['Vulnerability'][0] = copy.deepcopy(left['Vulnerability'][0])
    if missing:
        del right['Vulnerability'][0][field]
    else:
        right['Vulnerability'][0][field] = {'Value': 'Different title'} if field == 'Title' else [{'ID': 'CWE-125'}]
    for docs in ((_import(left), _import(right)), (_import(right), _import(left))):
        lookup = _index(*docs).lookup_cve(CVE, now=NOW)
        card, = lookup.cards
        assert card.title == (None if field == 'Title' else 'Alpha title in alpha.sys')
        assert card.stated_cwe == (None if field == 'CWE' else 'CWE-416')
        warning, = _conflicts(lookup)
        assert ('stated_cwe' in warning) == (field == 'CWE')
        assert ('title' in warning) == (field == 'Title')


def test_agreeing_active_cards_keep_facts_without_claiming_known_revision_order():
    left, _ = _snapshots()
    right = copy.deepcopy(left)
    right['DocumentTracking']['RevisionHistory'][0]['Number'] = 'unverified revision string'
    a, b = _import(left), _import(right)
    assert a.doc_id != b.doc_id
    lookup = _index(a, b).lookup_cve(CVE, now=NOW)
    assert lookup.cards == a.cards
    assert not _conflicts(lookup)
    assert any(w.startswith('REVISION_ORDER_UNKNOWN:') for w in lookup.warnings)


def test_one_native_snapshot_has_no_revision_order_ambiguity():
    doc = _import(_data())
    lookup = _index(doc).lookup_cve(CVE, now=NOW)
    assert not any(w.startswith('REVISION_ORDER_UNKNOWN:') for w in lookup.warnings)


def test_ambiguous_snapshots_dispute_edges_not_shared_by_every_snapshot():
    left, right = _snapshots()
    right['Vulnerability'][0]['Remediations'] = []
    a, b = _import(left), _import(right)
    lookup = _index(a, b).lookup_kb(KB, now=NOW)
    assert not lookup.edges
    assert {edge.ref.doc_id for edge in lookup.disputed} == {a.doc_id}
    assert all(edge.conflict_ids for edge in lookup.disputed)
    assert any(w.startswith('REVISION_EDGE_CONFLICT:') and CVE in w and KB in w for w in lookup.warnings)
    assert any(w.startswith('REVISION_ORDER_UNKNOWN:') for w in lookup.warnings)


def test_revision_conflict_does_not_spread_to_a_different_release_month():
    left, right = _snapshots()
    right['Vulnerability'][0]['Remediations'] = []
    separate_month = copy.deepcopy(left)
    separate_month['DocumentTracking']['Identification']['ID']['Value'] = '2024-Sep'
    separate_month['DocumentTracking']['CurrentReleaseDate'] = '2024-09-01T00:00:00Z'
    ambiguous, missing, independent = map(_import, (left, right, separate_month))
    lookup = _index(ambiguous, missing, independent).lookup_kb(KB, now=NOW)
    assert {edge.ref.doc_id for edge in lookup.edges} == {independent.doc_id}
    assert {edge.ref.doc_id for edge in lookup.disputed} == {ambiguous.doc_id}


def test_comparable_newer_revision_keeps_its_own_facts_without_conflict_with_superseded_cards():
    left, right = _snapshots(zoned=True)
    right['DocumentTracking']['CurrentReleaseDate'] = '2026-10-29T01:48:49Z'
    a, b = _import(left), _import(right)
    for docs in ((a, b), (b, a)):
        index = _index(*docs)
        lookup = index.lookup_cve(CVE, now=NOW)
        assert index.active_ids() == {b.doc_id}
        assert lookup.cards == b.cards and not _conflicts(lookup)
        assert {e.ref.doc_id for e in lookup.superseded} == {a.doc_id}


def test_cvrf_and_csaf_cards_remain_separate_consensus_groups():
    native, _ = _snapshots()
    csaf = valid_csaf()
    csaf['vulnerabilities'][0]['cve'] = CVE
    csaf['vulnerabilities'][0]['title'] = 'Separate CSAF title'
    csaf['vulnerabilities'][0]['cwe'] = {'id': 'CWE-787', 'name': 'Out-of-bounds Write'}
    native_doc = _import(native)
    csaf_doc = import_bytes(_raw(csaf), now=NOW, advisory=IntelligenceAdvisoryPort())
    for docs in ((native_doc, csaf_doc), (csaf_doc, native_doc)):
        lookup = _index(*docs).lookup_cve(CVE, now=NOW)
        assert {c.source_kind: (c.title, c.stated_cwe) for c in lookup.cards} == {
            'cvrf': ('Alpha title in alpha.sys', 'CWE-416'), 'csaf': ('Separate CSAF title', 'CWE-787')}
        assert not _conflicts(lookup)


def test_conflicts_survive_raw_snapshot_reload_and_reach_kb_search_and_attached_context(tmp_path):
    values = _snapshots()
    service = wiring.build_service(tmp_path / 'ws', clock=FixedClock())
    originals = []
    with WorkspaceStore(service.root) as ws:
        for value in values:
            raw = _raw(value)
            doc = _import(value)
            originals.append(doc)
            assert ws.add_document(doc, raw)
    with WorkspaceStore(service.root, create=False) as ws:
        reloaded = ws.load_index()
        for doc, value in zip(originals, values, strict=True):
            assert reloaded.get(doc.doc_id) == doc
            raw = ws.read_object(doc.source.sha256)
            assert raw == _raw(value) and hashlib.sha256(raw).hexdigest() == doc.source.sha256
        assert _conflicts(reloaded.lookup_cve(CVE, now=NOW))
    search = service.search(KB)
    assert any(w.startswith('CARD_FACT_CONFLICT:') for w in search.warnings)
    assert search.result['cards'][0]['stated_cwe'] is None
    old, new = write_pair(tmp_path)
    project = tmp_path / 'P'
    assert service.import_pair(search.result['investigation_id'], str(old), str(new), str(project)).exit == 0
    explanation = service.explain(str(project), None)
    assert any(w.startswith('CARD_FACT_CONFLICT:') for w in explanation.result['unknowns'])
    card, = explanation.result['cves']
    assert card['card']['stated_cwe'] is None and not card['hypotheses']


def test_type2_missing_description_has_resolvable_diagnostic_and_skips_only_its_row(tmp_path):
    value = _data()
    baseline = _import(value)
    del value['Vulnerability'][0]['Remediations'][0]['Description']
    raw = _raw(value)
    doc = _import(value)
    problem, = (p for p in doc.problems if p.code == 'ROW_SHAPE')
    assert problem.pointer == '/Vulnerability/0/Remediations/0' and 'Description' in problem.detail
    target = value
    for part in problem.pointer.split('/')[1:]:
        target = target[int(part)] if isinstance(target, list) else target[part]
    assert 'Description' not in target and target['Type'] == 2
    assert not [e for e in doc.edges if e.kb == KB]
    assert len(doc.edges) == len(baseline.edges) - 2
    assert all(rem.pointer != problem.pointer for rem in parse_cvrf(raw).vulnerabilities[0].remediations)
    with WorkspaceStore(tmp_path / 'ws') as ws:
        ws.add_document(doc, raw)
        assert ws.read_object(doc.source.sha256) == raw
        restored, = ws.load_index().documents
        assert restored == doc


def test_missing_native_fields_use_existing_parent_pointers():
    value = _data()
    del value['DocumentTracking']['CurrentReleaseDate']
    del value['Vulnerability'][0]['Remediations'][0]['Description']
    raw = _raw(value)
    doc = _import(value)

    def resolve(pointer):
        target = json.loads(raw)
        for part in pointer.split('/')[1:]:
            part = part.replace('~1', '/').replace('~0', '~')
            target = target[int(part)] if isinstance(target, list) else target[part]
        return True

    for problem in doc.problems:
        assert resolve(problem.pointer)
    assert next(p for p in doc.problems if p.code == 'DATE_INVALID').pointer == '/DocumentTracking'


def test_legitimate_nonfix_rows_may_omit_description_without_new_shape_errors():
    value = _data()
    missing = [i for i, rem in enumerate(value['Vulnerability'][0]['Remediations']) if 'Description' not in rem]
    assert missing and {value['Vulnerability'][0]['Remediations'][i]['Type'] for i in missing} == {3}
    doc = _import(value)
    assert not [p for p in doc.problems if p.code == 'ROW_SHAPE']
    parsed = parse_cvrf(_raw(value))
    assert {f'/Vulnerability/0/Remediations/{i}' for i in missing} <= {
        rem.pointer for rem in parsed.vulnerabilities[0].remediations}


@pytest.mark.parametrize(('description', 'suffix'), [
    (None, '/Description'), ({}, '/Description'), ({'Value': None}, '/Description/Value'),
    ('5041571', '/Description')])
def test_present_malformed_type2_description_keeps_existing_rejection(description, suffix):
    value = _data()
    value['Vulnerability'][0]['Remediations'][0]['Description'] = description
    doc = _import(value)
    assert not [e for e in doc.edges if e.kb == KB]
    assert any(p.code == 'ROW_SHAPE' and p.pointer == '/Vulnerability/0/Remediations/0' + suffix
               for p in doc.problems)


def test_mixed_native_and_synthetic_revisions_dispute_withdrawn_remediation():
    native = _import(_data())
    synthetic = native.model_copy(update={
        'source': native.source.model_copy(update={
            'doc_id': native.doc_id + '-synthetic',
            'dialect': 'cvrf-json/0',
        }),
        'edges': (),
    })
    lookup = _index(native, synthetic).lookup_kb(KB, now=NOW)
    assert not lookup.edges
    assert {edge.ref.doc_id for edge in lookup.disputed} == {native.doc_id}
    assert any(w.startswith('REVISION_EDGE_CONFLICT:') and CVE in w and KB in w
               for w in lookup.warnings)
