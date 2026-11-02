"""Authored, offline advisory controls for field/source attribution through actual rules and persistence."""
from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import json
from dataclasses import replace

import kbc_helpers as h
import pytest
from kbc_k1_support import IntelligenceAdvisoryPort, no_sockets, valid_csaf  # noqa: F401
from kbc_k3_support import FixedClock, write_pair

from patchtrace.kbcorrelation import context, wiring
from patchtrace.kbcorrelation.contracts import Lead, SearchScope, domain_id
from patchtrace.kbcorrelation.index import ReverseIndex
from patchtrace.kbcorrelation.products import clean_text
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import WorkspaceStore

pytestmark = pytest.mark.usefixtures('no_sockets')
NOW = '2099-02-15T00:00:00Z'
INV = '00000000-0000-4000-8000-000000000153'


def imported(value):
    return import_bytes(h.render_json(value), now=NOW, advisory=IntelligenceAdvisoryPort())


def index_of(*docs):
    index = ReverseIndex()
    for doc in docs:
        index.add(doc)
    return index


def bundle(*docs):
    index = index_of(*docs)
    return context.build_bundle(
        investigation_id=INV, base_revision=1, lead=Lead(kind='cve', value=h.CVE_A, raw=h.CVE_A),
        cves=(h.CVE_A,), index=index, rules=wiring.IntelligenceRules(), now=NOW,
        coverage=(index.coverage(now=NOW),), scope_id=None, pair_id=None, older_sha=None, newer_sha=None)


def mixed_sources():
    cvrf = h.cvrf_document([
        h.vulnerability(h.CVE_A, 'Authored target read issue', cwe=('CWE-125', 'Out-of-bounds Read')),
        h.vulnerability(h.CVE_B, 'Unrelated null issue', cwe=('CWE-476', 'NULL Pointer Dereference'))])
    csaf = valid_csaf()
    target = csaf['vulnerabilities'][0]
    target.update(title='Authored target write issue', cwe={'id': 'CWE-787', 'name': 'Out-of-bounds Write'})
    decoy = dict(target, cve=h.CVE_B, title='Unrelated integer issue',
                 cwe={'id': 'CWE-190', 'name': 'Integer Overflow'},
                 product_status={'known_affected': [h.PRODUCT_SERVER]})
    decoy.pop('remediations', None)
    csaf['vulnerabilities'] = [decoy, target]
    return cvrf, csaf


def native(*, title='Shared advisory title', cwe='CWE-125', edge=True, position=0):
    row = {'CVE': h.CVE_A, 'Title': {'Value': title}, 'CWE': [{'ID': cwe}, {'ID': cwe}],
           'ProductStatuses': [{'Type': 3, 'ProductID': ['P1']}],
           'Remediations': [{'Type': 2, 'Description': {'Value': h.KB_SERVER}, 'ProductID': ['P1']}]
           if edge else []}
    rows = [{'CVE': h.CVE_B, 'Title': {'Value': 'Unrelated entry'}, 'CWE': [{'ID': 'CWE-476'}]}] * position
    return {'DocumentType': {'Value': 'Security Update'},
            'DocumentTracking': {'Identification': {'ID': {'Value': '2099-Feb'}}, 'Status': 2, 'Version': '1'},
            'ProductTree': {'FullProductName': [{'ProductID': 'P1', 'Value': 'Example Server 2099 x64'}]},
            'Vulnerability': [*rows, row]}


def resolve(value, pointer):
    for part in pointer.split('/')[1:]:
        part = part.replace('~1', '/').replace('~0', '~')
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def assert_resolves(result, originals):
    assert result.card_facts
    for ref in result.card_facts:
        raw = originals[ref.source_sha256]
        assert hashlib.sha256(raw).hexdigest() == ref.source_sha256
        actual = resolve(json.loads(raw), ref.pointer)
        assert (clean_text(actual) if ref.field == 'title' else actual) == ref.value
        assert next(s for s in result.sources if s.doc_id == ref.doc_id).sha256 == ref.source_sha256
    for profile in result.cwe_profiles:
        refs = [r for r in result.card_facts if r.cve == profile.cve]
        for item in profile.classifications:
            assert set(item.pointers) <= {r.pointer for r in refs}
            if item.basis.startswith('explicit-'):
                assert any(r.field == 'stated_cwe' and r.value == item.cwe_id for r in refs)


@pytest.mark.parametrize('reverse', [False, True])
def test_card_only_fact_never_borrows_other_source_edge_pointer(reverse, monkeypatch):
    from patchtrace.intelligence import lexicon
    values = mixed_sources()
    a, b = map(imported, values)
    assert not a.edges and any(e.cve == h.CVE_A for e in b.edges)
    original = lexicon.classify
    calls = []
    def record(fact, **kwargs):
        calls.append(fact)
        return original(fact, **kwargs)
    monkeypatch.setattr(lexicon, 'classify', record)
    result = bundle(*(b, a) if reverse else (a, b))
    assert result.context.cards[0].stated_cwe == 'CWE-125'
    classification, = result.cwe_profiles[0].classifications
    assert classification.basis == 'explicit-advisory-cwe'
    assert classification.pointers == ('/vulnerabilities/0/cwe/id',)
    assert result.hypotheses[0].hypotheses[0].basis == 'explicit-advisory-cwe'
    assert {fact.source_id for fact in calls} == {a.source.sha256}
    assert calls[0].cwe.pointer == '/vulnerabilities/0/cwe/id'
    assert calls[0].notes[0].pointer == '/vulnerabilities/0/title'
    assert {r.doc_id for r in result.card_facts} == {a.doc_id}
    assert {s.doc_id for s in result.sources} == {a.doc_id, b.doc_id}
    restored = context.ContextBundle.model_validate_json(result.model_dump_json())
    assert restored == result
    assert_resolves(restored, {d.source.sha256: h.render_json(v) for d, v in zip((a, b), values, strict=True)})


def test_native_agreeing_contributors_keep_all_exact_fields_without_strength_promotion(monkeypatch):
    from patchtrace.intelligence import lexicon
    values = (native(title='out-of-bounds read in exampledrv.sys'),
              native(title='out-of-bounds read in exampledrv.sys', edge=False, position=1))
    a, b = map(imported, values)
    calls, original = [], lexicon.classify
    def record(fact, **kwargs):
        calls.append(fact)
        return original(fact, **kwargs)
    monkeypatch.setattr(lexicon, 'classify', record)
    one, both = bundle(a), bundle(a, b)
    assert {fact.source_id for fact in calls} == {a.source.sha256, b.source.sha256}
    assert both == bundle(b, a)
    assert both.hypotheses == one.hypotheses
    assert both.cwe_profiles[0].status == one.cwe_profiles[0].status == 'explicit'
    refs = both.card_facts
    assert len([r for r in refs if r.field == 'stated_cwe']) == 4
    assert {r.pointer for r in refs if r.field == 'title'} == {
        '/Vulnerability/0/Title/Value', '/Vulnerability/1/Title/Value'}
    assert '/cwe' not in both.cwe_profiles[0].classifications[0].pointers
    assert_resolves(both, {d.source.sha256: h.render_json(v) for d, v in zip((a, b), values, strict=True)})


@pytest.mark.parametrize('field,missing', [('title', False), ('title', True), ('stated_cwe', False), ('stated_cwe', True)])
def test_conflicting_and_missing_fields_are_withheld_without_borrowed_refs(field, missing):
    left, right = native(), native(edge=False, position=1)
    row = right['Vulnerability'][1]
    key = 'Title' if field == 'title' else 'CWE'
    if missing:
        del row[key]
    else:
        row[key] = {'Value': 'Other title'} if field == 'title' else [{'ID': 'CWE-787'}]
    a, b = map(imported, (left, right))
    result = bundle(a, b)
    assert getattr(result.context.cards[0], field) is None
    assert all(r.field != field for r in result.card_facts)
    assert any('CARD_FACT_CONFLICT:' in warning for warning in result.context.unknowns)
    if field == 'stated_cwe':
        assert not result.hypotheses[0].hypotheses
    assert_resolves(result, {d.source.sha256: h.render_json(v) for d, v in zip((a, b), (left, right), strict=True)})


def test_missing_internal_locator_is_withheld_instead_of_using_edge():
    doc = imported(native())
    broken = replace(doc, card_facts=tuple(r for r in doc.card_facts if r.field != 'stated_cwe'))
    result = bundle(broken)
    assert result.context.cards[0].stated_cwe is None
    assert not result.hypotheses[0].hypotheses
    assert any('CARD_FACT_SOURCE_MISSING:' in w for w in result.context.unknowns)


def test_duplicate_cve_rows_remain_ambiguous_and_xml_does_not_invent_json_locations():
    value = native()
    value['Vulnerability'].append(copy.deepcopy(value['Vulnerability'][0]))
    duplicate = imported(value)
    assert not duplicate.card_facts and not duplicate.cards and not duplicate.edges
    from test_kbc_cvrf import XML_VULN, xml_doc
    xml = import_bytes(xml_doc(XML_VULN.replace('CVE-2099-30002', h.CVE_A)), now=NOW)
    assert xml.cards and xml.edges and not xml.card_facts
    result = bundle(xml)
    assert not result.context.cards and not result.cwe_profiles and not result.card_facts
    assert {s.sha256 for s in result.sources} == {xml.source.sha256}
    assert any('CARD_FACT_SOURCE_MISSING:' in w for w in result.context.unknowns)


def test_selected_lookup_excludes_out_of_scope_field_contributors():
    a, b = imported(native()), imported(native(cwe='CWE-787', edge=False))
    index = index_of(a, b)
    lookup = index.lookup_cve(h.CVE_A, scope=SearchScope(kind='provided_files', doc_ids=(a.doc_id,)), now=NOW)
    assert lookup.card_doc_ids == (a.doc_id,)
    from patchtrace.kbcorrelation.card_provenance import bind_consensus
    card, refs, missing = bind_consensus(lookup.cards[0], (index.get(i) for i in lookup.card_doc_ids))
    assert card.stated_cwe == 'CWE-125' and not missing
    assert {r.doc_id for r in refs} == {a.doc_id}


def test_csaf_default_basis_and_exact_raw_cwe_id_are_preserved():
    from patchtrace.intelligence import lexicon
    from patchtrace.intelligence.contracts import CVEFact, CweRef
    fact = CVEFact(source_id='1' * 64, cve=h.CVE_A, pointer='/vulnerabilities/0',
                   cwe=CweRef(id='CWE-125', name='Read', pointer='/vulnerabilities/0/cwe'))
    assert lexicon.classify(fact).classifications[0].basis == 'explicit-csaf-cwe'
    result = bundle(imported(mixed_sources()[1]))
    assert result.cwe_profiles[0].classifications[0].basis == 'explicit-csaf-cwe'
    assert result.cwe_profiles[0].classifications[0].pointers == ('/vulnerabilities/1/cwe/id',)


@pytest.mark.parametrize('mutation', ['sha', 'value', 'pointer', 'hypothesis'])
def test_persisted_provenance_rejects_cross_record_mismatches(mutation):
    data = bundle(imported(native())).model_dump(mode='json')
    if mutation == 'sha':
        data['card_facts'][0]['source_sha256'] = 'a' * 64
    elif mutation == 'value':
        data['card_facts'][0]['value'] = 'CVE-2099-29999'
    elif mutation == 'pointer':
        data['cwe_profiles'][0]['classifications'][0]['pointers'] = ['/wrong']
    else:
        data['hypotheses'][0]['hypotheses'][0]['cwe_id'] = 'CWE-787'
    with pytest.raises(ValueError):
        context.ContextBundle.model_validate_json(json.dumps(data))


def test_key_policy_three_invalidates_old_result_but_old_wire_stays_readable():
    result = bundle(imported(native()))
    payload = {'inv': INV, 'revision': 1, 'edge_set_digest': result.edge_set_digest,
               'advisory_sources': [s.model_dump(mode='json') for s in result.sources],
               'rules_digest': result.rules_digest, 'lexicon_digest': result.lexicon_digest,
               'kev_snapshot_sha': None, 'older': None, 'newer': None, 'scope_id': None,
               'versions': {'contract': 'kbcorrelation/1', 'bundle': 1}}
    assert context.CONTEXT_KEY_VERSION == 3 and context.BUNDLE_VERSION == 1
    assert domain_id('kbc.context', 2, payload) != result.context_key == domain_id('kbc.context', 3, payload)
    old = result.model_dump(mode='json')
    old.pop('card_facts')
    old['context_key'] = domain_id('kbc.context', 2, payload)
    old['cwe_profiles'][0]['classifications'][0]['basis'] = 'explicit-csaf-cwe'
    old['hypotheses'][0]['hypotheses'][0]['basis'] = 'explicit-csaf-cwe'
    restored = context.ContextBundle.model_validate_json(json.dumps(old))
    assert not restored.card_facts and restored.context_key == old['context_key']


def test_actual_attach_reload_and_export_retain_raw_values_and_field_references(tmp_path):
    service = wiring.build_service(tmp_path / 'ws', clock=FixedClock())
    originals = {}
    with WorkspaceStore(service.root) as ws:
        for value in mixed_sources():
            raw, doc = h.render_json(value), imported(value)
            assert ws.add_document(doc, raw)
            originals[doc.source.sha256] = raw
        reloaded = ws.load_index(IntelligenceAdvisoryPort())
        assert all(doc.card_facts for doc in reloaded.documents)
    search = service.search(h.CVE_A)
    older, newer = write_pair(tmp_path)
    project = tmp_path / 'P'
    out = service.import_pair(search.result['investigation_id'], str(older), str(newer), str(project))
    assert out.exit == 0
    exported = tmp_path / 'context.json'
    assert service.export(str(project), str(exported), overwrite=False).exit == 0
    result = context.ContextBundle.model_validate_json(exported.read_bytes())
    assert result.context_key == out.result['context_key']
    assert_resolves(result, originals)
    for sha, raw in originals.items():
        stored = json.loads(gzip.decompress((project / 'kb/sources' / (sha + '.json.gz')).read_bytes()))
        assert base64.b64decode(stored['bytes'], validate=True) == raw
    reopened = wiring.build_service(service.root, clock=FixedClock())
    assert reopened.explain(str(project), None).exit == 0
