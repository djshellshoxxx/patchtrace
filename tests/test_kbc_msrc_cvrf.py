"""Native monthly JSON: a provenance-pinned factual projection, never synthetic live evidence.

No network is used. Mutated copies below are explicitly negative controls, not vendor statements.
"""
from __future__ import annotations

import copy
import gzip
import hashlib
import json
from pathlib import Path

import pytest
from kbc_k1_support import IntelligenceAdvisoryPort, no_sockets, valid_csaf  # noqa: F401

from patchtrace.kbcorrelation.index import ReverseIndex
from patchtrace.kbcorrelation.sources.cvrf import SourceError, parse_cvrf
from patchtrace.kbcorrelation.sources.cvrf_fetch import FetchedDocument, to_imported
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import WorkspaceStore

FIXTURES = Path(__file__).parent / 'fixtures' / 'kbcve' / 'msrc'
NAME = '2024-Aug-CVE-2024-38193'
NOW = '2026-11-01T12:00:00Z'
pytestmark = pytest.mark.usefixtures('no_sockets')


def data():
    return json.loads((FIXTURES / f'{NAME}.facts.json').read_bytes())


def raw(value):
    return (json.dumps(value, ensure_ascii=True) + '\n').encode()


def imported(value=None, *, now=NOW):
    return import_bytes(raw(data() if value is None else value), now=now)


def resolve(value, pointer):
    for part in pointer.split('/')[1:]:
        part = part.replace('~1', '/').replace('~0', '~')
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def test_native_capture_projection_has_product_scoped_edges_and_original_pointers():
    value = data()
    doc = imported(value)
    assert doc.source.dialect == 'msrc-cvrf-json/1'
    assert doc.source.authenticity == 'unverified-local-file'
    assert doc.source.lineage == 'msrc'
    assert doc.source.sha256 == hashlib.sha256(raw(value)).hexdigest()
    assert doc.tracking_id == '2024-Aug'
    rows = [e for e in doc.edges if e.kb == 'KB5041571']
    assert len(rows) == 2
    assert {e.fixed_build for e in rows} == {'26100.1457'}
    assert {e.supersedes for e in rows} == {('KB5040435',)}
    scopes = {s.scope_id: s for s in doc.scopes}
    assert {(scopes[e.scope_id].family, scopes[e.scope_id].release,
             scopes[e.scope_id].architecture) for e in rows} == {
        ('windows-client', '24H2', 'amd64'), ('windows-client', '24H2', 'arm64')}
    for edge in doc.edges:
        assert edge.cve == 'CVE-2024-38193'
        rem = resolve(value, edge.ref.pointer)
        assert rem['Type'] == 2
        assert edge.kb == 'KB' + rem['Description']['Value']
        assert edge.product_status.value == 'Known Affected'
        assert resolve(value, edge.product_status.pointer) in rem['ProductID']
    assert doc.cards[0].stated_cwe == 'CWE-416'


def test_unzoned_revisions_are_retained_without_hash_or_retrieval_time_replacement():
    earlier = data()
    later = copy.deepcopy(earlier)
    later['DocumentTracking']['CurrentReleaseDate'] = '2026-10-29T01:48:49'
    later['DocumentTracking']['RevisionHistory'][0]['Number'] = '548'
    later['Vulnerability'][0]['Remediations'][0]['Description']['Value'] = '5999999'
    a, b = imported(earlier, now='2026-11-02T00:00:00Z'), imported(later)
    assert a.source.current_release_date is None and b.source.current_release_date is None
    assert any(p.code == 'DATE_ZONE_UNKNOWN' for p in a.problems)
    idx = ReverseIndex()
    idx.add(a)
    idx.add(b)
    assert idx.active_ids() == {a.doc_id, b.doc_id}
    lookup = idx.lookup_cve('CVE-2024-38193', now=NOW)
    assert not lookup.superseded
    assert any(w.startswith('REVISION_ORDER_UNKNOWN:') for w in lookup.warnings)
    parsed = parse_cvrf(raw(earlier))
    assert parsed.revisions[0].number == '547'
    assert parsed.revisions[0].date == '2026-10-28T01:48:49'
    assert parsed.revisions[0].pointer == '/DocumentTracking/RevisionHistory/0'
    assert parsed.vulnerabilities[0].revisions[0].number == '1.0'


def test_unverified_status_code_is_retained_but_cannot_assert_affected_or_disputed():
    value = data()
    value['Vulnerability'][0]['ProductStatuses'] = [{'Type': 4, 'ProductID': ['12389', '12390']}]
    doc = imported(value)
    assert not doc.edges
    assert {s.klass for s in doc.statuses} == {'unknown'}
    assert all('4' in s.value for s in doc.statuses)
    assert all(resolve(value, s.pointer) in ('12389', '12390') for s in doc.statuses)
    assert any(p.code == 'STATUS_TYPE_UNSUPPORTED' for p in doc.problems)


def test_known_zoned_revisions_replace_active_view_and_preserve_exact_raw_snapshots(tmp_path):
    older = data()
    newer = copy.deepcopy(older)
    older['DocumentTracking']['CurrentReleaseDate'] = '2026-10-28T01:48:49Z'
    newer['DocumentTracking']['CurrentReleaseDate'] = '2026-10-29T01:48:49Z'
    newer['Vulnerability'][0]['Remediations'][0]['Description']['Value'] = '5999999'
    a, b = imported(older, now='2026-11-02T00:00:00Z'), imported(newer)
    with WorkspaceStore(tmp_path / 'kb') as store:
        store.add_document(a, raw(older))
        store.add_document(b, raw(newer))
        idx = store.load_index()
        assert idx.active_ids() == {b.doc_id}
        lookup = idx.lookup_kb('KB5041571', now=NOW)
        assert not lookup.edges and len(lookup.superseded) == 2
        assert len(idx.documents) == 2
        assert gzip.decompress((store.root / a.source.object_path).read_bytes()) == raw(older)
        assert gzip.decompress((store.root / b.source.object_path).read_bytes()) == raw(newer)


def test_fixture_provenance_pins_imported_projection_separately_from_full_capture():
    provenance = json.loads((FIXTURES / f'{NAME}.provenance.json').read_bytes())
    payload = (FIXTURES / provenance['fixture']).read_bytes()
    assert hashlib.sha256(payload).hexdigest() == provenance['fixture_sha256']
    assert provenance['fixture_sha256'] != provenance['capture']['sha256']
    assert provenance['upstream_index_maps']['Vulnerability'] == [193]
    assert provenance['capture']['status'] == 200


@pytest.mark.parametrize('mutate', [
    lambda d: d.update(dialect='cvrf-json/0'),
    lambda d: d.update(document={}),
    lambda d: d.update(DocumentType={'Value': 'New Dialect'}),
    lambda d: d.update(DocumentTracking=[]),
    lambda d: d['DocumentTracking'].update(Identification={'ID': '2024-Aug'}),
    lambda d: d['DocumentTracking']['Identification']['ID'].update(Value='2024-Xyz'),
    lambda d: d['DocumentTracking'].update(Status=True),
    lambda d: d['DocumentTracking'].update(Status=99),
    lambda d: d['DocumentTracking'].update(Version={}),
    lambda d: d.update(ProductTree={'Branch': []}),
    lambda d: d.update(ProductTree={'FullProductName': {}}),
    lambda d: d.update(Vulnerability={}),
])
def test_unknown_structural_dialects_fail_closed(mutate):
    value = data()
    mutate(value)
    with pytest.raises(SourceError) as error:
        imported(value)
    assert error.value.code == 'PT-KBC-SOURCE'


@pytest.mark.parametrize('mutate', [
    lambda b: b.replace(b'"Type": 2', b'"Type": 2, "Type": 3', 1),
    lambda b: b.replace(b'"Type": 2', b'"Type": NaN', 1),
    lambda b: b.replace(b'"Type": 2', b'"Type": 1e9999', 1),
    lambda b: b'\xef\xbb\xbf' + b,
    lambda b: b'\xff' + b,
    lambda b: b[:-10],
])
def test_native_dispatch_does_not_bypass_strict_json(mutate):
    with pytest.raises(SourceError) as error:
        import_bytes(mutate(raw(data())), now=NOW)
    assert error.value.code == 'PT-KBC-SOURCE'


def test_diagnostics_keep_original_member_index_after_status_abstention():
    value = data()
    value['Vulnerability'][0]['ProductStatuses'].append({'Type': 99, 'ProductID': ['12389']})
    value['ProductTree']['FullProductName'] = [p for p in value['ProductTree']['FullProductName']
                                             if p['ProductID'] != '12390']
    doc = imported(value)
    assert not [e for e in doc.edges if e.kb == 'KB5041571']
    problem = next(p for p in doc.problems if p.code == 'UNKNOWN_PRODUCT_ID' and '/Remediations/0/' in p.pointer)
    assert problem.pointer == '/Vulnerability/0/Remediations/0/ProductID/1'
    assert resolve(value, problem.pointer) == '12390'
    withheld = next(p for p in doc.problems if p.code == 'PRODUCT_STATUS_UNRESOLVED')
    assert withheld.pointer == '/Vulnerability/0/Remediations/0/ProductID/0'


def test_duplicate_products_and_cves_are_not_arbitrarily_selected():
    value = data()
    product = next(p for p in value['ProductTree']['FullProductName'] if p['ProductID'] == '12389')
    value['ProductTree']['FullProductName'].append({**product, 'Value': 'Unrelated product'})
    doc = imported(value)
    rows = [e for e in doc.edges if e.kb == 'KB5041571']
    assert len(rows) == 1
    assert sum(p.code == 'PRODUCT_DUPLICATE' for p in doc.problems) == 2
    value['Vulnerability'].append(copy.deepcopy(value['Vulnerability'][0]))
    doc = imported(value)
    assert not doc.edges
    assert {p.pointer for p in doc.problems if p.code == 'CVE_DUPLICATE'} == {'/Vulnerability/0', '/Vulnerability/1'}


@pytest.mark.parametrize('status', [None, {}, True, [{'Type': '3', 'ProductID': ['12389']}],
                                    [{'Type': 3, 'ProductID': ['12389', 12390]}],
                                    [{'Type': True, 'ProductID': ['12389']}],
                                    [{'Type': 3, 'ProductID': ['12389', '\ud800']}], []])
def test_malformed_or_absent_status_membership_never_makes_a_vendor_fix(status):
    value = data()
    value['Vulnerability'][0]['ProductStatuses'] = status
    doc = imported(value)
    assert not doc.edges
    assert any(p.code in ('STATUS_SHAPE', 'PRODUCT_STATUS_UNRESOLVED') for p in doc.problems)


def test_unknown_status_does_not_erase_other_products_or_become_a_negative_status():
    value = data()
    value['Vulnerability'][0]['ProductStatuses'].append({'Type': 4, 'ProductID': ['12389']})
    doc = imported(value)
    rows = [e for e in doc.edges if e.kb == 'KB5041571']
    assert len(rows) == 1
    scopes = {s.scope_id: s for s in doc.scopes}
    assert scopes[rows[0].scope_id].architecture == 'amd64'
    assert {p.product_id for p in scopes[rows[0].scope_id].source_product_ids} == {'12390'}
    assert all(e.relation == 'vendor-remediation' for e in doc.edges)
    assert {'affected', 'unknown'} <= {s.klass for s in doc.statuses}


@pytest.mark.parametrize('rem', [
    {'Type': 2, 'Description': '5041571', 'ProductID': ['12389']},
    {'Type': True, 'Description': {'Value': '5041571'}, 'ProductID': ['12389']},
    {'Type': '2', 'Description': {'Value': '5041571'}, 'ProductID': ['12389']},
    {'Type': 2, 'Description': {'Value': '5041571'}, 'ProductID': '12389'},
    {'Type': 2, 'Description': {'Value': '\ud800'}, 'ProductID': ['12389']},
    {'Type': 2, 'Description': {'Value': '5041571'}, 'ProductID': ['12389'], 'GroupID': ['group']},
    {'Type': 3, 'URL': 'https://support.microsoft.com/help/5041571', 'ProductID': ['12389']},
    {'Type': 2, 'Description': {'Value': '5041571'}, 'ProductID': ['undefined']},
])
def test_bad_remediation_and_unresolved_product_never_produce_a_fix(rem):
    value = data()
    value['Vulnerability'][0]['Remediations'] = [rem]
    doc = imported(value)
    assert not doc.edges


def test_known_issue_and_prose_are_mentions_only_and_notes_are_not_scanned():
    value = data()
    v = value['Vulnerability'][0]
    v['Remediations'] = [{'Type': 5, 'Description': {'Value': 'Known issue with KB5041571'},
                          'ProductID': ['12389']},
                         {'Type': 2, 'Description': {'Value': 'See KB5041571'}, 'ProductID': ['12390']}]
    doc = imported(value)
    assert len(doc.edges) == 2 and {e.relation for e in doc.edges} == {'mention-only'}
    assert resolve(value, next(p.pointer for p in doc.problems if p.code == 'KB_UNPARSED')) == 'See KB5041571'
    v.update(Remediations=[], Title={'Value': 'KB5041571'}, Notes=[{'Value': 'KB5041571'}])
    assert not imported(value).edges


def test_text_limit_never_truncates_a_partial_description_into_a_kb():
    from patchtrace.kbcorrelation.limits import KbcLimits
    value = data()
    value['Vulnerability'][0]['Remediations'] = [
        {'Type': 2, 'Description': {'Value': '5041571 ' + 'x' * 8}, 'ProductID': ['12389']}]
    doc = import_bytes(raw(value), now=NOW, limits=KbcLimits(text_field_bytes=8))
    assert not doc.edges
    assert [(p.code, p.pointer) for p in doc.problems if p.code == 'TEXT_LIMIT'] == [
        ('TEXT_LIMIT', '/Vulnerability/0/Remediations/0/Description/Value')]


def test_fixed_build_and_supersedence_never_extract_numbers_from_prose():
    value = data()
    rem = value['Vulnerability'][0]['Remediations'][0]
    rem['FixedBuild'] = 'Version 10.0.26100.1457'
    rem['Supercedence'] = '5040435, KB5040437, see KB9999999'
    doc = imported(value)
    rows = [e for e in doc.edges if e.kb == 'KB5041571']
    assert {e.fixed_build for e in rows} == {None}
    assert {e.supersedes for e in rows} == {('KB5040435', 'KB5040437')}
    assert {p.pointer for p in doc.problems if p.code in ('FIXED_BUILD_UNPARSED', 'SUPERSEDES_UNPARSED')} == {
        '/Vulnerability/0/Remediations/0/FixedBuild', '/Vulnerability/0/Remediations/0/Supercedence'}


def test_opaque_vendor_product_id_is_not_a_build_or_architecture_hint():
    value = data()
    product = next(p for p in value['ProductTree']['FullProductName'] if p['ProductID'] == '12389')
    product['Value'] = 'Unspecified platform'
    # Unverified CPE parsing is deliberately outside the supported product-name adapter.
    product['CPE'] = 'cpe:2.3:o:microsoft:windows_11:24h2:*:*:*:*:x64:*:*'
    doc = imported(value)
    scope = next(s for s in doc.scopes if any(p.product_id == '12389' for p in s.source_product_ids))
    assert scope.family == 'unknown' and scope.architecture == 'unknown'
    assert scope.release is None and scope.build is None and scope.mapping == 'unknown'


def test_tied_native_revisions_and_known_plus_unzoned_revisions_remain_ambiguous():
    value = data()
    value['DocumentTracking']['CurrentReleaseDate'] += 'Z'
    revised = copy.deepcopy(value)
    revised['Vulnerability'][0]['Remediations'][0]['FixedBuild'] = '10.0.26100.1458'
    a, b = imported(value), imported(revised)
    for other in (b, imported(data())):
        idx = ReverseIndex()
        idx.add(a)
        idx.add(other)
        assert idx.active_ids() == {a.doc_id, other.doc_id}
        assert any(w.startswith('REVISION_ORDER_UNKNOWN:') for w in idx.lookup_kb('KB5041571', now=NOW).warnings)


def test_explicit_zone_order_uses_instants_not_lexicographic_clock_time():
    value = data()
    value['DocumentTracking']['CurrentReleaseDate'] = '2026-10-28T10:00:00+05:00'
    revised = copy.deepcopy(value)
    revised['DocumentTracking']['CurrentReleaseDate'] = '2026-10-28T08:00:00Z'
    a, b = imported(value), imported(revised)
    idx = ReverseIndex()
    idx.add(a)
    idx.add(b)
    assert idx.active_ids() == {b.doc_id}


def test_fetch_boundary_retains_existing_authenticity_and_month_checks():
    payload = raw(data())
    fetched = FetchedDocument('2024-Aug', 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2024-Aug',
                              payload, hashlib.sha256(payload).hexdigest(), NOW)
    doc = to_imported(fetched)
    assert doc.doc_id == imported().doc_id
    assert doc.source.authenticity == 'tls-allowlisted-host'
    assert doc.source.sha256 == hashlib.sha256(payload).hexdigest()
    assert doc.edges == imported().edges
    wrong = FetchedDocument('2024-Sep', fetched.url, payload, fetched.sha256, NOW)
    with pytest.raises(SourceError, match='not the 2024-Sep'):
        to_imported(wrong)


@pytest.mark.parametrize('name', ['', '   ', '\u200b\u200b', 'Windows ' + 'x' * 1000])
def test_empty_or_truncated_product_names_cannot_collapse_into_a_claim(name):
    value = data()
    for p in value['ProductTree']['FullProductName']:
        if p['ProductID'] in ('12389', '12390'):
            p['Value'] = name
    doc = imported(value)
    assert not [e for e in doc.edges if e.kb == 'KB5041571']
    assert any(p.code == 'PRODUCT_ID_INVALID' for p in doc.problems)


@pytest.mark.parametrize('cwes', [[{'ID': 'CWE-416'}, {'ID': 'CWE-787'}],
                                  [{'ID': 'CWE-416'}, {'ID': 'not a CWE'}], {'ID': 'CWE-416'}])
def test_ambiguous_or_malformed_cwe_is_not_coerced_to_a_single_weakness(cwes):
    value = data()
    value['Vulnerability'][0]['CWE'] = cwes
    doc = imported(value)
    assert doc.cards[0].stated_cwe is None
    assert any(p.code.startswith('CWE_') for p in doc.problems)
    assert doc.edges


def test_native_edge_budget_is_enforced_by_the_shared_edge_builder():
    from patchtrace.kbcorrelation.limits import KbcLimits
    with pytest.raises(SourceError) as error:
        import_bytes(raw(data()), now=NOW, limits=KbcLimits(cvrf_edges_per_doc=1))
    assert error.value.code == 'PT-KBC-LIMIT'


def test_unknown_revision_order_survives_store_reload_and_failed_import(tmp_path):
    original = data()
    later = copy.deepcopy(original)
    later['DocumentTracking']['RevisionHistory'][0]['Number'] = '548'
    a, b = imported(original), imported(later)
    with WorkspaceStore(tmp_path / 'kb') as store:
        store.add_document(a, raw(original))
        store.add_document(b, raw(later))
        with pytest.raises(SourceError):
            bad = copy.deepcopy(original)
            bad['DocumentTracking']['Status'] = 99
            store.add_document(imported(bad), raw(bad))
        assert store.load_index().active_ids() == {a.doc_id, b.doc_id}
        assert len(store.sources()) == 2
        assert gzip.decompress((store.root / a.source.object_path).read_bytes()) == raw(original)


def test_native_markers_cannot_hide_inside_a_synthetic_document():
    value = json.loads((Path(__file__).parent / 'fixtures' / 'kbcorrelation' / 'cvrf-2099-Feb.json').read_bytes())
    value['ProductTree'] = {'FullProductName': []}
    with pytest.raises(SourceError, match='mixed native and synthetic'):
        imported(value)


def test_public_importer_refuses_native_csaf_ambiguity_before_real_port_dispatch():
    """A valid CSAF document must not conceal contradictory native CVRF fields as allowed extensions."""
    port = IntelligenceAdvisoryPort()
    csaf = valid_csaf()
    accepted = import_bytes(raw(csaf), now=NOW, advisory=port)
    assert accepted.source.dialect == 'csaf/2.0'
    assert accepted.counts()['edges'] == 2
    csaf.update(data())
    with pytest.raises(SourceError, match='mixed native') as error:
        import_bytes(raw(csaf), now=NOW, advisory=port)
    assert error.value.code == 'PT-KBC-SOURCE'
