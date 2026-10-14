"""OLD/NEW applicability (SPEC-28 section G) over SYNTHETIC fixtures. A missing status is never "affected",
an unverified identity abstains, and contradictions are reported instead of resolved."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from patchtrace.intelligence.contracts import ApplicabilityReport, ArtifactIdentity, IntelError
from patchtrace.intelligence.csaf import applicability as ap
from patchtrace.intelligence.csaf import normalize, validate

FIXTURES = Path(__file__).parent / 'fixtures' / 'csaf'
OLD_SHA = 'dc71b8420acc68418eaebfb8a4848cd2f63626125868e9977f017010c8d30215'  # PT-800 file hash (synthetic_pe(0))
NEW_SHA = '4af23bcb773054ad469c57363d50e2b53a6590bfba2286f16a06b4fb1440a168'  # PT-900 file hash (synthetic_pe(1))


def facts(name: str | None = None, doc: dict | None = None):
    raw = json.dumps(doc).encode() if doc is not None else (FIXTURES / name).read_bytes()
    parsed, report = validate.load_document(raw)
    return normalize.normalize(parsed, report, hashlib.sha256(raw).hexdigest())


def ident(side: str, sha: str = 'e' * 64, *, asserted=(), state='verified-bytes', version=None) -> ArtifactIdentity:
    return ArtifactIdentity(side=side, sha256=sha, asserted_product_ids=tuple(sorted(asserted)), facts_state=state,
                            file_version=version)


def resolve(docs, older, newer, cve='CVE-2099-10001') -> ApplicabilityReport:
    return ap.resolve(cve, docs, older, newer)


REV1 = facts('synthetic-advisory-rev1.json')
REV2 = facts('synthetic-advisory-rev2.json')
VEX = facts('synthetic-vex.json')


def test_verified_component_hashes_resolve_old_affected_new_fixed():
    report = resolve([REV1], ident('older', OLD_SHA), ident('newer', NEW_SHA))
    older, newer = report.older, report.newer
    assert (older.resolution, older.product_mapping_status) == ('affected', 'candidate')
    assert (newer.resolution, newer.product_mapping_status) == ('fixed', 'candidate')
    bases = {(m.product_id, m.status, m.basis) for m in older.mappings}
    assert bases == {('PT-800', 'verified', 'advisory-file-hash'),
                     ('PT-801', 'candidate', 'relationship-from-verified-component')}
    (status,) = older.statuses
    assert (status.product_id, status.status, status.pointer) == (
        'PT-801', 'known_affected', '/vulnerabilities/0/product_status/known_affected/3')
    assert older.assessment == 'advisory-claim' and report.contradictions == ()
    assert any('PT-800' in reason for reason in older.why)


def test_unverified_identity_abstains_and_file_names_are_irrelevant():
    report = resolve([REV1], ident('older'), ident('newer'))
    for side in (report.older, report.newer):
        assert (side.resolution, side.product_mapping_status, side.assessment) == ('unknown', 'unknown', 'unknown')
        assert side.mappings == () and any('abstain' in reason for reason in side.why)


def test_missing_status_never_means_affected():
    # PT-101-2 exists but CVE-2099-10002 names no status for it.
    report = resolve([REV1], ident('older', asserted=['PT-101-2']), ident('newer'), cve='CVE-2099-10002')
    assert report.older.product_mapping_status == 'candidate' and report.older.resolution == 'unknown'
    assert any('missing status never means affected' in reason for reason in report.older.why)


def test_asserted_products_are_labelled_candidates_and_unknown_ids_are_reported():
    report = resolve([REV1], ident('older', asserted=['PT-100-1', 'PT-NOPE']), ident('newer', asserted=['PT-100-2']))
    (mapping,) = report.older.mappings
    assert (mapping.basis, mapping.status) == ('asserted-product-id', 'candidate')
    assert 'analyst assertion' in mapping.detail
    assert report.older.resolution == 'affected' and report.newer.resolution == 'fixed'
    assert any('PT-NOPE' in reason and 'not defined' in reason for reason in report.older.why)


def test_file_version_equality_is_a_candidate_and_ranges_are_never_evaluated():
    fixed_build = resolve([REV1], ident('older'), ident('newer', version='10.0.22621.4037'))
    newer = fixed_build.newer
    assert {m.product_id for m in newer.mappings} == {'PT-100-2', 'PT-101-2'}
    assert all(m.basis == 'file-version-equals-product-version' and m.status == 'candidate' for m in newer.mappings)
    assert newer.resolution == 'fixed'
    # A fixed driver whose file version is below the fixed OS build would fall inside "<10.0.22621.4037":
    # ranges must not map it (wrong-file/product trap).
    inside_range = resolve([REV1], ident('older', version='10.0.22621.4036'), ident('newer'))
    assert inside_range.older.resolution == 'unknown' and inside_range.older.mappings == ()
    assert any('product_version_range' in limitation for limitation in inside_range.limitations)


def test_record_only_identity_never_yields_a_verified_mapping():
    report = resolve([REV1], ident('older', OLD_SHA, state='record-only'), ident('newer'))
    assert {m.status for m in report.older.mappings} == {'candidate'}
    assert report.older.resolution == 'affected'


def test_vex_not_affected_contradicting_the_advisory_is_reported():
    report = resolve([REV1, VEX], ident('older', asserted=['PT-100-1']), ident('newer'))
    older = report.older
    assert older.resolution == 'contradictory'
    assert {(m.source_id, m.product_id, m.basis) for m in older.mappings} >= {
        (VEX.source_id, 'VEX-1', 'same-product-name')}
    kinds = {c.kind for c in report.contradictions}
    assert 'vex-vs-advisory' in kinds
    vex = next(c for c in report.contradictions if c.kind == 'vex-vs-advisory')
    assert {e.status for e in vex.claims} == {'known_affected', 'known_not_affected'}


def test_vex_agreeing_with_the_advisory_is_not_a_contradiction():
    report = resolve([REV1, VEX], ident('older', asserted=['PT-200-1']), ident('newer'))
    assert report.older.resolution == 'affected'
    assert not [c for c in report.contradictions if c.product_name and 'Server 2022' in c.product_name]


def test_conflicting_revisions_are_reported_not_silently_resolved():
    report = resolve([REV1, REV2], ident('older', asserted=['PT-101-1']), ident('newer'))
    older = report.older
    assert older.resolution == 'contradictory'
    assert {(e.status, e.superseded) for e in older.statuses} == {('known_not_affected', False),
                                                                  ('known_affected', True)}
    (conflict,) = [c for c in report.contradictions if c.kind == 'cross-revision']
    assert 'ARM64' in conflict.product_name
    assert report.superseded_sources == (REV1.source_id,) and REV2.source_id in report.sources


def test_under_investigation_to_decision_is_a_progression():
    doc1 = json.loads((FIXTURES / 'synthetic-advisory-rev1.json').read_text(encoding='utf-8'))
    status = doc1['vulnerabilities'][0]['product_status']
    status['known_affected'].remove('PT-101-1')
    status['under_investigation'] = ['PT-101-1']
    doc1['vulnerabilities'][0]['scores'][0]['products'].remove('PT-101-1')
    doc1['vulnerabilities'][0]['threats'][0]['product_ids'].remove('PT-101-1')
    report = resolve([facts(doc=doc1), REV2], ident('older', asserted=['PT-101-1']), ident('newer'))
    assert report.older.resolution == 'not_affected' and report.contradictions == ()


def test_orientation_contradiction_when_older_is_fixed_and_newer_affected():
    report = resolve([REV1], ident('older', NEW_SHA), ident('newer', OLD_SHA))
    assert (report.older.resolution, report.newer.resolution) == ('fixed', 'affected')
    assert [c.kind for c in report.contradictions] == ['orientation']


def test_mapped_products_that_disagree_make_the_side_ambiguous():
    report = resolve([REV1], ident('older', asserted=['PT-100-1', 'PT-100-2']), ident('newer'))
    assert report.older.resolution == 'ambiguous'


def test_recommended_is_a_flag_not_a_class():
    doc = json.loads((FIXTURES / 'synthetic-advisory-rev1.json').read_text(encoding='utf-8'))
    doc['vulnerabilities'][0]['product_status']['recommended'] = ['PT-100-2']
    report = resolve([facts(doc=doc)], ident('older'), ident('newer', asserted=['PT-100-2']))
    assert report.newer.resolution == 'fixed' and report.newer.recommended


def test_cve_must_be_present_and_report_is_deterministic():
    with pytest.raises(IntelError) as info:
        resolve([REV1], ident('older'), ident('newer'), cve='CVE-2099-99999')
    assert info.value.code == 'PT-INTEL-NOTFOUND'
    first = resolve([REV1, REV2, VEX], ident('older', OLD_SHA), ident('newer', NEW_SHA))
    second = resolve([VEX, REV2, REV1], ident('older', OLD_SHA), ident('newer', NEW_SHA))
    assert first == second
    assert ApplicabilityReport.model_validate_json(first.model_dump_json()) == first
