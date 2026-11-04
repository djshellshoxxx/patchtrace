"""``IntelligenceAdvisory.report_for``: CSAF applicability for a KB context (KBF-03 s5.1). SYNTHETIC, hermetic.

The facts come from the production port's own ``parse_csaf`` over committed synthetic CSAF fixtures; nothing is
fetched and no target file is read. Unknown stays unknown, a withdrawn or superseded entry is reported as such,
every claim names its source, and nothing ties a function to a CVE.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
from kbc_k4a_golden import all_text, banned_in

from patchtrace.kbcorrelation.ports import AdvisoryPort
from patchtrace.kbcorrelation.store import KbcStoreError
from patchtrace.kbcorrelation.wiring import IntelligenceAdvisory

FIXTURES = Path(__file__).parent / 'fixtures'
CVE = 'CVE-2099-10001'
OLD_SHA = 'dc71b8420acc68418eaebfb8a4848cd2f63626125868e9977f017010c8d30215'  # PT-800 file hash in rev1/rev2
NEW_SHA = '4af23bcb773054ad469c57363d50e2b53a6590bfba2286f16a06b4fb1440a168'  # PT-900 file hash in rev1/rev2
UNMAPPED = 'e' * 64
PORT = IntelligenceAdvisory()


def raw_doc(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding='utf-8'))


def parsed(doc: dict) -> tuple[dict, dict]:
    raw = json.dumps(doc).encode()
    return PORT.parse_csaf(raw, source_sha256=hashlib.sha256(raw).hexdigest()), doc


def withdrawn_rev2() -> dict:
    """Revision 2 of the same tracking id with CVE-2099-10001 removed (the vendor withdrew the entry)."""
    doc = raw_doc('csaf/synthetic-advisory-rev2.json')
    doc['vulnerabilities'] = [v for v in doc['vulnerabilities'] if v['cve'] != CVE]
    return doc


REV1, REV1_DOC = parsed(raw_doc('csaf/synthetic-advisory-rev1.json'))
REV2, REV2_DOC = parsed(raw_doc('csaf/synthetic-advisory-rev2.json'))
GONE, GONE_DOC = parsed(withdrawn_rev2())
KB_ONLY, _ = parsed(raw_doc('kbcorrelation/csaf-kb-valid.json'))
RAW = {f['source_id']: d for f, d in ((REV1, REV1_DOC), (REV2, REV2_DOC), (GONE, GONE_DOC))}


def pointer_value(doc, pointer: str):
    """RFC 6901 lookup in the raw document, so a pointer is checked against the bytes it claims to come from."""
    value = doc
    for token in pointer.split('/')[1:]:
        token = token.replace('~1', '/').replace('~0', '~')
        value = value[int(token)] if isinstance(value, list) else value[token]
    return value


def side(report: dict, name: str) -> dict:
    return report['applicability'][name]


def source_ids_used(report: dict) -> set[str]:
    used = {w for entry in report['withdrawn'] for w in (*entry['listed_in'], *entry['current'])}
    app = report['applicability']
    if app is not None:
        used |= {*app['sources'], *app['superseded_sources']}
        for name in ('older', 'newer'):
            used |= {m['source_id'] for m in app[name]['mappings']}
            used |= {s['source_id'] for s in app[name]['statuses']}
        used |= {c['source_id'] for item in app['contradictions'] for c in item['claims']}
    return used


def keys(value) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {k for v in value.values() for k in keys(v)}
    if isinstance(value, list):
        return {k for v in value for k in keys(v)}
    return set()


def test_the_production_port_satisfies_the_protocol():
    assert isinstance(PORT, AdvisoryPort)


def test_hash_tied_files_restate_old_affected_new_fixed_as_candidate_mappings():
    report = PORT.report_for(CVE, [REV1], OLD_SHA, NEW_SHA)
    assert report['contract'] == 'kbc-csaf-applicability/1' and report['cve'] == CVE
    assert (report['older_sha256'], report['newer_sha256']) == (OLD_SHA, NEW_SHA)
    assert report['assessment'] == 'advisory-claim'
    assert (side(report, 'older')['resolution'], side(report, 'newer')['resolution']) == ('affected', 'fixed')
    for name in ('older', 'newer'):
        mappings = side(report, name)['mappings']
        assert mappings and {m['status'] for m in mappings} == {'candidate'}  # recorded hash, never "verified"
        assert {m['basis'] for m in mappings} == {'advisory-file-hash', 'relationship-from-verified-component'}
        assert side(report, name)['identity']['facts_state'] == 'record-only'
    assert report['withdrawn'] == [] and report['sources'] == [{
        'source_id': REV1['source_id'], 'facts_id': REV1['facts_id'], 'tracking_id': REV1['tracking_id'],
        'revision': '1', 'current_release_date': REV1['current_release_date'],
        'document_category': 'csaf_security_advisory', 'lists_cve': True, 'superseded': False}]


def test_every_status_points_into_its_source_and_every_source_is_listed():
    for facts in ([REV1], [REV1, REV2], [REV1, GONE]):
        report = PORT.report_for(CVE, facts, OLD_SHA, NEW_SHA)
        listed = {s['source_id'] for s in report['sources']}
        assert source_ids_used(report) <= listed
        for name in ('older', 'newer'):
            for status in side(report, name)['statuses']:
                assert pointer_value(RAW[status['source_id']], status['pointer']) == status['product_id']
                assert status['tracking_id'] and status['revision']
            for mapping in side(report, name)['mappings']:
                assert mapping['basis'] and mapping['detail']


@pytest.mark.parametrize('facts', [[], [REV1], [KB_ONLY, REV2]], ids=['none', 'other-cve', 'two-docs'])
def test_no_document_listing_the_cve_is_unknown_never_a_negative_vote(facts):
    report = PORT.report_for('CVE-2099-19999', facts, OLD_SHA, NEW_SHA)
    assert (report['assessment'], report['applicability']) == ('unknown', None)
    assert report['sources'] == [] and report['withdrawn'] == []
    assert any('no loaded CSAF document lists CVE-2099-19999' in u for u in report['unknowns'])
    texts = ' '.join(all_text(report)).lower()
    assert not any(word in texts for word in ('not_affected', 'not affected', 'fixed', 'known_'))


@pytest.mark.parametrize('missing', ['older', 'newer'], ids=['old', 'new'])
def test_a_file_without_a_sha256_is_unknown_and_the_documents_stay_visible(missing):
    older, newer = (None, NEW_SHA) if missing == 'older' else (OLD_SHA, None)
    report = PORT.report_for(CVE, [REV1], older, newer)
    assert (report['assessment'], report['applicability']) == ('unknown', None)
    assert [s['source_id'] for s in report['sources']] == [REV1['source_id']]
    assert any(f'the {missing} file has no SHA-256' in u for u in report['unknowns'])


@pytest.mark.parametrize('facts', [[REV1], [KB_ONLY]], ids=['hashed', 'unhashed'])
def test_files_no_advisory_product_ties_to_abstain(facts):
    cve = CVE if facts == [REV1] else 'CVE-2099-20001'
    report = PORT.report_for(cve, facts, UNMAPPED, UNMAPPED.replace('e', 'f'))
    assert report['assessment'] == 'unknown'
    for name in ('older', 'newer'):
        assert (side(report, name)['resolution'], side(report, name)['mappings']) == ('unknown', [])
        assert any(f'{name} file: applicability is unknown' in u for u in report['unknowns'])


def test_a_withdrawn_cve_is_reported_and_its_earlier_claims_are_not_current():
    report = PORT.report_for(CVE, [REV1, GONE], OLD_SHA, NEW_SHA)
    assert report['withdrawn'] == [{'publisher_namespace': REV1['publisher_namespace'],
                                    'tracking_id': REV1['tracking_id'], 'listed_in': [REV1['source_id']],
                                    'current': [GONE['source_id']]}]
    flags = {s['source_id']: (s['lists_cve'], s['superseded']) for s in report['sources']}
    assert flags == {REV1['source_id']: (True, True), GONE['source_id']: (False, False)}
    assert report['applicability']['superseded_sources'] == [REV1['source_id']]
    for name in ('older', 'newer'):
        assert side(report, name)['resolution'] == 'unknown'  # never "still affected" or "still fixed"
        assert {s['superseded'] for s in side(report, name)['statuses']} == {True}
    assert report['assessment'] == 'unknown'
    assert any('no longer lists CVE-2099-10001' in u for u in report['unknowns'])


def test_a_superseded_revision_is_marked_and_the_current_revision_decides():
    report = PORT.report_for(CVE, [REV1, REV2], OLD_SHA, NEW_SHA)
    flags = {s['source_id']: s['superseded'] for s in report['sources']}
    assert flags == {REV1['source_id']: True, REV2['source_id']: False} and report['withdrawn'] == []
    assert report['applicability']['superseded_sources'] == [REV1['source_id']]
    older = side(report, 'older')
    assert older['resolution'] == 'affected'
    assert {(s['source_id'], s['superseded']) for s in older['statuses']} == {
        (REV1['source_id'], True), (REV2['source_id'], False)}


def test_order_and_repetition_of_the_documents_do_not_change_the_report():
    expected = PORT.report_for(CVE, [REV1, REV2, GONE, KB_ONLY], OLD_SHA, NEW_SHA)
    again = PORT.report_for(CVE, [KB_ONLY, GONE, REV2, copy.deepcopy(REV1), REV1], OLD_SHA, NEW_SHA)
    assert json.dumps(again, sort_keys=True) == json.dumps(expected, sort_keys=True)


def test_no_function_level_claim_and_no_banned_wording():
    for facts in ([REV1], [REV1, GONE], []):
        report = PORT.report_for(CVE, facts, OLD_SHA, NEW_SHA)
        json.dumps(report, allow_nan=False)  # JSON-compatible plain data
        assert not keys(report) & {'function', 'function_id', 'rva', 'match_id', 'address', 'lead_id'}
        assert banned_in(all_text(report)) == []
        assert any('does not show that any changed function addresses' in t for t in report['limitations'])


def test_two_different_facts_for_one_source_are_refused():
    forged = {**REV1, 'title': 'Another title for the same bytes'}
    with pytest.raises(KbcStoreError) as info:
        PORT.report_for(CVE, [REV1, forged], OLD_SHA, NEW_SHA)
    assert info.value.code == 'PT-KBC-SOURCE'


@pytest.mark.parametrize('cve, facts, code', [
    ('CVE-99-1', [REV1], 'PT-KBC-INPUT'),
    (CVE, [{'source_id': 'x'}], 'PT-KBC-SOURCE'),
    (CVE, ['not a mapping'], 'PT-KBC-SOURCE'),
], ids=['bad-cve', 'bad-facts', 'not-mapping'])
def test_malformed_input_is_refused(cve, facts, code):
    with pytest.raises(KbcStoreError) as info:
        PORT.report_for(cve, facts, OLD_SHA, NEW_SHA)
    assert info.value.code == code


def test_a_malformed_sha256_is_refused():
    with pytest.raises(KbcStoreError) as info:
        PORT.report_for(CVE, [REV1], 'not-a-sha', NEW_SHA)
    assert info.value.code == 'PT-KBC-INPUT'
