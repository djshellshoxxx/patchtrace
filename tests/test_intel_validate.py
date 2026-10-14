"""CSAF 2.0 validation (SPEC-28 section E). All inputs are SYNTHETIC fixtures or mutations of them."""
from __future__ import annotations

import copy
import json
import re
import threading
import warnings
from pathlib import Path

import pytest

from patchtrace.intelligence.contracts import IntelError
from patchtrace.intelligence.csaf import schema_data
from patchtrace.intelligence.csaf import validate as v

FIXTURES = Path(__file__).parent / 'fixtures' / 'csaf'


def fixture(name: str = 'synthetic-advisory-rev1.json') -> dict:
    return json.loads((FIXTURES / name).read_text(encoding='utf-8'))


def encode(doc) -> bytes:
    return json.dumps(doc).encode('utf-8')


def failing(doc) -> v.ValidationReport:
    with pytest.raises(v.ValidationFailed) as info:
        v.load_document(encode(doc))
    assert info.value.code == 'PT-INTEL-VALIDATE'
    return info.value.report


def failed_tests(report) -> set[str]:
    return {f.test for f in report.errors}


@pytest.mark.parametrize('name', ['synthetic-advisory-rev1.json', 'synthetic-advisory-rev2.json', 'synthetic-vex.json'])
def test_synthetic_fixtures_are_valid_csaf(name):
    doc, report = v.load_document((FIXTURES / name).read_bytes())
    assert report.valid and report.errors == () and report.warnings == ()
    assert doc['document']['csaf_version'] == '2.0'
    assert '6.1.1' in report.tests_run and '6.1.8' in report.tests_not_implemented


# ---- 1. strict JSON and limits ------------------------------------------------------------------------------------

@pytest.mark.parametrize('raw, code, needle', [
    (b'{"document": {}, "document": {}}', 'PT-INTEL-FORMAT', 'ambiguous duplicate key'),
    (b'\xef\xbb\xbf{}', 'PT-INTEL-FORMAT', 'byte order mark'),
    (b'{"a": "\xff"}', 'PT-INTEL-FORMAT', 'UTF-8'),
    (b'{"a": NaN}', 'PT-INTEL-FORMAT', 'invalid number'),
    (b'{"a": 1e999}', 'PT-INTEL-FORMAT', 'invalid number'),
    (b'{"a": ' + b'9' * 5000 + b'}', 'PT-INTEL-FORMAT', 'invalid number'),
    (b'{"a": ', 'PT-INTEL-FORMAT', 'not valid JSON'),
    (b'[' * 100_000 + b']' * 100_000, 'PT-INTEL-LIMIT', 'nesting'),
], ids=['duplicate-key', 'bom', 'bad-utf8', 'nan', 'huge-exponent', 'long-integer', 'truncated', 'deep-nesting'])
def test_malformed_json_is_rejected_with_a_typed_error(raw, code, needle):
    with pytest.raises(IntelError) as info:
        v.parse_json(raw)
    assert info.value.code == code and needle in info.value.message


def test_duplicate_key_message_never_echoes_long_or_control_text():
    key = '‮' + 'k' * 500
    raw = json.dumps({key: 1}).replace('}', ', ' + json.dumps(key) + ': 2}').encode()
    with pytest.raises(IntelError) as info:
        v.parse_json(raw)
    assert '‮' not in info.value.message and len(info.value.message) < 200


def test_depth_node_and_string_limits():
    deep = b'{"a":' * 70 + b'1' + b'}' * 70  # parses fine, exceeds the 64-level processing cap
    with pytest.raises(IntelError, match='nesting exceeds 64'):
        v.parse_json(deep)
    with pytest.raises(IntelError, match='more than 10 JSON values'):
        v.parse_json(b'[1,2,3,4,5,6,7,8,9,10,11]', limits=v.Limits(max_nodes=10))
    with pytest.raises(IntelError, match='string longer than 4'):
        v.parse_json(b'["abcde"]', limits=v.Limits(max_string=4))
    with pytest.raises(IntelError, match='key longer than 4'):
        v.parse_json(b'{"abcde": 1}', limits=v.Limits(max_string=4))


def test_oversized_document_is_rejected_before_decoding():
    raw = b' ' * (16 * 1024 * 1024 + 1)
    with pytest.raises(IntelError) as info:
        v.load_document(raw)
    assert info.value.code == 'PT-INTEL-LIMIT' and '16777216' in info.value.message


def test_non_object_and_unsupported_version():
    with pytest.raises(IntelError) as info:
        v.load_document(b'[]')
    assert info.value.code == 'PT-INTEL-FORMAT'
    doc = fixture()
    doc['document']['csaf_version'] = '2.1'
    with pytest.raises(IntelError) as info:
        v.load_document(encode(doc))
    assert info.value.code == 'PT-INTEL-UNSUPPORTED'


# ---- 2. schema keywords -------------------------------------------------------------------------------------------

def test_missing_required_and_wrong_enum_are_schema_errors():
    doc = fixture()
    del doc['document']['title']
    doc['document']['tracking']['status'] = 'published'
    report = failing(doc)
    messages = {(f.pointer, f.message) for f in report.errors}
    assert ('/document', "required property 'title' is missing") in messages
    assert any(p == '/document/tracking/status' for p, _ in messages)
    assert failed_tests(report) == {'schema'}  # mandatory tests never run on a schema-invalid document


def test_pattern_end_anchor_follows_ecma_not_python():
    doc = fixture()
    doc['vulnerabilities'][0]['cve'] = 'CVE-2099-10001\n'  # Python `$` would accept the trailing newline
    report = failing(doc)
    assert any(f.pointer == '/vulnerabilities/0/cve' for f in report.errors)


@pytest.mark.parametrize('value, ok', [('CVE-2099-10001', True), ('CVE-2099-123', False),
                                        ('CVE-٢٠٩٩-10001', False)])
def test_cve_pattern(value, ok):
    compiled = re.compile(v.translate_pattern(schema_data.CSAF_SCHEMA['properties']['vulnerabilities']['items']
                                              ['properties']['cve']['pattern']))
    assert bool(compiled.search(value)) is ok


def test_translate_pattern_ascii_digits_dot_and_dollar():
    assert re.search(v.translate_pattern(r'^CWE-[1-9]\d{0,5}$'), 'CWE-1٢') is None  # Arabic-Indic digit
    assert re.search(v.translate_pattern(r'^a.b$'), 'a b') is None
    assert re.search(v.translate_pattern(r'^a.b$'), 'axb')
    assert re.search(v.translate_pattern(r'^ab$'), 'ab\n') is None
    assert v.translate_pattern(r'[\d\-]') == r'[0-9\-]'
    assert v.translate_pattern(r'\$x') == r'\$x'


def test_every_generated_pattern_compiles_without_warnings():
    patterns = []

    def walk(node):
        if isinstance(node, dict):
            if isinstance(node.get('pattern'), str):
                patterns.append(node['pattern'])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
    walk(schema_data.CSAF_SCHEMA)
    walk(schema_data.PROVIDER_SCHEMA)
    assert len(patterns) >= 8
    with warnings.catch_warnings():
        warnings.simplefilter('error')
        for pattern in patterns:
            re.compile(v.translate_pattern(pattern))


@pytest.mark.parametrize('value, ok', [
    ('2099-01-10T08:00:00.000Z', True), ('2099-01-10T08:00:00+05:30', True), ('2099-02-30T00:00:00Z', False),
    ('2099-01-10T08:00:00+25:00', False), ('2099-01-10 08:00:00Z', False), ('2099-01-10T08:00:00', False)])
def test_date_time_format(value, ok):
    assert (v.parse_date_time(value) is not None) is ok


def test_format_and_cvss_structure_errors():
    doc = fixture()
    doc['document']['publisher']['namespace'] = 'not a uri'
    doc['vulnerabilities'][0]['scores'][0]['cvss_v3']['baseScore'] = 11
    report = failing(doc)
    pointers = {f.pointer for f in report.errors}
    assert '/document/publisher/namespace' in pointers
    assert '/vulnerabilities/0/scores/0/cvss_v3' in pointers  # oneOf v3.0/v3.1: matched 0


def test_branch_needs_exactly_three_properties():
    doc = fixture()
    branch = doc['product_tree']['branches'][0]['branches'][0]['branches'][0]['branches'][0]
    branch['branches'] = [copy.deepcopy(branch)]  # product + branches: 4 properties
    report = failing(doc)
    assert any('at most 3 properties' in f.message for f in report.errors)


def test_additional_properties_are_warnings_only():
    doc = fixture()
    doc['vulnerabilities'][0]['x_vendor_extension'] = {'anything': True}
    _, report = v.load_document(encode(doc))
    assert report.valid
    assert [(w.test, w.pointer) for w in report.warnings] == [('6.2.20', '/vulnerabilities/0/x_vendor_extension')]


# ---- 3. mandatory tests -------------------------------------------------------------------------------------------

def tree(doc):
    return doc['product_tree']


def test_6_1_1_undefined_product_and_group_cannot_nest():
    doc = fixture()
    doc['vulnerabilities'][0]['product_status']['fixed'].append('PT-404')
    tree(doc)['product_groups'].append({'group_id': 'PT-G-NEST', 'product_ids': ['PT-100-1', 'PT-G-NEST']})
    report = failing(doc)
    assert failed_tests(report) == {'6.1.1'}
    assert {f.pointer for f in report.errors} == {'/vulnerabilities/0/product_status/fixed/4',
                                                  '/product_tree/product_groups/1/product_ids/1'}


def test_6_1_2_duplicate_product_definition():
    doc = fixture()
    tree(doc)['full_product_names'].append({'name': 'dup', 'product_id': 'PT-100-1'})
    assert '6.1.2' in failed_tests(failing(doc))


@pytest.mark.parametrize('relationships', [
    [('PT-C1', 'PT-100-1', 'PT-C1')],  # self reference (CSAF example 51)
    [('PT-C1', 'PT-C2', 'PT-100-1'), ('PT-C2', 'PT-C1', 'PT-100-2')],  # two-step cycle
    [('PT-C1', 'PT-C2', 'PT-100-1'), ('PT-C2', 'PT-C3', 'PT-100-1'), ('PT-C3', 'PT-C1', 'PT-100-1')],
])
def test_6_1_3_circular_relationships(relationships):
    doc = fixture()
    for pid, ref, rel in relationships:
        tree(doc)['relationships'].append({'category': 'installed_on', 'product_reference': ref,
                                           'relates_to_product_reference': rel,
                                           'full_product_name': {'name': pid, 'product_id': pid}})
    report = failing(doc)
    assert failed_tests(report) == {'6.1.3'}


def test_6_1_3_deep_acyclic_chain_is_accepted_without_recursion():
    doc = fixture()
    previous = 'PT-100-1'
    for i in range(3000):  # far deeper than Python's recursion limit
        pid = f'PT-CHAIN-{i}'
        tree(doc)['relationships'].append({'category': 'installed_with', 'product_reference': previous,
                                           'relates_to_product_reference': 'PT-100-2',
                                           'full_product_name': {'name': pid, 'product_id': pid}})
        previous = pid
    _, report = v.load_document(encode(doc))
    assert report.valid and all(w.test == '6.2.1' for w in report.warnings)


def test_6_1_4_and_6_1_5_groups():
    doc = fixture()
    doc['vulnerabilities'][0]['threats'][0]['group_ids'] = ['PT-G-MISSING']
    tree(doc)['product_groups'].append({'group_id': 'PT-G-22H2-BEFORE-FIX', 'product_ids': ['PT-200-1', 'PT-200-2']})
    assert failed_tests(failing(doc)) == {'6.1.4', '6.1.5'}


def test_6_1_6_contradicting_status_within_a_document():
    doc = fixture()
    doc['vulnerabilities'][0]['product_status']['known_not_affected'] = ['PT-100-1']
    report = failing(doc)
    assert failed_tests(report) == {'6.1.6'}
    assert 'both "affected" and "not affected"' in report.errors[0].message


def test_6_1_6_recommended_is_never_a_contradiction():
    doc = fixture()
    doc['vulnerabilities'][0]['product_status']['recommended'] = ['PT-100-1', 'PT-100-2']
    assert v.load_document(encode(doc))[1].valid


def test_6_1_7_two_scores_with_the_same_version_for_one_product():
    doc = fixture()
    doc['vulnerabilities'][0]['scores'].append(copy.deepcopy(doc['vulnerabilities'][0]['scores'][0]))
    assert '6.1.7' in failed_tests(failing(doc))


@pytest.mark.parametrize('history, version, status, expected', [
    ([('2099-01-02', '2'), ('2099-01-01', '1'), ('2099-01-03', '3')], '3', 'final', set()),  # order by date
    ([('2099-01-01', '2'), ('2099-01-02', '1')], '2', 'final', {'6.1.14', '6.1.16', '6.1.21'}),  # first must be 0|1
    ([('2099-01-01', '1'), ('2099-01-02', '2')], '1', 'final', {'6.1.16'}),
    ([('2099-01-01', '0.9.0')], '0.9.0', 'final', {'6.1.17', '6.1.18'}),
    ([('2099-01-01', '1.0.0-rc1')], '1.0.0-rc1', 'final', {'6.1.17', '6.1.19', '6.1.20'}),
    ([('2099-01-01', '1'), ('2099-01-02', '3')], '3', 'final', {'6.1.21'}),
    ([('2099-01-01', '2')], '2', 'final', {'6.1.21'}),
    ([('2099-01-01', '1'), ('2099-01-02', '1')], '1', 'final', {'6.1.22'}),
    ([('2099-01-01', '1.0.0'), ('2099-01-02', '2')], '2', 'final', {'6.1.30'}),
    ([('2099-01-01', '1.0.0'), ('2099-01-02', '1.1.0+build.7')], '1.1.0', 'final', set()),
])
def test_revision_history_tests(history, version, status, expected):
    doc = fixture()
    tracking = doc['document']['tracking']
    tracking['revision_history'] = [{'date': f'{d}T00:00:00Z', 'number': n, 'summary': 's'} for d, n in history]
    tracking['version'], tracking['status'] = version, status
    if expected:
        assert failed_tests(failing(doc)) == expected
    else:
        assert v.load_document(encode(doc))[1].valid


def test_6_1_23_same_cve_twice():
    doc = fixture()
    doc['vulnerabilities'][1]['cve'] = 'CVE-2099-10001'
    assert failed_tests(failing(doc)) == {'6.1.23'}


def test_6_1_25_same_hash_algorithm_twice():
    doc = fixture()
    hashes = tree(doc)['full_product_names'][0]['product_identification_helper']['hashes'][0]['file_hashes']
    hashes.append({'algorithm': 'sha256', 'value': 'a' * 64})
    assert failed_tests(failing(doc)) == {'6.1.25'}


@pytest.mark.parametrize('category, ok', [('csaf_base', True), ('Example Company Notice', True),
                                          ('Security_Incident_Response', False), ('veX', False),
                                          ('Csaf_a', False)])
def test_6_1_26_prohibited_category_names(category, ok):
    doc = {'document': {'category': category, 'csaf_version': '2.0', 'title': 't',
                        'publisher': {'category': 'vendor', 'name': 'n', 'namespace': 'https://example.invalid'},
                        'tracking': {'current_release_date': '2099-01-01T00:00:00Z', 'id': 'X-1',
                                     'initial_release_date': '2099-01-01T00:00:00Z', 'status': 'final',
                                     'version': '1', 'revision_history': [
                                         {'date': '2099-01-01T00:00:00Z', 'number': '1', 'summary': 's'}]}}}
    if ok:
        assert v.load_document(encode(doc))[1].valid
    else:
        assert failed_tests(failing(doc)) == {'6.1.26'}


def test_6_1_27_vex_impact_and_action_statements():
    doc = fixture('synthetic-vex.json')
    del doc['vulnerabilities'][0]['flags']
    doc['vulnerabilities'][0]['remediations'][0]['product_ids'] = ['VEX-1']
    report = failing(doc)
    assert failed_tests(report) == {'6.1.27.9', '6.1.27.10'}


def test_6_1_27_security_advisory_needs_notes_and_status():
    doc = fixture()
    del doc['vulnerabilities'][1]['notes']
    del doc['vulnerabilities'][1]['product_status']
    assert failed_tests(failing(doc)) == {'6.1.27.5', '6.1.27.6'}


def test_6_1_29_6_1_31_6_1_32_6_1_33():
    doc = fixture('synthetic-vex.json')
    vuln = doc['vulnerabilities'][0]
    vuln['remediations'].append({'category': 'mitigation', 'details': 'no products named'})
    vuln['flags'].append({'label': 'component_not_present', 'product_ids': ['VEX-1']})
    vuln['flags'].append({'label': 'vulnerable_code_not_in_execute_path'})
    adv = fixture()
    adv['product_tree']['branches'][0]['branches'][0]['branches'][0]['branches'][1]['name'] = 'all versions'
    assert failed_tests(failing(doc)) == {'6.1.29', '6.1.32', '6.1.33'}
    assert failed_tests(failing(adv)) == {'6.1.31'}


def test_findings_are_sorted_and_truncated_deterministically():
    doc = fixture()
    doc['vulnerabilities'][0]['product_status']['fixed'] += [f'PT-MISSING-{i:03d}' for i in range(300)]
    first = failing(doc)
    second = failing(copy.deepcopy(doc))
    assert first == second
    assert first.truncated and len(first.errors) == v.LIMITS.max_findings
    assert [f.pointer for f in first.errors] == sorted(f.pointer for f in first.errors)


def test_cancellation_is_honoured_during_validation():
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(IntelError) as info:
        v.load_document((FIXTURES / 'synthetic-advisory-rev1.json').read_bytes(), cancel=cancel)
    assert info.value.code == 'PT-INTEL-CANCEL'


def test_provider_metadata_schema_check():
    meta = json.loads((FIXTURES / 'discovery' / 'provider-metadata.json').read_text(encoding='utf-8'))
    assert v.provider_metadata_errors(meta) == []
    del meta['role']
    meta['canonical_url'] = 'https://msrc.microsoft.com/csaf/other.json'
    pointers = {f.pointer for f in v.provider_metadata_errors(meta)}
    assert pointers == {'', '/canonical_url'}
