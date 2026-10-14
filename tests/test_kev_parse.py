"""kev/1 parser: real CC0 fixture golden facts, strict JSON, tolerant fields, hostile and malformed input."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.kev import limits
from patchtrace.kev.contracts import KevCatalog, KevError
from patchtrace.kev.parse import content_digest, parse_catalog

FIXTURES = Path(__file__).parent / 'fixtures' / 'kev'
STAMP = '2026-10-14T00:00:00Z'


def parse(raw: bytes, **kw) -> KevCatalog:
    return parse_catalog(raw, source=kw.pop('source', 'local-import'), retrieved_at=STAMP, **kw)


def real() -> bytes:
    return (FIXTURES / 'kev-real-trimmed.json').read_bytes()


def doc(**changes) -> dict:
    base = json.loads((FIXTURES / 'kev-synthetic-2099.json').read_text(encoding='utf-8'))
    base.update(changes)
    return base


def raw_of(value) -> bytes:
    return json.dumps(value).encode('utf-8')


def test_fixtures_are_lf_and_ascii_safe():
    for path in FIXTURES.glob('*.json'):
        assert b'\r' not in path.read_bytes(), path.name


def test_parse_real_trimmed_golden():
    catalog = parse(real(), file_name='C:\\Users\\me\\kev-real-trimmed.json')
    meta = catalog.meta
    assert (meta.catalog_version, meta.date_released, meta.count, meta.entry_count, meta.skipped_entries) == (
        '2026.10.13', '2026-10-13T19:10:43Z', 12, 12, 0)
    assert meta.raw_sha256 == '0e20b283b9ed08ef10acf033a429b671f425ea07b74279e07708005ce62d9eef'
    assert meta.snapshot_id == '2c9fae3dc6e8620317a60de5a8fa7ee99471809b56323c827d49350cd890feab'
    assert meta.content_digest == 'f2d52245d57a6e9711610b0850d8749e3873c263097e8da7023db36a840b5f03'
    assert (meta.authenticity, meta.license, meta.file_name, meta.unknown_fields, meta.warnings) == (
        'unverified-local-file', 'CC0-1.0', 'kev-real-trimmed.json', (), ())
    by = {e.cve_id: e for e in catalog.entries}
    assert list(by) == sorted(by)
    assert by['CVE-2024-30088'].product == 'Windows'  # trailing space stripped
    assert '\ufffd' in by['CVE-2021-41773'].required_action + by['CVE-2021-41773'].short_description + \
        by['CVE-2021-41773'].name + by['CVE-2021-41773'].notes
    assert '<?php' in by['CVE-2017-9841'].short_description + by['CVE-2017-9841'].name
    assert by['CVE-2013-2597'].notes.count('https:/') >= 1
    assert by['CVE-2019-1068'].cwes == ()
    assert by['CVE-2021-44228'].cwes == ('CWE-20', 'CWE-400', 'CWE-502')
    assert (by['CVE-2025-60710'].ransomware_use, by['CVE-2021-38648'].ransomware_use) == ('known', 'unknown')
    assert {c for c, e in by.items() if e.forensic_triage == 'yes'} == {'CVE-2026-104935', 'CVE-2026-96951',
                                                                        'CVE-2019-1068'}
    assert by['CVE-2021-38648'].date_added == '2021-11-03'


def test_parse_is_fast_enough_for_ci():
    start = time.perf_counter()
    parse(real())
    assert time.perf_counter() - start <= limits.PARSE_CEILING_S


def test_parse_rejects_count_mismatch_and_duplicate_keys():
    with pytest.raises(KevError) as mismatch:
        parse(raw_of(doc(count=5)))
    assert mismatch.value.code == 'PT-KEV-VALIDATE'
    with pytest.raises(KevError) as dup:
        parse(b'{"catalogVersion":"1","catalogVersion":"2","dateReleased":"2099-03-01T00:00:00Z","count":0,'
              b'"vulnerabilities":[]}')
    assert dup.value.code == 'PT-KEV-FORMAT'


def test_unknown_upstream_field_is_reported_not_fatal():
    data = doc(extraTop=1)
    data['vulnerabilities'][0]['newEntryField'] = 'x'
    data['vulnerabilities'][1]['\u202ebidi'] = 'x'
    catalog = parse(raw_of(data))
    assert catalog.meta.unknown_fields == ('\\u202ebidi', 'extraTop', 'newEntryField')
    assert catalog.meta.entry_count == 4


def test_unknown_fields_are_capped_at_sixteen_names():
    data = doc()
    data['vulnerabilities'][0].update({f'field{i:02}': 1 for i in range(30)})
    assert len(parse(raw_of(data)).meta.unknown_fields) == limits.MAX_UNKNOWN_FIELDS


def test_missing_required_field_is_fatal():
    data = doc()
    del data['vulnerabilities'][2]['dueDate']
    with pytest.raises(KevError) as err:
        parse(raw_of(data))
    assert err.value.code == 'PT-KEV-FORMAT'
    for key in ('catalogVersion', 'dateReleased', 'count', 'vulnerabilities'):
        data = doc()
        del data[key]
        with pytest.raises(KevError) as err:
            parse(raw_of(data))
        assert err.value.code == 'PT-KEV-FORMAT', key


def test_content_digest_ignores_key_order_and_whitespace():
    data = doc()
    first = parse(raw_of(data))
    reordered = dict(reversed(list(data.items())))
    reordered['vulnerabilities'] = [dict(reversed(list(v.items()))) for v in reversed(data['vulnerabilities'])]
    second = parse(json.dumps(reordered, indent=7).encode('utf-8'))
    assert first.meta.raw_sha256 != second.meta.raw_sha256
    assert first.meta.snapshot_id != second.meta.snapshot_id
    assert first.meta.content_digest == second.meta.content_digest
    assert content_digest(first.entries) == content_digest(tuple(reversed(first.entries)))
    padded = doc()
    padded['vulnerabilities'][0]['product'] = '  ' + padded['vulnerabilities'][0]['product'] + '\t '
    assert parse(raw_of(padded)).meta.content_digest == first.meta.content_digest


def test_content_digest_changes_with_a_fact():
    data = doc()
    data['vulnerabilities'][0]['knownRansomwareCampaignUse'] = 'Unknown'
    assert parse(raw_of(data)).meta.content_digest != parse(raw_of(doc())).meta.content_digest


@pytest.mark.parametrize(('mutate', 'code'), [
    (lambda d: d['vulnerabilities'].append(dict(d['vulnerabilities'][0])), 'PT-KEV-VALIDATE'),
    (lambda d: d.update(vulnerabilities=[], count=0), 'PT-KEV-VALIDATE'),
    (lambda d: d.update(dateReleased='yesterday'), 'PT-KEV-FORMAT'),
    (lambda d: d.update(dateReleased='2099-13-01T00:00:00Z'), 'PT-KEV-FORMAT'),
    (lambda d: d.update(count='4'), 'PT-KEV-FORMAT'),
    (lambda d: d.update(count=True), 'PT-KEV-FORMAT'),
    (lambda d: d.update(catalogVersion=''), 'PT-KEV-FORMAT'),
    (lambda d: d.update(vulnerabilities={}), 'PT-KEV-FORMAT'),
], ids=['dup-cve', 'empty', 'bad-time', 'bad-month', 'count-str', 'count-bool', 'no-version', 'not-list'])
def test_structural_failures_have_stable_codes(mutate, code):
    data = doc()
    mutate(data)
    if code == 'PT-KEV-VALIDATE' and len(data['vulnerabilities']) == 5:
        data['count'] = 5
    with pytest.raises(KevError) as err:
        parse(raw_of(data))
    assert err.value.code == code


@pytest.mark.parametrize('raw', [
    b'', b'[]', b'null', b'{"a":', b'\xff\xfe{}', b'{"a": NaN}', b'{"a": Infinity}', b'{"a": -Infinity}',
    b'[' * 5000 + b']' * 5000, b'{"x":' * 30 + b'1' + b'}' * 30, b'<html></html>',
], ids=['empty', 'array', 'null', 'truncated', 'utf16', 'nan', 'inf', 'neginf', 'deep-array', 'deep-object', 'html'])
def test_malformed_input_is_a_format_error(raw):
    with pytest.raises(KevError) as err:
        parse(raw)
    assert err.value.code == 'PT-KEV-FORMAT'


def test_truncated_real_catalog_is_a_format_error():
    with pytest.raises(KevError) as err:
        parse(real()[:-40])
    assert err.value.code == 'PT-KEV-FORMAT'


def test_csv_is_refused_as_unsupported():
    with pytest.raises(KevError) as err:
        parse(b'cveID,vendorProject,product\r\nCVE-2021-44228,Apache,Log4j2\r\n')
    assert err.value.code == 'PT-KEV-UNSUPPORTED'


def test_oversize_input_is_a_limit_error_before_parsing():
    with pytest.raises(KevError) as err:
        parse(b' ' * (limits.MAX_BYTES + 1))
    assert err.value.code == 'PT-KEV-LIMIT'


def test_bom_and_crlf_are_tolerated():
    text = json.dumps(doc(), indent=4).replace('\n', '\r\n').encode('utf-8')
    catalog = parse(b'\xef\xbb\xbf' + text)
    assert catalog.meta.entry_count == 4
    assert catalog.meta.raw_sha256 != parse(text).meta.raw_sha256
    assert catalog.meta.warnings == ('A UTF-8 byte order mark was ignored.',)
    assert catalog.meta.content_digest == parse(text).meta.content_digest


def test_release_time_is_normalised_to_utc_seconds():
    for text, expected in [('2026-10-13T19:10:43.6568Z', '2026-10-13T19:10:43Z'),
                           ('2026-10-13T19:10:43Z', '2026-10-13T19:10:43Z'),
                           ('2026-10-13T21:10:43+02:00', '2026-10-13T19:10:43Z')]:
        assert parse(raw_of(doc(dateReleased=text))).meta.date_released == expected


@pytest.mark.parametrize(('field', 'value'), [
    ('cveID', 'CVE-\uff12\uff10\uff12\uff14-12345'), ('cveID', 'cve-2099-10001'), ('cveID', 'CVE-2099-1'),
    ('dueDate', '2098-01-01'), ('dateAdded', '2099-02-30'), ('dateAdded', '99-1-1'),
    ('product', 'x' * 257), ('vulnerabilityName', 5), ('cwes', ['CWE-1'] * 17), ('cwes', ['CWE-x']),
    ('cwes', 'CWE-1'), ('shortDescription', 'lone \ud800 surrogate'),
], ids=['fullwidth-id', 'lowercase-id', 'short-id', 'due-before-added', 'bad-day', 'bad-date-shape', 'long-product',
        'name-int', 'many-cwes', 'bad-cwe', 'cwes-str', 'surrogate'])
def test_bad_entry_values_are_skipped_and_counted(field, value):
    data = doc()
    data['vulnerabilities'][0][field] = value
    text = json.dumps(data).encode('ascii')  # ensure_ascii keeps lone surrogates as escapes
    catalog = parse(text)
    assert (catalog.meta.count, catalog.meta.entry_count, catalog.meta.skipped_entries) == (4, 3, 1)
    assert 'CVE-2099-10001' not in {e.cve_id for e in catalog.entries}
    assert catalog.meta.warnings == ('Entry 1 failed validation and was skipped.',)


def test_enum_fields_map_absent_and_unrecognized_values():
    data = doc()
    first, second, third = data['vulnerabilities'][:3]
    del first['knownRansomwareCampaignUse']
    del first['forensicTriage']
    second['knownRansomwareCampaignUse'] = 'known'
    second['forensicTriage'] = 7
    third['knownRansomwareCampaignUse'] = 'Known'
    by = {e.cve_id: e for e in parse(raw_of(data)).entries}
    assert (by['CVE-2099-10001'].ransomware_use, by['CVE-2099-10001'].forensic_triage) == ('absent', 'absent')
    assert (by['CVE-2099-10002'].ransomware_use, by['CVE-2099-10002'].forensic_triage) == ('unrecognized',
                                                                                          'unrecognized')
    assert by['CVE-2099-10003'].ransomware_use == 'known'


def test_optional_fields_default_when_absent():
    data = doc()
    for key in ('notes', 'cwes'):
        del data['vulnerabilities'][0][key]
    entry = parse(raw_of(data)).entries[0]
    assert (entry.notes, entry.cwes) == ('', ())


def test_hostile_text_is_stored_verbatim_and_never_executed():
    catalog = parse((FIXTURES / 'kev-synthetic-2099.json').read_bytes())
    hostile = {e.cve_id: e for e in catalog.entries}['CVE-2099-10003']
    assert '<script>' in hostile.name and 'file:///' in hostile.notes and '\u202e' in hostile.product


def test_source_and_authenticity_fields():
    site = parse(real(), source='cisa-site', source_url='https://x.invalid/a', final_url='https://x.invalid/a')
    assert (site.meta.authenticity, site.meta.source_url) == ('tls-allowlisted-host', 'https://x.invalid/a')


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.binary(max_size=400))
def test_parser_raises_only_kev_error_on_arbitrary_bytes(raw):
    try:
        parse(raw)
    except KevError:
        pass


_json = st.recursive(st.none() | st.booleans() | st.integers() | st.text(),
                     lambda s: st.lists(s, max_size=4) | st.dictionaries(st.text(max_size=12), s, max_size=5),
                     max_leaves=12)


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(_json)
def test_parser_raises_only_kev_error_on_arbitrary_json(value):
    try:
        parse(json.dumps(value).encode('utf-8'))
    except KevError:
        pass


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.dictionaries(st.sampled_from(['cveID', 'vendorProject', 'product', 'vulnerabilityName', 'dateAdded',
                                        'shortDescription', 'requiredAction', 'dueDate', 'notes', 'cwes',
                                        'knownRansomwareCampaignUse', 'forensicTriage']),
                       st.none() | st.integers() | st.text(max_size=30) | st.lists(st.text(max_size=8), max_size=3),
                       max_size=12))
def test_parser_raises_only_kev_error_on_arbitrary_entries(entry):
    data = doc()
    data['vulnerabilities'] = [entry]
    data['count'] = 1
    try:
        parse(json.dumps(data).encode('utf-8', 'surrogatepass'))
    except KevError:
        pass
