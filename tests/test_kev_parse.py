"""kev/1 parser: strict JSON, fail-closed checks, tolerant of unknown fields, identities independent of layout."""
from __future__ import annotations

import hashlib
import json
import random
import re
import time

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from kev_helpers import (
    ABSENT,
    FIXTURES,
    REAL,
    RETRIEVED,
    ROOT,
    SYNTHETIC,
    document,
    entry,
    fixture_bytes,
    fixture_document,
    mutated,
    parse_bytes,
    parse_document,
    parse_fixture,
    render,
    socket_guard,
)

from patchtrace.enrichment.identity import domain_id
from patchtrace.kev import parse
from patchtrace.kev.contracts import ConsentRecord, KevError, plan_for
from patchtrace.kev.limits import MAX_CATALOG_BYTES, MAX_ENTRIES
from patchtrace.kev.parse import parse_catalog

FORMAT, VALIDATE, LIMIT = 'PT-KEV-FORMAT', 'PT-KEV-VALIDATE', 'PT-KEV-LIMIT'
README = (FIXTURES / 'README.md').read_text(encoding='utf-8')
SCHEMA_PATH = ROOT / 'docs' / 'schemas' / 'kev' / 'upstream' / 'known_exploited_vulnerabilities_schema.json'
SCHEMA_SHA = '0d5865c98694c5bfba2c78a26caf814f406b3fce8bfb81bef79e99c7f288b0e7'
BASE = document()
FAST = settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
no_sockets = pytest.fixture(autouse=True, scope='module')(socket_guard)


# --- K0 data: LF bytes, README inventory, vendored schema ---------------------------------------------------

@pytest.mark.parametrize('name', [REAL, SYNTHETIC], ids=['real', 'synthetic'])
def test_fixture_is_lf_and_matches_its_readme_inventory(name):
    data = fixture_bytes(name)
    assert b'\r' not in data and not data.startswith(b'\xef\xbb\xbf')
    row = re.search(rf'\| `{re.escape(name)}` \| ([0-9,]+) \| `([0-9a-f]{{64}})` \| (\d+) \|', README)
    assert row, name
    assert (int(row.group(1).replace(',', '')), row.group(2), int(row.group(3))) == (
        len(data), hashlib.sha256(data).hexdigest(), len(json.loads(data)['vulnerabilities']))


def test_real_entries_match_the_readme_entry_hashes():
    text = fixture_bytes(REAL).decode('utf-8')
    decoder, seen = json.JSONDecoder(), {}
    position = text.index('[', text.index('"vulnerabilities"')) + 1
    while True:
        while text[position] in ' \n,':
            position += 1
        if text[position] == ']':
            break
        value, end = decoder.raw_decode(text, position)
        seen[value['cveID']] = hashlib.sha256(text[position:end].encode('utf-8')).hexdigest()
        position = end
    assert len(seen) == 12
    assert seen == dict(re.findall(r'\| (CVE-[0-9]{4}-[0-9]+) \| [^|]+ \| [^|]+ \| `([0-9a-f]{64})` \|', README))


def test_vendored_upstream_schema_is_pinned_and_agrees_with_the_parser():
    data = SCHEMA_PATH.read_bytes()
    assert hashlib.sha256(data).hexdigest() == SCHEMA_SHA and b'\r' not in data
    assert SCHEMA_SHA in (SCHEMA_PATH.parent / 'README.md').read_text(encoding='utf-8')
    schema = json.loads(data)
    entry_schema = schema['$defs']['vulnerability']
    assert tuple(schema['required']) == parse.TOP_REQUIRED
    assert tuple(entry_schema['required']) == parse.ENTRY_REQUIRED
    assert set(entry_schema['properties']) - set(entry_schema['required']) == set(parse.ENTRY_OPTIONAL)
    assert entry_schema['properties']['cveID']['pattern'] == '^CVE-[0-9]{4}-[0-9]{4,19}$'


# --- golden -------------------------------------------------------------------------------------------------

GOLDEN_ENTRIES = (
    ('CVE-2013-2597', 'Code Aurora', 'ACDB Audio Driver', '2022-09-15', '2022-10-06', 'unknown', 'no', ('CWE-119',)),
    ('CVE-2017-0144', 'Microsoft', 'SMBv1', '2022-02-10', '2022-08-10', 'known', 'no', ('CWE-20',)),
    ('CVE-2017-9841', 'PHPUnit', 'PHPUnit', '2022-02-15', '2022-08-15', 'unknown', 'no', ('CWE-94',)),
    ('CVE-2019-1068', 'Microsoft', 'SQL Server', '2026-08-26', '2026-08-29', 'unknown', 'yes', ()),
    ('CVE-2021-34527', 'Microsoft', 'Windows', '2021-11-03', '2022-05-03', 'known', 'no', ('CWE-269',)),
    ('CVE-2021-38648', 'Microsoft', 'Open Management Infrastructure (OMI)', '2021-11-03', '2021-11-17', 'unknown',
     'no', ('CWE-1390',)),
    ('CVE-2021-41773', 'Apache', 'HTTP Server', '2021-11-03', '2021-11-17', 'known', 'no', ('CWE-22',)),
    ('CVE-2021-44228', 'Apache', 'Log4j2', '2021-12-10', '2021-12-24', 'known', 'no',
     ('CWE-20', 'CWE-400', 'CWE-502')),
    ('CVE-2024-30088', 'Microsoft', 'Windows', '2024-10-15', '2024-11-05', 'known', 'no', ('CWE-367',)),
    ('CVE-2025-60710', 'Microsoft', 'Windows', '2026-04-13', '2026-04-27', 'known', 'no', ('CWE-59',)),
    ('CVE-2026-104935', 'Ivanti', 'Connect Secure', '2026-10-13', '2026-10-16', 'unknown', 'yes', ('CWE-290',)),
    ('CVE-2026-96951', 'Microsoft', 'Windows', '2026-10-13', '2026-10-16', 'unknown', 'yes', ('CWE-77',)),
)
GOLDEN_SNAPSHOT_ID = '591569ce9ae394849d52791e25a584ba84e9c9d03921d5146f1bf3921487e8d6'
GOLDEN_CONTENT_DIGEST = '014cafc4196f522ed77117959c7dc60fe483a528a524c9e29abe0291903c3ac9'


def test_parse_real_trimmed_golden():
    raw = fixture_bytes(REAL)
    catalog = parse_bytes(raw, name=REAL)
    meta = catalog.meta
    assert (meta.catalog_version, meta.date_released) == ('2026.10.13', '2026-10-13T19:10:43Z')
    assert (meta.count, meta.entry_count, meta.skipped_entries) == (12, 12, 0)
    assert (meta.raw_sha256, meta.raw_size) == (hashlib.sha256(raw).hexdigest(), len(raw))
    assert (meta.unknown_fields, meta.warnings) == ((), ())          # title is known; every entry is well formed
    assert (meta.source, meta.authenticity, meta.file_name) == ('local-import', 'unverified-local-file', REAL)
    assert (meta.snapshot_id, meta.content_digest) == (GOLDEN_SNAPSHOT_ID, GOLDEN_CONTENT_DIGEST)
    assert tuple((e.cve_id, e.vendor_project, e.product, e.date_added, e.due_date, e.ransomware_use,
                  e.forensic_triage, e.cwes) for e in catalog.entries) == GOLDEN_ENTRIES
    assert [e.cve_id for e in catalog.entries] == sorted(e.cve_id for e in catalog.entries)
    assert catalog.by_cve['CVE-2021-44228'] is catalog.entries[7]


def test_identities_follow_the_documented_recipe():
    """Recomputed here straight from the JSON, not through the parser: the recipe is a persisted contract."""
    raw = fixture_bytes(REAL)
    meta = parse_bytes(raw).meta
    assert meta.snapshot_id == domain_id('kev-snapshot', 1, {'raw_sha256': hashlib.sha256(raw).hexdigest(),
                                                             'parser_version': 1})
    digests = []
    for row in sorted(json.loads(raw)['vulnerabilities'], key=lambda item: item['cveID']):
        digests.append(domain_id('kev-entry', 1, {
            'cve_id': row['cveID'], 'vendor_project': row['vendorProject'].strip(), 'product': row['product'].strip(),
            'name': row['vulnerabilityName'], 'date_added': row['dateAdded'], 'due_date': row['dueDate'],
            'short_description': row['shortDescription'].strip(), 'required_action': row['requiredAction'],
            'notes': row['notes'], 'cwes': row['cwes'], 'ransomware_use': row['knownRansomwareCampaignUse'].lower(),
            'forensic_triage': row['forensicTriage'].lower()}))
    assert meta.content_digest == domain_id('kev-content', 1, digests)
    assert digests == [item.entry_digest for item in parse_bytes(raw).entries]


def test_real_quirks_survive_as_data_not_as_markup():
    by = parse_fixture(REAL).by_cve
    assert by['CVE-2024-30088'].product == 'Windows'                       # CISA wrote "Windows "
    assert by['CVE-2024-30088'].short_description == by['CVE-2024-30088'].short_description.strip()
    assert '�' in by['CVE-2021-41773'].short_description               # replacement characters are kept as text
    assert '<?php' in by['CVE-2017-9841'].short_description                 # never escaped or removed at parse time
    assert '/https:/www.codeaurora.org/' in by['CVE-2013-2597'].notes             # malformed inner URL kept verbatim
    assert by['CVE-2026-104935'].notes.startswith('https:/forums.ivanti.com/')    # malformed first segment kept
    assert by['CVE-2019-1068'].cwes == () and by['CVE-2021-44228'].cwes == ('CWE-20', 'CWE-400', 'CWE-502')
    assert by['CVE-2026-96951'].required_action.startswith('Apply mitigations')
    assert 'CISA’s' in by['CVE-2026-96951'].required_action          # typographic quote preserved


def test_parse_synthetic_catalog():
    catalog = parse_fixture(SYNTHETIC)
    assert [e.cve_id for e in catalog.entries] == ['CVE-2099-10001', 'CVE-2099-10004', 'CVE-2099-10009',
                                                   'CVE-2099-10010']
    first, last = catalog.by_cve['CVE-2099-10001'], catalog.by_cve['CVE-2099-10010']
    assert (first.ransomware_use, first.forensic_triage, first.cwes) == ('known', 'yes', ('CWE-787',))
    assert (last.product, last.ransomware_use, last.forensic_triage, last.notes, last.cwes) == (
        'Router', 'absent', 'absent', '', ())
    assert catalog.meta.date_released == '2099-03-01T18:00:00Z' and catalog.meta.catalog_version == '2099.03.01'
    assert catalog.meta.unknown_fields == ()


# --- fail closed --------------------------------------------------------------------------------------------

def put(path: tuple, value) -> bytes:
    return render(mutated(BASE, path, value))


def entry_text(path: tuple, value) -> bytes:
    return put(('vulnerabilities', 0, *path), value)


def cases():
    text = render(BASE).decode('utf-8')
    yield 'empty', lambda: b'', FORMAT
    yield 'whitespace-only', lambda: b' \n\t ', FORMAT
    yield 'not-json', lambda: b'<html>no</html>', FORMAT
    yield 'truncated-in-an-entry', lambda: render(BASE)[:len(render(BASE)) // 2], FORMAT
    yield 'truncated-before-the-last-brace', lambda: render(BASE).rstrip()[:-1], FORMAT
    yield 'trailing-garbage', lambda: render(BASE) + b' {}', FORMAT
    yield 'top-level-array', lambda: b'[]', FORMAT
    yield 'top-level-string', lambda: b'"x"', FORMAT
    yield 'nan-count', lambda: text.replace('"count": 2', '"count": NaN').encode(), FORMAT
    yield 'infinity-anywhere', lambda: text.replace('"SYNTHETIC"', 'Infinity').encode(), FORMAT
    yield 'duplicate-top-level-key', lambda: text.replace('"count": 2,', '"count": 2, "count": 2,').encode(), FORMAT
    yield 'duplicate-entry-key', lambda: text.replace(
        '"product": "Example Product",', '"product": "Example Product", "product": "Other",', 1).encode(), FORMAT
    yield 'deep-nesting', lambda: (b'{"catalogVersion": "1", "x": ' + b'[' * 60_000 + b']' * 60_000 + b'}'), FORMAT
    yield 'utf-16', lambda: render(BASE).decode('utf-8').encode('utf-16'), FORMAT
    yield 'invalid-utf-8', lambda: b'{"catalogVersion": "\xff"}', FORMAT
    yield 'csv', lambda: b'cveID,vendorProject,product\r\nCVE-2099-1,a,b\r\n', 'PT-KEV-UNSUPPORTED'
    yield 'csv-with-bom', lambda: b'\xef\xbb\xbfcveID,vendorProject\n', 'PT-KEV-UNSUPPORTED'
    yield 'oversize', lambda: b' ' * (MAX_CATALOG_BYTES + 1), LIMIT
    yield 'too-many-entries', lambda: render(document([entry(1)] * (MAX_ENTRIES + 1)), indent=None), LIMIT
    for key in parse.TOP_REQUIRED:
        yield f'missing-{key}', lambda key=key: put((key,), ABSENT), FORMAT
    for value, name in ((2.0, 'float'), (True, 'bool'), (-1, 'negative'), ('2', 'string'), (None, 'null')):
        yield f'count-{name}', lambda value=value: put(('count',), value), FORMAT
    for value, name in (({}, 'object'), (None, 'null'), ('x', 'string')):
        yield f'vulnerabilities-{name}', lambda value=value: put(('vulnerabilities',), value), FORMAT
    for value, name in ((7, 'number'), ('', 'empty'), ('v' * 33, 'long'), ('1\n2', 'control'), ('1‮2', 'bidi'),
                        ('café', 'non-ascii')):
        yield f'version-{name}', lambda value=value: put(('catalogVersion',), value), FORMAT
    for value, name in (('2098-02-01', 'date-only'), ('2098-02-01T12:00:00+00:00', 'offset'),
                        ('2098-02-30T12:00:00Z', 'impossible'), (5, 'number'), ('2098-02-01T12:00:00z', 'lowercase-z'),
                        ('2098-02-01T12:00Z', 'no-seconds'), ('2098-02-01T24:00:00Z', 'hour-24'),
                        ('２０９８-02-01T12:00:00Z', 'fullwidth')):
        yield f'release-{name}', lambda value=value: put(('dateReleased',), value), FORMAT
    yield 'count-lower-than-entries', lambda: put(('count',), 1), VALIDATE
    yield 'count-higher-than-entries', lambda: put(('count',), 3), VALIDATE
    yield 'no-entries', lambda: render(document([])), VALIDATE
    yield 'entry-is-a-string', lambda: put(('vulnerabilities', 0), 'CVE-2098-00001'), VALIDATE
    yield 'entry-is-null', lambda: put(('vulnerabilities', 0), None), VALIDATE
    for field in parse.ENTRY_REQUIRED:
        yield f'entry-missing-{field}', lambda field=field: entry_text((field,), ABSENT), VALIDATE
        yield f'entry-wrong-type-{field}', lambda field=field: entry_text((field,), {'x': 'SECRET'}), VALIDATE
    for field in parse.ENTRY_OPTIONAL:
        yield f'entry-wrong-type-{field}', lambda field=field: entry_text((field,), {'x': 'SECRET'}), VALIDATE
    yield 'entry-null-optional', lambda: entry_text(('notes',), None), VALIDATE
    yield 'cwes-is-a-string', lambda: entry_text(('cwes',), 'CWE-20'), VALIDATE
    yield 'cwes-item-is-a-number', lambda: entry_text(('cwes',), ['CWE-20', 5]), VALIDATE
    for value, name in (('CVE-２０９８-00001', 'fullwidth'), ('CVE-2098-٠٠٠٠١', 'arabic-indic'),
                        ('cve-2098-00001', 'lowercase'), ('CVE-2098-00001\n', 'newline'), ('CVE-2098-1', 'short'),
                        (' CVE-2098-00001', 'padded'), ('', 'empty')):
        yield f'cve-{name}', lambda value=value: entry_text(('cveID',), value), VALIDATE
    for field in ('dateAdded', 'dueDate'):
        for value, name in (('2098-1-10', 'unpadded'), ('2098-02-30', 'impossible'), ('２０９８-01-10', 'fullwidth'),
                            ('2098-01-10T00:00:00Z', 'timestamp'), ('', 'empty'), (' 2098-01-31', 'padded')):
            yield f'{field}-{name}', lambda field=field, value=value: entry_text((field,), value), VALIDATE
    yield 'due-before-added', lambda: entry_text(('dueDate',), '2098-01-09'), VALIDATE
    yield 'duplicate-cve-id', lambda: render(document([entry(1), entry(2), entry(1)])), VALIDATE


@pytest.mark.parametrize(('build', 'code'), [pytest.param(build, code, id=name) for name, build, code in cases()])
def test_hostile_files_fail_closed_with_a_typed_message(build, code):
    with pytest.raises(KevError) as caught:
        parse_bytes(build())
    assert caught.value.code == code and caught.value.recoverable
    assert 'SECRET' not in str(caught.value) and len(caught.value.message) < 200


def test_parse_rejects_count_mismatch_and_duplicate_keys():
    with pytest.raises(KevError, match='count') as mismatch:
        parse_bytes(put(('count',), 5))
    assert mismatch.value.code == VALIDATE and '5' in mismatch.value.message and '2' in mismatch.value.message
    twice = render(BASE).decode('utf-8').replace('"count": 2,', '"count": 2, "count": 3,')
    with pytest.raises(KevError, match='repeats a key') as duplicate:
        parse_bytes(twice.encode('utf-8'))
    assert duplicate.value.code == FORMAT
    with pytest.raises(KevError, match=r'CVE-2098-00001') as listed_twice:
        parse_bytes(render(document([entry(1), entry(1)])))
    assert listed_twice.value.code == VALIDATE


def test_the_first_failing_entry_is_named_by_position_and_field():
    with pytest.raises(KevError) as caught:
        parse_bytes(render(mutated(BASE, ('vulnerabilities', 1, 'dueDate'), ABSENT)))
    assert 'entry 2' in caught.value.message and 'dueDate' in caught.value.message


# --- tolerant where it is safe ------------------------------------------------------------------------------

def test_unknown_upstream_field_is_reported_not_fatal():
    changed = document(extraTop={'a': 1})
    changed['vulnerabilities'][0]['epssScore'] = 'SECRET-TOKEN'
    catalog = parse_document(changed)
    assert catalog.meta.unknown_fields == ('catalog.extraTop', 'entry.epssScore')
    assert catalog.meta.warnings == ('unknown field names found: 2 (listed in unknown_fields)',)
    assert 'SECRET-TOKEN' not in catalog.meta.model_dump_json() and catalog.meta.entry_count == 2


def test_unknown_field_names_are_cleaned_capped_and_limited_to_sixteen():
    changed = document()
    for number in range(20):
        changed['vulnerabilities'][0][f'extra{number:02d}'] = number
    changed['vulnerabilities'][1]['\x1b[31m' + 'n' * 100] = 1
    changed['vulnerabilities'][1]['\x1b'] = 2
    catalog = parse_document(changed)
    names = catalog.meta.unknown_fields
    assert len(names) == 16 and list(names) == sorted(set(names)) and all(len(name) <= 64 for name in names)
    assert names[0] == 'entry.?' and not any('\x1b' in name for name in names)    # a nameless field reads "?"
    assert catalog.meta.warnings == ('unknown field names found: 22 (listed in unknown_fields)',
                                     'unknown field names not listed: 6')


def test_absent_optional_fields_are_absent_not_negative():
    optional = {key: ABSENT for key in parse.ENTRY_OPTIONAL}
    item = parse_document(document([entry(1, **optional)])).entries[0]
    assert (item.ransomware_use, item.forensic_triage, item.notes, item.cwes) == ('absent', 'absent', '', ())


@pytest.mark.parametrize(('raw', 'expected'), [
    ('Known', 'known'), ('Unknown', 'unknown'), (' Known ', 'known'), ('known', 'unrecognized'),
    ('UNKNOWN', 'unrecognized'), ('Maybe', 'unrecognized'), ('', 'unrecognized'), ('No', 'unrecognized')],
    ids=['known', 'unknown', 'padded', 'lowercase', 'uppercase', 'other-word', 'empty', 'no'])
def test_ransomware_value_mapping_never_invents_a_no(raw, expected):
    catalog = parse_document(document([entry(1, knownRansomwareCampaignUse=raw)]))
    assert catalog.entries[0].ransomware_use == expected
    assert bool(catalog.meta.warnings) == (expected == 'unrecognized')


@pytest.mark.parametrize(('raw', 'expected'), [
    ('Yes', 'yes'), ('No', 'no'), ('yes', 'unrecognized'), ('Maybe', 'unrecognized')],
    ids=['yes', 'no', 'lowercase', 'other-word'])
def test_forensic_triage_value_mapping(raw, expected):
    assert parse_document(document([entry(1, forensicTriage=raw)])).entries[0].forensic_triage == expected


def test_unrecognized_values_are_counted_in_one_warning():
    catalog = parse_document(document([entry(1, forensicTriage='x'), entry(2, knownRansomwareCampaignUse='y')]))
    assert catalog.meta.warnings == ('ransomware or forensic triage values not recognized: 2',)


def test_cwe_tokens_are_kept_only_when_they_are_cwe_numbers():
    tokens = [' CWE-79 ', 'NVD-CWE-Other', 'CWE-1234567', 'CWE-', 'cwe-20', 'CWE-２０', 'CWE-787']
    catalog = parse_document(document([entry(1, cwes=tokens)]))
    assert catalog.entries[0].cwes == ('CWE-79', 'CWE-787')
    assert catalog.meta.warnings == ('weakness identifiers left out (not CWE-n, or beyond 16 per entry): 5',)


def test_more_than_sixteen_cwes_keep_the_first_sixteen():
    catalog = parse_document(document([entry(1, cwes=[f'CWE-{n}' for n in range(1, 21)])]))
    assert catalog.entries[0].cwes == tuple(f'CWE-{n}' for n in range(1, 17))
    assert catalog.meta.warnings == ('weakness identifiers left out (not CWE-n, or beyond 16 per entry): 4',)


def test_text_is_stripped_cleaned_and_capped():
    hostile = entry(1, vendorProject='  Microsoft  ', product='Wind\x1b[31mows‮', vulnerabilityName='n' * 300,
                    shortDescription='line one\nSource: forged\r\nline\ttwo', requiredAction='act\ud800ion',
                    notes='a b')
    catalog = parse_bytes(json.dumps(document([hostile])).encode('ascii'))     # ASCII JSON keeps the lone surrogate
    item = catalog.entries[0]
    assert item.vendor_project == 'Microsoft' and item.product == 'Wind[31mows'
    assert item.name == 'n' * 253 + '...' and len(item.name) == 256
    assert item.short_description == 'line one Source: forged  line two' and '\n' not in item.short_description
    assert item.required_action == 'action' and item.notes == 'a b'
    assert catalog.meta.warnings == ('text values shortened to their length limit: 1',)


def test_lone_surrogate_escapes_in_json_text_do_not_crash_hashing():
    raw = render(document([entry(1)])).replace(b'SYNTHETIC description 1.', b'bad \\ud800 text')
    assert parse_bytes(raw).entries[0].short_description == 'bad  text'


@pytest.mark.parametrize('field', ['cveID', 'dateAdded', 'dueDate'])
def test_lone_surrogates_in_the_strictly_formatted_fields_are_a_typed_failure(field):
    """These fields are hashed before the model checks their form; a surrogate must not escape as UnicodeEncodeError."""
    raw = json.dumps(mutated(BASE, ('vulnerabilities', 0, field), 'CVE-\ud800')).encode('ascii')
    with pytest.raises(KevError) as caught:
        parse_bytes(raw)
    assert caught.value.code == VALIDATE and field in caught.value.message
    odd_cwe = json.dumps(mutated(BASE, ('vulnerabilities', 0, 'cwes'), ['\ud800', 'CWE-20'])).encode('ascii')
    assert parse_bytes(odd_cwe).entries[0].cwes == ('CWE-20',)


def test_a_utf8_bom_and_crlf_are_accepted_and_do_not_change_the_content():
    plain = parse_bytes(render(BASE))
    bom = parse_bytes(b'\xef\xbb\xbf' + render(BASE))
    crlf = parse_bytes(render(BASE).replace(b'\n', b'\r\n'))
    assert bom.meta.content_digest == crlf.meta.content_digest == plain.meta.content_digest
    assert len({plain.meta.raw_sha256, bom.meta.raw_sha256, crlf.meta.raw_sha256}) == 3
    assert len({plain.meta.snapshot_id, bom.meta.snapshot_id, crlf.meta.snapshot_id}) == 3
    assert bom.meta.raw_size == len(render(BASE)) + 3


def test_release_time_keeps_seconds_and_drops_fractions():
    assert parse_bytes(render(BASE)).meta.date_released == '2098-02-01T12:00:00Z'
    exact = parse_bytes(put(('dateReleased',), '2098-02-01T12:00:00Z'))
    assert exact.meta.date_released == '2098-02-01T12:00:00Z'


def test_catalog_version_and_title_are_free_but_bounded():
    assert parse_bytes(put(('catalogVersion',), ' 2098.02.01 rev 2 ')).meta.catalog_version == '2098.02.01 rev 2'
    assert parse_bytes(put(('title',), {'any': ['thing']})).meta.unknown_fields == ()


# --- identities ---------------------------------------------------------------------------------------------

def shuffled(value, rng: random.Random):
    if isinstance(value, dict):
        keys = list(value)
        rng.shuffle(keys)
        return {key: shuffled(value[key], rng) for key in keys}
    if isinstance(value, list) and value and isinstance(value[0], dict):
        rows = [shuffled(item, rng) for item in value]
        rng.shuffle(rows)
        return rows
    return value


def test_content_digest_ignores_key_order_and_whitespace():
    base = fixture_document(REAL)
    digests = {parse_document(base, indent=indent).meta.content_digest for indent in (None, 0, 2, 4, 8)}
    for seed in range(5):
        digests.add(parse_document(shuffled(base, random.Random(seed)), indent=seed).meta.content_digest)
    padded = json.loads(json.dumps(base))
    padded['vulnerabilities'][0]['vendorProject'] = '  ' + padded['vulnerabilities'][0]['vendorProject'] + '  '
    digests.add(parse_document(padded).meta.content_digest)
    assert len(digests) == 1


def test_content_digest_follows_every_listed_fact_and_ignores_unknown_fields():
    base = fixture_document(SYNTHETIC)
    reference = parse_document(base).meta.content_digest
    for path, value in ((('vulnerabilities', 0, 'dueDate'), '2099-12-31'), (('vulnerabilities', 1, 'cwes'), ['CWE-1']),
                        (('vulnerabilities', 2, 'product'), 'Other'),
                        (('vulnerabilities', 3, 'knownRansomwareCampaignUse'), 'Unknown'),
                        (('vulnerabilities', 0, 'forensicTriage'), 'Yes'),
                        (('vulnerabilities', 1, 'requiredAction'), 'Do something else.'),
                        (('vulnerabilities', 1, 'notes'), 'changed')):
        assert parse_document(mutated(base, path, value)).meta.content_digest != reference, path
    extra = mutated(base, ('vulnerabilities', 0, 'epssScore'), 0.5)
    assert parse_document(extra).meta.content_digest == reference
    assert parse_document(extra).meta.snapshot_id != parse_document(base).meta.snapshot_id
    grown = json.loads(json.dumps(base))
    grown['vulnerabilities'].append(entry(7))
    grown['count'] = 5
    assert parse_document(grown).meta.content_digest != reference


def test_snapshot_identity_is_the_raw_bytes():
    raw = fixture_bytes(SYNTHETIC)
    first = parse_bytes(raw)
    again = parse_bytes(raw, retrieved_at='2099-04-01T00:00:00Z')
    other = parse_bytes(raw + b'\n')
    assert first.meta.snapshot_id == again.meta.snapshot_id               # retrieval time is not identity
    assert first.meta.snapshot_id != other.meta.snapshot_id
    assert first.meta.content_digest == other.meta.content_digest


def test_entry_digests_do_not_depend_on_the_file_around_them():
    alone = parse_document(document([entry(1)]))
    among = parse_document(document([entry(2), entry(1), entry(3)]))
    assert alone.by_cve['CVE-2098-00001'].entry_digest == among.by_cve['CVE-2098-00001'].entry_digest
    assert alone.by_cve['CVE-2098-00001'].entry_digest != among.by_cve['CVE-2098-00002'].entry_digest


@given(order=st.permutations(range(4)), indent=st.sampled_from([None, 0, 2, 4]), seed=st.integers(0, 10 ** 6))
@FAST
def test_content_digest_is_invariant_under_layout_property(order, indent, seed):
    base = fixture_document(SYNTHETIC)
    reordered = dict(base, vulnerabilities=[base['vulnerabilities'][i] for i in order])
    assert (parse_document(shuffled(reordered, random.Random(seed)), indent=indent).meta.content_digest
            == parse_document(base).meta.content_digest)


# --- provenance ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize('source', ['cisa-site', 'cisa-github'])
def test_a_fetched_catalog_records_where_it_came_from_and_who_agreed(source):
    plan = plan_for(source)
    consent = ConsentRecord(operation='fetch-kev-catalog', source=source, url=plan.url, plan_sha=plan.plan_sha,
                            granted_at='2099-03-02T07:59:00Z', surface='gui')
    catalog = parse_catalog(fixture_bytes(SYNTHETIC), source=source, retrieved_at=RETRIEVED, source_url=plan.url,
                            final_url=plan.url, consent=consent)
    assert catalog.meta.source == source and catalog.meta.consent == consent
    assert catalog.meta.authenticity == 'tls-allowlisted-host' and catalog.meta.file_name is None


@pytest.mark.parametrize('arguments', [
    {'source': 'somewhere'}, {'source': 'local-import', 'source_url': 'https://www.cisa.gov/x'},
    {'source': 'cisa-site'}, {'source': 'local-import', 'file_name': '../x.json'},
    {'source': 'local-import', 'retrieved_at': 'yesterday'}],
    ids=['unknown-source', 'local-with-url', 'fetch-without-consent', 'path-in-file-name', 'bad-timestamp'])
def test_inconsistent_provenance_is_an_input_error_not_a_crash(arguments):
    call = {'source': 'local-import', 'retrieved_at': RETRIEVED} | arguments
    with pytest.raises(KevError) as caught:
        parse_catalog(fixture_bytes(SYNTHETIC), **call)
    assert caught.value.code == 'PT-KEV-INPUT'


# --- budget and properties ----------------------------------------------------------------------------------

def test_a_full_size_catalog_parses_within_the_budget():
    rows = [entry(n, shortDescription='D' * 700, requiredAction='A' * 400, notes='https://example.invalid/' + 'n' * 80)
            for n in range(1, 1742)]
    raw = render(document(rows))
    assert len(raw) > 1_500_000
    started = time.perf_counter()
    catalog = parse_bytes(raw)
    elapsed = time.perf_counter() - started
    assert catalog.meta.entry_count == 1741 and elapsed < 1.0, f'{elapsed:.3f}s'


@given(st.binary(max_size=3000))
@FAST
def test_arbitrary_bytes_raise_only_kev_error(data):
    try:
        parse_bytes(data)
    except KevError:
        pass


@given(flips=st.lists(st.tuples(st.integers(0, 10 ** 6), st.integers(0, 255)), max_size=6),
       cut=st.one_of(st.none(), st.integers(0, 10 ** 6)),
       insert=st.tuples(st.integers(0, 10 ** 6), st.binary(max_size=12)))
@FAST
def test_mutated_valid_files_raise_only_kev_error(flips, cut, insert):
    data = bytearray(fixture_bytes(SYNTHETIC))
    for position, value in flips:
        data[position % len(data)] = value
    position, extra = insert
    data[position % len(data):position % len(data)] = extra
    if cut is not None:
        del data[cut % len(data):]
    try:
        catalog = parse_bytes(bytes(data))
    except KevError:
        return
    assert [e.cve_id for e in catalog.entries] == sorted(e.cve_id for e in catalog.entries)
    assert catalog.meta.entry_count == len(catalog.entries) >= 1


# Hypothesis seldom draws lone surrogates by itself, so every example carries one.
SURROGATE_TEXT = st.builds('{}{}{}'.format, st.text(max_size=5), st.sampled_from(['\ud800', '\udbff', '\udc00', '\udfff']),
                           st.text(max_size=5))


@given(field=st.sampled_from(sorted(parse.ENTRY_KNOWN)), value=SURROGATE_TEXT)
@FAST
def test_surrogates_in_any_entry_field_or_key_raise_only_kev_error(field, value):
    for path, item in ((('vulnerabilities', 0, field), value), (('vulnerabilities', 0, value), 1)):
        try:
            parse_bytes(json.dumps(mutated(BASE, path, item)).encode('ascii'))     # ASCII JSON keeps lone surrogates
        except KevError:
            pass


@given(st.text(max_size=60), st.text(max_size=60))
@FAST
def test_any_text_in_a_text_field_parses_to_a_clean_single_line(vendor, notes):
    item = parse_document(document([entry(1, vendorProject=vendor, notes=notes)])).entries[0]
    for text in (item.vendor_project, item.notes):
        assert text == text.strip() and not any(ord(char) < 32 or 0x7F <= ord(char) <= 0x9F for char in text)
