"""PW-01 authored synthetic CSV mechanics; no live Microsoft compatibility claim."""
from __future__ import annotations

import hashlib
import io
import itertools
import json
import socket
import subprocess
import threading
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from patchtrace.kbcorrelation import inventory_csv
from patchtrace.kbcorrelation.inventory_contracts import (
    DEFAULT_LIMITS,
    MAX_BYTES,
    MAX_COLUMNS,
    MAX_DIAGNOSTICS,
    MAX_ENTRIES,
    MAX_FIELD_CHARS,
    MAX_RECORD_CHARS,
    MAX_RECORDS,
    MAX_SECTIONS,
    UINT64_MAX,
    CsvInventory,
    CsvRecordRef,
    InventoryContext,
    InventoryEntry,
    InventoryLimits,
    InventorySection,
    entry_identity,
    inventory_identity,
)
from patchtrace.kbcorrelation.inventory_csv import parse_inventory
from patchtrace.kbcorrelation.sources.cvrf import SourceError

CONTEXT = InventoryContext(kb='KB1234567')
AMD64 = InventoryContext(kb='KB1234567', architecture='amd64')
HEADER = 'File name,File version\n'


def csv_bytes(rows, *, delimiter=',', newline='\n'):
    """Generate authored fields with an independent stdlib quoting oracle."""
    import csv

    stream = io.StringIO(newline='')
    csv.writer(stream, delimiter=delimiter, lineterminator=newline).writerows(rows)
    return stream.getvalue().encode()


def assert_failure(raw, *, code='PT-KBC-SOURCE', context=AMD64, **kwargs):
    with pytest.raises(SourceError) as caught:
        parse_inventory(raw, context, **kwargs)
    assert caught.value.code == code
    assert len(caught.value.message) <= 500
    return caught.value


def example_inventory():
    raw = b'Windows example x64-based\nFile name,File version\nexample.dll,1.2.3.4\n'
    sha = hashlib.sha256(raw).hexdigest()
    ident = inventory_identity(sha, CONTEXT)
    header = CsvRecordRef(raw_sha256=sha, logical_record=1, line_start=1, line_end=1, section_index=0)
    row = CsvRecordRef(raw_sha256=sha, logical_record=3, line_start=3, line_end=3, section_index=0)
    entry = InventoryEntry(entry_id=entry_identity(ident, 3), reference=row,
                           original_fields=('example.dll', '1.2.3.4'), original_filename='example.dll',
                           basename='example.dll', original_version='1.2.3.4', version_components=(1, 2, 3, 4),
                           original_size=None, size_bytes=None, date_text=None, time_text=None,
                           architecture='amd64', architecture_basis='section', product=None, release=None,
                           build=None, state='metadata-only')
    return CsvInventory(inventory_id=ident, raw_sha256=sha, raw_size=len(raw), encoding='utf-8', context=CONTEXT,
                        entries=(entry,), sections=(InventorySection(index=0, banner='Windows example x64-based',
                                                                     architecture='amd64', reference=header),),
                        diagnostics=(), records_scanned=3, accepted_count=1, rejected_count=0,
                        duplicate_count=0, conflict_count=0, diagnostics_omitted=0, truncated=False, status='complete')


def test_inventory_contract_roundtrip_and_frozen_fields():
    record = example_inventory()
    assert CsvInventory.model_validate_json(record.model_dump_json()) == record
    with pytest.raises(ValidationError):
        record.raw_size = 1
    with pytest.raises(ValidationError):
        InventoryContext(kb='KB1234567', source_url='https://example.invalid')


@pytest.mark.parametrize('changes', [{'max_bytes': 0}, {'max_entries': 5001}, {'max_seconds': 11.0},
                                   {'max_seconds': float('inf')}, {'max_records': True}])
def test_inventory_contract_limits_have_hard_ceilings(changes):
    with pytest.raises(ValidationError):
        InventoryLimits(**changes)


def test_inventory_contract_identity_binds_full_configured_limits():
    sha = 'a' * 64
    assert inventory_identity(sha, CONTEXT) != inventory_identity(sha, CONTEXT, InventoryLimits(max_entries=1))
    assert inventory_identity(sha, CONTEXT) != inventory_identity(sha, CONTEXT, InventoryLimits(max_seconds=5.0))
    assert inventory_identity(sha, CONTEXT) != inventory_identity(sha, InventoryContext(kb='KB7654321'))


@pytest.mark.parametrize('edit', ['identity', 'foreign-ref', 'line-span', 'count', 'missing-duplicate', 'hidden-partial'])
def test_inventory_contract_rejects_forged_ownership_and_counts(edit):
    body = example_inventory().model_dump(mode='json')
    if edit == 'identity':
        body['inventory_id'] = 'b' * 64
    elif edit == 'foreign-ref':
        body['entries'][0]['reference']['raw_sha256'] = 'c' * 64
    elif edit == 'line-span':
        body['entries'][0]['reference']['line_end'] = 1
    elif edit == 'count':
        body['accepted_count'] = 0
    elif edit == 'missing-duplicate':
        body['duplicate_count'] = 1
        body['entries'][0]['duplicate_of'] = 'd' * 64
    else:
        body['truncated'] = True
    with pytest.raises(ValidationError):
        CsvInventory.model_validate_json(json.dumps(body))


def test_inventory_contract_default_limits_are_immutable():
    with pytest.raises(ValidationError):
        DEFAULT_LIMITS.max_bytes = 1


def test_inventory_contract_parser_version_does_not_coerce_boolean_literal():
    body = example_inventory().model_dump()
    body['parser_version'] = True
    with pytest.raises(ValidationError):
        CsvInventory.model_validate(body)


@pytest.mark.parametrize('changes', [
    {'basename': '../a.dll'}, {'basename': 'A.dll'}, {'basename': 'readme.txt'},
    {'size_bytes': 1.5}, {'version_components': (1, 2, 3, True)}, {'version_components': None},
    {'architecture': 'unknown'}, {'product': 'hidden\u202eproduct'}, {'state': 'descriptive-only'},
])
def test_inventory_entry_cannot_assert_unsafe_or_unknown_eligible_metadata(changes):
    body = example_inventory().entries[0].model_dump()
    body.update(changes)
    with pytest.raises(ValidationError):
        InventoryEntry.model_validate(body)


@pytest.mark.parametrize('context', [{'kb': 'kb1234567'}, {'kb': '1234567'},
                                   {'kb': 'KB1234567', 'product': 'Example\u202eOS'}])
def test_inventory_contract_context_is_canonical_and_plain(context):
    with pytest.raises(ValidationError):
        InventoryContext(**context)


@pytest.mark.parametrize('encoding,bom,label', [
    ('utf-8', b'', 'utf-8'), ('utf-8', b'\xef\xbb\xbf', 'utf-8-sig'),
    ('utf-16-le', b'\xff\xfe', 'utf-16-le'), ('utf-16-be', b'\xfe\xff', 'utf-16-be'),
])
def test_supported_encoding_preserves_digest_and_unquoted_banner(encoding, bom, label):
    source = ('Windows synthetic, version 22H2 for x64-based Systems\n'
              'File name,File version,File size,Date,Time\n'
              'Example.DLL,10.0.9007199254740993.4,"9,007,199,254,740,993",03/04/26,01:02\n')
    raw = bom + source.encode(encoding)
    result = parse_inventory(raw, CONTEXT)
    entry, = result.entries
    assert result.encoding == label
    assert result.raw_sha256 == hashlib.sha256(raw).hexdigest()
    assert result.raw_size == len(raw)
    assert result.status == 'complete'
    assert result.sections[0].banner == 'Windows synthetic, version 22H2 for x64-based Systems'
    assert (entry.original_filename, entry.basename) == ('Example.DLL', 'example.dll')
    assert entry.version_components == (10, 0, 9007199254740993, 4)
    assert entry.size_bytes == 9007199254740993
    assert entry.architecture == 'amd64' and entry.architecture_basis == 'section'
    assert (entry.date_text, entry.time_text) == ('03/04/26', '01:02')
    assert entry.reference.logical_record == entry.reference.line_start == entry.reference.line_end == 3
    assert entry.product is None and entry.build is None  # Never inferred from banner/version.


@pytest.mark.parametrize('newline', ['\n', '\r\n'])
@pytest.mark.parametrize('name,delimiter', [('comma', ','), ('semicolon', ';'), ('tab', '\t')])
def test_explicit_delimiters_and_multiline_physical_spans(name, delimiter, newline):
    date = 'unknown' + newline + 'quoted "date",;\t spelling'
    raw = csv_bytes([
        ['File version', 'Date', 'File name', 'Architecture'],
        ['1.2.3.4', date, 'one.dll', 'amd64'],
        ['2.3.4.5', 'later', 'two.dll', 'aarch64'],
    ], delimiter=delimiter, newline=newline)
    result = parse_inventory(raw, InventoryContext(kb='KB1234567', delimiter=name))
    first, second = result.entries
    assert first.original_fields == ('1.2.3.4', date, 'one.dll', 'amd64')
    assert first.date_text == date
    assert (first.reference.logical_record, first.reference.line_start, first.reference.line_end) == (2, 2, 3)
    assert (second.reference.logical_record, second.reference.line_start, second.reference.line_end) == (3, 4, 4)
    assert result.records_scanned == 3 and len(result.sections) == 1
    assert second.architecture == 'arm64'
    if name != 'comma':
        assert_failure(raw)  # No delimiter sniffing.


def test_reordered_repeated_headers_and_blanks_retain_record_numbering():
    raw = (HEADER + '\nFirst.dll,1.2.3.4\n  FILE VERSION  , file NAME \n2.3.4.5,second.dll\n\n').encode()
    result = parse_inventory(raw, AMD64)
    assert [(entry.basename, entry.reference.logical_record) for entry in result.entries] == [
        ('first.dll', 3), ('second.dll', 5)]
    assert result.records_scanned == 6
    assert result.rejected_count == 0 and len(result.sections) == 1
    assert result.entries[1].version_components == (2, 3, 4, 5)


def test_header_words_in_data_remain_optional_metadata_or_unknown_versions():
    raw = csv_bytes([['File name', 'File version', 'Product'],
                     ['one.dll', 'File version', 'Desktop'], ['two.dll', '1.2.3.4', 'File name']])
    result = parse_inventory(raw, AMD64)
    assert len(result.sections) == 1 and result.accepted_count == 2
    assert result.entries[0].version_components is None
    assert result.entries[1].product == 'File name'


@pytest.mark.parametrize('header', [
    'File name,File name,File version', 'FILE NAME, file NAME ,FILE VERSION',
    'File name,Date', 'Date,File version', 'File name,File version,Mystery',
    'Nom du fichier,Version du fichier', 'Date,Time',
])
def test_missing_duplicate_and_undocumented_headers_fail(header):
    assert_failure((header + '\nexample.dll,1.2.3.4\n').encode())


@pytest.mark.parametrize('alias,expected', [('x64-based', 'amd64'), ('amd64 based', 'amd64'),
                                        ('arm64-based', 'arm64'), ('aarch64 based', 'arm64'),
                                        ('x86-based', 'x86'), ('i386 based', 'x86')])
def test_banner_architecture_aliases(alias, expected):
    result = parse_inventory((f'Synthetic Windows {alias}\n' + HEADER + 'a.dll,1.2.3.4\n').encode(), CONTEXT)
    assert result.entries[0].architecture == expected
    assert result.entries[0].architecture_basis == 'section'


def test_unknown_section_resets_architecture_and_explicit_context_can_supply_it():
    raw = ('Synthetic x64-based\n' + HEADER + 'one.dll,1.2.3.4\n'
           'Undocumented architecture\n' + HEADER + 'two.dll,2.3.4.5\n').encode()
    result = parse_inventory(raw, CONTEXT)
    assert [section.architecture for section in result.sections] == ['amd64', 'unknown']
    first, second = result.entries
    assert first.architecture == 'amd64'
    assert second.architecture == 'unknown' and second.architecture_basis == 'unknown'
    assert second.state == 'unknown' and result.status == 'partial'
    assert second.reference.section_index == 1
    asserted = parse_inventory(raw, AMD64)
    assert asserted.entries[1].architecture_basis == 'context'
    assert asserted.entries[1].architecture == 'amd64'
    assert 'UNKNOWN_SECTION' in [diag.code for diag in asserted.diagnostics]


def test_architecture_words_in_data_cannot_become_banners():
    raw = csv_bytes([
        ['File name', 'File version', 'Product'],
        ['a.dll', '1.2.3.4', 'Synthetic x86-based desktop'],
        ['not a basename', '1.2.3.4', 'Windows synthetic x64-based'],
    ])
    result = parse_inventory(raw, AMD64)
    assert len(result.sections) == 1
    assert len(result.entries) == 1 and result.entries[0].product == 'Synthetic x86-based desktop'
    assert result.rejected_count == 1 and result.diagnostics[0].code == 'INVALID_FILENAME'


@pytest.mark.parametrize('banner,column,context', [
    ('Synthetic x64-based', 'arm64', CONTEXT), ('Synthetic arm64-based', '', AMD64),
    ('Synthetic x64 and x86', '', CONTEXT), ('Synthetic x64-based', 'x64',
                                             InventoryContext(kb='KB1234567', architecture='x86')),
])
def test_conflicting_architecture_is_retained_and_ineligible(banner, column, context):
    raw = csv_bytes([[banner], ['File name', 'File version', 'Architecture'], ['a.dll', '1.2.3.4', column]])
    result = parse_inventory(raw, context)
    entry, = result.entries
    assert entry.architecture == 'unknown' and entry.architecture_basis == 'conflicted'
    assert entry.state == 'conflicted' and entry.conflict_group is not None
    assert 'ARCHITECTURE_CONFLICT' in entry.diagnostics
    assert result.conflict_count == 1


def test_unrecognized_explicit_architecture_is_not_silently_overridden():
    raw = b'Synthetic x64-based\nFile name,File version,Architecture\na.dll,1.2.3.4,mips\n'
    entry, = parse_inventory(raw, AMD64).entries
    assert entry.architecture == 'unknown' and entry.architecture_basis == 'unknown'
    assert entry.state == 'unknown'


def test_product_release_build_context_conflicts_preserve_source_spellings():
    context = InventoryContext(kb='KB1234567', architecture='amd64', product='Desktop', release='22H2', build='19045')
    raw = csv_bytes([['File name', 'File version', 'Product', 'Release', 'Build'],
                     ['a.dll', '1.2.3.4', 'Server', '23H2', '22631']])
    result = parse_inventory(raw, context)
    entry, = result.entries
    assert (entry.product, entry.release, entry.build) == ('Server', '23H2', '22631')
    assert set(entry.diagnostics) == {'PRODUCT_CONFLICT', 'RELEASE_CONFLICT', 'BUILD_CONFLICT'}
    assert entry.state == 'conflicted' and entry.conflict_group is not None
    assert result.context == context and result.conflict_count == 1


def test_invalid_optional_product_metadata_stays_unknown_and_raw_is_preserved():
    raw = csv_bytes([['File name', 'File version', 'Product'], ['a.dll', '1.2.3.4', 'raw\u202eproduct']])
    entry, = parse_inventory(raw, AMD64).entries
    assert entry.product is None and entry.original_fields[-1] == 'raw\u202eproduct'
    assert entry.state == 'unknown' and 'INVALID_METADATA' in entry.diagnostics


@pytest.mark.parametrize('original,expected', [
    ('0.0.0.0', (0, 0, 0, 0)), ('001.02.3.4', (1, 2, 3, 4)),
    (f'{UINT64_MAX}.1.2.3', (UINT64_MAX, 1, 2, 3)),
    ('1.2.3', None), ('1.2.3.4.5', None), ('1.2.3.4-beta', None), ('1.2.-3.4', None),
    ('1e3.2.3.4', None), ('１.2.3.4', None), (f'{UINT64_MAX + 1}.1.2.3', None), ('', None),
])
def test_versions_are_exact_and_unsupported_syntax_is_unknown(original, expected):
    raw = csv_bytes([['File name', 'File version'], ['a.dll', original]])
    entry, = parse_inventory(raw, AMD64).entries
    assert entry.original_version == original
    assert entry.version_components == expected
    assert ('UNKNOWN_VERSION' in entry.diagnostics) is (expected is None)


def test_long_zero_padding_does_not_hit_python_integer_conversion_limits():
    raw_version, raw_size = '0' * 5_000 + '1.2.3.4', '0' * 5_000 + '100'
    raw = csv_bytes([['File name', 'File version', 'File size'], ['a.dll', raw_version, raw_size]])
    entry, = parse_inventory(raw, AMD64).entries
    assert entry.version_components == (1, 2, 3, 4) and entry.size_bytes == 100
    assert entry.original_version == raw_version and entry.original_size == raw_size


@pytest.mark.parametrize('locale,original,expected', [
    ('en-US', '18,446,744,073,709,551,615', UINT64_MAX), ('de-DE', '9.007.199.254.740.993', 9007199254740993),
    ('invariant', str(UINT64_MAX), UINT64_MAX), ('en-US', '0', 0), ('en-US', '000123', 123),
    ('en-US', '1,23', None), ('en-US', '1.234', None), ('de-DE', '1,234', None),
    ('invariant', '1,234', None), ('en-US', '1234,567', None), ('en-US', '+123', None),
    ('en-US', '-123', None), ('en-US', '1e3', None), ('en-US', '1 234', None), ('en-US', '١٢٣', None),
    ('en-US', '1,234.50', None), ('en-US', str(UINT64_MAX + 1), None),
])
def test_sizes_use_precise_integers_and_explicit_locale(locale, original, expected):
    raw = csv_bytes([['File name', 'File version', 'File size'], ['a.dll', '1.2.3.4', original]])
    result = parse_inventory(raw, InventoryContext(kb='KB1234567', architecture='amd64', locale=locale))
    entry, = result.entries
    assert entry.original_size == original and entry.size_bytes == expected
    assert ('INVALID_SIZE' in entry.diagnostics) is (expected is None)


def test_duplicates_and_conflicts_keep_every_claim_without_selecting_a_version():
    raw = csv_bytes([
        ['File name', 'File version', 'File size', 'Architecture', 'Product'],
        ['A.DLL', '01.2.3.4', '1,234', 'amd64', 'Desktop'],
        ['a.dll', '1.2.3.4', '1234', 'x64', 'Desktop'],
        ['a.dll', '1.2.3.5', '1235', 'x64', 'Desktop'],
        ['a.dll', '9.2.3.4', '9999', 'arm64', 'Desktop'],
        ['a.dll', '9.2.3.4', '9999', 'amd64', 'Server'],
        ['a.dll', '9.2.3.4', '9999', 'amd64', 'desktop'],
    ])
    result = parse_inventory(raw, CONTEXT)
    assert result.accepted_count == 6 and result.duplicate_count == 1 and result.conflict_count == 3
    first, duplicate, conflict, *other_scopes = result.entries
    assert duplicate.duplicate_of == first.entry_id
    assert first.duplicate_of is conflict.duplicate_of is None
    assert first.conflict_group == duplicate.conflict_group == conflict.conflict_group
    assert first.conflict_group is not None
    assert all(entry.state == 'metadata-only' and entry.conflict_group is None for entry in other_scopes)
    assert len({entry.entry_id for entry in result.entries}) == 6


def test_absent_or_unknown_metadata_does_not_invent_a_conflict():
    raw = csv_bytes([['File name', 'File version', 'File size'],
                     ['a.dll', 'unknown', ''], ['a.dll', '1.2.3.4', '100']])
    result = parse_inventory(raw, AMD64)
    assert result.conflict_count == result.duplicate_count == 0
    assert [entry.state for entry in result.entries] == ['unknown', 'metadata-only']


@pytest.mark.parametrize('filename', [
    '../a.dll', '..\\a.dll', '/a.dll', 'a/b.dll', 'a\\b.dll', 'C:a.dll', '\\\\host\\share\\a.dll',
    'a.dll:stream', 'con.dll', 'LPT9.sys', 'COM1', '.', '..', '.hidden.dll', 'a.dll.', 'a.dll ',
    'a\t.dll', 'a\n.dll', 'a\x1b.dll', 'a\u202e.dll', '=1+1.dll', '+1.dll', '-1.dll', '@a.dll',
    'a' * 129 + '.dll',
])
def test_unsafe_filenames_are_rejected_rows(filename):
    raw = csv_bytes([['File name', 'File version'], [filename, '1.2.3.4'], ['safe.dll', '1.2.3.4']])
    result = parse_inventory(raw, AMD64)
    assert result.rejected_count == 1 and result.accepted_count == 1
    assert result.entries[0].basename == 'safe.dll'
    assert result.diagnostics[0].code == 'INVALID_FILENAME'
    assert result.diagnostics[0].message == 'The filename is unsafe or is not a supported plain basename.'


def test_safe_non_pe_rows_are_descriptive_only():
    raw = csv_bytes([['File name', 'File version'], ['Readme.txt', '1.2.3.4'], ['LICENSE', '1.2.3.4']])
    result = parse_inventory(raw, AMD64)
    assert [entry.basename for entry in result.entries] == ['readme.txt', 'license']
    assert all(entry.state == 'descriptive-only' for entry in result.entries)


def test_wrong_width_is_counted_without_discarding_following_valid_data():
    result = parse_inventory((HEADER + 'a.dll\nb.dll,1.2.3.4,extra\ngood.dll,1.2.3.4\n').encode(), AMD64)
    assert result.rejected_count == 2 and result.accepted_count == 1
    assert result.records_scanned == 4 and result.status == 'partial'
    assert {diag.code for diag in result.diagnostics} == {'COLUMN_COUNT'}


@pytest.mark.parametrize('raw', [
    b'\xffbad', b'\xff\xfe\x00\x00', b'\x00\x00\xfe\xff',
    HEADER.encode('utf-16-le'), HEADER.encode('utf-16-be'), b'\xff\xfe\x00',
    b'File name,File version\na\x00.dll,1.2.3.4\n',
])
def test_invalid_and_unsupported_encodings_are_fatal(raw):
    assert_failure(raw)


@pytest.mark.parametrize('suffix', [
    '"unterminated,1.2.3.4', 'a".dll,1.2.3.4\n', '"a.dll" tail,1.2.3.4\n',
    '"a.dll"\t,1.2.3.4\n', 'a.dll,1.2.3.4\r', '"a\rb.dll",1.2.3.4\n',
])
def test_malformed_quotes_and_line_endings_are_fatal_without_echo(suffix):
    failure = assert_failure((HEADER + suffix).encode())
    assert suffix not in failure.message


def test_default_budgets_match_the_contract():
    assert DEFAULT_LIMITS.model_dump() == {
        'max_bytes': MAX_BYTES, 'max_text_chars': MAX_BYTES, 'max_field_chars': MAX_FIELD_CHARS,
        'max_record_chars': MAX_RECORD_CHARS, 'max_columns': MAX_COLUMNS, 'max_records': MAX_RECORDS,
        'max_entries': MAX_ENTRIES, 'max_diagnostics': MAX_DIAGNOSTICS,
        'max_sections': MAX_SECTIONS, 'max_seconds': 10.0,
    }


@pytest.mark.parametrize('raw,limits', [
    (b'\xff' * 9, InventoryLimits(max_bytes=8)),
    ((HEADER + 'a.dll,1.2.3.4\n').encode(), InventoryLimits(max_text_chars=10)),
    ((HEADER + 'a' * 13 + ',1.2.3.4\n').encode(), InventoryLimits(max_field_chars=12)),
    ((HEADER + 'a' * 30 + '.dll,1.2.3.4\n').encode(), InventoryLimits(max_record_chars=30)),
    ((HEADER + 'a.dll,1.2.3.4,extra\n').encode(), InventoryLimits(max_columns=2)),
    (('First x64-based\n' + HEADER + 'Second x64-based\n' + HEADER).encode(), InventoryLimits(max_sections=1)),
])
def test_hard_resource_limits_fail_before_publication(raw, limits):
    assert_failure(raw, code='PT-KBC-LIMIT', limits=limits)


def test_default_byte_field_and_record_limits_are_enforced():
    assert_failure(b'\xff' * (MAX_BYTES + 1), code='PT-KBC-LIMIT')
    assert_failure((HEADER + 'a' * (MAX_FIELD_CHARS + 1)).encode(), code='PT-KBC-LIMIT')
    header = 'File name,File version,Date,Time,File size\n'
    oversized_record = ','.join('a' * MAX_FIELD_CHARS for _ in range(5))
    assert_failure((header + oversized_record).encode(), code='PT-KBC-LIMIT')
    assert_failure((HEADER + ','.join(['x'] * (MAX_COLUMNS + 1))).encode(), code='PT-KBC-LIMIT')
    sections = ('Synthetic x64-based\n' + HEADER) * (MAX_SECTIONS + 1)
    assert_failure(sections.encode(), code='PT-KBC-LIMIT')


@pytest.mark.parametrize('limits,expected,scanned,code', [
    (InventoryLimits(max_entries=1), 1, 2, 'RESULT_LIMIT'),
    (InventoryLimits(max_records=1), 0, 1, 'RECORD_LIMIT'),
    (InventoryLimits(max_records=2), 1, 2, 'RECORD_LIMIT'),
])
def test_count_budgets_return_explicit_partial_results(limits, expected, scanned, code):
    result = parse_inventory((HEADER + 'a.dll,1.2.3.4\nb.dll,1.2.3.4\n').encode(), AMD64, limits=limits)
    assert result.accepted_count == expected and result.records_scanned == scanned
    assert result.truncated and result.status == 'partial'
    assert result.diagnostics[-1].code == code
    assert result.limits == limits


def test_exact_count_limit_at_end_is_complete_and_unseen_tail_is_not_claimed_parsed():
    limits = InventoryLimits(max_entries=1, max_records=2)
    raw = (HEADER + 'a.dll,1.2.3.4\n').encode()
    complete = parse_inventory(raw, AMD64, limits=limits)
    assert complete.status == 'complete' and not complete.truncated
    partial = parse_inventory(raw + b'"malformed unseen tail', AMD64, limits=limits)
    assert partial.status == 'partial' and partial.truncated
    assert partial.accepted_count == 1 and partial.records_scanned == 2
    assert partial.raw_sha256 == hashlib.sha256(raw + b'"malformed unseen tail').hexdigest()


def test_default_entry_and_logical_record_caps_are_enforced():
    raw = (HEADER + ''.join(f'a{index}.dll,1.2.3.4\n' for index in range(MAX_ENTRIES + 1))).encode()
    result = parse_inventory(raw, AMD64)
    assert result.accepted_count == MAX_ENTRIES and result.truncated
    assert result.diagnostics[-1].code == 'RESULT_LIMIT'
    blank_records = (HEADER + '\n' * MAX_RECORDS + 'a.dll,1.2.3.4\n').encode()
    result = parse_inventory(blank_records, AMD64)
    assert result.records_scanned == MAX_RECORDS and result.truncated
    assert result.diagnostics[-1].code == 'RECORD_LIMIT'


def test_diagnostic_omissions_are_counted_and_entry_codes_remain_visible():
    raw = csv_bytes([['File name', 'File version', 'File size'], ['a.dll', 'bad', '1,23'], ['b.dll', 'bad', '-1']])
    result = parse_inventory(raw, CONTEXT, limits=InventoryLimits(max_diagnostics=1))
    assert len(result.diagnostics) == 1 and result.diagnostics_omitted == 5
    assert all(set(entry.diagnostics) == {'UNKNOWN_ARCHITECTURE', 'UNKNOWN_VERSION', 'INVALID_SIZE'}
               for entry in result.entries)
    assert result.status == 'partial'


def test_default_diagnostics_cap_counts_every_omission():
    raw = (HEADER + ''.join(f'a{index}.dll,unknown\n' for index in range(MAX_DIAGNOSTICS + 1))).encode()
    result = parse_inventory(raw, AMD64)
    assert len(result.diagnostics) == MAX_DIAGNOSTICS and result.diagnostics_omitted == 1
    assert result.accepted_count == MAX_DIAGNOSTICS + 1 and result.status == 'partial'


def test_cancel_before_decode_and_during_a_long_quoted_field():
    cancelled = threading.Event()
    cancelled.set()
    assert_failure(b'\xff', code='PT-KBC-CANCEL', cancel=cancelled)

    class CancelAfterChecks:
        def __init__(self):
            self.calls = 0

        def is_set(self):
            self.calls += 1
            return self.calls > 6

    token = CancelAfterChecks()
    raw = csv_bytes([['File name', 'File version', 'Date'], ['a.dll', '1.2.3.4', 'x' * 30_000]])
    assert_failure(raw, code='PT-KBC-CANCEL', cancel=token)
    assert token.calls == 7


def test_time_budget_uses_cooperative_checks_without_partial_publication(monkeypatch):
    ticks = itertools.count()
    monkeypatch.setattr(inventory_csv, 'time', SimpleNamespace(monotonic=lambda: next(ticks)))
    assert_failure((HEADER + 'a.dll,1.2.3.4\n').encode(), code='PT-KBC-LIMIT',
                   limits=InventoryLimits(max_seconds=2.0))


@pytest.mark.parametrize('raw,context,kwargs', [
    ('not bytes', AMD64, {}), (bytearray(HEADER.encode()), AMD64, {}),
    (HEADER.encode(), {'kb': 'KB1234567'}, {}), (HEADER.encode(), AMD64, {'limits': {}}),
    (HEADER.encode(), AMD64, {'cancel': object()}),
    (HEADER.encode(), AMD64, {'limits': DEFAULT_LIMITS.model_copy(update={'max_entries': 50_001})}),
])
def test_invalid_api_arguments_fail_with_typed_input_error(raw, context, kwargs):
    assert_failure(raw, code='PT-KBC-INPUT', context=context, **kwargs)


def test_determinism_includes_raw_context_and_complete_limits():
    raw = (HEADER + 'a.dll,1.2.3.4\n').encode()
    one = parse_inventory(raw, AMD64)
    assert parse_inventory(raw, AMD64) == one
    assert CsvInventory.model_validate_json(one.model_dump_json()) == one
    assert parse_inventory(b'\xef\xbb\xbf' + raw, AMD64).inventory_id != one.inventory_id
    assert parse_inventory(raw, CONTEXT).inventory_id != one.inventory_id
    assert parse_inventory(raw, AMD64, limits=InventoryLimits(max_seconds=5.0)).inventory_id != one.inventory_id


def test_parser_has_no_network_process_or_filesystem_io_and_no_global_csv_mutation(monkeypatch):
    import builtins
    import csv
    import os

    raw = (HEADER + 'a.dll,1.2.3.4\n').encode()
    prior_limit = csv.field_size_limit()

    def forbidden(*args, **kwargs):
        raise AssertionError('the pure parser attempted an external side effect')

    with monkeypatch.context() as guard:
        for owner, name in [(socket, 'socket'), (socket, 'create_connection'), (socket, 'getaddrinfo'),
                            (urllib.request, 'urlopen'), (subprocess, 'Popen'), (os, 'system'),
                            (os, 'open'), (builtins, 'open'), (Path, 'open'), (csv, 'field_size_limit')]:
            guard.setattr(owner, name, forbidden)
        assert parse_inventory(raw, AMD64).accepted_count == 1
    assert csv.field_size_limit() == prior_limit


@settings(max_examples=100, deadline=None, derandomize=True)
@given(st.binary(max_size=4_096))
def test_arbitrary_bounded_bytes_produce_typed_failure_or_bounded_records(raw):
    limits = InventoryLimits(max_bytes=4_096, max_text_chars=4_096, max_field_chars=128,
                             max_record_chars=256, max_columns=8, max_records=30,
                             max_entries=10, max_diagnostics=5, max_sections=5)
    try:
        result = parse_inventory(raw, AMD64, limits=limits)
    except SourceError as exc:
        assert exc.code in {'PT-KBC-SOURCE', 'PT-KBC-LIMIT'}
    else:
        assert len(result.entries) <= 10 and len(result.sections) <= 5 and len(result.diagnostics) <= 5
        assert result.records_scanned <= 30
        assert parse_inventory(raw, AMD64, limits=limits) == result


@settings(max_examples=60, deadline=None, derandomize=True)
@given(st.lists(st.text(alphabet='abcXYZ0123,;"\n\t ', max_size=80), min_size=1, max_size=10))
def test_quoted_fields_roundtrip_and_physical_spans_match_independent_csv_writer(dates):
    raw = csv_bytes([['File name', 'File version', 'Date']]
                    + [[f'f{index}.dll', '1.2.3.4', date] for index, date in enumerate(dates)])
    result = parse_inventory(raw, AMD64)
    physical_line = 2
    assert result.accepted_count == len(dates)
    for index, (date, entry) in enumerate(zip(dates, result.entries, strict=True)):
        assert entry.date_text == date
        assert entry.reference.logical_record == index + 2
        assert entry.reference.line_start == physical_line
        assert entry.reference.line_end == physical_line + date.count('\n')
        physical_line += date.count('\n') + 1
