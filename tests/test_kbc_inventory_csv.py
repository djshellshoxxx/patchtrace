"""PW-01 authored synthetic CSV mechanics; no live Microsoft compatibility claim."""
from __future__ import annotations

import hashlib
import json

import pytest
from pydantic import ValidationError

from patchtrace.kbcorrelation.inventory_contracts import (
    DEFAULT_LIMITS,
    CsvInventory,
    CsvRecordRef,
    InventoryContext,
    InventoryEntry,
    InventoryLimits,
    InventorySection,
    entry_identity,
    inventory_identity,
)

CONTEXT = InventoryContext(kb='KB1234567')


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


@pytest.mark.parametrize('context', [{'kb': 'kb1234567'}, {'kb': '1234567'},
                                   {'kb': 'KB1234567', 'product': 'Example\u202eOS'}])
def test_inventory_contract_context_is_canonical_and_plain(context):
    with pytest.raises(ValidationError):
        InventoryContext(**context)
