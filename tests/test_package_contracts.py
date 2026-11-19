"""PW-02 ownership and observation controls. All native-looking values are authored."""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from patchtrace.acquisition.contracts import AcquisitionError
from tests.package_support import A, B, C, contracts, decoder, inventory, part, selection, source


@pytest.mark.parametrize('field,value', [('max_entries', True), ('max_seconds', 1.0),
                                       ('max_depth', '4'), ('max_source_bytes', 2**31),
                                       ('max_expanded_bytes', 8 * 2**30 + 1),
                                       ('max_entry_bytes', 2**30 + 1), ('max_callbacks', 2_000_001),
                                       ('max_live_allocation_bytes', 512 * 2**20 + 1),
                                       ('max_process_bytes', 2**30 + 1), ('max_seconds', 1801),
                                       ('max_name_bytes', 1025), ('max_depth', -1),
                                       ('max_json_bytes', 0), ('unexpected', 1)])
def test_limits_are_lowerable_strict_finite_and_bounded(field, value):
    with pytest.raises(ValidationError):
        contracts().PackageLimits(**{field: value})


def test_source_identity_is_content_based_but_inventory_keeps_capture_identity():
    c = contracts()
    first = source()
    second = source(display_name='renamed.cab', file_identity=c.PackageFileIdentity(
        volume_serial=9, file_id='2' * 32, size=128, last_write_ticks=11))
    assert first.source_id == second.source_id
    assert inventory(source=first).inventory_id != inventory(source=second).inventory_id
    assert first.signature_state == 'signature-unknown'
    with pytest.raises(ValidationError):
        source(signature_state='catalog-signature-valid')
    with pytest.raises(ValidationError):
        source(size=129)
    with pytest.raises(ValidationError):
        source(display_name='C:/secret/authored.cab')


def test_record_is_frozen_and_unknown_fields_refuse():
    limits = contracts().PackageLimits()
    with pytest.raises(ValidationError):
        limits.max_entries = 1
    with pytest.raises(ValidationError):
        contracts().PackageFileIdentity(volume_serial=1, file_id='0' * 32, size=1, last_write_ticks=1)


@pytest.mark.parametrize('change', [{'observed_sha256': B}, {'observed_size': 4},
                                   {'rehash_sha256': B}, {'machine': 34404}])
def test_header_only_cannot_invent_observed_bytes_or_pe_identity(change):
    with pytest.raises(ValidationError):
        part(**change)


@pytest.mark.parametrize('change', [{'observed_size': 3}, {'observed_sha256': None},
                                   {'rehash_sha256': C}])
def test_reverified_record_requires_exact_size_and_matching_independent_hash(change):
    with pytest.raises(ValidationError):
        part(state='reverified', basis='content', **change)


def test_member_identity_binds_raw_name_ordinal_parent_and_ancestry():
    c = contracts()
    first = part()
    alternatives = [part(name=b'Sample.dll'), part(ordinal=2), part(container=B), part(ancestors=(C,))]
    assert len({first.member_id, *(x.member_id for x in alternatives)}) == 5
    bad = first.model_dump(mode='python') | {'member_id': C}
    with pytest.raises(ValidationError):
        c.PackagePart(**bad)
    with pytest.raises(ValidationError):
        c.PackagePart(**(first.model_dump(mode='python') | {'logical_path': 'different.dll'}))


def test_completed_headers_do_not_claim_complete_payload_verification():
    item = part()
    inv = inventory(parts=(item,))
    assert inv.complete and inv.parts[0].observed_sha256 is None
    assert inv.parts[0].compressed_size is None
    with pytest.raises(AcquisitionError):
        contracts().select_member(inv, selection(inv, item))


@pytest.mark.parametrize('field,value', [('inventory_id', C), ('parser_version', True),
                                       ('contract', 'local-package/2')])
def test_saved_inventory_cannot_change_its_identity_or_version(field, value):
    inv = inventory()
    with pytest.raises(ValidationError):
        contracts().PackageInventory(**(inv.model_dump(mode='python') | {field: value}))


@pytest.mark.parametrize('items', [lambda: (part(), part(ordinal=2)),
                                 lambda: (part(), part(name=b'other.dll')),
                                 lambda: (part(), part(name=b'SAMPLE.DLL', ordinal=2)),
                                 lambda: (part(name=b'a'), part(name=b'a/b.dll', ordinal=2))])
def test_duplicate_name_ordinal_or_prefix_does_not_enter_inventory(items):
    with pytest.raises((ValidationError, AcquisitionError)):
        inventory(parts=items())


def test_foreign_part_or_disconnected_container_is_refused():
    c = contracts()
    with pytest.raises(ValidationError):
        inventory(parts=(part(container=B),))
    root = c.PackageContainer(container_sha256=A, ancestors=(), size=128, entry_count=0, complete=True)
    child = c.PackageContainer(container_sha256=B, ancestors=(C,), size=4, entry_count=0, complete=True)
    with pytest.raises(ValidationError):
        inventory(containers=(root, child), mode='recursive')


def test_recursive_complete_requires_reverified_nested_container_ownership():
    c = contracts()
    nested = part(name=b'inner.cab', kind='cab', basis='content', state='reverified')
    leaf = part(container=B, ancestors=(nested.member_id,))
    scopes = (c.PackageContainer(container_sha256=A, ancestors=(), size=128, entry_count=1, complete=True),
              c.PackageContainer(container_sha256=B, ancestors=(nested.member_id,), size=4,
                                 entry_count=1, complete=True))
    inv = inventory(parts=(nested, leaf), containers=scopes, mode='recursive')
    assert inv.complete
    with pytest.raises(ValidationError):
        inventory(parts=(nested,), mode='recursive', complete=True)
    incomplete = inventory(parts=(nested,), mode='recursive', complete=False)
    assert not incomplete.complete
    with pytest.raises(ValidationError):
        inventory(parts=(nested, leaf), containers=(scopes[0], scopes[1].model_copy(update={'size': 3})),
                  mode='recursive')


@pytest.mark.parametrize('change', [{'inventory_id': C}, {'source_sha256': C}, {'member_id': C},
                                   {'ancestors': (C,)}, {'expected_basename': 'other.dll'},
                                   {'expected_sha256': C}])
def test_selection_refuses_foreign_receipt_or_expected_identity(change):
    item = part(state='reverified', basis='content')
    inv = inventory(parts=(item,), mode='recursive')
    with pytest.raises(AcquisitionError):
        contracts().select_member(inv, selection(inv, item, **change))


@pytest.mark.parametrize('state,kind,basis,machine', [('decoded', 'fullfile', 'content', 34404),
                                                   ('reverified', 'delta', 'content', None),
                                                   ('reverified', 'psfx', 'content', None),
                                                   ('reverified', 'fullfile', 'filename-hint', None),
                                                   ('reverified', 'fullfile', 'content', 332)])
def test_non_full_or_unverified_content_is_never_selected(state, kind, basis, machine):
    item = part(state=state, kind=kind, basis=basis, machine=machine)
    inv = inventory(parts=(item,), mode='recursive')
    with pytest.raises(AcquisitionError):
        contracts().select_member(inv, selection(inv, item))


def test_valid_full_pe_selection_keeps_manual_authenticity_uncertainty():
    item = part(state='reverified', basis='content', name=b'SAMPLE.DLL')
    inv = inventory(parts=(item,), mode='recursive')
    selected = contracts().select_member(inv, selection(inv, item, expected_sha256=B))
    assert selected is item or selected == item
    assert inv.source.signature_state == selected.signature_state == 'signature-unknown'
    assert inv.decoder.qualification == 'pending'


@pytest.mark.parametrize('raw', [b'{"max_entries":1,"max_entries":2}', b'{"max_entries":NaN}',
                               b'{"max_seconds":1e999}', b'{"max_seconds":-1e999}', b'\xff',
                               b'[]', b'{"max_entries":true}', b'{"unknown":1}'])
def test_strict_json_refuses_duplicate_nonfinite_malformed_or_unknown_evidence(raw):
    with pytest.raises(AcquisitionError):
        contracts().parse_record(contracts().PackageLimits, raw)


def test_json_round_trip_preserves_ids_and_byte_limit_is_enforced_first():
    c = contracts()
    inv = inventory(parts=(part(),))
    raw = inv.model_dump_json().encode()
    parsed = c.parse_record(c.PackageInventory, raw)
    assert parsed == inv
    with pytest.raises(AcquisitionError) as error:
        c.parse_record(c.PackageInventory, raw, max_bytes=len(raw) - 1)
    assert error.value.code == 'PT-ACQ-LIMIT'
    changed = json.loads(raw)
    changed['limits']['max_entries'] -= 1
    with pytest.raises(AcquisitionError):
        c.parse_record(c.PackageInventory, json.dumps(changed).encode())


def test_available_capability_requires_matching_native_probe_and_platform():
    c = contracts()
    with pytest.raises(ValidationError):
        c.PackageCapability(platform='linux', architecture='amd64', status='available', decoder=decoder())
    with pytest.raises(ValidationError):
        c.PackageCapability(platform='windows', architecture='amd64', status='available', decoder=None)
    cap = c.PackageCapability(platform='windows', architecture='amd64', status='available', decoder=decoder())
    assert cap.decoder.qualification == 'pending'
