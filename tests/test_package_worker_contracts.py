"""Strict frozen worker metadata cannot manufacture native qualification."""
from __future__ import annotations

import importlib
import json

import pytest
from pydantic import ValidationError

from patchtrace.acquisition.contracts import AcquisitionError
from tests.package_support import source
from tests.package_worker_support import api, binding, changed_raw, issue, parent, raw, success


def test_records_roundtrip_are_frozen_and_bound_to_full_capture():
    owner, clock = parent()
    grant = issue(owner)
    receipt = success(grant, clock)
    for record in (binding(), grant, receipt):
        assert api().parse_worker_record(type(record), raw(record)) == record
        assert record.model_config['frozen'] and record.model_config['strict']
        with pytest.raises(ValidationError):
            record.arbitrary_authority = True
    assert grant.grant_id == api().worker_grant_identity(grant.model_dump(mode='python'))
    assert receipt.binding.source == source()
    assert receipt.grant_id == grant.grant_id


@pytest.mark.parametrize('field', ['operation_id', 'request_id', 'attempt_id'])
@pytest.mark.parametrize('value', ['', 'A' * 64, 'a' * 63, 'a' * 64 + '\n', True, 12])
def test_binding_ids_are_exact_canonical_strings(field, value):
    with pytest.raises(ValidationError):
        binding(**{field: value})


@pytest.mark.parametrize('kind', ['grant', 'receipt'])
@pytest.mark.parametrize('value', [True, 1.0, '1', 0, 2])
def test_worker_versions_do_not_coerce(kind, value):
    owner, clock = parent()
    grant = issue(owner)
    record = grant if kind == 'grant' else success(grant, clock)
    body = changed_raw(record, lambda x: x.update(parser_version=value))
    with pytest.raises(AcquisitionError):
        api().parse_worker_record(type(record), body)


@pytest.mark.parametrize('change', [
    lambda x: x.update(grant_nonce='d' * 64),
    lambda x: x['binding'].update(operation_id='d' * 64),
    lambda x: x['binding'].update(request_id='d' * 64),
    lambda x: x['binding'].update(attempt_id='d' * 64),
    lambda x: x['binding']['source'].update(sha256='d' * 64),
    lambda x: x['binding']['source']['file_identity'].update(file_id='2' * 32),
    lambda x: x['binding']['source'].update(source_claims=['a different manual claim']),
    lambda x: x['limits'].update(max_entries=42),
    lambda x: x['baseline'].update(callbacks=2),
    lambda x: x.update(issued_ns=x['issued_ns'] + 1),
])
def test_grant_digest_binds_every_captured_identity_and_allowance(change):
    owner, _ = parent()
    grant = issue(owner)
    with pytest.raises(AcquisitionError):
        api().parse_worker_record(type(grant), changed_raw(grant, change))


@pytest.mark.parametrize('change', [
    lambda x: x.update(deadline_ns=x['deadline_ns'] + 1),
    lambda x: x.update(issued_ns=x['started_ns'] - 1),
    lambda x: x.update(issued_ns=x['deadline_ns']),
    lambda x: x['baseline'].update(elapsed_ns=1),
    lambda x: x['baseline'].update(live_allocated_bytes=1, peak_allocated_bytes=1),
    lambda x: x['baseline'].update(reserved_output_bytes=1),
    lambda x: x['baseline'].update(failed=True, failure_code='PT-ACQ-VERIFY'),
    lambda x: x['limits'].update(max_source_bytes=127),
    lambda x: x['baseline'].update(callbacks=2_000_001),
])
def test_recomputed_digest_does_not_make_inconsistent_grant_valid(change):
    owner, _ = parent()
    grant = issue(owner)
    value = json.loads(raw(grant))
    change(value)
    value['grant_id'] = api().worker_grant_identity(value)
    with pytest.raises(AcquisitionError):
        api().parse_worker_record(type(grant), json.dumps(value).encode())


@pytest.mark.parametrize('field', ['native_qualified', 'handle', 'path', 'decoder_passed'])
def test_extra_fields_cannot_add_native_authority(field):
    owner, clock = parent()
    grant = issue(owner)
    receipt = success(grant, clock)
    for record in (grant, receipt):
        with pytest.raises(AcquisitionError):
            api().parse_worker_record(type(record), changed_raw(record, lambda x: x.update({field: True})))


@pytest.mark.parametrize('token', ['NaN', 'Infinity', '-Infinity', '1e999', '-1e999'])
def test_nonfinite_tokens_refuse_before_record_validation(token):
    with pytest.raises(AcquisitionError):
        api().parse_worker_record(api().PackageWorkerReceipt, ('{"observed_ns":' + token + '}').encode())


@pytest.mark.parametrize('body', [b'{"contract":1,"contract":1}', b'[]', b'null', b'{', b'\xff'])
def test_malformed_or_duplicate_wire_values_refuse(body):
    with pytest.raises(AcquisitionError):
        api().parse_worker_record(api().PackageWorkerGrant, body)


def test_worker_wire_cap_and_captured_lower_cap_include_whitespace():
    owner, _ = parent(max_json_bytes=4096)
    grant = issue(owner)
    for body in (raw(grant) + b' ' * 4096, b' ' * (api().WORKER_MAX_JSON + 1)):
        with pytest.raises(AcquisitionError) as error:
            api().parse_worker_record(type(grant), body)
        assert error.value.code == 'PT-ACQ-LIMIT'
    tiny, _ = parent(max_json_bytes=1)
    with pytest.raises(AcquisitionError):
        issue(tiny)
    assert tiny.snapshot().failed and not tiny.worker_pending


@pytest.mark.parametrize('field', ['observed_ns', 'open_entries', 'pending_outputs'])
@pytest.mark.parametrize('value', [True, -1, 1.5, '1', 2**64])
def test_receipt_counts_are_strict_bounded_integers(field, value):
    owner, clock = parent()
    grant = issue(owner)
    receipt = success(grant, clock)
    with pytest.raises(AcquisitionError):
        api().parse_worker_record(type(receipt), changed_raw(receipt, lambda x: x.update({field: value})))


@pytest.mark.parametrize('change', [
    lambda x: x.update(open_entries=1),
    lambda x: x.update(pending_outputs=1),
    lambda x: x['usage'].update(live_allocated_bytes=1, peak_allocated_bytes=1),
    lambda x: x['usage'].update(reserved_output_bytes=4),
    lambda x: x.update(status='failed'),
])
def test_complete_receipt_cannot_hide_pending_or_failed_state(change):
    owner, clock = parent()
    grant = issue(owner)
    receipt = success(grant, clock)
    with pytest.raises(AcquisitionError):
        api().parse_worker_record(type(receipt), changed_raw(receipt, change))


def test_unsafe_constructed_binding_is_revalidated_at_grant_admission():
    owner, _ = parent()
    malformed = binding().model_copy(update={'operation_id': True})
    with pytest.raises(AcquisitionError):
        owner.issue_worker(malformed)
    assert owner.snapshot().failed and not owner.worker_pending


def test_worker_schemas_are_additive_registered_and_not_capability_schemas():
    generator = importlib.import_module('tools.generate_package_schemas')
    schemas = generator.render()
    required = {'PackageWorkerBinding.json', 'PackageWorkerGrant.json', 'PackageWorkerReceipt.json'}
    assert required <= schemas.keys()
    for name in required:
        document = json.loads(schemas[name])
        assert document['additionalProperties'] is False
        assert 'native_qualified' not in document['properties']
