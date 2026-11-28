"""Independent envelope presence and feasible serial-entry accounting boundaries."""
from __future__ import annotations

import json

import pytest

from patchtrace.acquisition.contracts import AcquisitionError
from tests.package_support import D
from tests.package_worker_support import api, binding, changed_raw, emit, issue, parent, raw, success, worker


@pytest.mark.parametrize('kind', ['grant', 'receipt'])
@pytest.mark.parametrize('field', ['contract', 'parser_version'])
def test_wire_envelope_fields_are_required_instead_of_inferred(kind, field):
    owner, clock = parent()
    grant = issue(owner)
    record = grant if kind == 'grant' else success(grant, clock)
    with pytest.raises(AcquisitionError):
        api().parse_worker_record(type(record), changed_raw(record, lambda x: x.pop(field)))


@pytest.mark.parametrize('change', [
    lambda x: x['baseline'].update(callbacks=0),
    lambda x: x['baseline'].update(reserved_output_bytes=1, confirmed_output_bytes=1),
])
def test_grant_baseline_requires_issuance_work_and_possible_entry_capacity(change):
    owner, _ = parent()
    grant = issue(owner)
    value = json.loads(raw(grant))
    change(value)
    value['grant_id'] = api().worker_grant_identity(value)
    with pytest.raises(AcquisitionError):
        api().parse_worker_record(type(grant), json.dumps(value).encode())


def test_new_output_cannot_exceed_new_entries_times_captured_entry_limit():
    owner, clock = parent(max_entry_bytes=3, max_expanded_bytes=10)
    grant = issue(owner)
    receipt = success(grant, clock)
    body = changed_raw(receipt, lambda x: x['usage'].update(reserved_output_bytes=4, confirmed_output_bytes=4))
    with pytest.raises(AcquisitionError):
        owner.reconcile_worker(grant, body)
    assert owner.snapshot().reserved_output_bytes == 0 and owner.worker_usage_unknown


def test_closed_baseline_entry_cannot_supply_capacity_to_new_worker_output():
    owner, clock = parent()
    emit(owner, 3)
    grant = issue(owner)
    receipt = worker(grant, clock).worker_receipt()
    body = changed_raw(receipt, lambda x: x['usage'].update(reserved_output_bytes=4, confirmed_output_bytes=4))
    with pytest.raises(AcquisitionError):
        owner.reconcile_worker(grant, body)
    assert owner.snapshot().reserved_output_bytes == 3 and owner.worker_usage_unknown


def test_failed_receipt_cannot_reopen_an_entry_from_the_quiescent_baseline():
    owner, clock = parent()
    emit(owner, 3)
    grant = issue(owner)
    receipt = worker(grant, clock).worker_receipt()

    def change(value):
        value.update(status='failed', open_entries=1)
        value['usage'].update(failed=True, failure_code='PT-ACQ-VERIFY')

    with pytest.raises(AcquisitionError):
        owner.reconcile_worker(grant, changed_raw(receipt, change))
    assert owner.worker_usage_unknown  # Contradictory failed usage was refused, not credited as known.


def test_private_capture_survives_unsafe_mutation_of_public_grant_object():
    owner, clock = parent()
    grant = issue(owner)
    receipt = success(grant, clock)
    object.__setattr__(grant, 'binding', binding(operation_id=D))
    owner.reconcile_worker(grant, raw(receipt))
    assert owner.snapshot().reserved_output_bytes == 3 and not owner.snapshot().failed
