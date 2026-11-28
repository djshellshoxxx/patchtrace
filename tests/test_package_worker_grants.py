"""Serial grant ownership and cumulative usage survive success, refusal and loss."""
from __future__ import annotations

import threading

import pytest

from patchtrace.acquisition.contracts import AcquisitionError
from tests.package_support import D
from tests.package_worker_support import (
    changed_raw,
    emit,
    issue,
    parent,
    raw,
    success,
    worker,
)


def known(usage):
    return usage.model_dump(exclude={'failed', 'failure_code', 'elapsed_ns'})


def test_two_sides_nested_and_parent_hash_share_one_original_allowance():
    owner, clock = parent(max_expanded_bytes=8, max_seconds=3)
    owner.charge_hash(128)
    original_deadline = owner.deadline_ns
    first = issue(owner)
    clock.now += 1_000_000_000
    child = worker(first, clock)
    assert child.deadline_ns == original_deadline
    assert child.snapshot().hashed_input_bytes == 128
    emit(child, 3)
    child.begin_container(size=32, depth=1)
    child.charge_hash(32)
    owner.reconcile_worker(first, raw(child.worker_receipt()))
    owner.charge_hash(3)
    second = issue(owner, request_id=D, attempt_id='e' * 64)
    child = worker(second, clock)
    assert child.snapshot().reserved_output_bytes == 3
    emit(child, 5)
    owner.reconcile_worker(second, raw(child.worker_receipt()))
    assert owner.snapshot().reserved_output_bytes == owner.snapshot().confirmed_output_bytes == 8
    assert owner.snapshot().hashed_input_bytes == 163
    assert owner.snapshot().entries == 2 and owner.snapshot().containers == 3
    assert owner.deadline_ns == original_deadline and owner.remaining_seconds() == 2
    with pytest.raises(AcquisitionError):
        owner.reserve_output(owner.begin_entry(1), 1)


def test_identical_parent_captures_get_distinct_wire_grants_and_foreign_token_refuses():
    first, clock = parent()
    second, _ = parent(clock=clock)
    a, b = issue(first), issue(second)
    assert a.grant_nonce != b.grant_nonce and a.grant_id != b.grant_id
    receipt = success(a, clock)
    with pytest.raises(AcquisitionError):
        second.reconcile_worker(a, raw(receipt))
    assert second.worker_usage_unknown and second.snapshot().reserved_output_bytes == 0
    first.reconcile_worker(a, raw(receipt))
    assert first.snapshot().reserved_output_bytes == 3


def test_copied_parent_grant_is_not_the_active_control_token():
    owner, clock = parent()
    grant = issue(owner)
    with pytest.raises(AcquisitionError):
        owner.reconcile_worker(grant.model_copy(), raw(success(grant, clock)))
    assert owner.worker_usage_unknown and not owner.worker_pending


def test_successful_receipt_cannot_be_replayed_or_refund_prior_work():
    owner, clock = parent()
    grant = issue(owner)
    body = raw(success(grant, clock))
    owner.reconcile_worker(grant, body)
    before = known(owner.snapshot())
    with pytest.raises(AcquisitionError):
        owner.reconcile_worker(grant, body)
    assert known(owner.snapshot()) == before and owner.snapshot().failed
    assert not owner.worker_usage_unknown


@pytest.mark.parametrize('action', [
    lambda b: issue(b, attempt_id='d' * 64),
    lambda b: b.begin_entry(0),
    lambda b: b.begin_container(size=1, depth=0),
    lambda b: b.callback(),
    lambda b: b.charge_hash(1),
    lambda b: b.charge_metadata(1),
    lambda b: b.allocate(1),
])
def test_outstanding_grant_excludes_parent_mutation(action):
    owner, _ = parent()
    grant = issue(owner)
    before = known(owner.snapshot())
    assert owner.worker_pending
    owner.check()
    owner.snapshot()
    with pytest.raises(AcquisitionError):
        action(owner)
    assert known(owner.snapshot()) == before and owner.snapshot().failed
    with pytest.raises(AcquisitionError):
        owner.abandon_worker(grant)
    assert owner.worker_usage_unknown and not owner.worker_pending


@pytest.mark.parametrize('prepare', [
    lambda b: b.begin_entry(0),
    lambda b: b.reserve_output(b.begin_entry(1), 1),
    lambda b: b.allocate(1),
])
def test_grant_requires_no_open_local_entry_write_or_allocation(prepare):
    owner, _ = parent()
    prepare(owner)
    before = known(owner.snapshot())
    with pytest.raises(AcquisitionError):
        issue(owner)
    assert known(owner.snapshot()) == before and not owner.worker_pending


def test_completed_header_entry_and_released_allocation_can_precede_grant():
    owner, clock = parent()
    owner.skip_entry(owner.begin_entry(100))
    allocation = owner.allocate(7)
    owner.free(allocation)
    grant = issue(owner)
    child = worker(grant, clock)
    assert child.snapshot().entries == 1 and child.snapshot().peak_allocated_bytes == 7
    owner.reconcile_worker(grant, raw(child.worker_receipt()))
    assert not owner.snapshot().failed and owner.snapshot().entries == 1


def test_worker_cannot_delegate_or_issue_further_grants():
    owner, clock = parent()
    child = worker(issue(owner), clock)
    with pytest.raises(AcquisitionError):
        issue(child)
    assert child.snapshot().failed


@pytest.mark.parametrize('change', [
    {'operation_id': D, 'attempt_id': 'e' * 64},
    {'request_id': D},
])
def test_operation_identity_and_attempt_uniqueness_persist_after_success(change):
    owner, clock = parent()
    grant = issue(owner)
    owner.reconcile_worker(grant, raw(success(grant, clock)))
    with pytest.raises(AcquisitionError):
        issue(owner, **change)
    assert owner.snapshot().failed and not owner.worker_pending


def test_new_attempt_after_success_is_charged_even_for_same_request():
    owner, clock = parent(max_expanded_bytes=6)
    first = issue(owner)
    owner.reconcile_worker(first, raw(success(first, clock)))
    second = issue(owner, attempt_id=D)
    owner.reconcile_worker(second, raw(success(second, clock)))
    assert owner.snapshot().reserved_output_bytes == 6


@pytest.mark.parametrize('field', ['operation_id', 'request_id', 'attempt_id'])
def test_receipt_must_match_each_binding_component_before_counter_mutation(field):
    owner, clock = parent()
    grant = issue(owner)
    receipt = success(grant, clock)
    before = known(owner.snapshot())
    body = changed_raw(receipt, lambda x: x['binding'].update({field: D}))
    with pytest.raises(AcquisitionError):
        owner.reconcile_worker(grant, body)
    assert known(owner.snapshot()) == before and owner.worker_usage_unknown


@pytest.mark.parametrize('change', [
    lambda x: x.update(grant_id=D),
    lambda x: x['binding']['source'].update(sha256=D),
    lambda x: x['binding']['source']['file_identity'].update(file_id='2' * 32),
    lambda x: x['binding']['source']['file_identity'].update(last_write_ticks=11),
    lambda x: x['binding']['source'].update(source_claims=['different captured source']),
])
def test_receipt_full_source_and_grant_identity_are_exact(change):
    owner, clock = parent()
    grant = issue(owner)
    receipt = success(grant, clock)
    before = known(owner.snapshot())
    with pytest.raises(AcquisitionError):
        owner.reconcile_worker(grant, changed_raw(receipt, change))
    assert known(owner.snapshot()) == before and owner.worker_usage_unknown


@pytest.mark.parametrize('field', ['reserved_output_bytes', 'confirmed_output_bytes', 'entries',
                                  'containers', 'callbacks', 'hashed_input_bytes', 'metadata_bytes',
                                  'peak_allocated_bytes'])
def test_cumulative_receipt_cannot_roll_back_any_spent_counter(field):
    owner, clock = parent()
    emit(owner)
    owner.callback()
    owner.charge_hash(7)
    owner.charge_metadata(2)
    allocated = owner.allocate(4)
    owner.free(allocated)
    grant = issue(owner)
    receipt = worker(grant, clock).worker_receipt()
    before = known(owner.snapshot())
    body = changed_raw(receipt, lambda x: x['usage'].update({field: 0}))
    with pytest.raises(AcquisitionError):
        owner.reconcile_worker(grant, body)
    assert known(owner.snapshot()) == before and owner.worker_usage_unknown


@pytest.mark.parametrize('limit,field,value', [
    ('max_expanded_bytes', 'reserved_output_bytes', 9),
    ('max_entries', 'entries', 9),
    ('max_containers', 'containers', 9),
    ('max_callbacks', 'callbacks', 9),
    ('max_metadata_bytes', 'metadata_bytes', 9),
    ('max_live_allocation_bytes', 'peak_allocated_bytes', 9),
])
def test_valid_global_counts_cannot_exceed_lower_captured_limit(limit, field, value):
    owner, clock = parent(**{limit: 8})
    grant = issue(owner)
    receipt = success(grant, clock)
    before = known(owner.snapshot())

    def update(item):
        item['usage'][field] = value
        if field == 'reserved_output_bytes':
            item['usage']['confirmed_output_bytes'] = value

    with pytest.raises(AcquisitionError):
        owner.reconcile_worker(grant, changed_raw(receipt, update))
    assert known(owner.snapshot()) == before


@pytest.mark.parametrize('change', [
    lambda x: x.update(observed_ns=x['observed_ns'] - 1),
    lambda x: x.update(observed_ns=x['observed_ns'] + 1),
    lambda x: x['usage'].update(elapsed_ns=1),
])
def test_receipt_clock_observation_cannot_be_before_grant_future_or_rebased(change):
    owner, clock = parent()
    grant = issue(owner)
    before = known(owner.snapshot())
    with pytest.raises(AcquisitionError):
        owner.reconcile_worker(grant, changed_raw(success(grant, clock), change))
    assert known(owner.snapshot()) == before


@pytest.mark.parametrize('condition', ['deadline', 'cancel', 'already-cancelled'])
def test_known_completed_usage_is_retained_before_later_parent_refusal(condition):
    cancel = threading.Event()
    owner, clock = parent(max_seconds=1, cancel=cancel)
    grant = issue(owner)
    receipt = success(grant, clock)
    prior = None
    if condition == 'deadline':
        clock.now += 1_000_000_000
    else:
        cancel.set()
        if condition == 'already-cancelled':
            with pytest.raises(AcquisitionError) as failure:
                owner.check()
            prior = failure.value
    with pytest.raises(AcquisitionError) as error:
        owner.reconcile_worker(grant, raw(receipt))
    assert error.value.code == ('PT-ACQ-LIMIT' if condition == 'deadline' else 'PT-ACQ-CANCEL')
    if prior is not None:
        assert error.value is prior
    assert owner.snapshot().reserved_output_bytes == owner.snapshot().confirmed_output_bytes == 3
    assert not owner.worker_usage_unknown and not owner.worker_pending
    cancel.clear()
    with pytest.raises(AcquisitionError):
        issue(owner, attempt_id=D)


def test_valid_failed_receipt_keeps_known_partial_usage_without_refund_or_retry():
    owner, clock = parent()
    grant = issue(owner)
    child = worker(grant, clock)
    entry = child.begin_entry(3)
    reservation = child.reserve_output(entry, 3)
    with pytest.raises(AcquisitionError):
        child.complete_output(reservation, 1)
    receipt = child.worker_receipt()
    assert receipt.status == 'failed' and receipt.open_entries == 1
    with pytest.raises(AcquisitionError):
        owner.reconcile_worker(grant, raw(receipt))
    usage = owner.snapshot()
    assert usage.failed and usage.reserved_output_bytes == 3 and usage.confirmed_output_bytes == 1
    assert not owner.worker_usage_unknown and not owner.worker_pending
    with pytest.raises(AcquisitionError):
        issue(owner, attempt_id=D)


def test_missing_receipt_retains_prior_usage_and_marks_unobserved_worker_consumption():
    owner, _ = parent()
    emit(owner, 2)
    grant = issue(owner)
    before = known(owner.snapshot())
    with pytest.raises(AcquisitionError):
        owner.abandon_worker(grant)
    assert known(owner.snapshot()) == before and owner.worker_usage_unknown
    assert not owner.worker_pending and owner.snapshot().failed
    with pytest.raises(AcquisitionError):
        issue(owner, attempt_id=D)


@pytest.mark.parametrize('body', [b'{', b'null', b'{"a":1,"a":2}', b' ' * (2**20 + 1), None, 'not bytes'])
def test_unusable_receipt_fails_whole_operation_without_counter_mutation(body):
    owner, _ = parent()
    grant = issue(owner)
    before = known(owner.snapshot())
    with pytest.raises(AcquisitionError):
        owner.reconcile_worker(grant, body)
    assert known(owner.snapshot()) == before and owner.worker_usage_unknown
    assert not owner.worker_pending


@pytest.mark.parametrize('open_resource', ['entry', 'output', 'allocation'])
def test_terminal_receipt_fails_if_worker_left_resources_open(open_resource):
    owner, clock = parent()
    grant = issue(owner)
    child = worker(grant, clock)
    allocation = None
    if open_resource == 'entry':
        child.begin_entry(0)
    elif open_resource == 'output':
        child.reserve_output(child.begin_entry(1), 1)
    else:
        allocation = child.allocate(7)
    receipt = child.worker_receipt()
    assert receipt.status == 'failed'
    if allocation is not None:
        child.free(allocation)  # Only known cleanup remains legal after the terminal snapshot.
    with pytest.raises(AcquisitionError):
        child.worker_receipt()


def test_terminal_worker_cannot_keep_spending_or_export_another_receipt():
    owner, clock = parent()
    child = worker(issue(owner), clock)
    assert child.worker_receipt().status == 'complete'
    with pytest.raises(AcquisitionError):
        child.charge_hash(1)
    with pytest.raises(AcquisitionError):
        child.worker_receipt()


def test_parent_cannot_export_a_worker_receipt():
    owner, _ = parent()
    with pytest.raises(AcquisitionError):
        owner.worker_receipt()


@pytest.mark.parametrize('position', ['before-issuance', 'at-deadline'])
def test_worker_constructor_preserves_original_clock_boundary(position):
    owner, clock = parent(max_seconds=2)
    grant = issue(owner)
    clock.now = grant.issued_ns - 1 if position == 'before-issuance' else grant.deadline_ns
    with pytest.raises(AcquisitionError):
        worker(grant, clock)


def test_empty_successful_grants_still_consume_shared_callback_allowance():
    owner, clock = parent(max_callbacks=2)
    for attempt in ('c' * 64, 'd' * 64):
        grant = issue(owner, attempt_id=attempt)
        owner.reconcile_worker(grant, raw(worker(grant, clock).worker_receipt()))
    assert owner.snapshot().callbacks == 2
    with pytest.raises(AcquisitionError) as error:
        issue(owner, attempt_id='e' * 64)
    assert error.value.code == 'PT-ACQ-LIMIT'


def test_parent_clock_after_reconcile_does_not_rewind_to_child_observation():
    owner, clock = parent(max_seconds=5)
    grant = issue(owner)
    receipt = success(grant, clock)
    clock.now += 2_000_000_000
    owner.reconcile_worker(grant, raw(receipt))
    assert owner.snapshot().elapsed_ns == 2_000_000_000
    follow = issue(owner, attempt_id=D)
    assert follow.baseline.elapsed_ns == 2_000_000_000 and follow.deadline_ns == grant.deadline_ns
