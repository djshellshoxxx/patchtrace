"""One operation spends one deadline/output allowance across sides and recursion."""
from __future__ import annotations

import importlib
import threading

import pytest

from patchtrace.acquisition.contracts import AcquisitionError
from tests.package_support import contracts


class Clock:
    now = 1_000_000_000

    def __call__(self):
        return self.now


def budget(**limits):
    module = importlib.import_module('patchtrace.acquisition.package_budget')
    clock = Clock()
    return module.PackageBudget(contracts().PackageLimits(**limits), clock_ns=clock), clock


def test_reservations_share_total_across_old_new_nested_and_discarded_files():
    b, _ = budget(max_expanded_bytes=7)
    for size, depth in [(2, 0), (3, 1), (2, 0)]:
        b.begin_container(size=4, depth=depth)
        entry = b.begin_entry(size)
        r = b.reserve_output(entry, size)
        b.complete_output(r, size)
        b.finish_entry(entry)
    usage = b.snapshot()
    assert usage.reserved_output_bytes == usage.confirmed_output_bytes == 7
    assert usage.containers == usage.entries == 3
    extra = b.begin_entry(1)
    with pytest.raises(AcquisitionError) as error:
        b.reserve_output(extra, 1)
    assert error.value.code == 'PT-ACQ-LIMIT'
    assert b.snapshot().reserved_output_bytes == 7 and b.snapshot().failed


def test_size_lie_fails_before_the_next_write_and_does_not_refund():
    b, _ = budget()
    entry = b.begin_entry(2)
    reservation = b.reserve_output(entry, 2)
    b.complete_output(reservation, 2)
    with pytest.raises(AcquisitionError):
        b.reserve_output(entry, 1)
    assert b.snapshot().reserved_output_bytes == b.snapshot().confirmed_output_bytes == 2


@pytest.mark.parametrize('count', [0, 1, None, True, -1, 4])
def test_short_or_unknown_write_completion_poison_attempt_without_refund(count):
    b, _ = budget()
    entry = b.begin_entry(3)
    reservation = b.reserve_output(entry, 3)
    with pytest.raises(AcquisitionError):
        b.complete_output(reservation, count)
    usage = b.snapshot()
    assert usage.failed and usage.reserved_output_bytes == 3
    assert usage.confirmed_output_bytes == (count if type(count) is int and 0 <= count <= 3 else 0)
    with pytest.raises(AcquisitionError):
        b.begin_entry(1)


def test_pending_or_short_entry_never_closes_as_verified():
    b, _ = budget()
    entry = b.begin_entry(3)
    b.reserve_output(entry, 3)
    with pytest.raises(AcquisitionError):
        b.finish_entry(entry)
    b, _ = budget()
    entry = b.begin_entry(3)
    b.complete_output(b.reserve_output(entry, 2), 2)
    with pytest.raises(AcquisitionError):
        b.finish_entry(entry)


def test_zero_length_entry_and_header_skip_are_distinct_valid_states():
    b, _ = budget()
    empty = b.begin_entry(0)
    b.finish_entry(empty)
    header = b.begin_entry(100)
    b.skip_entry(header)
    assert b.snapshot().entries == 2 and b.snapshot().confirmed_output_bytes == 0
    with pytest.raises(AcquisitionError):
        b.reserve_output(header, 1)


def test_reservation_tokens_are_single_use_and_bound_to_exact_operation():
    first, _ = budget()
    second, _ = budget()
    reservation = first.reserve_output(first.begin_entry(1), 1)
    with pytest.raises(AcquisitionError):
        second.complete_output(reservation, 1)
    first.complete_output(reservation, 1)
    with pytest.raises(AcquisitionError):
        first.complete_output(reservation, 1)
    assert first.snapshot().confirmed_output_bytes == 1


def test_failed_output_retains_reservation_and_first_failure():
    b, _ = budget()
    reservation = b.reserve_output(b.begin_entry(5), 5)
    with pytest.raises(AcquisitionError) as first:
        b.fail_output(reservation)
    with pytest.raises(AcquisitionError) as second:
        b.check()
    assert first.value is second.value
    assert b.snapshot().reserved_output_bytes == 5 and b.snapshot().confirmed_output_bytes == 0


def test_deadline_includes_parent_hashing_and_all_sides_without_reset():
    b, clock = budget(max_seconds=3)
    b.charge_hash(100)
    clock.now += 2_000_000_000
    b.begin_container(size=100, depth=0)
    assert b.remaining_seconds() == 1.0
    clock.now += 1_000_000_000
    with pytest.raises(AcquisitionError) as error:
        b.charge_hash(100)
    assert error.value.code == 'PT-ACQ-LIMIT'
    assert b.snapshot().hashed_input_bytes == 100


def test_cancellation_remains_failed_even_if_token_is_cleared():
    c = contracts()
    module = importlib.import_module('patchtrace.acquisition.package_budget')
    cancel = threading.Event()
    b = module.PackageBudget(c.PackageLimits(), cancel=cancel, clock_ns=Clock())
    allocation = b.allocate(4)
    cancel.set()
    with pytest.raises(AcquisitionError) as error:
        b.check()
    assert error.value.code == 'PT-ACQ-CANCEL'
    cancel.clear()
    b.free(allocation)  # Owned cleanup remains possible after cancellation.
    assert b.snapshot().live_allocated_bytes == 0
    with pytest.raises(AcquisitionError):
        b.begin_entry(1)


@pytest.mark.parametrize('clock_value', [-1, 0, True, 1.5, float('nan'), float('inf')])
def test_clock_reversal_or_invalid_reading_refuses(clock_value):
    b, clock = budget()
    clock.now = clock_value
    with pytest.raises(AcquisitionError):
        b.check()


def test_allocation_bound_counts_live_and_peak_and_refuses_double_free():
    b, _ = budget(max_live_allocation_bytes=8)
    first = b.allocate(5)
    second = b.allocate(3)
    b.free(first)
    third = b.allocate(5)
    assert b.snapshot().peak_allocated_bytes == b.snapshot().live_allocated_bytes == 8
    b.free(second)
    b.free(third)
    assert b.snapshot().peak_allocated_bytes == 8 and b.snapshot().live_allocated_bytes == 0
    with pytest.raises(AcquisitionError):
        b.free(first)


def test_unknown_allocation_and_limit_never_change_previous_accounting():
    b, _ = budget(max_live_allocation_bytes=2)
    b.allocate(2)
    with pytest.raises(AcquisitionError):
        b.allocate(1)
    assert b.snapshot().live_allocated_bytes == 2
    other, _ = budget()
    with pytest.raises(AcquisitionError):
        other.free(object())


@pytest.mark.parametrize('method,arguments', [('begin_entry', (True,)), ('begin_entry', (-1,)),
                                             ('allocate', (0,)), ('allocate', (1.0,)),
                                             ('charge_hash', (-1,)), ('charge_hash', (True,)),
                                             ('charge_metadata', ('2',))])
def test_counter_inputs_are_strict_nonnegative_integers(method, arguments):
    b, _ = budget()
    with pytest.raises(AcquisitionError):
        getattr(b, method)(*arguments)


def test_entries_containers_depth_callbacks_and_metadata_share_their_limits():
    actions = [({'max_entries': 1}, lambda b: (b.begin_entry(0), b.begin_entry(0))),
               ({'max_containers': 1}, lambda b: (b.begin_container(size=1, depth=0),
                                                b.begin_container(size=1, depth=0))),
               ({'max_depth': 1}, lambda b: b.begin_container(size=1, depth=2)),
               ({'max_source_bytes': 4}, lambda b: b.begin_container(size=5, depth=0)),
               ({'max_callbacks': 1}, lambda b: (b.callback(), b.callback())),
               ({'max_metadata_bytes': 4}, lambda b: (b.charge_metadata(3), b.charge_metadata(2))),
               ({'max_xml_bytes': 3}, lambda b: b.charge_metadata(4))]
    for limits, run in actions:
        b, _ = budget(**limits)
        with pytest.raises(AcquisitionError) as error:
            run(b)
        assert error.value.code == 'PT-ACQ-LIMIT' and b.snapshot().failed
