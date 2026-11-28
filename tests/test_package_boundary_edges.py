"""Additional authored controls found during the first implementation's review."""
from __future__ import annotations

import importlib
import threading

import pytest
from pydantic import ValidationError

from patchtrace.acquisition.contracts import AcquisitionError
from tests.package_support import contracts, inventory, part
from tests.test_package_budget import Clock, budget


def test_completed_write_is_accounted_even_when_cancellation_arrives_during_io():
    module = importlib.import_module('patchtrace.acquisition.package_budget')
    cancel = threading.Event()
    b = module.PackageBudget(contracts().PackageLimits(), cancel=cancel, clock_ns=Clock())
    reservation = b.reserve_output(b.begin_entry(3), 3)
    cancel.set()  # The sink already reported all three bytes before cancellation is observed.
    with pytest.raises(AcquisitionError) as error:
        b.complete_output(reservation, 3)
    assert error.value.code == 'PT-ACQ-CANCEL'
    assert b.snapshot().confirmed_output_bytes == 3 and b.snapshot().reserved_output_bytes == 3
    assert b.snapshot().failed


def test_completed_write_is_accounted_even_when_the_deadline_elapsed_in_io():
    b, clock = budget(max_seconds=1)
    reservation = b.reserve_output(b.begin_entry(3), 3)
    clock.now += 1_000_000_000
    with pytest.raises(AcquisitionError):
        b.complete_output(reservation, 3)
    assert b.snapshot().confirmed_output_bytes == 3 and b.snapshot().failed


def test_unread_header_cannot_claim_content_classification_even_without_a_pe_machine():
    with pytest.raises(ValidationError):
        part(basis='content', machine=None)


def test_raw_json_must_obey_its_own_captured_limit_including_whitespace():
    c = contracts()
    inv = inventory(limits=c.PackageLimits(max_json_bytes=4096))
    raw = inv.model_dump_json().encode() + b' ' * 4096
    with pytest.raises(AcquisitionError) as error:
        c.parse_record(c.PackageInventory, raw)
    assert error.value.code == 'PT-ACQ-LIMIT'


def test_constructed_inventory_cannot_exceed_its_captured_serialization_budget():
    c = contracts()
    with pytest.raises((ValueError, AcquisitionError)):
        inventory(limits=c.PackageLimits(max_json_bytes=64))


def test_a_serial_entry_cannot_stack_uncompleted_write_reservations():
    b, _ = budget()
    entry = b.begin_entry(4)
    b.reserve_output(entry, 2)
    with pytest.raises(AcquisitionError):
        b.reserve_output(entry, 2)
    assert b.snapshot().reserved_output_bytes == 2 and b.snapshot().failed
