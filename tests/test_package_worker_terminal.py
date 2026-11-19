"""A published terminal receipt freezes all accounting except owned allocation release."""
from __future__ import annotations

import threading

import pytest

from patchtrace.acquisition.contracts import AcquisitionError
from tests.package_worker_support import issue, parent, worker


@pytest.mark.parametrize('completed', [1, 3])
def test_pending_completion_after_terminal_cannot_add_unreportable_confirmed_bytes(completed):
    owner, clock = parent()
    child = worker(issue(owner), clock)
    pending = child.reserve_output(child.begin_entry(3), 3)
    terminal = child.worker_receipt()
    with pytest.raises(AcquisitionError) as stopped:
        child.check()
    with pytest.raises(AcquisitionError) as completed_error:
        child.complete_output(pending, completed)
    assert completed_error.value is stopped.value
    assert child.snapshot() == terminal.usage


def test_pending_output_failure_after_terminal_cannot_consume_its_resource_token():
    owner, clock = parent()
    child = worker(issue(owner), clock)
    entry = child.begin_entry(3)
    pending = child.reserve_output(entry, 3)
    terminal = child.worker_receipt()
    # The token registry is the resource-ownership oracle. A rejected terminal
    # call cannot silently consume the pending resource recorded by that receipt.
    pending_before = tuple(child._outputs)
    entry_pending_before = child._entries[entry].pending
    with pytest.raises(AcquisitionError) as stopped:
        child.check()
    with pytest.raises(AcquisitionError) as output_error:
        child.fail_output(pending)
    assert output_error.value is stopped.value
    assert child.snapshot() == terminal.usage
    assert tuple(child._outputs) == pending_before
    assert child._entries[entry].pending == entry_pending_before == 1


@pytest.mark.parametrize('reason', ['cancel', 'deadline'])
def test_preterminal_completion_retains_known_bytes_and_already_observed_first_error(reason):
    cancel = threading.Event()
    owner, clock = parent()
    child = worker(issue(owner), clock, cancel=cancel)
    pending = child.reserve_output(child.begin_entry(3), 3)
    if reason == 'cancel':
        cancel.set()
    else:
        clock.now = child.deadline_ns
    with pytest.raises(AcquisitionError) as first:
        child.check()
    with pytest.raises(AcquisitionError) as completion:
        child.complete_output(pending, 3)
    assert completion.value is first.value
    terminal = child.worker_receipt()
    assert terminal.usage.failure_code == ('PT-ACQ-CANCEL' if reason == 'cancel' else 'PT-ACQ-LIMIT')
    assert terminal.usage.confirmed_output_bytes == terminal.usage.reserved_output_bytes == 3
    assert terminal.pending_outputs == 0 and terminal.open_entries == 1
