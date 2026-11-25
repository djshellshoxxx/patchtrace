"""Abandoned network-call slots must cover time spent closing late responses."""
import threading
import time

import pytest

from patchtrace import netutil


def test_abandoned_count_includes_late_response_cleanup():
    initial = netutil.abandoned_count()
    release_cleanup = threading.Event()
    try:
        for _ in range(netutil.MAX_ABANDONED - initial):
            worker_release = threading.Event()
            in_cleanup = threading.Event()
            cancelled = threading.Event()

            def call(release=worker_release):
                release.wait(3)
                return object()

            def cleanup(_value, entered=in_cleanup):
                entered.set()
                release_cleanup.wait(3)

            timer = threading.Timer(0.02, cancelled.set)
            timer.start()
            try:
                with pytest.raises(netutil.Cancelled):
                    netutil.interruptible(call, cancelled, poll=0.005, cleanup=cleanup)
            finally:
                timer.cancel()
                timer.join(timeout=1)
            worker_release.set()
            assert in_cleanup.wait(1), 'the cancelled call must run cleanup on the worker'

        assert netutil.abandoned_count() == netutil.MAX_ABANDONED
        with pytest.raises(netutil.TooManyAbandoned):
            netutil.interruptible(lambda: object(), threading.Event())
    finally:
        release_cleanup.set()
        end = time.monotonic() + 2
        while netutil.abandoned_count() != initial and time.monotonic() < end:
            time.sleep(0.01)
    assert netutil.abandoned_count() == initial


def test_cancelled_call_slot_released_after_failing_cleanup():
    initial = netutil.abandoned_count()
    release_worker = threading.Event()
    entered_cleanup = threading.Event()
    cancel = threading.Event()

    def late_result():
        release_worker.wait(2)
        return object()

    def bad_cleanup(_value):
        entered_cleanup.set()
        raise RuntimeError('synthetic cleanup failure')

    timer = threading.Timer(0.02, cancel.set)
    timer.start()
    try:
        with pytest.raises(netutil.Cancelled):
            netutil.interruptible(late_result, cancel, poll=0.005, cleanup=bad_cleanup)
    finally:
        timer.cancel()
        timer.join(timeout=1)
    release_worker.set()
    assert entered_cleanup.wait(1)
    end = time.monotonic() + 2
    while netutil.abandoned_count() != initial and time.monotonic() < end:
        time.sleep(0.01)
    assert netutil.abandoned_count() == initial
