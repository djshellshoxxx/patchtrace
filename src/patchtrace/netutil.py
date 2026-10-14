"""Stdlib-only helper that makes a blocking network call observe cancellation promptly (H9)."""
from __future__ import annotations

import threading
from collections.abc import Callable

MAX_ABANDONED = 4
_lock = threading.Lock()
_abandoned = 0


class Cancelled(Exception):
    """Raised when the cancel event fired while a blocking call was in flight."""


class TooManyAbandoned(OSError):
    """Previous cancelled calls have not yet released their sockets."""


def abandoned_count() -> int:
    with _lock:
        return _abandoned


def interruptible[T](call: Callable[[], T], cancel: threading.Event | None, *, poll: float = 0.1,
                     cleanup: Callable[[T], None] | None = None) -> T:
    """Run ``call`` and return its result, or raise `Cancelled` within ~``poll`` s of ``cancel.set()``.

    The call runs on a daemon thread. After abandonment the thread closes whatever it eventually
    returns through ``cleanup`` and publishes nothing else. At most MAX_ABANDONED abandoned threads
    may be alive at once; further calls fail with `TooManyAbandoned` instead of leaking more.
    """
    global _abandoned
    if cancel is None:
        return call()
    if cancel.is_set():
        raise Cancelled()
    with _lock:
        if _abandoned >= MAX_ABANDONED:
            raise TooManyAbandoned('previous requests still closing')
    done = threading.Event()
    state: dict = {'abandoned': False}

    def worker() -> None:
        global _abandoned
        try:
            outcome = (call(), None)
        except BaseException as exc:  # noqa: BLE001 - re-raised on the caller thread
            outcome = (None, exc)
        with _lock:
            late = state['abandoned']
            if late:
                _abandoned -= 1
            else:
                state['outcome'] = outcome
        if late and outcome[1] is None and cleanup is not None:
            try:
                cleanup(outcome[0])
            except Exception:  # noqa: BLE001 - best effort close
                pass
        done.set()

    threading.Thread(target=worker, daemon=True, name='patchtrace-net').start()
    while not done.wait(poll):
        if cancel.is_set():
            with _lock:
                if 'outcome' not in state:
                    state['abandoned'] = True
                    _abandoned += 1
                    raise Cancelled()
            break
    value, error = state['outcome']
    if error is not None:
        raise error
    return value
