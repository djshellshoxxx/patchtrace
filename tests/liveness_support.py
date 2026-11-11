"""Polling helpers for process-liveness checks. A negative check ("the child stopped", "the marker never appeared")
is only meaningful when the child provably started, so these helpers refuse to pass vacuously."""
from __future__ import annotations

import threading
import time
from collections.abc import Callable
from pathlib import Path


def wait_for(predicate: Callable[[], bool], timeout: float = 10.0, interval: float = 0.02) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        if predicate():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


def heartbeat_code(beat: Path, beats: int = 400) -> str:
    """A child that appends to `beat` every 50 ms: self-limiting (20 s) even if containment regresses."""
    return (f'import time\nf=open({str(beat)!r},"ab",buffering=0)\n'
            f'for _ in range({beats}):\n    f.write(b"x")\n    time.sleep(0.05)\n')


def heartbeat_stopped(beat: Path, settle: float = 0.5, start_timeout: float = 10.0) -> bool:
    """True only when the heartbeat file exists and does not grow over `settle` seconds. A beat that never
    appeared is a failure (the child never started), never a pass. The settle wait is inherent: absence of
    growth cannot be observed any other way."""
    if not wait_for(lambda: beat.exists() and beat.stat().st_size > 0, timeout=start_timeout):
        return False
    size = beat.stat().st_size
    time.sleep(settle)
    return beat.stat().st_size == size


def never_appears(path: Path, within: float) -> bool:
    """True when `path` does not appear within `within` seconds (returns early with False once it does)."""
    return not wait_for(path.exists, timeout=within, interval=0.05)


def cancel_when_started(started: Path, timeout: float = 20.0) -> threading.Event:
    """An event set as soon as the child's `started` file exists (also set at `timeout`, so a child that never
    starts fails the caller's `started.exists()` check instead of hanging the test)."""
    cancel = threading.Event()

    def watch() -> None:
        wait_for(started.exists, timeout=timeout, interval=0.01)
        cancel.set()
    threading.Thread(target=watch, daemon=True).start()
    return cancel
