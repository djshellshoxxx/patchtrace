"""Process-wide runtime tuning, installed once at startup (GUI plan 8.5 rule 7)."""
from __future__ import annotations

import sys

# A CPU-bound pure-Python worker raised a 1,218-call table repaint from 6.5 ms to 274 ms median at the default
# 5 ms switch interval; 1 ms with checkpoint() keeps p95 near 20 ms. Trade-off: worker throughput about -27%.
SWITCH_INTERVAL = 0.001

_previous: float | None = None


def install() -> bool:
    """Set the 1 ms thread switch interval; returns False when it was already installed."""
    global _previous
    if _previous is not None:
        return False
    _previous = sys.getswitchinterval()
    sys.setswitchinterval(SWITCH_INTERVAL)
    return True


def uninstall() -> None:
    """Restore the previous interval (tests)."""
    global _previous
    if _previous is not None:
        sys.setswitchinterval(_previous)
        _previous = None
