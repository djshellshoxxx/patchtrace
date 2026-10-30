"""GUI write boundary: report success only after project persistence completes."""
from __future__ import annotations

from collections.abc import Callable


def commit_and_report(window, writer: Callable[[], None], success_message: str = '') -> bool:
    """Commit a state change or display its error; never claim success after a failed write."""
    try:
        writer()
    except Exception as exc:
        window.show_error(str(exc))
        return False
    if success_message:
        window.statusBar().showMessage(success_message)
    return True
