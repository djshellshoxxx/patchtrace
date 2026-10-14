"""Limits (GL-xx) and the error type shared by the call-graph kernel."""
from __future__ import annotations

from collections.abc import Callable

MAX_LABEL_STORED = 512  # GL-02
MAX_LABEL_SHOWN = 120
MAX_PATHS = 5  # GL-04
MAX_PATH_LENGTH = 12
PATH_VISIT_BUDGET = 200_000
CANCEL_POP_INTERVAL = 4_096  # GL-12 (queue pops)
CANCEL_CLAIM_INTERVAL = 200  # GL-12 (claims)

CancelCheck = Callable[[], bool] | None


class GraphError(Exception):
    """Call-graph failure with a stable `PT-GRAPH-*` code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f'{code}: {message}')
        self.code = code
        self.message = message
