"""Who produces a `.BinExport` (SPEC-10b §8). v1: the user supplies it; Phase E adds a headless producer.

Whatever a producer returns is UNTRUSTED and goes through `accept_binexport` unchanged (no fast path).
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Protocol


class BinExportProducer(Protocol):
    name: str

    def produce(self, artifact: Path, out_dir: Path, *, cancel: threading.Event) -> Path: ...


class UserSuppliedProducer:
    """The only v1 producer: hands back the file the user selected for this artifact."""

    name = 'user-supplied'

    def __init__(self, supplied: Path):
        self._supplied = Path(supplied)

    def produce(self, artifact: Path, out_dir: Path, *, cancel: threading.Event) -> Path:
        return self._supplied
