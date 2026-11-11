"""Reusable test-side process and I/O failure injection checkpoints for KB lifecycle tests.

The names follow SPEC-32D §6. This module is an adapter utility only: current inspected code did not expose the
proposed patch_search.sqlite3 companion store, so this harness does not claim to test its recovery.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal

CRASH_EXIT_CODE = 86


@dataclass(frozen=True)
class Injection:
    checkpoint: str
    mode: Literal["hard_exit", "io_error"] = "hard_exit"

    def hit(self, name: str) -> None:
        """Terminate a child process or raise an I/O failure at the selected named checkpoint."""
        if name != self.checkpoint:
            return
        if self.mode == "hard_exit":
            os._exit(CRASH_EXIT_CODE)
        raise OSError(f"injected I/O failure at {name}")


CHECKPOINTS = (
    "source_before_commit",
    "source_after_commit",
    "first_binary_verified",
    "both_binaries_verified",
    "project_created_before_attach",
    "sidecar_before_transaction_commit",
    "sidecar_after_commit_before_ack",
    "triage_before_store",
    "sidecar_migration_midflight",
)
