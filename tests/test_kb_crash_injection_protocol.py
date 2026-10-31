"""Validate the crash-injection names required by the lifecycle test protocol."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from kb_crash_harness import CHECKPOINTS, CRASH_EXIT_CODE, Injection

ROOT = Path(__file__).resolve().parent / "fixtures" / "kb"


def test_harness_names_match_all_nine_spec_checkpoints() -> None:
    """Checkpoint order mirrors the nine crash boundaries in SPEC-32D §6."""
    fixture = json.loads((ROOT / "crash_points.json").read_text(encoding="utf-8"))
    assert tuple(item["name"] for item in fixture["points"]) == CHECKPOINTS
    assert len(CHECKPOINTS) == 9


def test_injection_ignores_other_checkpoint() -> None:
    marker = Injection("sidecar_before_transaction_commit", "io_error")
    marker.hit("source_after_commit")


def test_io_failure_raises_only_at_selected_checkpoint() -> None:
    marker = Injection("sidecar_before_transaction_commit", "io_error")
    with pytest.raises(OSError, match="sidecar_before_transaction_commit"):
        marker.hit("sidecar_before_transaction_commit")


def test_hard_exit_code_is_reserved_for_child_process_harness() -> None:
    assert CRASH_EXIT_CODE == 86
