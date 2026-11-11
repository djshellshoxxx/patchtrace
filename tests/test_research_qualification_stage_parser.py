"""RQ-01a stage parser. The synthetic log reproduces the times in docs/qa/ghidriff-timeout-20261106.md only;
it is NOT the real ghidriff.log and says nothing about the installed Ghidriff line format."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.research_qualification.stage_parser import parse_log_text  # noqa: E402

SYNTH = """\
20:47:23.720 INFO Starting Ghidra
20:59:26.564 INFO analysis complete
21:09:00.000 INFO BSim finished in 109.8506 seconds
21:09:30.000 INFO StructuralGraphHash 2,161,955 entries one_to_many: True
21:11:07.405 INFO Generating matches JSON
21:12:40.539 INFO Sorting functions
21:41:22.294 INFO esym lookups starting
21:41:44.841 INFO esym Completed 72 at 100%
"""


def test_quiet_interval_matches_hand_computed_value():
    out = parse_log_text(SYNTH)
    top = out["quiet_intervals"][0]
    # 21:41:22.294 - 21:12:40.539 = 28 min 41.755 s = 1,721,755 ms (hand computed from the QA table)
    assert (top["from_stage"], top["to_stage"], top["gap_ms"]) == ("sorting_functions", "esym_lookup", 1_721_755)


def test_stage_order_counts_and_span():
    out = parse_log_text(SYNTH)
    assert [s["stage"] for s in out["stages"]] == [
        "bsim", "structural_graph_hash", "generating_matches_json", "sorting_functions", "esym_lookup"]
    assert out["entry_counts"] == [{"line": 4, "entries": 2_161_955}]
    assert out["span_ms"] == (21 * 3600 + 41 * 60 + 44) * 1000 + 841 - (20 * 3600 + 47 * 60 + 23) * 1000 - 720
    assert "ghidriff_log_line_format_of_installed_revision" in out["unverified"]


def test_midnight_rollover_keeps_offsets_monotonic():
    out = parse_log_text("23:59:59.000 a\n00:00:01.000 b\n00:00:02.500 c\n")
    assert out["span_ms"] == 3500 and out["quiet_intervals"][0]["gap_ms"] == 2000


def test_iso_dates_are_used_without_guessing_rollover():
    out = parse_log_text("2026-11-05T23:59:59.000 a\n2026-11-06T00:00:01.000 b\n")
    assert out["span_ms"] == 2000


def test_lines_without_timestamps_are_counted_not_guessed():
    out = parse_log_text("no time here Sorting functions\n12:00:00 x\n")
    assert out["timestamped_lines"] == 1 and out["stage_marker_lines_without_timestamp"] == 1


def test_empty_and_garbage_input_are_safe():
    for text in ("", "\n\n", "\x00\xff garbage 99:99:99", "a" * 100_000):
        out = parse_log_text(text)
        assert out["span_ms"] >= 0 and isinstance(out["stages"], list)
