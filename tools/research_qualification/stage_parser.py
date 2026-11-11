"""RQ-01a: tolerant Ghidriff log stage/quiet-interval extractor (offline, no process execution).

The exact Ghidriff log line format of the installed revision is NOT verified; this parser only assumes that a
line may begin with a wall-clock time (`HH:MM:SS[.mmm]`, optionally with an ISO date) and that stage messages
contain the marker text recorded in docs/qa/ghidriff-timeout-20261106.md. Lines it cannot place are counted,
never guessed. Times are handled as integer milliseconds so quiet intervals are exact.
"""
from __future__ import annotations

import re
from typing import Any

_TS = re.compile(r"(?:(\d{4})-(\d{2})-(\d{2})[T ])?(\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,6}))?")
_TS_WINDOW = 48  # only a timestamp near the start of the line counts

# (stage id, pattern). Order is irrelevant; the first matching marker wins for a line.
STAGE_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("structural_graph_hash", re.compile(r"StructuralGraphHash", re.I)),
    ("bsim", re.compile(r"\bBSim\b", re.I)),
    ("generating_matches_json", re.compile(r"Generating matches JSON", re.I)),
    ("sorting_functions", re.compile(r"Sorting functions", re.I)),
    ("esym_lookup", re.compile(r"\besym\b|enhanced[- ]symbol", re.I)),
)
_ENTRIES = re.compile(r"(\d[\d,]*)\s+entries", re.I)
_SECONDS = re.compile(r"(\d+(?:\.\d+)?)\s+seconds", re.I)
_DAY_MS = 86_400_000


def _line_ms(line: str) -> tuple[int | None, bool]:
    """Milliseconds within the day (or since the ISO date's ordinal day) and whether a date was present."""
    m = _TS.search(line[:_TS_WINDOW])
    if not m:
        return None, False
    y, mo, d, hh, mm, ss, frac = m.groups()
    ms = ((int(hh) * 60 + int(mm)) * 60 + int(ss)) * 1000
    if frac:
        ms += int((frac + "000")[:3])
    if y:
        from datetime import date

        ms += date(int(y), int(mo), int(d)).toordinal() * _DAY_MS
        return ms, True
    return ms, False


def parse_log_text(text: str, *, top_gaps: int = 5) -> dict[str, Any]:
    """Return stage first-seen offsets, the largest quiet intervals and extracted counts.

    Offsets are milliseconds from the first timestamped line. A time-of-day that goes backwards without a date
    is treated as a midnight rollover (+24h), so a run crossing midnight keeps monotonic offsets.
    """
    lines = text.splitlines()
    prev_abs: int | None = None
    base: int | None = None
    rollover = 0
    stamped: list[tuple[int, int, str | None]] = []  # (line_no, offset_ms, stage)
    stages: dict[str, dict[str, Any]] = {}
    entry_counts: list[dict[str, int]] = []
    stage_seconds: list[dict[str, Any]] = []
    unplaced = 0
    last_stage: str | None = None
    for no, line in enumerate(lines, 1):
        ms, dated = _line_ms(line)
        stage = next((sid for sid, pat in STAGE_MARKERS if pat.search(line)), None)
        if stage:
            last_stage = stage
        if ms is None:
            unplaced += 1 if stage else 0
            continue
        absolute = ms + (0 if dated else rollover)
        if prev_abs is not None and not dated and absolute < prev_abs:
            rollover += _DAY_MS
            absolute += _DAY_MS
        prev_abs = absolute
        if base is None:
            base = absolute
        off = absolute - base
        stamped.append((no, off, stage))
        if stage and stage not in stages:
            stages[stage] = {"stage": stage, "line": no, "offset_ms": off}
        em = _ENTRIES.search(line)
        if em:
            entry_counts.append({"line": no, "entries": int(em.group(1).replace(",", ""))})
        sm = _SECONDS.search(line)
        if sm and last_stage:
            stage_seconds.append({"line": no, "stage": last_stage, "seconds": float(sm.group(1))})
    gaps = []
    for (n1, o1, s1), (n2, o2, s2) in zip(stamped, stamped[1:], strict=False):
        gaps.append({"from_line": n1, "to_line": n2, "from_stage": s1, "to_stage": s2, "gap_ms": o2 - o1})
    gaps.sort(key=lambda g: (-g["gap_ms"], g["from_line"]))
    return {
        "lines": len(lines),
        "timestamped_lines": len(stamped),
        "stage_marker_lines_without_timestamp": unplaced,
        "stages": sorted(stages.values(), key=lambda s: s["offset_ms"]),
        "quiet_intervals": gaps[:top_gaps],
        "entry_counts": entry_counts,
        "stage_seconds": stage_seconds,
        "span_ms": (stamped[-1][1] - stamped[0][1]) if stamped else 0,
        "unverified": ["ghidriff_log_line_format_of_installed_revision"],
    }
