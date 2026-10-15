"""Provisional WB3 limits (spec WB3 s7); raised only after the measured S0 gate (`tests/test_strings_table.py`)."""
from __future__ import annotations

MAX_ROWS_PER_SIDE = 200_000  # T-track cap until the gate allows 400k (Q4)
DISPLAY_CHARS = 256
DETAIL_WINDOW_BYTES = 4 * 1024
MAX_DELTA_ROWS = 50_000
MAX_CHANGE_OFFSETS = 16
MAX_CHANGE_LINKS = 8
MAX_CHANGE_CUES = 8
MAX_GHIDRIFF_STRINGS = 100_000
MAX_LITERALS_PER_FUNCTION = 4000
MAX_LITERAL_LINES = 20_000
MAX_EDIT_PAIRS = 64
MAX_ANCHORS = 200
MAX_FRAGMENTS = 1_000_000
MAX_TABLE_BYTES = 256 * 1024 * 1024  # hostile sidecar bound, checked before any column is read
NONE_U32 = 0xFFFFFFFF
