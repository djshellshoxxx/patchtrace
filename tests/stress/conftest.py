"""Hostile-input QA helpers: make the shared test builders (pe_builder, kev_helpers) importable from this folder."""
from __future__ import annotations

import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))
