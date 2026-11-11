"""Scratch directory for live-test status files (importable; tests/conftest.py is not, see tests/stress/conftest.py)."""
from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from pathlib import Path

_SCRATCH_STATUS: list[Path] = []


def live_status_dir() -> Path:
    explicit = os.environ.get('PATCHTRACE_LIVE_STATUS_DIR')
    if explicit:
        return Path(explicit)
    if not _SCRATCH_STATUS:
        _SCRATCH_STATUS.append(Path(tempfile.mkdtemp(prefix='patchtrace-live-status-')))
        atexit.register(shutil.rmtree, _SCRATCH_STATUS[0], ignore_errors=True)
    return _SCRATCH_STATUS[0]
