"""Session hooks shared by the suite. Live acceptance is never skipped silently (SPEC-29 §9.4):
live tests record `passed | failed | blocked` JSON into PATCHTRACE_LIVE_STATUS_DIR (the live workflows set it to
build/live-status; a plain run uses a throwaway temp directory so it never clobbers a real live run's files) and
blocked checks are printed in a `LIVE ACCEPTANCE BLOCKED` section. Each entry says whether it is `mocked`:
PATCHTRACE_LIVE_MOCKED=1 (set by the harness tests that run against fake executables) or `mocked=True`."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from live_status import live_status_dir

ROOT = Path(__file__).resolve().parents[1]
LIVE_STATUS_KEY = pytest.StashKey[list]()




def pytest_configure(config):
    config.stash[LIVE_STATUS_KEY] = []


@pytest.fixture
def record_live_status(request):
    """record(engine, status, reason, mocked=None, **extra) -> Path of the written status JSON."""
    def record(engine: str, status: str, reason: str, *, mocked: bool | None = None, **extra) -> Path:
        if status not in ('passed', 'failed', 'blocked'):
            raise ValueError(f'unknown live status {status!r}')
        directory = live_status_dir()
        directory.mkdir(parents=True, exist_ok=True)
        if mocked is None:
            mocked = os.environ.get('PATCHTRACE_LIVE_MOCKED') == '1'
        entry = {'engine': engine, 'status': status, 'reason': reason, 'mocked': mocked, **extra}
        path = directory / f'{engine}.json'
        path.write_text(json.dumps(entry, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        request.config.stash[LIVE_STATUS_KEY].append(entry)
        return path
    return record


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    entries = config.stash.get(LIVE_STATUS_KEY, [])
    blocked = [e for e in entries if e['status'] == 'blocked']
    if blocked:
        terminalreporter.write_sep('=', 'LIVE ACCEPTANCE BLOCKED')
        for entry in blocked:
            terminalreporter.write_line(f'LIVE ACCEPTANCE BLOCKED: {entry["engine"]} ({entry["reason"]})')
