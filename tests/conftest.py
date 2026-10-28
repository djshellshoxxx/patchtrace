"""Session hooks shared by the suite. Live acceptance is never skipped silently (SPEC-29 §9.4):
live tests record `passed | failed | blocked` JSON under build/live-status/ (override with
PATCHTRACE_LIVE_STATUS_DIR) and blocked checks are printed in a `LIVE ACCEPTANCE BLOCKED` section."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LIVE_STATUS_KEY = pytest.StashKey[list]()


def live_status_dir() -> Path:
    return Path(os.environ.get('PATCHTRACE_LIVE_STATUS_DIR') or ROOT / 'build' / 'live-status')


def pytest_configure(config):
    config.stash[LIVE_STATUS_KEY] = []


@pytest.fixture
def record_live_status(request):
    """record(engine, status, reason, **extra) -> Path of the written status JSON."""
    def record(engine: str, status: str, reason: str, **extra) -> Path:
        if status not in ('passed', 'failed', 'blocked'):
            raise ValueError(f'unknown live status {status!r}')
        directory = live_status_dir()
        directory.mkdir(parents=True, exist_ok=True)
        entry = {'engine': engine, 'status': status, 'reason': reason, 'mocked': False, **extra}
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


@pytest.fixture(autouse=True)
def _no_real_kev_catalog(monkeypatch, tmp_path_factory):
    """``kb leads`` reads the KEV catalog in use from the user's data folder by default; point that at an empty
    folder so no test depends on a catalog installed on the machine that runs it."""
    from patchtrace.kbcorrelation.adapters import kev as kev_adapter
    monkeypatch.setattr(kev_adapter, 'default_kev_dir', lambda: tmp_path_factory.getbasetemp() / 'no-kev-catalog')
