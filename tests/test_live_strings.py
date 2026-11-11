"""Live strings acceptance (WB3 s9). REAL pinned FLOSS only; the mocked orchestration lives in test_ui_strings_run.

Never silent: without `PATCHTRACE_FLOSS` the live tests record `blocked` in build/live-status and the run prints
`LIVE ACCEPTANCE BLOCKED`; with `PATCHTRACE_REQUIRE_LIVE_INTEL_TOOLS=1` an unusable or unpinned FLOSS FAILS. The
goldens in tests/fixtures/strings/goldens are derived from the committed FLOSS 3.1.1 output of the SYNTHETIC
pairs (never a real binary); `test_goldens_match_the_committed_floss_output` keeps them honest without the tool.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import pytest
from test_ui_strings_run import fake_floss, make_project

from patchtrace.intelligence.tools import floss
from patchtrace.strings.run_service import make_request, run_strings
from patchtrace.strings.table import ENCODINGS, TYPES

GOLDENS = Path(__file__).resolve().parent / 'fixtures' / 'strings' / 'goldens'
REQUIRE = os.environ.get('PATCHTRACE_REQUIRE_LIVE_INTEL_TOOLS') == '1'
CASES = {'static': ('floss-static', False), 'decode': ('floss-decode', True)}


def golden_rows(outcome) -> dict[str, list[list]]:
    """Content without run identity, paths, timestamps or addresses: what FLOSS found and where in the file."""
    return {side.side: sorted([bytes(r.value_sha256).hex(), TYPES[r.type], ENCODINGS[r.encoding], r.length, r.offset]
                              for r in side.table) for side in outcome.sides}


def committed(case: str) -> dict:
    return json.loads((GOLDENS / f'floss-{case}.json').read_text(encoding='utf-8'))


@pytest.mark.parametrize('case', CASES, ids=list(CASES))
def test_goldens_match_the_committed_floss_output(case, tmp_path):
    pair, deobfuscate = CASES[case]
    service = make_project(tmp_path, pair)
    try:
        config = fake_floss(tmp_path, service, deobfuscate=deobfuscate,
                            consent_sha256=floss.EMULATION_CONSENT_SHA256 if deobfuscate else None)
        outcome = run_strings(make_request(service, floss=config), threading.Event())
    finally:
        service.close()
    assert outcome.state == 'ready'
    assert committed(case)['sides'] == golden_rows(outcome)


@pytest.mark.parametrize('case', CASES, ids=list(CASES))
def test_pinned_floss_reproduces_the_string_goldens(case, tmp_path, record_live_status):
    name = f'strings-floss-{case}'
    value = os.environ.get('PATCHTRACE_FLOSS')
    if not value or not Path(value).is_file():
        reason = 'PATCHTRACE_FLOSS is not set to an existing file (run tools/provision_intel_tools.py)'
        record_live_status(name, 'failed' if REQUIRE else 'blocked', reason)
        if REQUIRE:
            pytest.fail(reason)
        pytest.skip(reason)
    pair, deobfuscate = CASES[case]
    config = floss.FlossConfig(Path(value), deobfuscate=deobfuscate,
                               consent_sha256=floss.EMULATION_CONSENT_SHA256 if deobfuscate else None)
    service = make_project(tmp_path, pair)
    try:
        outcome = run_strings(make_request(service, floss=config), threading.Event())
    finally:
        service.close()
    if outcome.state != 'ready':
        record_live_status(name, 'failed', f'{outcome.code}: {outcome.message}')
        pytest.fail(f'{outcome.state} {outcome.code}')
    if golden_rows(outcome) != committed(case)['sides']:
        record_live_status(name, 'failed', 'live strings differ from the committed golden')
        pytest.fail(f'{case}: live strings differ from the committed golden')
    record_live_status(name, 'passed', 'pinned FLOSS reproduced the string goldens on the synthetic pair',
                       version=outcome.sides[0].table.basis.parts[0].source_version, input='synthetic')
