"""Live capa pair-delta acceptance (CAP-8). REAL pinned capa only; the mocked legs are test_capa_pairs / _synergy.

Never skipped silently: without `PATCHTRACE_CAPA` the check records `blocked` in build/live-status/capa-pairs-*.json
and the run prints `LIVE ACCEPTANCE BLOCKED`. With `PATCHTRACE_REQUIRE_LIVE_CAPA=1` (the required Linux leg of
live-capa.yml) an unavailable, unsupported or unpinned capa FAILS. The pinned capa runs on the SYNTHETIC `capa-api`
pair and the resulting `capa-pairs/1` delta is compared with the committed golden `expected-pairs-capa-api.json`:
real-tool behaviour on synthetic input, never evidence about real binaries or a measure of accuracy."""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import pytest
from intel_tools_support import FIXTURES
from test_capa_synergy import BASE, CHANGED, UNCHANGED_RAW
from test_intel_tools_pe import PAIRS

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.tools import capa, runner, store
from patchtrace.intelligence.tools.capa_pairs import compute_pairs, groups_from_project
from patchtrace.service import ProjectService

REQUIRE = os.environ.get('PATCHTRACE_REQUIRE_LIVE_CAPA') == '1'
EXPECTED = FIXTURES / 'expected-pairs-capa-api.json'
COMPARED = ('comparable', 'pairing', 'changes', 'unattributed', 'coverage', 'counts', 'value_gate')
ENGINE = 'capa-pairs-api'


def block_or_fail(record, engine: str, reason: str) -> None:
    record(engine, 'failed' if REQUIRE else 'blocked', reason)
    if REQUIRE:
        pytest.fail(reason)
    pytest.skip(reason)  # recorded as blocked in the status JSON and printed by conftest; never silent


def capa_executable(record, engine: str) -> Path:
    value = os.environ.get('PATCHTRACE_CAPA')
    if not value or not Path(value).is_file():
        block_or_fail(record, engine, 'PATCHTRACE_CAPA is not set to an existing file '
                                      '(run tools/provision_intel_tools.py)')
    return Path(value)


def comparable(delta: dict) -> dict:
    """The delta without run identity."""
    return {key: delta[key] for key in COMPARED}


def test_pinned_capa_reproduces_the_golden_pair_delta(tmp_path, record_live_status):
    exe = capa_executable(record_live_status, ENGINE)
    older, newer = PAIRS['capa-api']()
    files = {}
    for side, data in (('older', older), ('newer', newer)):
        files[side] = tmp_path / f'{side}.exe'
        files[side].write_bytes(data)
    service = ProjectService.create(files['older'], files['newer'], 'live', tmp_path / 'case')
    try:
        setup = runner.Setup(capa=capa.CapaConfig(exe))
        manifest = runner.probe_engine('capa', setup.config('capa'), threading.Event(), runner.run_process)
        if not manifest.supported or manifest.pin_status != 'pinned':
            reason = f'capa is not usable or not the pinned build: {manifest.reason or manifest.pin_status}'
            if not REQUIRE:
                record_live_status(ENGINE, 'blocked', reason)
                pytest.skip(reason)
            record_live_status(ENGINE, 'failed', reason)
            pytest.fail(reason)
        ts = store.ToolStore(EnrichmentStore(service.store), service.root, service.project.id,
                             service.project.revision)
        refs = tuple(runner.ArtifactRef(a.side, service.root / a.relative_path, a.sha256, a.size)
                     for a in service.project.artifacts)
        results = runner.run_tools(runner.RunRequest(refs, setup, profile='basic', engines=('capa',)), ts,
                                   threading.Event())
        statuses = [r.run.status for r in results]
        if statuses != ['ok', 'ok']:
            record_live_status(ENGINE, 'failed', f'run statuses {statuses}: {[r.run.error for r in results]}')
            pytest.fail(f'capa: {statuses}')
        by_side = {r.run.side: r for r in results}
        groups = groups_from_project(CHANGED, UNCHANGED_RAW, (BASE, BASE))
        live = compute_pairs(by_side['older'].run, by_side['older'].evidence, by_side['newer'].run,
                             by_side['newer'].evidence, groups, include_unchanged=True)
        got = comparable(json.loads(live.model_dump_json()))
        want = comparable(json.loads(EXPECTED.read_text(encoding='utf-8')))
        if got != want:
            record_live_status(ENGINE, 'failed', 'live pair delta differs from the committed golden')
            pytest.fail('live capa pair delta differs from expected-pairs-capa-api.json')
        record_live_status(ENGINE, 'passed',
                           f'pinned capa {manifest.version} reproduced the pair-delta golden on the synthetic pair',
                           version=manifest.version, input='synthetic')
    finally:
        service.store.close()


def test_move_pair_needs_its_builder(record_live_status):
    """The `capa-move` PE pair (tests/capa_pairs_pe.py, CAP-2) is not on this base: record it, never pass silently."""
    if (Path(__file__).parent / 'capa_pairs_pe.py').is_file():
        pytest.skip('capa_pairs_pe.py exists: replace this placeholder with the live capa-move leg')
    reason = 'tests/capa_pairs_pe.py (capa-move pair builder) is absent, so the live move leg cannot run'
    record_live_status('capa-pairs-move', 'blocked', reason)
    pytest.skip(reason)
