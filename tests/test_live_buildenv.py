"""Live build-environment acceptance (DIE plan s9 D8). REAL pinned `diec` 3.21 on the SYNTHETIC PE pairs; never evidence
about real binaries and never a Microsoft binary.

Never skipped silently: without `PATCHTRACE_DIEC` the case records `blocked` in build/live-status/buildenv-diec.json and
the run prints `LIVE ACCEPTANCE BLOCKED`. With `PATCHTRACE_REQUIRE_LIVE_INTEL_TOOLS=1` (set by the dispatch-only
workflow job after a verified provisioning) an unusable tool FAILS. The live toolchain verdict and the change set must
equal what the committed goldens (captured from the same pinned release) give through the same code.
"""
from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest
from test_buildenv_support import pair_fingerprints
from test_intel_tools_pe import PAIRS

from patchtrace.buildenv.cli import _read_sides
from patchtrace.buildenv.delta import compute_delta
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.tools import diec, runner, store
from patchtrace.service import ProjectService

REQUIRE = os.environ.get('PATCHTRACE_REQUIRE_LIVE_INTEL_TOOLS') == '1'
ENGINE = 'buildenv-diec'
CASES = {'diec-same': ('same', 'same'), 'diec-toolchain': ('toolchain', 'differs')}  # pair -> (golden kind, verdict)


def changes_of(delta) -> set[tuple]:
    return {(c.key, c.older, c.newer, c.change, c.strength) for c in delta.changes if c.change != 'unchanged'}


def diec_exe(record) -> Path:
    value = os.environ.get('PATCHTRACE_DIEC')
    if not value or not Path(value).is_file():
        reason = 'PATCHTRACE_DIEC is not set to an existing file (run tools/provision_intel_tools.py)'
        record(ENGINE, 'failed' if REQUIRE else 'blocked', reason)
        if REQUIRE:
            pytest.fail(reason)
        pytest.skip(reason)  # recorded as blocked and printed by conftest; never silent
    return Path(value)


@pytest.mark.parametrize('pair', sorted(CASES), ids=['same', 'toolchain'])
def test_live_diec_gives_the_golden_build_delta(pair, tmp_path, record_live_status):
    exe = diec_exe(record_live_status)
    older, newer = PAIRS[pair]()
    files = {}
    for side, data in (('older', older), ('newer', newer)):
        files[side] = tmp_path / f'{side}.exe'
        files[side].write_bytes(data)
    service = ProjectService.create(files['older'], files['newer'], 'live', tmp_path / 'case')
    try:
        database = os.environ.get('PATCHTRACE_DIEC_DB')
        setup = runner.Setup(diec=diec.DiecConfig(exe, database=Path(database) if database else None,
                                                  library_path=None))
        manifest = runner.probe_engine('diec', setup.config('diec'), threading.Event(), runner.run_process)
        if not manifest.supported or manifest.pin_status != 'pinned':
            reason = f'diec is not usable or not the pinned build: {manifest.reason or manifest.pin_status}'
            record_live_status(ENGINE, 'failed' if REQUIRE else 'blocked', reason)
            pytest.fail(reason) if REQUIRE else pytest.skip(reason)
        tools = store.ToolStore(EnrichmentStore(service.store), service.root, service.project.id,
                                service.project.revision)
        refs = tuple(runner.ArtifactRef(a.side, service.root / a.relative_path, a.sha256, a.size)
                     for a in service.project.artifacts)
        statuses = [r.run.status for r in runner.run_tools(
            runner.RunRequest(refs, setup, profile='full', engines=('diec',)), tools, threading.Event())]
        if statuses != ['ok', 'ok']:
            record_live_status(ENGINE, 'failed', f'{pair}: diec run statuses {statuses}')
            pytest.fail(f'{pair}: {statuses}')
        sides = _read_sides(service, ('older', 'newer'), threading.Event())
        live = compute_delta(sides[0].fingerprint, sides[1].fingerprint)
        kind, verdict = CASES[pair]
        golden = compute_delta(*pair_fingerprints(tmp_path, pair, kind))
        problems = []
        if live.toolchain != verdict:
            problems.append(f'toolchain {live.toolchain}, expected {verdict}')
        if changes_of(live) != changes_of(golden):
            problems.append('live change set differs from the golden')
        if problems:
            record_live_status(ENGINE, 'failed', f'{pair}: ' + '; '.join(problems))
            pytest.fail(f'{pair}: ' + '; '.join(problems))
        record_live_status(ENGINE, 'passed', f'pinned {manifest.version} reproduced the golden build delta for {pair}',
                           version=manifest.version, input='synthetic')
    finally:
        service.store.close()
