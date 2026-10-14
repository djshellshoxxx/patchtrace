"""Live capa / FLOSS / diec acceptance (SPEC-29 tools T9). REAL pinned tools only; mocked tests live elsewhere.

Never skipped: without `PATCHTRACE_CAPA` / `PATCHTRACE_FLOSS` / `PATCHTRACE_DIEC` an engine records `blocked` in
build/live-status/intel-tools-<engine>.json and the run prints `LIVE ACCEPTANCE BLOCKED`. With
`PATCHTRACE_REQUIRE_LIVE_INTEL_TOOLS=1` (set by the live workflow after a verified provisioning) an unavailable or
unsupported tool FAILS. The tools run on the SYNTHETIC PE pairs of tests/test_intel_tools_pe.py and are compared
with the committed goldens (tests/fixtures/intel_tools, captured from the same pinned releases); that is real-tool
behaviour on synthetic input, never evidence about real binaries.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import threading
from pathlib import Path

import pytest
from intel_tools_support import golden
from test_intel_tools_pe import PAIRS

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.tools import capa, diec, floss, runner, store
from patchtrace.intelligence.tools.common import DEFAULT_LIMITS
from patchtrace.intelligence.tools.normalize import PeMap
from patchtrace.intelligence.tools.process import ArtifactCopy
from patchtrace.service import ProjectService

REQUIRE = os.environ.get('PATCHTRACE_REQUIRE_LIVE_INTEL_TOOLS') == '1'
ENV = {'capa': 'PATCHTRACE_CAPA', 'floss': 'PATCHTRACE_FLOSS', 'diec': 'PATCHTRACE_DIEC'}
PAIR = {'capa': 'capa-api', 'floss': 'floss-static', 'diec': 'diec-same'}


def executable(engine: str, record) -> Path:
    value = os.environ.get(ENV[engine])
    if not value or not Path(value).is_file():
        reason = f'{ENV[engine]} is not set to an existing file (run tools/provision_intel_tools.py)'
        record(f'intel-tools-{engine}', 'failed' if REQUIRE else 'blocked', reason)
        if REQUIRE:
            pytest.fail(reason)
        pytest.skip(reason)  # recorded as blocked in the status JSON and printed by conftest; never silent
    return Path(value)


def setup_for(engine: str, exe: Path) -> runner.Setup:
    if engine == 'capa':
        return runner.Setup(capa=capa.CapaConfig(exe))
    if engine == 'floss':
        return runner.Setup(floss=floss.FlossConfig(exe))
    database = os.environ.get('PATCHTRACE_DIEC_DB')
    return runner.Setup(diec=diec.DiecConfig(exe, database=Path(database) if database else None,
                                             library_path=None))


def golden_content(engine: str, side: str, tmp_path: Path):
    data = dict(zip(('older', 'newer'), PAIRS[PAIR[engine]](), strict=True))[side]
    path = tmp_path / f'golden-{side}.bin'
    path.write_bytes(data)
    copy = ArtifactCopy(path, hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest(),
                        hashlib.sha1(data).hexdigest(), len(data))
    from patchtrace.artifact_bytes import VerifiedArtifactReader
    reader = VerifiedArtifactReader.open_path(path, copy.sha256)
    try:
        pe = PeMap.from_reader(reader)
        key = 'c' * 64
        if engine == 'capa':
            return capa.parse(golden(f'capa/capa-api-{side}.json'),
                              capa.ParseContext('g', side, copy, key, key, pe, DEFAULT_LIMITS['capa']))
        if engine == 'floss':
            return floss.parse(golden(f'floss/floss-static-{side}.static.json'),
                               floss.ParseContext('g', side, copy, key, key, pe, reader, DEFAULT_LIMITS['floss'],
                                                  False))
        return diec.parse(golden(f'diec/diec-same-{side}.json'),
                          diec.ParseContext('g', side, copy.sha256, key, key, DEFAULT_LIMITS['diec']))
    finally:
        reader.close()


def comparable(evidence) -> set:
    """Content without run identity, timestamps or paths."""
    caps = {(c.rule_id, c.scope, c.location.rva, c.location.function_id) for c in evidence.capabilities}
    strings = {(s.value_hash, s.type, s.encoding, s.source_location.file_offset) for s in evidence.strings}
    env = {(e.category, e.detector_rule, e.certainty, e.version) for e in evidence.environment}
    return caps | strings | env


@pytest.mark.parametrize('engine', ['capa', 'floss', 'diec'])
def test_pinned_tool_probes_and_reproduces_the_goldens(engine, tmp_path, record_live_status):
    exe = executable(engine, record_live_status)
    older, newer = PAIRS[PAIR[engine]]()
    files = {}
    for side, data in (('older', older), ('newer', newer)):
        files[side] = tmp_path / f'{side}.exe'
        files[side].write_bytes(data)
    service = ProjectService.create(files['older'], files['newer'], 'live', tmp_path / 'case')
    try:
        setup = setup_for(engine, exe)
        manifest = runner.probe_engine(engine, setup.config(engine), threading.Event(), runner.run_process)
        if not manifest.supported or manifest.pin_status != 'pinned':
            reason = f'{engine} is not usable or not the pinned build: {manifest.reason or manifest.pin_status}'
            if engine == 'diec' and not REQUIRE:
                record_live_status(f'intel-tools-{engine}', 'blocked', reason)
                pytest.skip(reason)
            record_live_status(f'intel-tools-{engine}', 'failed', reason)
            pytest.fail(reason)
        ts = store.ToolStore(EnrichmentStore(service.store), service.root, service.project.id,
                             service.project.revision)
        refs = tuple(runner.ArtifactRef(a.side, service.root / a.relative_path, a.sha256, a.size)
                     for a in service.project.artifacts)
        profile = {'capa': 'basic', 'floss': 'context', 'diec': 'full'}[engine]
        results = runner.run_tools(runner.RunRequest(refs, setup, profile=profile, engines=(engine,)), ts,
                                   threading.Event())
        statuses = [r.run.status for r in results]
        if statuses != ['ok', 'ok']:
            record_live_status(f'intel-tools-{engine}', 'failed', f'run statuses {statuses}: '
                               f'{[r.run.error for r in results]}')
            pytest.fail(f'{engine}: {statuses}')
        for result in results:
            expected = comparable(golden_content(engine, result.run.side, tmp_path))
            if comparable(result.evidence) != expected:
                record_live_status(f'intel-tools-{engine}', 'failed', 'live evidence differs from the golden')
                pytest.fail(f'{engine} {result.run.side}: live evidence differs from the committed golden')
        record_live_status(f'intel-tools-{engine}', 'passed',
                           f'pinned {manifest.version} reproduced the goldens on the synthetic pair',
                           version=manifest.version, input='synthetic')
    finally:
        service.store.close()


def test_floss_default_runs_without_network_and_without_emulation(tmp_path, record_live_status):
    exe = executable('floss', record_live_status)
    unshare = shutil.which('unshare')
    if os.name == 'nt' or unshare is None:
        record_live_status('intel-tools-floss-offline', 'blocked', 'unshare -rn is unavailable on this platform')
        pytest.skip('unshare -rn is unavailable')
    sample = tmp_path / 'sample.bin'
    sample.write_bytes(PAIRS['floss-static']()[0])
    argv = floss.build_argv(floss.FlossConfig(exe), str(exe), sample)
    assert 'stack' not in argv and 'decoded' not in argv
    probe = subprocess.run([unshare, '-rn', 'true'], capture_output=True)  # noqa: S603
    if probe.returncode != 0:
        record_live_status('intel-tools-floss-offline', 'blocked', 'user namespaces are not permitted here')
        pytest.skip('unshare -rn not permitted')
    done = subprocess.run([unshare, '-rn', *argv], capture_output=True, timeout=300, cwd=tmp_path,  # noqa: S603
                          env={'HOME': str(tmp_path), 'TMPDIR': str(tmp_path), 'PATH': '/usr/bin:/bin'})
    ok = done.returncode == 0 and done.stdout.strip().startswith(b'{')
    record_live_status('intel-tools-floss-offline', 'passed' if ok else 'failed',
                       'FLOSS static strings ran in an empty network namespace' if ok else
                       f'exit {done.returncode}')
    assert ok
