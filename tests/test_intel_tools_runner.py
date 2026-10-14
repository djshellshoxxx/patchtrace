"""SPEC-29 tools T4/T7 runner and store, driven through FAKE engine executables (a Python script behind a native
launcher, spawned by the real `jobs.run_process`). The fakes print committed REAL tool output captured on SYNTHETIC
PE pairs; they prove orchestration, containment and persistence, not tool behaviour. Not live evidence."""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

import pytest
from intel_tools_support import fake_engine, golden
from test_intel_tools_pe import PAIRS

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.tools import capa, diec, floss, process, runner, store
from patchtrace.intelligence.tools.common import ToolError, ToolLimits
from patchtrace.service import ProjectService

PAIR = 'capa-api'


@pytest.fixture
def project(tmp_path):
    older, newer = PAIRS[PAIR]()
    paths = {}
    for side, data in (('older', older), ('newer', newer)):
        paths[side] = tmp_path / f'{side}.exe'
        paths[side].write_bytes(data)
    service = ProjectService.create(paths['older'], paths['newer'], 'tools', tmp_path / 'case')
    yield service
    service.store.close()


def tool_store(service) -> store.ToolStore:
    return store.ToolStore(EnrichmentStore(service.store), service.root, service.project.id,
                           service.project.revision)


def artifacts(service) -> tuple[runner.ArtifactRef, ...]:
    return tuple(runner.ArtifactRef(a.side, service.root / a.relative_path, a.sha256, a.size)
                 for a in service.project.artifacts)


def output_map(service, engine: str) -> dict[str, str]:
    names = {'capa': 'capa/capa-api-{}.json', 'floss': 'floss/floss-static-{}.static.json'}
    return {a.sha256: golden(names[engine].format(a.side)).decode() for a in service.project.artifacts}


def body_for(service, engine: str, counter: Path, *, extra: str = '') -> str:
    return ('import hashlib, os, sys, time\n'
            f'open({str(counter)!r}, "a").write("x")\n' + extra +
            'sha = hashlib.sha256(open(ARGS[-1], "rb").read()).hexdigest()\n'
            f'OUT = {output_map(service, engine)!r}\n'
            'sys.stdout.write(OUT[sha])\n')


def capa_setup(tmp_path, service, **kw):
    counter = tmp_path / 'counter'
    exe = fake_engine(tmp_path / 'bin', 'capa', run_body=body_for(service, 'capa', counter, extra=kw.pop(
        'extra', '')))
    return runner.Setup(capa=capa.CapaConfig(exe, accept_untested=True)), counter


def request(service, setup, **kw) -> runner.RunRequest:
    return runner.RunRequest(artifacts(service), setup, scratch_root=kw.pop('scratch_root', None), **kw)


def spawns(counter: Path) -> int:
    return len(counter.read_text()) if counter.exists() else 0


def test_end_to_end_persists_runs_and_evidence_then_serves_the_cache(tmp_path, project):
    setup, counter = capa_setup(tmp_path, project)
    ts = tool_store(project)
    results = runner.run_tools(request(project, setup), ts, threading.Event())
    assert [r.run.status for r in results] == ['ok', 'ok'] and spawns(counter) == 2
    assert all(r.run.raw_sidecar and (project.root / r.run.raw_sidecar).is_file() for r in results)
    assert all(r.run.manifest.pin_status == 'unpinned' and r.run.manifest.untested_version for r in results)
    assert {r.side for r in ts.runs("capa")} == {'older', 'newer'}
    older = ts.latest('capa', 'older')
    assert older is not None and older[1].evidence_count() == older[0].evidence_count > 0
    again = runner.run_tools(request(project, setup), ts, threading.Event())
    assert [r.run.cache_hit for r in again] == [True, True] and spawns(counter) == 2   # no spawn on a hit
    assert len(ts.runs('capa')) == 4                                                    # new run records, same evidence
    fresh = runner.run_tools(request(project, setup, use_cache=False), ts, threading.Event())
    assert not any(r.run.cache_hit for r in fresh) and spawns(counter) == 4


def test_raw_stdout_is_stored_byte_exact_and_content_addressed(tmp_path, project):
    setup, _counter = capa_setup(tmp_path, project)
    result = runner.run_tools(request(project, setup), tool_store(project), threading.Event())[0]
    raw = (project.root / result.run.raw_sidecar).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == result.run.stdout_digest
    assert result.run.raw_sidecar.endswith(f'{result.run.stdout_digest}.json')


def test_missing_and_unconfigured_executables_are_absent_not_empty(tmp_path, project):
    setup = runner.Setup(capa=capa.CapaConfig(tmp_path / 'nope' / 'capa'))
    results = runner.run_tools(request(project, setup, profile='context'), tool_store(project), threading.Event())
    assert {(r.run.engine, r.run.status, r.run.error_code) for r in results} == {
        ('capa', 'absent', 'PT-TOOL-ABSENT'), ('floss', 'absent', 'PT-TOOL-ABSENT')}
    assert all(r.evidence is None and r.run.evidence_count == 0 for r in results)


def test_unpinned_build_is_unsupported_without_the_opt_in(tmp_path, project):
    setup, counter = capa_setup(tmp_path, project)
    strict = runner.Setup(capa=capa.CapaConfig(setup.capa.executable))
    results = runner.run_tools(request(project, strict), tool_store(project), threading.Event())
    assert {r.run.status for r in results} == {'unsupported'} and spawns(counter) == 0


def test_timeout_is_a_timeout_run_and_the_tree_is_killed(tmp_path, project, monkeypatch):
    monkeypatch.setattr(runner, 'TIMEOUT_RANGE', (1, 86_400))
    setup, _counter = capa_setup(tmp_path, project, extra='time.sleep(60)\n')
    started = time.monotonic()
    results = runner.run_tools(request(project, setup, timeout=1), tool_store(project), threading.Event())
    assert {(r.run.status, r.run.error_code) for r in results} == {('timeout', 'PT-TOOL-TIMEOUT')}
    assert time.monotonic() - started >= 1


def test_cancel_stops_a_running_job_and_pending_jobs_never_spawn(tmp_path, project):
    marker = tmp_path / 'started'
    setup, counter = capa_setup(tmp_path, project, extra=f'open({str(marker)!r}, "w").write("1")\ntime.sleep(60)\n')
    cancel = threading.Event()

    def trip():
        for _ in range(400):
            if marker.exists():
                cancel.set()
                return
            time.sleep(0.05)
        cancel.set()
    thread = threading.Thread(target=trip)
    thread.start()
    results = runner.run_tools(request(project, setup), tool_store(project), cancel)
    thread.join()
    assert [(r.run.status, r.run.error_code) for r in results] == [('cancelled', 'PT-TOOL-CANCEL')] * 2
    assert spawns(counter) == 1                      # the second job was cancelled before it was spawned


def test_oversize_output_is_a_limit_failure(tmp_path, project, monkeypatch):
    monkeypatch.setitem(runner.DEFAULT_LIMITS, 'capa', ToolLimits(1000, 4096))
    setup, _counter = capa_setup(tmp_path, project)
    results = runner.run_tools(request(project, setup), tool_store(project), threading.Event())
    assert {(r.run.status, r.run.error_code) for r in results} == {('failed', 'PT-TOOL-LIMIT')}


def test_stderr_noise_is_bounded_and_never_breaks_the_json(tmp_path, project):
    noise = 'sys.stderr.write("warning: noisy \\x1b[31m" * 20000)\n'
    setup, _counter = capa_setup(tmp_path, project, extra=noise)
    results = runner.run_tools(request(project, setup), tool_store(project), threading.Event())
    assert [r.run.status for r in results] == ['ok', 'ok']
    assert all(len(r.run.stderr_excerpt) <= 4096 and '\x1b' not in r.run.stderr_excerpt for r in results)


def test_nonzero_exit_is_a_failed_run_with_a_sanitised_message(tmp_path, project):
    setup, _counter = capa_setup(tmp_path, project, extra='sys.stderr.write("ERROR: /home/secret/user/x broke\\n")\n'
                                 'sys.exit(3)\n')
    run = runner.run_tools(request(project, setup), tool_store(project), threading.Event())[0].run
    assert (run.status, run.error_code, run.returncode) == ('failed', 'PT-TOOL-RUN', 3)
    assert '/home/secret' not in (run.error or '')


def test_corrupt_output_is_failed_output_and_keeps_earlier_results(tmp_path, project):
    setup, _counter = capa_setup(tmp_path, project)
    ts = tool_store(project)
    runner.run_tools(request(project, setup), ts, threading.Event())
    bad_exe = fake_engine(tmp_path / 'bin2', 'capa', run_body='sys.stdout.write("{not json")\n')
    bad = runner.Setup(capa=capa.CapaConfig(bad_exe, accept_untested=True))
    results = runner.run_tools(request(project, bad), ts, threading.Event())
    assert {(r.run.status, r.run.error_code) for r in results} == {('failed', 'PT-TOOL-OUTPUT')}
    assert ts.latest('capa', 'older') is not None        # the earlier good run is untouched


def test_floss_empty_stdout_is_none_found_with_stored_empty_evidence(tmp_path, project):
    exe = fake_engine(tmp_path / 'bin', 'floss', run_body='')
    setup = runner.Setup(floss=floss.FlossConfig(exe, accept_untested=True))
    results = runner.run_tools(request(project, setup, profile='context', engines=('floss',)),
                               tool_store(project), threading.Event())
    assert {r.run.status for r in results} == {'none-found'} and all(r.evidence.evidence_count() == 0
                                                                      for r in results)


def test_stale_cache_hit_is_a_miss_and_the_tool_runs(tmp_path, project, monkeypatch):
    monkeypatch.setattr(store, 'INLINE_LIMIT', 10)       # force sidecar pointers
    setup, counter = capa_setup(tmp_path, project)
    ts = tool_store(project)
    runner.run_tools(request(project, setup), ts, threading.Event())
    sidecars = [p for p in (project.root / 'intel-tools').glob('*.json')]
    assert len(sidecars) == 2
    sidecars[0].write_bytes(sidecars[0].read_bytes() + b' ')   # corrupt one sidecar
    again = runner.run_tools(request(project, setup), ts, threading.Event())
    assert sorted(r.run.cache_hit for r in again) == [False, True] and spawns(counter) == 3


def test_changed_executable_changes_the_cache_key(tmp_path, project):
    setup, counter = capa_setup(tmp_path, project)
    ts = tool_store(project)
    runner.run_tools(request(project, setup), ts, threading.Event())
    other = fake_engine(tmp_path / 'bin3', 'capa', run_body=body_for(project, 'capa', counter, extra='# v2\n'))
    runner.run_tools(request(project, runner.Setup(capa=capa.CapaConfig(other, accept_untested=True))), ts,
                     threading.Event())
    assert spawns(counter) == 4


def test_executable_swapped_after_the_probe_is_stale(tmp_path, project):
    setup, counter = capa_setup(tmp_path, project)
    req = request(project, setup)
    manifest = capa.probe(setup.capa, use_cache=False)
    assert manifest.supported
    Path(setup.capa.executable).write_text('#!/bin/sh\necho swapped\n', encoding='utf-8')
    result = runner.run_job('capa', req.artifacts[0], manifest, req, threading.Event(), runner.run_process,
                            project.root)
    assert (result.run.status, result.run.error_code) == ('failed', 'PT-TOOL-STALE') and spawns(counter) == 0


def test_child_environment_is_the_allow_list_and_the_target_is_data(tmp_path, project, monkeypatch):
    monkeypatch.setenv('HTTPS_PROXY', 'http://proxy.invalid:3128')
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'sekrit')
    monkeypatch.setenv('PYTHONPATH', '/evil')
    seen = tmp_path / 'seen.json'
    extra = (f'import json, stat\nopen({str(seen)!r}, "w").write(json.dumps({{"env": sorted(os.environ), '
             '"mode": os.stat(ARGS[-1]).st_mode, "cwd": os.getcwd(), "arg": ARGS[-1]}))\n')
    setup, _counter = capa_setup(tmp_path, project, extra=extra)
    runner.run_tools(request(project, setup), tool_store(project), threading.Event())
    info = json.loads(seen.read_text())
    assert not {'HTTPS_PROXY', 'AWS_SECRET_ACCESS_KEY', 'PYTHONPATH'} & set(info['env'])
    assert info['arg'].endswith('artifact.bin') and str(project.root) not in info['arg']
    if os.name != 'nt':
        assert info['mode'] & 0o111 == 0 and info['mode'] & 0o222 == 0     # read-only, never executable


def test_long_scratch_root_is_rejected_before_anything_runs(tmp_path, project):
    setup, counter = capa_setup(tmp_path, project)
    long_root = tmp_path / ('d' * 120) / ('e' * 120)
    results = runner.run_tools(request(project, setup, scratch_root=long_root), tool_store(project),
                               threading.Event())
    assert {(r.run.status, r.run.error_code) for r in results} == {('failed', 'PT-TOOL-INPUT')}
    assert spawns(counter) == 0


def test_windows_environment_layout_is_private_and_semicolon_separated(tmp_path):
    scratch = process.make_scratch('win', tmp_path)
    env = process.tool_env(Path('C:/tools/capa/capa.exe'), scratch, windows=True,
                           environ={'SystemRoot': 'C:\\Windows', 'USERNAME': 'someone', 'HTTP_PROXY': 'x'})
    assert env['SystemRoot'] == 'C:\\Windows' and 'HTTP_PROXY' not in env and 'USERNAME' not in env
    assert ';' in env['PATH']
    for key in ('TEMP', 'TMP', 'APPDATA', 'LOCALAPPDATA'):
        assert str(scratch) in env[key]


def test_profiles_and_engine_subsets_are_validated(tmp_path, project):
    setup, _counter = capa_setup(tmp_path, project)
    ts = tool_store(project)
    for bad in (dict(profile='basic', engines=('floss',)), dict(profile='bogus'), dict(profile='full', engines=())):
        with pytest.raises(ToolError) as info:
            runner.run_tools(request(project, setup, **bad), ts, threading.Event())
        assert info.value.code == 'PT-TOOL-INPUT'
    with pytest.raises(ToolError):
        runner.run_tools(request(project, setup, max_parallel=3), ts, threading.Event())


def test_two_workers_persist_every_result_on_the_calling_thread(tmp_path, project):
    setup, counter = capa_setup(tmp_path, project)
    owner = threading.get_ident()
    threads = []
    results = runner.run_tools(request(project, setup, max_parallel=2), tool_store(project), threading.Event(),
                               on_result=lambda _r: threads.append(threading.get_ident()))
    assert [r.run.status for r in results] == ['ok', 'ok'] and spawns(counter) == 2
    assert set(threads) == {owner}


def test_diec_without_a_database_is_unsupported_not_failed(tmp_path, project):
    exe = fake_engine(tmp_path / 'bin', 'diec', run_body='sys.stdout.write("{}")\n')
    setup = runner.Setup(diec=diec.DiecConfig(exe, accept_untested=True))
    results = runner.run_tools(request(project, setup, profile='full', engines=('diec',)), tool_store(project),
                               threading.Event())
    assert {r.run.status for r in results} == {'unsupported'}
