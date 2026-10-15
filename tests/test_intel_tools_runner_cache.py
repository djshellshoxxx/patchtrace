"""CAP-4 wiring: the raw capa cache inside `runner.run_job`. Fake engine, no real capa; a hit never spawns."""
from __future__ import annotations

import threading
from pathlib import Path

import pytest
from intel_tools_support import fake_engine
from test_intel_tools_runner import (
    body_for,
    capa_setup,
    request,
    spawns,
)
from test_intel_tools_runner import project as base_project  # noqa: F401 - re-exported fixture

from patchtrace.intelligence.tools import capa, runner
from patchtrace.jobs import run_process as process_runner


@pytest.fixture
def project(base_project):  # noqa: F811
    return base_project


def cached_setup(tmp_path, service, **kw):
    counter = tmp_path / 'counter'
    exe = fake_engine(tmp_path / 'bin', 'capa', run_body=body_for(service, 'capa', counter, extra=kw.pop('extra', '')))
    return runner.Setup(capa=capa.CapaConfig(exe, accept_untested=True, cache_dir=tmp_path / 'rawcache')), counter


def entries(tmp_path) -> list[Path]:
    return [p for p in (tmp_path / 'rawcache').rglob('*')
            if p.is_file() and 'capa-raw' in p.parts and p.name != 'manifest.json']


def run(service, setup, cancel=None, **kw):
    """Jobs straight through `run_job`: the project store's own evidence cache would otherwise answer first."""
    req, cancel = request(service, setup, **kw), cancel or threading.Event()
    manifest = runner.probe_engine('capa', setup.capa, cancel, process_runner)
    return [runner.run_job('capa', a, manifest, req, cancel, process_runner, service.root) for a in req.artifacts]


def test_hit_reparses_without_spawning_even_with_an_empty_project_store(tmp_path, project):
    setup, counter = cached_setup(tmp_path, project)
    first = run(project, setup)
    assert spawns(counter) == 2 and len(entries(tmp_path)) == 2
    second = run(project, setup, use_cache=True)
    assert spawns(counter) == 2 and [r.run.status for r in second] == ['ok', 'ok']
    assert [r.evidence.evidence_count() for r in second] == [r.evidence.evidence_count() for r in first]


def test_cache_is_off_without_cache_dir_or_with_use_cache_false(tmp_path, project):
    setup, counter = capa_setup(tmp_path, project)
    run(project, setup)
    run(project, setup, use_cache=False)
    assert spawns(counter) == 4 and not (tmp_path / 'rawcache').exists()
    setup, _ = cached_setup(tmp_path, project)
    run(project, setup, use_cache=False)
    assert spawns(counter) == 6 and not entries(tmp_path)


def test_corrupt_entry_is_a_miss_and_is_rewritten(tmp_path, project):
    setup, counter = cached_setup(tmp_path, project)
    run(project, setup)
    for entry in entries(tmp_path):
        entry.write_bytes(b'not zlib at all')
    again = run(project, setup)
    assert spawns(counter) == 4 and {r.run.status for r in again} == {'ok'}
    run(project, setup)
    assert spawns(counter) == 4


def test_nonzero_exit_and_unparseable_output_are_never_cached(tmp_path, project):
    setup, _counter = cached_setup(tmp_path, project, extra='sys.exit(3)\n')
    run(project, setup)
    assert not entries(tmp_path)
    bad = fake_engine(tmp_path / 'bin2', 'capa', run_body='sys.stdout.write("{not json")\n')
    setup = runner.Setup(capa=capa.CapaConfig(bad, accept_untested=True, cache_dir=tmp_path / 'rawcache'))
    results = run(project, setup)
    assert {r.run.error_code for r in results} == {'PT-TOOL-OUTPUT'} and not entries(tmp_path)


def test_cancelled_run_is_never_cached(tmp_path, project):
    setup, counter = cached_setup(tmp_path, project)
    cancel = threading.Event()
    cancel.set()
    results = run(project, setup, cancel)
    assert {r.run.status for r in results} == {'cancelled'} and spawns(counter) == 0 and not entries(tmp_path)
