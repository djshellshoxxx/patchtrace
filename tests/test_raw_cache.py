"""SPEC-07 §13 raw-output cache integration, using a fake Ghidriff child only."""
import dataclasses
import shutil
import threading
from pathlib import Path

import pytest
from test_jobs import fake_runtime, write_backend  # noqa: F401 - pytest fixture reuse

from patchtrace import backend
from patchtrace.backend import run_comparison
from patchtrace.enrichment import cache as cache_module
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService


def _ghidriff_body(project, counter: Path) -> str:
    older = next(a.sha256 for a in project.artifacts if a.side == 'older')
    newer = next(a.sha256 for a in project.artifacts if a.side == 'newer')
    document = {'old_meta': {'SHA256': older}, 'new_meta': {'SHA256': newer},
                'functions': {'added': [{'name': 'fresh_fn', 'address': '1000'}],
                              'deleted': [], 'modified': []}}
    # The counter proves whether the external engine actually ran.
    return (f'c=pathlib.Path({str(counter)!r});c.write_text(str(int(c.read_text() or 0)+1) if c.exists() else "1")\n'
            f'(out/"json"/"old-new.ghidriff.json").write_text(json.dumps({document!r}))\n')


@pytest.fixture
def cached(fake_runtime, monkeypatch, tmp_path):  # noqa: F811
    base, package, _fixture_project, config = fake_runtime
    (base / 'older.dll').write_bytes(synthetic_pe(0))
    (base / 'newer.dll').write_bytes(synthetic_pe(1))
    service = ProjectService.create(base / 'older.dll', base / 'newer.dll', 'cache case', base / 'case')
    root, project = service.root, service.project
    monkeypatch.setattr(backend, '_java_version', lambda *_: '21.0.2')
    counter = tmp_path / 'engine-runs.txt'
    write_backend(package, _ghidriff_body(project, counter))
    cache_dir = tmp_path / 'global-cache'
    config = dataclasses.replace(config, cache_dir=str(cache_dir))

    def run(cfg=None, proj=None):
        events = []
        path, result = run_comparison(cfg or config, proj or project, root, threading.Event(), events.append)
        return path, result, events

    def engine_runs():
        return int(counter.read_text()) if counter.exists() else 0
    yield root, project, config, cache_dir, run, engine_runs, service
    service.close()


def _raw_entries(cache_dir: Path) -> list[Path]:
    return list((cache_dir / 'v1' / 'raw').glob('*/*/manifest.json')) if cache_dir.exists() else []


def _normalize(service, path, run):
    prepared = service.prepare_analysis(path, run)
    service.discard_import(prepared)
    side = {'__all__': {'id', 'run_id'}}
    # IDs are per-run UUIDs; everything else must be identical.
    return [m.model_dump(exclude={'id': True, 'run_id': True, 'older': side, 'newer': side})
            for m in prepared.matches]


def test_miss_then_hit_is_byte_identical_and_normalizes_identically(cached):
    root, project, config, cache_dir, run, engine_runs, service = cached
    path1, run1, events1 = run()
    assert run1.status == 'completed' and engine_runs() == 1
    assert 'cache_origin' not in run1.settings
    assert len(_raw_entries(cache_dir)) == 1
    path2, run2, events2 = run()
    assert run2.status == 'completed' and engine_runs() == 1
    assert path2.read_bytes() == path1.read_bytes()
    assert run2.raw_sha256 == run1.raw_sha256 and run2.id != run1.id
    assert path2.is_relative_to(root / 'runs' / run2.id)
    origin = run2.settings['cache_origin']
    assert set(origin) == {'key', 'created'} and len(origin['key']) == 64
    assert {k: v for k, v in run2.settings.items() if k != 'cache_origin'} == run1.settings
    assert any(e.message == 'raw output reused from cache' for e in events2)
    assert not any(e.stage == 'analysis' for e in events2)
    assert _normalize(service, path1, run1) == _normalize(service, path2, run2)


def test_version_change_misses(cached, monkeypatch):
    _root, _project, _config, cache_dir, run, engine_runs, service = cached
    run()
    monkeypatch.setattr(backend, '_java_version', lambda *_: '25.0.1')
    _, result, _ = run()
    assert engine_runs() == 2 and 'cache_origin' not in result.settings
    assert len(_raw_entries(cache_dir)) == 2


def test_swapped_orientation_misses(cached):
    root, project, config, cache_dir, run, engine_runs, service = cached
    run()
    fp = backend._open_raw_cache(config, 'fake-test-only', {
        'ghidra_version': '12.0.4', 'pyghidra_version': 'fake-test-only', 'python_version': '3.12.0'},
        threading.Event())[1]
    older, newer = (next(a.sha256 for a in project.artifacts if a.side == s) for s in ('older', 'newer'))
    store = cache_module.DerivedCache(cache_module.CacheConfig(root=cache_dir))
    assert store.get_raw(fp, older, newer) is not None
    assert store.get_raw(fp, newer, older) is None


@pytest.mark.parametrize('field', ['java', 'pyghidra'])
def test_unknown_version_is_ineligible(cached, monkeypatch, field):
    _root, _project, _config, cache_dir, run, engine_runs, service = cached
    if field == 'java':
        monkeypatch.setattr(backend, '_java_version', lambda *_: 'unknown')
    else:
        monkeypatch.setattr(backend, '_probe_backend', lambda *_: {
            'python': '3.12.0', 'ghidriff': 'fake-test-only', 'pyghidra': 'unknown', 'available': True})
    run()
    run()
    assert engine_runs() == 2 and _raw_entries(cache_dir) == []


def test_online_symbol_policy_is_ineligible(cached):
    _root, _project, config, cache_dir, run, engine_runs, service = cached
    online = dataclasses.replace(config, allow_symbol_downloads=True)
    run(online)
    run(online)
    assert engine_runs() == 2 and _raw_entries(cache_dir) == []


def test_corrupted_entry_falls_back_to_real_run(cached):
    _root, _project, _config, cache_dir, run, engine_runs, service = cached
    path1, _, _ = run()
    (manifest,) = _raw_entries(cache_dir)
    (manifest.parent / 'payload').write_bytes(b'{"functions": "tampered"}')
    path2, result, _ = run()
    assert result.status == 'completed' and engine_runs() == 2
    assert 'cache_origin' not in result.settings
    assert path2.read_bytes() == path1.read_bytes()


def test_cache_deletion_after_hit_leaves_project_loadable(cached):
    root, project, _config, cache_dir, run, _engine_runs, service = cached
    run()
    path, result, _ = run()
    assert 'cache_origin' in result.settings
    service.apply_import(service.prepare_analysis(path, result))
    service.close()
    shutil.rmtree(cache_dir)
    reopened = ProjectService.open(root)
    try:
        stored = next(r for r in reopened.project.runs if r.id == result.id)
        assert stored.settings['cache_origin'] == result.settings['cache_origin']
        assert (root / stored.raw_path).is_file()
        assert reopened.project.matches
    finally:
        reopened.close()


def test_no_cache_does_no_cache_io(cached, monkeypatch):
    _root, _project, config, cache_dir, run, engine_runs, service = cached

    def forbidden(*_a, **_k):
        raise AssertionError('cache touched')
    monkeypatch.setattr(cache_module, 'DerivedCache', forbidden)
    run(dataclasses.replace(config, no_cache=True))
    assert engine_runs() == 1 and not cache_dir.exists()


def test_refresh_skips_read_but_admits(cached, monkeypatch):
    _root, _project, config, cache_dir, run, engine_runs, service = cached
    run()
    shutil.rmtree(cache_dir)
    reads = []
    monkeypatch.setattr(cache_module.DerivedCache, 'get_raw', lambda *a: reads.append(a))
    _, result, _ = run(dataclasses.replace(config, refresh=True))
    assert engine_runs() == 2 and reads == [] and 'cache_origin' not in result.settings
    assert len(_raw_entries(cache_dir)) == 1


def test_default_config_never_uses_cache(cached):
    root, project, config, cache_dir, run, engine_runs, service = cached
    run(dataclasses.replace(config, cache_dir=''))
    assert not cache_dir.exists()


def test_admission_failure_never_fails_run(cached, monkeypatch):
    _root, _project, _config, _cache_dir, run, _engine_runs, _service = cached

    def boom(*_a):
        raise OSError('disk full')
    monkeypatch.setattr(cache_module.DerivedCache, 'put_raw', boom)
    _, result, _ = run()
    assert result.status == 'completed'


def test_no_cache_and_refresh_together_rejected(cached):
    _root, _project, config, _cache_dir, run, _engine_runs, _service = cached
    _, result, _ = run(dataclasses.replace(config, no_cache=True, refresh=True))
    assert result.status == 'failed' and 'mutually exclusive' in result.error
