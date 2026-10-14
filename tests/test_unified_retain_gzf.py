"""SPEC-31 S1: retaining the analysed GZFs Ghidriff writes (D-05, 03 s8): the pure helper and the backend seam."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from test_jobs import fake_runtime, write_backend  # noqa: F401 - pytest fixture reuse

from patchtrace import backend
from patchtrace.backend import BackendConfig, run_comparison
from patchtrace.jobs import ProcessResult
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService
from patchtrace.unified.extract import retain

ROOT = Path(__file__).resolve().parents[1]


def sha1_name(path: Path) -> str:
    return f'{path.name}-{hashlib.sha1(path.read_bytes(), usedforsecurity=False).hexdigest()[:6]}.gzf'


@pytest.fixture
def pair(tmp_path):
    older, newer = tmp_path / 'in' / 'older.dll', tmp_path / 'in' / 'newer.dll'
    older.parent.mkdir()
    older.write_bytes(b'older-bytes')
    newer.write_bytes(b'newer-bytes')
    gzfs = tmp_path / 'scratch' / 'gzfs'
    gzfs.mkdir(parents=True)
    return {'older': older, 'newer': newer}, gzfs


def put_gzfs(sources, gzfs):
    for side, artifact in sources.items():
        (gzfs / sha1_name(artifact)).write_bytes(f'GZF-{side}'.encode() * 100)


# --- the pure helper ---------------------------------------------------------------------------------------------------

def test_retain_gzf_moves_two_files_and_records_hashes(pair, tmp_path):
    sources, gzfs = pair
    put_gzfs(dict(reversed(list(sources.items()))), gzfs)          # creation order must not matter
    target = tmp_path / 'run' / 'unified' / 'gzf'
    record = retain.retain_gzfs(gzfs, target, sources)
    assert set(record) == {'older', 'newer'}
    for side in ('older', 'newer'):
        data = f'GZF-{side}'.encode() * 100
        assert (target / f'{side}.gzf').read_bytes() == data
        assert record[side] == {'name': sha1_name(sources[side]), 'sha256': hashlib.sha256(data).hexdigest(),
                                'bytes': len(data)}
    assert list(gzfs.iterdir()) == [] and sorted(p.name for p in target.iterdir()) == ['newer.gzf', 'older.gzf']
    json.dumps(record)                                              # settings must stay JSON-serialisable


def test_expected_name_follows_ghidriff_naming(pair):
    sources, _ = pair
    assert retain.expected_name(sources['older']) == sha1_name(sources['older'])


def test_files_are_assigned_by_exact_name_not_by_order(pair, tmp_path):
    sources, gzfs = pair
    put_gzfs(sources, gzfs)
    older_name, newer_name = sha1_name(sources['older']), sha1_name(sources['newer'])
    # swap the contents: the name decides the side, the script later checks the program hash
    (gzfs / older_name).write_bytes(b'belongs-to-older-name')
    (gzfs / newer_name).write_bytes(b'belongs-to-newer-name')
    retain.retain_gzfs(gzfs, tmp_path / 't', sources)
    assert (tmp_path / 't' / 'older.gzf').read_bytes() == b'belongs-to-older-name'
    assert (tmp_path / 't' / 'newer.gzf').read_bytes() == b'belongs-to-newer-name'


def deviations(sources, gzfs, tmp_path):
    """name -> setup callable; every deviation must retain nothing and leave the sources alone."""
    def one_file():
        put_gzfs({'older': sources['older']}, gzfs)

    def three_files():
        put_gzfs(sources, gzfs)
        (gzfs / 'extra-abcdef.gzf').write_bytes(b'x')

    def wrong_names():
        (gzfs / 'older.dll.gzf').write_bytes(b'x')
        (gzfs / 'newer.dll.gzf').write_bytes(b'x')

    def wrong_hash_suffix():
        (gzfs / 'older.dll-000000.gzf').write_bytes(b'x')
        (gzfs / sha1_name(sources['newer'])).write_bytes(b'x')

    def directory_instead_of_file():
        (gzfs / sha1_name(sources['older'])).mkdir()
        (gzfs / sha1_name(sources['newer'])).write_bytes(b'x')

    def stray_file():
        put_gzfs({'older': sources['older']}, gzfs)
        (gzfs / 'other.gzf').write_bytes(b'x')

    def symlink():
        put_gzfs({'older': sources['older']}, gzfs)
        target = tmp_path / 'outside.gzf'
        target.write_bytes(b'secret')
        try:
            os.symlink(target, gzfs / sha1_name(sources['newer']))
        except (OSError, NotImplementedError):
            pytest.skip('symlinks are not available here')

    return {'one': one_file, 'three': three_files, 'names': wrong_names, 'suffix': wrong_hash_suffix,
            'dir': directory_instead_of_file, 'stray': stray_file, 'link': symlink}


@pytest.mark.parametrize('name', ['one', 'three', 'names', 'suffix', 'dir', 'stray', 'link'])
def test_any_deviation_retains_nothing(pair, tmp_path, name):
    sources, gzfs = pair
    deviations(sources, gzfs, tmp_path)[name]()
    before = sorted(p.name for p in gzfs.iterdir())
    assert retain.retain_gzfs(gzfs, tmp_path / 'target', sources) is None
    assert sorted(p.name for p in gzfs.iterdir()) == before
    assert not (tmp_path / 'target').exists() or list((tmp_path / 'target').iterdir()) == []


def test_over_limit_retains_nothing(pair, tmp_path):
    sources, gzfs = pair
    put_gzfs(sources, gzfs)
    size = sum(p.stat().st_size for p in gzfs.iterdir())
    assert retain.retain_gzfs(gzfs, tmp_path / 't', sources, limit=size - 1) is None
    assert retain.retain_gzfs(gzfs, tmp_path / 't', sources, limit=size) is not None


def test_identical_artifacts_or_missing_sides_retain_nothing(pair, tmp_path):
    sources, gzfs = pair
    put_gzfs(sources, gzfs)
    assert retain.retain_gzfs(gzfs, tmp_path / 't', {'older': sources['older']}) is None
    assert retain.retain_gzfs(gzfs, tmp_path / 't', {'older': sources['older'], 'newer': sources['older']}) is None
    assert retain.retain_gzfs(tmp_path / 'missing', tmp_path / 't', sources) is None


def test_an_io_failure_midway_cleans_up_and_retains_nothing(pair, tmp_path, monkeypatch):
    sources, gzfs = pair
    put_gzfs(sources, gzfs)
    real_replace = os.replace
    calls = []

    def flaky(source, destination):
        calls.append(destination)
        if len(calls) == 2:
            raise PermissionError('antivirus holds the file')
        return real_replace(source, destination)

    monkeypatch.setattr(os, 'replace', flaky)
    target = tmp_path / 'target'
    assert retain.retain_gzfs(gzfs, target, sources) is None
    assert list(target.iterdir()) == []                          # no half-retained pair and no `.part` leftovers


def test_retain_run_gzfs_records_settings_or_warns_and_never_raises(pair, tmp_path, monkeypatch):
    sources, gzfs = pair
    events, settings = [], {'existing': 1}
    retain.retain_run_gzfs(gzfs, tmp_path / 'quarantine', sources, settings, lambda *a: events.append(a))
    assert settings == {'existing': 1} and [e[0] for e in events] == ['warning']
    put_gzfs(sources, gzfs)
    retain.retain_run_gzfs(gzfs, tmp_path / 'quarantine', sources, settings, lambda *a: events.append(a))
    assert set(settings['gzf']) == {'older', 'newer'} and len(events) == 1
    assert (tmp_path / 'quarantine' / 'unified' / 'gzf' / 'older.gzf').is_file()

    def explode(*_args, **_kwargs):
        raise RuntimeError('surprise')

    monkeypatch.setattr(retain, 'retain_gzfs', explode)
    retain.retain_run_gzfs(gzfs, tmp_path / 'q2', sources, {}, lambda *a: events.append(a))
    assert [e[0] for e in events] == ['warning', 'warning']


# --- the backend seam -----------------------------------------------------------------------------------------------------

GZF_BODY = (
    'import hashlib\n'
    'gz = pathlib.Path(sys.argv[sys.argv.index("--gzfs-path")+1]); gz.mkdir(parents=True, exist_ok=True)\n'
    'for number, path in enumerate(sys.argv[1:3]):\n'
    '    data = pathlib.Path(path).read_bytes()\n'
    '    name = pathlib.Path(path).name + "-" + hashlib.sha1(data).hexdigest()[:6] + ".gzf"\n'
    '    (gz / name).write_bytes(b"GZF" + data)\n'
    '(out/"json"/"old-new.ghidriff.json").write_text(json.dumps({"functions": {"added": [], "deleted": [], '
    '"modified": []}}))\n')


def runtime(fake_runtime, body=GZF_BODY, **config):  # noqa: F811
    root, package, project, base = fake_runtime
    write_backend(package, body)
    return root, project, dataclasses.replace(base, **config)


def do_run(root, project, config, cancel=None):
    events = []
    path, run = run_comparison(config, project, root, cancel or threading.Event(), lambda e: events.append(e))
    return path, run, events


def test_backend_retains_gzfs_when_asked(fake_runtime, monkeypatch):  # noqa: F811
    root, project, config = runtime(fake_runtime, retain_gzf=True)
    scratch = []
    real_remove = backend._remove_scratch

    def watch(path, *args, **kwargs):
        scratch.append(sorted(p.name for p in (path / 'gzfs').iterdir()))     # what is left when scratch is removed
        return real_remove(path, *args, **kwargs)

    monkeypatch.setattr(backend, '_remove_scratch', watch)
    path, run, events = do_run(root, project, config)
    assert run.status == 'completed' and scratch == [[]]                      # moved out, not copied
    directory = root / 'runs' / run.id / 'unified' / 'gzf'
    record = run.settings['gzf']
    for side, artifact in (('older', root / 'older.bin'), ('newer', root / 'newer.bin')):
        data = b'GZF' + artifact.read_bytes()
        assert (directory / f'{side}.gzf').read_bytes() == data
        assert record[side] == {'name': sha1_name(artifact), 'sha256': hashlib.sha256(data).hexdigest(),
                                'bytes': len(data)}
    assert not any(e.stage == 'warning' for e in events) and path.is_file()
    json.dumps(run.settings)


def test_retain_gzf_off_is_byte_identical_to_today(fake_runtime):  # noqa: F811
    root, project, config = runtime(fake_runtime)
    assert config.retain_gzf is False
    path, run, events = do_run(root, project, config)
    assert run.status == 'completed' and 'gzf' not in run.settings
    assert not (root / 'runs' / run.id / 'unified').exists()
    assert set(run.settings) == {'timeout_seconds', 'allow_symbol_downloads', 'symbol_policy', 'ghidra_settings',
                                 'older_sha256', 'newer_sha256', 'python_version', 'pyghidra_version',
                                 'ghidra_version', 'java_runtime_version'}
    assert [e.stage for e in events] == ['preflight', 'analysis', 'completed']


def test_retain_gzf_skipped_on_failed_or_cancelled_run(fake_runtime, monkeypatch):  # noqa: F811
    root, project, config = runtime(fake_runtime, body='(out/"partial.txt").write_text("x");sys.exit(7)\n',
                                    retain_gzf=True)
    path, run, _events = do_run(root, project, config)
    assert run.status == 'failed' and not (path / 'unified').exists() and 'gzf' not in run.settings

    root, project, config = runtime(fake_runtime, retain_gzf=True)
    cancel = threading.Event()
    real = backend.run_process

    def cancelled_after_success(argv, **kwargs):
        result = real(argv, **kwargs)
        cancel.set()                                            # the user pressed cancel just as the child ended
        return result

    monkeypatch.setattr(backend, 'run_process', cancelled_after_success)
    path, run, _events = do_run(root, project, config, cancel)
    assert run.status == 'cancelled' and not (path / 'unified').exists() and 'gzf' not in run.settings


@pytest.mark.parametrize('body_change', ['one', 'three', 'extra-name'])
def test_unexpected_gzf_layout_warns_and_still_completes(fake_runtime, body_change):  # noqa: F811
    tweak = {'one': 'for f in list(gz.glob("*.gzf"))[:1]: f.unlink()\n',
             'three': '(gz / "third-abcdef.gzf").write_bytes(b"x")\n',
             'extra-name': ('for number, f in enumerate(sorted(gz.glob("*.gzf"))):\n'
                            '    f.rename(f.with_name("renamed%d.gzf" % number))\n')}
    root, project, config = runtime(fake_runtime, body=GZF_BODY + tweak[body_change], retain_gzf=True)
    path, run, events = do_run(root, project, config)
    assert run.status == 'completed' and 'gzf' not in run.settings
    assert [e.stage for e in events].count('warning') == 1 and not (root / 'runs' / run.id / 'unified').exists()


def test_raw_cache_hit_has_no_gzf_and_falls_back_to_analyze(fake_runtime, monkeypatch, tmp_path):  # noqa: F811
    root, package, project, base = fake_runtime
    (root / 'older.dll').write_bytes(synthetic_pe(0))
    (root / 'newer.dll').write_bytes(synthetic_pe(1))
    service = ProjectService.create(root / 'older.dll', root / 'newer.dll', 'gzf cache case', root / 'case')
    try:
        monkeypatch.setattr(backend, '_java_version', lambda *_: '21.0.2')
        older, newer = (next(a.sha256 for a in service.project.artifacts if a.side == s) for s in ('older', 'newer'))
        document = {'old_meta': {'SHA256': older}, 'new_meta': {'SHA256': newer},
                    'functions': {'added': [{'name': 'fresh_fn', 'address': '1000'}], 'deleted': [], 'modified': []}}
        write_backend(package, GZF_BODY.rsplit('(out/"json"', 1)[0]
                      + f'(out/"json"/"old-new.ghidriff.json").write_text(json.dumps({document!r}))\n')
        config = dataclasses.replace(base, cache_dir=str(tmp_path / 'global-cache'), retain_gzf=True)
        first_path, first, _ = do_run(service.root, service.project, config)
        second_path, second, events = do_run(service.root, service.project, config)
        assert first.status == second.status == 'completed' and 'gzf' in first.settings
        assert 'cache_origin' in second.settings and 'gzf' not in second.settings
        assert not (service.root / 'runs' / second.id / 'unified').exists()
        assert any(e.message == 'raw output reused from cache' for e in events)
    finally:
        service.close()


def test_seam_runs_only_after_a_clean_process_exit(fake_runtime, monkeypatch):  # noqa: F811
    root, project, config = runtime(fake_runtime, retain_gzf=True)
    calls = []
    monkeypatch.setattr('patchtrace.unified.extract.retain.retain_run_gzfs', lambda *a: calls.append(a))
    real = backend.run_process

    def nonzero(argv, **kwargs):
        result = real(argv, **kwargs)
        return ProcessResult(3, result.log_tail, result.reason, result.stderr_tail)

    monkeypatch.setattr(backend, 'run_process', nonzero)
    do_run(root, project, config)
    assert calls == []
    monkeypatch.setattr(backend, 'run_process', real)
    do_run(root, project, config)
    assert len(calls) == 1


def test_retain_gzf_must_be_a_boolean(fake_runtime):  # noqa: F811
    root, project, config = runtime(fake_runtime)
    bad = dataclasses.replace(config, retain_gzf='yes')
    assert any('retain_gzf must be a boolean' in e for e in backend._config_errors(bad))
    assert backend._config_errors(config) == []


def test_backend_does_not_import_the_unified_engine_unless_asked():
    code = ('import sys\nimport patchtrace.backend\n'
            'print(sorted(m for m in sys.modules if m.startswith("patchtrace.unified")))\n')
    env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'))
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env=env, check=True)
    assert result.stdout.strip() == '[]'


def test_config_default_is_off_and_frozen():
    config = BackendConfig(python_executable='', ghidra_dir='')
    assert config.retain_gzf is False
    with pytest.raises(dataclasses.FrozenInstanceError):
        config.retain_gzf = True
