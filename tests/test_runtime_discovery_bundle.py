"""BUNDLE B7: discovery precedence, fast bundle check, config fallback and the diagnose line.

Hermetic: tiny synthetic payloads only (never evidence about a real Ghidra/JDK/Python payload).
"""
from __future__ import annotations

import dataclasses
import os
import sys
from pathlib import Path

import pytest
from test_backend_bundle import make_bundle

from patchtrace import backend
from patchtrace.backend import BackendConfig, diagnose
from patchtrace.backend_bundle import find_bundled_runtime
from patchtrace.runtime_discovery import (
    RuntimeCandidates,
    bundle_config,
    bundle_work_dir,
    check_bundle,
    discover_local_runtimes,
    exclude_bundle,
    require_bundle_ok,
)

HOST = 'windows' if os.name == 'nt' else 'linux'
PROBE = {'python': '3.12.0', 'ghidriff': 'fake-test-only', 'pyghidra': '3.0.2', 'available': True}


def make_ghidra(root: Path) -> Path:
    (root / 'Ghidra').mkdir(parents=True)
    (root / 'Ghidra' / 'application.properties').write_text('application.version=12.0.4')
    return root


@pytest.fixture
def exe(tmp_path):
    directory = tmp_path / 'App Dir é'
    directory.mkdir()
    make_bundle(directory, HOST)
    return directory


def env_for(exe: Path, **extra) -> dict:
    return {'PATCHTRACE_BUNDLE_DIR': str(exe), **extra}


def symlink_or_skip(link: Path, target: Path):
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip('symlinks unavailable on this platform or account')


# ---- discovery precedence ---------------------------------------------------------------

def test_candidates_default_keeps_old_callers():
    assert RuntimeCandidates((), ()).bundle_roots == ()
    assert discover_local_runtimes({}).bundle_roots == ()


def test_precedence_explicit_then_bundle_then_user_then_other(tmp_path, exe):
    explicit_py = tmp_path / 'explicit' / 'python-explicit'
    explicit_py.parent.mkdir()
    explicit_py.write_bytes(b'x')
    explicit_ghidra = make_ghidra(tmp_path / 'explicit-ghidra')
    home, local = tmp_path / 'home', tmp_path / 'local'
    if os.name == 'nt':
        user_py = local / 'PatchTrace/runtimes/r1/payload/python/python.exe'
        user_ghidra = make_ghidra(local / 'PatchTrace/runtimes/r1/payload/ghidra')
    else:
        user_py = home / '.local/share/patchtrace/runtimes/r1/payload/python/bin/python3'
        user_ghidra = make_ghidra(home / '.local/share/patchtrace/runtimes/r1/payload/ghidra')
    user_py.parent.mkdir(parents=True)
    user_py.write_bytes(b'x')
    other = make_ghidra(tmp_path / 'tools' / 'ghidra_11.0_PUBLIC')
    env = env_for(exe, PATCHTRACE_BACKEND_PYTHON=str(explicit_py), GHIDRA_INSTALL_DIR=str(explicit_ghidra),
                  HOME=str(home), LOCALAPPDATA=str(local))
    found = discover_local_runtimes(env, search_roots=[tmp_path / 'tools'])
    ref = find_bundled_runtime(exe, host=HOST)
    assert found.python_executables == tuple(p.resolve() for p in (explicit_py, ref.python, user_py))
    assert found.ghidra_roots == tuple(p.resolve() for p in (explicit_ghidra, ref.ghidra, user_ghidra, other))
    assert found.bundle_roots == (exe / 'backend',)


def test_bundle_alone_is_discovered_without_execution(exe, monkeypatch):
    monkeypatch.setattr('subprocess.run', lambda *a, **k: pytest.fail('must not execute tools'))
    found = discover_local_runtimes(env_for(exe))
    ref = find_bundled_runtime(exe, host=HOST)
    assert found.python_executables == (ref.python.resolve(),)
    assert found.ghidra_roots == (ref.ghidra.resolve(),)


def test_exclude_bundle_drops_only_candidates_inside_the_bundle(tmp_path, exe):
    other = make_ghidra(tmp_path / 'tools' / 'ghidra_11.0_PUBLIC')
    found = discover_local_runtimes(env_for(exe), search_roots=[tmp_path / 'tools'])
    assert len(found.ghidra_roots) == 2 and len(found.python_executables) == 1
    kept = exclude_bundle(found)
    assert kept.ghidra_roots == (other.resolve(),) and kept.python_executables == ()
    assert kept.bundle_roots == found.bundle_roots


def test_explicit_bundle_exe_dir_argument(exe):
    found = discover_local_runtimes({}, bundle_exe_dir=exe)
    assert found.bundle_roots == (exe / 'backend',) and len(found.python_executables) == 1


@pytest.mark.parametrize('breakage', ['no-manifest', 'bad-json'])
def test_unusable_bundle_is_reported_but_never_offered(exe, breakage):
    manifest = exe / 'backend' / 'manifest.json'
    if breakage == 'no-manifest':
        manifest.unlink()
    else:
        manifest.write_text('{not json', encoding='utf-8')
    found = discover_local_runtimes(env_for(exe))
    assert found.bundle_roots == (exe / 'backend',)
    assert not found.python_executables and not found.ghidra_roots
    status = check_bundle(exe)
    assert status.ref is None and not status.ok
    assert status.code == ('PT-BUNDLE-MISSING' if breakage == 'no-manifest' else 'PT-BUNDLE-MANIFEST')
    assert status.line().startswith(status.code) and status.line().endswith('extract the complete ZIP again')


def test_symlinked_backend_dir_is_refused(tmp_path):
    real = tmp_path / 'real'
    real.mkdir()
    make_bundle(real, HOST)
    exe = tmp_path / 'exe'
    exe.mkdir()
    symlink_or_skip(exe / 'backend', real / 'backend')
    assert check_bundle(exe).code == 'PT-BUNDLE-LINK'
    assert not discover_local_runtimes({}, bundle_exe_dir=exe).python_executables


# ---- check_bundle ------------------------------------------------------------------------

def test_check_none_without_backend_dir(tmp_path):
    assert check_bundle(tmp_path) is None


def test_check_ok_line_and_counts(exe):
    status = check_bundle(exe)
    assert status.ok and status.code == '' and status.files == 5 and status.bytes > 0
    assert status.line() == f'Bundled runtime {status.ref.runtime_id}: fast check ok'


@pytest.mark.parametrize('damage, code', [('extra', 'PT-BUNDLE-EXTRA'), ('size', 'PT-BUNDLE-SIZE'),
                                          ('missing', 'PT-BUNDLE-MISSING')])
def test_check_reports_pt_bundle_problem(exe, damage, code):
    payload = exe / 'backend' / 'payload'
    if damage == 'extra':
        (payload / 'surprise.txt').write_bytes(b'x')
    elif damage == 'size':
        (payload / 'ghidra/docs/a.txt').write_bytes(b'short')
    else:
        (payload / 'ghidra/docs/a.txt').unlink()
    status = check_bundle(exe)
    assert status.code == code and status.line().startswith(code + ':')
    assert 'extract the complete ZIP again' in status.line()


# ---- work dir ----------------------------------------------------------------------------

@pytest.mark.skipif(os.name == 'nt', reason='POSIX state directory')
@pytest.mark.parametrize('env, expected', [
    ({'XDG_STATE_HOME': '/state', 'HOME': '/h'}, '/state/patchtrace/work'),
    ({'HOME': '/h'}, '/h/.local/state/patchtrace/work'),
    ({'XDG_STATE_HOME': 'relative', 'HOME': '/h'}, '/h/.local/state/patchtrace/work')],
    ids=['xdg', 'home', 'relative-xdg-ignored'])
def test_work_dir_posix(env, expected):
    assert bundle_work_dir(env) == Path(expected)


@pytest.mark.skipif(os.name != 'nt', reason='Windows local app data')
def test_work_dir_windows():
    assert bundle_work_dir({'LOCALAPPDATA': r'C:\Users\a\AppData\Local'}) == Path(
        r'C:\Users\a\AppData\Local\PatchTrace\work')


# ---- bundle_config -----------------------------------------------------------------------

def test_config_fallback_on_empty_paths_keeps_other_settings(exe, tmp_path):
    ref = find_bundled_runtime(exe, host=HOST)
    base = BackendConfig('', '', timeout_seconds=99, allow_symbol_downloads=True, cache_dir='/profile/cache')
    config = bundle_config(base, env_for(exe), tmp_path / 'work')
    assert config.bundle and config.restrict_env
    assert config.python_executable == str(ref.python) and config.ghidra_dir == str(ref.ghidra)
    assert config.java_home == str(ref.java_home)
    assert config.timeout_seconds == 99 and config.allow_symbol_downloads is True
    assert config.cache_dir == '/profile/cache'  # raw reuse stays opt-in via the profile
    assert base.bundle is False  # input untouched


def test_config_without_profile_cache_has_no_cache(exe, tmp_path):
    config = bundle_config(BackendConfig('', ''), env_for(exe), tmp_path / 'work')
    assert config.bundle and config.cache_dir == ''


def test_config_saved_paths_win(exe, tmp_path):
    saved = BackendConfig('/my/python', '/my/ghidra')
    assert bundle_config(saved, env_for(exe), tmp_path / 'work') is saved
    mixed = BackendConfig('', '/my/ghidra')
    assert bundle_config(mixed, env_for(exe), tmp_path / 'work') is mixed


def test_config_with_prefilled_bundle_paths_stays_isolated(exe, tmp_path):
    ref = find_bundled_runtime(exe, host=HOST)
    prefilled = BackendConfig(str(ref.python), str(ref.ghidra), java_home=str(ref.java_home))
    assert bundle_config(prefilled, env_for(exe), tmp_path / 'work').bundle is True


def test_config_unchanged_without_or_with_broken_bundle(exe, tmp_path):
    empty = BackendConfig('', '')
    assert bundle_config(empty, {}, tmp_path / 'w') is empty
    (exe / 'backend' / 'manifest.json').write_text('{', encoding='utf-8')
    assert bundle_config(empty, env_for(exe), tmp_path / 'w') is empty


def test_config_rejects_work_dir_inside_install(exe):
    empty = BackendConfig('', '')
    assert bundle_config(empty, env_for(exe), exe / 'backend' / 'work') is empty


# ---- require_bundle_ok ----------------------------------------------------------------------

def bundle_cfg(exe, tmp_path):
    return bundle_config(BackendConfig('', ''), env_for(exe), tmp_path / 'work')


def test_require_ok_noop_for_non_bundle_and_ok_bundle(exe, tmp_path):
    require_bundle_ok(BackendConfig('/p', '/g'))
    require_bundle_ok(bundle_cfg(exe, tmp_path))


def test_require_blocks_with_pt_bundle_line(exe, tmp_path):
    config = bundle_cfg(exe, tmp_path)
    (exe / 'backend' / 'payload' / 'surprise.txt').write_bytes(b'x')
    with pytest.raises(ValueError, match=r'^PT-BUNDLE-EXTRA: .*extract the complete ZIP again'):
        require_bundle_ok(config)


# ---- backend.diagnose line ---------------------------------------------------------------

@pytest.fixture
def probed(monkeypatch):
    monkeypatch.setattr(backend, '_probe_backend', lambda *_: PROBE)
    monkeypatch.setattr(backend, '_java_version', lambda *_: '21.0.2')


def test_diagnose_reports_fast_check_ok(exe, tmp_path, probed):
    config = bundle_cfg(exe, tmp_path)
    ref = find_bundled_runtime(exe, host=HOST)
    ref.python.chmod(0o755)
    lines = diagnose(config)
    assert f'Bundled runtime {ref.runtime_id}: fast check ok' in lines
    assert not [line for line in lines if line.startswith('PT-')]
    assert not any('isolated mode' in line for line in lines)  # the generic B6 line is gone


def test_diagnose_reports_pt_bundle_problem(exe, tmp_path, probed):
    config = bundle_cfg(exe, tmp_path)
    find_bundled_runtime(exe, host=HOST).python.chmod(0o755)
    (exe / 'backend' / 'payload' / 'surprise.txt').write_bytes(b'x')
    lines = diagnose(config)
    assert any(line.startswith('PT-BUNDLE-EXTRA') for line in lines)
    assert not any(line.endswith('fast check ok') for line in lines)


def test_diagnose_without_bundle_flag_has_no_bundle_line(exe, tmp_path, probed):
    config = dataclasses.replace(bundle_cfg(exe, tmp_path), bundle=False)
    find_bundled_runtime(exe, host=HOST).python.chmod(0o755)
    assert not any('Bundled runtime' in line for line in diagnose(config))


def test_sys_executable_is_not_a_bundle_location(tmp_path, monkeypatch):
    monkeypatch.delattr(sys, 'frozen', raising=False)
    assert check_bundle(None, {}) is None
