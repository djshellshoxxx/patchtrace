"""BUNDLE B6: bundle flag, isolated argv, child env and diagnose line (hermetic; fake engine only)."""
import dataclasses
import hashlib
import sys
import threading
from pathlib import Path

import pytest
from test_jobs import write_backend

from patchtrace import backend
from patchtrace.backend import BackendConfig, _config_errors, build_child_env, diagnose, run_comparison
from patchtrace.models import Artifact, ComparisonProject

POSIX = {'PATH': '/usr/bin', 'HOME': '/home/a', 'PYTHONPATH': '/evil', 'TMPDIR': '/usr/tmp', 'XDG_CACHE_HOME': '/c'}
WIN = {'Path': r'C:\Windows', 'Temp': r'C:\t', 'TMP': r'C:\t', 'SYSTEMROOT': r'C:\Windows', 'PYTHONPATH': 'x'}
PROBE = {'python': '3.12.0', 'ghidriff': 'fake-test-only', 'pyghidra': '3.0.2', 'available': True}


@pytest.fixture
def layout(tmp_path):
    payload = tmp_path / 'inst' / 'backend' / 'payload'
    (payload / 'ghidra' / 'Ghidra').mkdir(parents=True)
    (payload / 'ghidra' / 'Ghidra' / 'application.properties').write_text('application.version=12.0.4')
    java = payload / 'jdk' / 'bin' / ('java.exe' if sys.platform == 'win32' else 'java')
    java.parent.mkdir(parents=True)
    java.write_text('')
    config = BackendConfig(str(Path(sys.executable).resolve()), str(payload / 'ghidra'),
                           java_home=str(payload / 'jdk'), bundle=True)
    return tmp_path, payload, config


def test_default_is_not_bundle():
    assert BackendConfig('/p', '/g').bundle is False


@pytest.mark.parametrize('windows', [False, True], ids=['posix', 'windows'])
def test_bundle_env(layout, windows):
    tmp, payload, config = layout
    scratch = tmp / 'scr'
    env = build_child_env(WIN if windows else POSIX, config, scratch / 'ghidra-settings',
                          symbol_downloads=False, for_tool='ghidra', windows=windows)
    jdk = str((payload / 'jdk').resolve())
    assert env['JAVA_HOME_OVERRIDE'] == env['JAVA_HOME'] == jdk
    path = env['Path' if windows else 'PATH']
    assert path.startswith(str(Path(jdk) / 'bin'))
    assert env['PYTHONDONTWRITEBYTECODE'] == '1' and env['PYTHONNOUSERSITE'] == '1'
    assert 'PYTHONPATH' not in env and 'PYTHONHOME' not in env
    for name in ('XDG_CACHE_HOME', 'TEMP', 'TMP', 'TMPDIR'):
        assert env[name] == str(scratch)
    assert env['XDG_CONFIG_HOME'] == str(scratch / 'ghidra-settings')
    if windows:  # no duplicate case variants of TEMP
        assert sorted(k for k in env if k.lower() == 'temp') == ['TEMP']


def test_non_bundle_env_unchanged(layout):
    _tmp, _payload, config = layout
    plain = dataclasses.replace(config, bundle=False, restrict_env=True)
    env = build_child_env(POSIX, plain, Path('/x/s'), symbol_downloads=False, for_tool='ghidra', windows=False)
    assert 'PYTHONDONTWRITEBYTECODE' not in env
    assert env['TMPDIR'] == '/usr/tmp' and env['XDG_CACHE_HOME'] == '/c'


def test_bundle_forces_restricted_env_even_with_inherit_override(layout, monkeypatch):
    tmp, _payload, config = layout
    monkeypatch.setenv('PATCHTRACE_CHILD_ENV', 'inherit')
    monkeypatch.setenv('SECRET_TOKEN_B6', 'x')
    monkeypatch.setenv('PYTHONPATH', '/evil')
    env = backend._environment(config, tmp / 's' / 'g')
    assert 'SECRET_TOKEN_B6' not in env and 'PYTHONPATH' not in env and 'JAVA_HOME_OVERRIDE' in env


def test_bundle_requires_java_home_and_boolean(layout):
    _tmp, _payload, config = layout
    assert not _config_errors(config)
    assert any('bundled Java home' in e for e in _config_errors(dataclasses.replace(config, java_home='')))
    assert any('bundle must be a boolean' in e for e in _config_errors(dataclasses.replace(config, bundle=1)))


def test_workdir_inside_backend_is_rejected(layout, monkeypatch):
    tmp, payload, config = layout
    inside = dataclasses.replace(config, cache_dir=str(payload.parent / 'cache'))
    assert any('PT-BUNDLE-WORKDIR' in e for e in _config_errors(inside))
    assert not _config_errors(dataclasses.replace(config, cache_dir=str(tmp / 'cache')))
    monkeypatch.setattr('tempfile.tempdir', str(payload.parent / 'tmp'))
    assert any('PT-BUNDLE-WORKDIR' in e for e in _config_errors(config))


def test_diagnose_reports_bundle_line(layout, monkeypatch):
    _tmp, _payload, config = layout
    monkeypatch.setattr(backend, '_probe_backend', lambda *_: PROBE)
    # B7: the generic line became the real fast check; this layout has no manifest, so it is a PT-BUNDLE problem
    assert any(s.startswith('PT-BUNDLE-MISSING') for s in diagnose(config))
    assert not any('Bundled runtime' in s for s in diagnose(dataclasses.replace(config, bundle=False)))


def test_run_comparison_argv_is_isolated(layout, monkeypatch):
    base, payload, config = layout
    package = payload / 'ghidra' / 'ghidriff'
    package.mkdir()
    (package / '__init__.py').write_text('')
    root = base / 'case'
    root.mkdir()
    artifacts = []
    for side in ('older', 'newer'):
        data = side.encode()
        (root / f'{side}.bin').write_bytes(data)
        artifacts.append(Artifact(side=side, name=f'{side}.bin', size=len(data),
                                  sha256=hashlib.sha256(data).hexdigest(), relative_path=f'{side}.bin'))
    project = ComparisonProject(name='b6', artifacts=artifacts)
    write_backend(package, '(out/"json"/"o.ghidriff.json").write_text('
                  'json.dumps({"functions":{"added":[],"deleted":[],"modified":[]}}))\n')
    monkeypatch.setattr(backend, '_probe_backend', lambda *_: PROBE)
    monkeypatch.setattr(backend, '_java_version', lambda *_: '21.0.2')
    seen = {}
    real = backend.run_process

    def spy(argv, **kw):
        seen['argv'], seen['env'] = list(argv), kw['env']
        # -I would also drop the fake package from sys.path (cwd); run the stub without it.
        return real([a for a in argv if a != '-I'], **kw)

    monkeypatch.setattr(backend, 'run_process', spy)
    _path, run = run_comparison(config, project, root, threading.Event(), lambda _e: None)
    assert run.status == 'completed'
    assert seen['argv'][1:6] == ['-I', '-X', 'utf8', '-m', 'ghidriff']
    env = seen['env']
    scratch = Path(env['TEMP'] if 'TEMP' in env else env['TMPDIR'])
    assert not scratch.resolve().is_relative_to(payload.parent.resolve())
    assert env['JAVA_HOME_OVERRIDE'] == str((payload / 'jdk').resolve())
    assert env['XDG_CONFIG_HOME'].startswith(str(scratch))
    assert not scratch.exists()  # scratch removed after the run
    assert sorted(p.name for p in payload.iterdir()) == ['ghidra', 'jdk']
