"""One shared engine environment allow-list (SPEC-28 §9.6, SPEC-29 §4.2), per engine and per OS."""
from __future__ import annotations

from pathlib import Path

import pytest

from patchtrace.secondary.engine_env import engine_env

SECRETS = {'AWS_SECRET_ACCESS_KEY': 'k', 'GITHUB_TOKEN': 't', 'JAVA_TOOL_OPTIONS': '-javaagent:x',
           'LD_PRELOAD': '/x.so', 'HTTPS_PROXY': 'http://p', 'https_proxy': 'http://p', 'PYTHONPATH': '/evil',
           'NVD_API_KEY': 'n', 'OPENAI_API_KEY': 'o'}
POSIX = {'PATH': '/usr/bin', 'HOME': '/home/a', 'TMPDIR': '/tmp/a', 'LANG': 'C.UTF-8', 'LC_ALL': 'C',
         'LC_CTYPE': 'C.UTF-8', 'RZ_PREFIX': '/rz', 'RZ_LIBR_PLUGINS': '/rz/plugins', **SECRETS}
WINDOWS = {'SystemRoot': r'C:\Windows', 'SystemDrive': 'C:', 'windir': r'C:\Windows', 'Path': r'C:\Windows\System32',
           'PATHEXT': '.COM;.EXE', 'ComSpec': r'C:\Windows\system32\cmd.exe', 'TEMP': r'C:\t', 'TMP': r'C:\t',
           'USERPROFILE': r'C:\Users\a', 'APPDATA': r'C:\Users\a\AppData\Roaming', 'RZ_PREFIX': r'C:\rz', **SECRETS}


def test_rzdiff_posix_keeps_platform_and_rizin_vars_drops_secrets():
    env = engine_env(POSIX, 'rz-diff', windows=False)
    for name in ('PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'LC_CTYPE', 'RZ_PREFIX', 'RZ_LIBR_PLUGINS'):
        assert env[name] == POSIX[name]
    assert not set(SECRETS) & set(env)


def test_rzdiff_windows_keeps_pathext_comspec_temp_and_rizin_drops_secrets():
    env = engine_env(WINDOWS, 'rz-diff', windows=True)
    for name in ('SystemRoot', 'Path', 'PATHEXT', 'ComSpec', 'TEMP', 'TMP', 'USERPROFILE', 'RZ_PREFIX'):
        assert env[name] == WINDOWS[name]
    assert not set(SECRETS) & set(env)


def test_bindiff_posix_is_built_from_scratch(tmp_path):
    exe = tmp_path / 'bin' / 'bindiff'
    env = engine_env(POSIX, 'bindiff', windows=False, workdir=tmp_path / 'wd', executable=exe)
    assert env == {'PATH': f'{exe.parent}:/usr/bin:/bin', 'HOME': str(tmp_path / 'wd' / 'home'),
                   'TMPDIR': str(tmp_path / 'wd' / 'tmp'), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                   'XDG_CONFIG_HOME': str(tmp_path / 'wd' / 'home' / '.config')}


def test_bindiff_windows_copies_only_system_root_variables(tmp_path):
    wd = tmp_path / 'wd'
    exe = Path(r'C:\Program Files\BinDiff\bin\bindiff.exe')
    env = engine_env(WINDOWS, 'bindiff', windows=True, workdir=wd, executable=exe)
    assert env['SystemRoot'] == r'C:\Windows' and env['SystemDrive'] == 'C:' and env['windir'] == r'C:\Windows'
    assert env['PATH'] == f'{exe.parent};C:\\Windows\\System32'
    assert env['TEMP'] == env['TMP'] == str(wd / 'tmp')
    assert env['USERPROFILE'] == str(wd / 'home') and env['PROGRAMDATA'] == str(wd / 'programdata')
    assert env['APPDATA'].startswith(str(wd)) and env['LOCALAPPDATA'].startswith(str(wd))
    assert not set(SECRETS) & set(env) and 'RZ_PREFIX' not in env and 'ComSpec' not in env


def test_bindiff_windows_without_system_root_fails_closed(tmp_path):
    with pytest.raises(OSError):
        engine_env({'PATH': 'x'}, 'bindiff', windows=True, workdir=tmp_path, executable=tmp_path / 'bindiff.exe')


def test_bindiff_needs_workdir_and_unknown_engine_rejected(tmp_path):
    with pytest.raises(ValueError):
        engine_env(POSIX, 'bindiff', windows=False)
    with pytest.raises(ValueError):
        engine_env(POSIX, 'ghidra', windows=False)  # type: ignore[arg-type]
