"""T4 Intel-only synthetic Windows identity; controlled stdlib checks, not native tool acceptance."""
from __future__ import annotations

import builtins
import getpass
import os

import pytest

from patchtrace.intelligence.tools import process
from patchtrace.intelligence.tools.common import ToolError
from patchtrace.secondary.engine_env import engine_env

IDENTITIES = {'LOGNAME': 'parent-logname', 'USER': 'parent-user', 'LNAME': 'parent-lname',
              'USERNAME': 'parent-username', 'uSeRnAmE': 'parent-mixed-username'}
SECRETS = {'AWS_SECRET_ACCESS_KEY': 'parent-secret', 'HTTPS_PROXY': 'http://proxy.invalid',
           'PYTHONPATH': '/parent/python', 'CAPA_SAVE_WORKSPACE': '1', 'FLOSS_SAVE_WORKSPACE': '1'}
WINDOWS_PARENT = {'systemroot': r'C:\Windows', 'SystemDrive': 'C:', 'PATH': 'parent-path',
                  'USERPROFILE': 'parent-home', 'TEMP': 'parent-temp', **IDENTITIES, **SECRETS}


def test_windows_getuser_uses_synthetic_identity_without_pwd(tmp_path, monkeypatch):
    env = process.tool_env(tmp_path / 'floss.exe', tmp_path, environ=WINDOWS_PARENT, windows=True)
    original_import = builtins.__import__

    def without_pwd(name, *args, **kwargs):
        if name == 'pwd':
            raise ModuleNotFoundError("No module named 'pwd'")
        return original_import(name, *args, **kwargs)

    # Run the real stdlib consumer with only the child's environment and no POSIX pwd module.
    with monkeypatch.context() as child:
        child.setattr(os, 'environ', env)
        child.setattr(builtins, '__import__', without_pwd)
        assert getpass.getuser() == 'patchtrace'


def test_windows_identity_is_fixed_and_parent_environment_stays_private(tmp_path, monkeypatch):
    monkeypatch.setattr(os, 'environ', WINDOWS_PARENT.copy())
    executable = tmp_path / 'bin' / 'capa.exe'
    env = process.tool_env(executable, tmp_path, windows=True)
    assert env['USERNAME'] == 'patchtrace'
    assert not (set(IDENTITIES) - {'USERNAME'}) & env.keys()
    assert not SECRETS.keys() & env.keys()
    assert not set(IDENTITIES.values()) & set(env.values())
    assert env['SystemRoot'] == env['windir'] == r'C:\Windows' and env['SystemDrive'] == 'C:'
    assert env['PATH'] == f'{executable.parent};C:\\Windows\\System32'
    for key, parts in {'TEMP': ('tmp',), 'TMP': ('tmp',), 'USERPROFILE': ('home',),
                       'APPDATA': ('home', 'AppData', 'Roaming'),
                       'LOCALAPPDATA': ('home', 'AppData', 'Local'), 'PROGRAMDATA': ('programdata',)}.items():
        assert env[key] == str(tmp_path.joinpath(*parts))
    shared = engine_env(WINDOWS_PARENT, 'bindiff', windows=True, executable=executable, workdir=tmp_path)
    assert 'USERNAME' not in shared  # the Intel compatibility addition must not change shared policy
    assert {key: value for key, value in env.items() if key != 'USERNAME'} == shared


def test_posix_does_not_gain_or_inherit_an_identity(tmp_path):
    executable = tmp_path / 'floss'
    env = process.tool_env(executable, tmp_path, environ=WINDOWS_PARENT, windows=False)
    assert not IDENTITIES.keys() & env.keys()
    assert not SECRETS.keys() & env.keys()
    assert env == engine_env(WINDOWS_PARENT, 'bindiff', windows=False,
                             executable=executable, workdir=tmp_path)


@pytest.mark.parametrize('windows', [False, True])
def test_configured_java_and_diec_additions_keep_the_existing_path_layout(tmp_path, windows):
    extra = {'JAVA_HOME': str(tmp_path / 'java'), 'GHIDRA_INSTALL_DIR': str(tmp_path / 'ghidra'),
             'LD_LIBRARY_PATH': str(tmp_path / 'diec-libs')}
    executable = tmp_path / 'bin' / 'tool'
    env = process.tool_env(executable, tmp_path, environ=WINDOWS_PARENT, windows=windows, extra=extra)
    assert all(env[key] == value for key, value in extra.items())
    separator = ';' if windows else ':'
    assert env['PATH'].startswith(str(tmp_path / 'java' / 'bin') + separator + str(executable.parent))
    assert env.get('USERNAME') == ('patchtrace' if windows else None)


@pytest.mark.parametrize('key', [*IDENTITIES, 'SystemRoot', 'PATH', 'AWS_SECRET_ACCESS_KEY'])
def test_extra_cannot_override_identity_or_expand_inheritance(tmp_path, key):
    with pytest.raises(ToolError) as error:
        process.tool_env(tmp_path / 'tool.exe', tmp_path, environ=WINDOWS_PARENT, windows=True,
                         extra={key: 'caller-override'})
    assert error.value.code == 'PT-TOOL-INPUT'


@pytest.mark.parametrize('value', ['', 'bad\0path', 'bad\rpath', 'bad\npath'])
def test_invalid_configured_extra_still_refuses(tmp_path, value):
    with pytest.raises(ToolError) as error:
        process.tool_env(tmp_path / 'tool.exe', tmp_path, environ=WINDOWS_PARENT, windows=True,
                         extra={'JAVA_HOME': value})
    assert error.value.code == 'PT-TOOL-INPUT'


def test_synthetic_identity_does_not_bypass_required_windows_system_root(tmp_path):
    with pytest.raises(OSError, match='SystemRoot is not set'):
        process.tool_env(tmp_path / 'tool.exe', tmp_path, environ=IDENTITIES, windows=True)
