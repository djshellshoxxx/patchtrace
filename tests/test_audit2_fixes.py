"""Second-audit regression tests (items 3-13)."""
import pytest

from patchtrace.backend import BackendConfig, _passthrough_error, build_child_env


def _cfg(tmp_path, **kw):
    return BackendConfig('/py', str(tmp_path), **kw)


def test_restricted_env_keeps_inherited_java_home(tmp_path):
    base = {'PATH': '/usr/bin', 'JAVA_HOME': '/opt/jdk', 'JDK_HOME': '/opt/jdk2', 'GITHUB_TOKEN': 'x'}
    env = build_child_env(base, _cfg(tmp_path), None, symbol_downloads=False, for_tool='ghidra', windows=False)
    assert env['JAVA_HOME'] == '/opt/jdk' and env['JDK_HOME'] == '/opt/jdk2' and 'GITHUB_TOKEN' not in env
    win = build_child_env({'Path': 'x', 'java_home': 'C:/jdk'}, _cfg(tmp_path), None, symbol_downloads=False,
                          for_tool='ghidra', windows=True)
    assert win['java_home'] == 'C:/jdk'
    rizin = build_child_env(base, _cfg(tmp_path), None, symbol_downloads=False, for_tool='rizin', windows=False)
    assert 'JAVA_HOME' not in rizin


@pytest.mark.parametrize('name', ['PYTHONSTARTUP', 'PYTHONBREAKPOINT', 'pythonwarnings', 'LD_AUDIT',
                                  'LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH', 'BASH_ENV', 'ENV'])
def test_passthrough_denylist(name):
    assert _passthrough_error(name)


def test_passthrough_allows_ordinary_names():
    assert not _passthrough_error('HTTPS_PROXY') and not _passthrough_error('ENVIRONMENT_X')
