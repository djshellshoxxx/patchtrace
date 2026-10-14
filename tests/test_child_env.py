"""H7: child-process environment allowlist (SPEC-07h)."""
import pytest

from patchtrace.backend import BackendConfig, _config_errors, build_child_env

WIN_BASE = {'SYSTEMROOT': r'C:\Windows', 'Path': r'C:\Windows\System32', 'TEMP': r'C:\t', 'GITHUB_TOKEN': 'sekret',
            'JAVA_TOOL_OPTIONS': '-javaagent:x.jar', 'PYTHONSTARTUP': 'x.py', 'LD_PRELOAD': 'x.so',
            'HTTPS_PROXY': 'http://p', 'AWS_SECRET_ACCESS_KEY': 'k', 'ProgramFiles(x86)': r'C:\pf'}
LIN_BASE = {'PATH': '/usr/bin', 'HOME': '/home/a', 'LANG': 'C.UTF-8', 'LC_ALL': 'C', 'JAVA_TOOL_OPTIONS': '-Dx=1',
            '_JAVA_OPTIONS': '-Dy', 'NVD_API_KEY': 'k', 'LD_LIBRARY_PATH': '/opt/jdk/lib', 'PYTHONPATH': '/evil',
            'https_proxy': 'http://p', 'SSL_CERT_FILE': '/c.pem', 'RZ_PREFIX': '/rz', 'GHIDRA_INSTALL_DIR': '/old'}


def _cfg(tmp_path, **kw):
    return BackendConfig('/py', str(tmp_path), **kw)


def test_windows_allowlist_is_case_insensitive_and_drops_secrets(tmp_path):
    env = build_child_env(WIN_BASE, _cfg(tmp_path), None, symbol_downloads=False, for_tool='ghidra', windows=True)
    assert env['SYSTEMROOT'] == r'C:\Windows' and env['Path'] == r'C:\Windows\System32'
    assert env['ProgramFiles(x86)'] == r'C:\pf'
    for bad in ('GITHUB_TOKEN', 'JAVA_TOOL_OPTIONS', 'PYTHONSTARTUP', 'LD_PRELOAD', 'HTTPS_PROXY',
                'AWS_SECRET_ACCESS_KEY'):
        assert bad not in env
    assert env['PYTHONNOUSERSITE'] == '1' and env['PYTHONIOENCODING'] == 'utf-8'
    again = build_child_env(dict(reversed(list(WIN_BASE.items()))), _cfg(tmp_path), None, symbol_downloads=False,
                            for_tool='ghidra', windows=True)
    assert list(env.items()) == list(again.items())


def test_linux_allowlist_and_ld_library_path_only_without_private_java(tmp_path):
    env = build_child_env(LIN_BASE, _cfg(tmp_path), tmp_path / 's', symbol_downloads=False, for_tool='ghidra',
                          windows=False)
    assert env['LANG'] == 'C.UTF-8' and env['LC_ALL'] == 'C' and env['LD_LIBRARY_PATH'] == '/opt/jdk/lib'
    assert env['GHIDRA_INSTALL_DIR'] == str(tmp_path.resolve())
    assert env['XDG_CONFIG_HOME'] == str(tmp_path / 's')
    for bad in ('JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'NVD_API_KEY', 'PYTHONPATH', 'https_proxy', 'SSL_CERT_FILE',
                'RZ_PREFIX'):
        assert bad not in env
    jdk = tmp_path / 'jdk'
    private = build_child_env(LIN_BASE, _cfg(tmp_path, java_home=str(jdk)), None, symbol_downloads=False,
                              for_tool='ghidra', windows=False)
    assert 'LD_LIBRARY_PATH' not in private and private['JAVA_HOME'] == str(jdk.resolve())
    assert private['PATH'].startswith(str(jdk.resolve() / 'bin'))


def test_proxy_vars_only_with_symbol_downloads(tmp_path):
    env = build_child_env(LIN_BASE, _cfg(tmp_path), None, symbol_downloads=True, for_tool='ghidra', windows=False)
    assert env['https_proxy'] == 'http://p' and env['SSL_CERT_FILE'] == '/c.pem'


def test_rizin_gets_rz_vars_but_no_java_or_python(tmp_path):
    env = build_child_env({**LIN_BASE, 'RZ_LIBR_PLUGINS': '/p'}, _cfg(tmp_path), None, symbol_downloads=False,
                          for_tool='rizin', windows=False)
    assert env['RZ_PREFIX'] == '/rz' and env['RZ_LIBR_PLUGINS'] == '/p'
    assert not any(k.startswith(('JAVA', 'GHIDRA', 'PYTHON', '_JAVA')) for k in env)


def test_env_passthrough_adds_names_and_denylist_rejected(tmp_path):
    base = {**LIN_BASE, 'CORP_PROXY_CA': '/ca'}
    env = build_child_env(base, _cfg(tmp_path, env_passthrough=('CORP_PROXY_CA',)), None, symbol_downloads=False,
                          for_tool='ghidra', windows=False)
    assert env['CORP_PROXY_CA'] == '/ca'
    for name in ('PYTHONPATH', 'LD_PRELOAD', 'JAVA_TOOL_OPTIONS', 'bad name', '1X'):
        errors = _config_errors(_cfg(tmp_path, env_passthrough=(name,)))
        assert any('env_passthrough' in e for e in errors), name
    with pytest.raises(ValueError):
        build_child_env(base, _cfg(tmp_path, env_passthrough=('LD_PRELOAD',)), None, symbol_downloads=False,
                        for_tool='ghidra', windows=False)


def test_restrict_env_off_by_default_keeps_inherit(tmp_path, monkeypatch):
    from patchtrace.backend import _environment
    monkeypatch.setenv('CUSTOM_MARKER', '1')
    monkeypatch.delenv('PATCHTRACE_CHILD_ENV', raising=False)
    assert _environment(_cfg(tmp_path))['CUSTOM_MARKER'] == '1'
    restricted = _environment(_cfg(tmp_path, restrict_env=True))
    assert 'CUSTOM_MARKER' not in restricted and restricted['GHIDRA_INSTALL_DIR']
    monkeypatch.setenv('PATCHTRACE_CHILD_ENV', 'inherit')
    assert _environment(_cfg(tmp_path, restrict_env=True))['CUSTOM_MARKER'] == '1'
