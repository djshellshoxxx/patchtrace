"""Audit #121 P2-3 / P2-8: default child-process hygiene of the Ghidra/Ghidriff runner."""
import inspect

import pytest

from patchtrace import backend
from patchtrace.backend import BackendConfig, _environment

SECRETS = {'GH_TOKEN': 'x', 'NVD_API_KEY': 'x', 'HTTPS_PROXY': 'http://p'}


@pytest.mark.xfail(strict=True, reason='audit121#3: BackendConfig.restrict_env defaults False so the parent '
                   'environment (GH_TOKEN, NVD_API_KEY, proxies) reaches the external process; owner WS-backend '
                   '(backend.py is frozen)')
def test_default_config_does_not_forward_secrets(tmp_path, monkeypatch):
    for key, value in SECRETS.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv('PATCHTRACE_CHILD_ENV', raising=False)
    env = _environment(BackendConfig('/py', str(tmp_path)))
    assert not set(SECRETS) & set(env)


def test_restricted_config_drops_secrets(tmp_path, monkeypatch):
    for key, value in SECRETS.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv('PATCHTRACE_CHILD_ENV', raising=False)
    env = _environment(BackendConfig('/py', str(tmp_path), restrict_env=True))
    assert not set(SECRETS) & set(env)


@pytest.mark.xfail(strict=True, reason='audit121#8: the primary Ghidriff run_process call passes no '
                   'memory_limit_bytes/max_output_bytes; owner WS-backend (backend.py is frozen)')
def test_primary_ghidriff_run_is_resource_capped():
    source = inspect.getsource(backend.run_comparison)
    call = source[source.index("run_process(argv, cwd=scratch_root"):]
    call = call[:call.index('check_output')]
    assert 'max_output_bytes' in call and 'memory_limit_bytes' in call
