from types import SimpleNamespace
import threading

from patchtrace import backend
from patchtrace.backend import BackendConfig


def test_java_version_retries_timeout_once_with_longer_bound(monkeypatch, tmp_path):
    config = BackendConfig('/python', str(tmp_path))
    monkeypatch.setattr(backend, '_java_executable', lambda _config: '/usr/bin/java')
    monkeypatch.setattr(backend, '_environment', lambda *_args: {})

    results = iter((
        SimpleNamespace(returncode=-1, reason='timeout', log_tail=''),
        SimpleNamespace(
            returncode=0,
            reason=None,
            log_tail='openjdk version "21.0.2" 2024-01-16',
        ),
    ))
    timeouts = []

    def fake_run_process(_argv, *, timeout_seconds, **_kwargs):
        timeouts.append(timeout_seconds)
        return next(results)

    monkeypatch.setattr(backend, 'run_process', fake_run_process)

    assert backend._java_version(config, threading.Event()) == '21.0.2'
    assert timeouts == [15, 30]
