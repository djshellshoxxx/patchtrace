import threading
from types import SimpleNamespace

from patchtrace import backend
from patchtrace.backend import BackendConfig


def _configured_probe(monkeypatch, tmp_path):
    config = BackendConfig('/python', str(tmp_path))
    monkeypatch.setattr(backend, '_java_executable', lambda _config: '/usr/bin/java')
    monkeypatch.setattr(backend, '_environment', lambda *_args: {})
    return config


def _result(*, reason=None, returncode=0, log_tail=''):
    return SimpleNamespace(reason=reason, returncode=returncode, log_tail=log_tail)


def test_java_version_retries_timeout_once_with_longer_bound(monkeypatch, tmp_path):
    config = _configured_probe(monkeypatch, tmp_path)
    results = iter((
        _result(reason='timeout', returncode=-1),
        _result(log_tail='openjdk version "21.0.2" 2024-01-16'),
    ))
    timeouts = []

    def fake_run_process(_argv, *, timeout_seconds, **_kwargs):
        timeouts.append(timeout_seconds)
        return next(results)

    monkeypatch.setattr(backend, 'run_process', fake_run_process)

    assert backend._java_version(config, threading.Event()) == '21.0.2'
    assert timeouts == [15, 30]


def test_java_version_stops_after_second_timeout(monkeypatch, tmp_path):
    config = _configured_probe(monkeypatch, tmp_path)
    timeouts = []

    def fake_run_process(_argv, *, timeout_seconds, **_kwargs):
        timeouts.append(timeout_seconds)
        return _result(reason='timeout', returncode=-1)

    monkeypatch.setattr(backend, 'run_process', fake_run_process)

    assert backend._java_version(config) == 'unknown'
    assert timeouts == [15, 30]


def test_java_version_does_not_retry_non_timeout_failures(monkeypatch, tmp_path):
    config = _configured_probe(monkeypatch, tmp_path)
    calls = []
    current = []

    def fake_run_process(_argv, *, timeout_seconds, **_kwargs):
        calls.append(timeout_seconds)
        return current[0]

    monkeypatch.setattr(backend, 'run_process', fake_run_process)
    for outcome in (
        _result(reason='cancelled', returncode=-1),
        _result(reason='spawn-error', returncode=-1),
        _result(returncode=1, log_tail='java failed'),
        _result(log_tail='unrecognized version text'),
    ):
        current[:] = [outcome]
        calls.clear()
        assert backend._java_version(config) == 'unknown'
        assert calls == [15]


def test_java_version_does_not_retry_timeout_after_cancellation(monkeypatch, tmp_path):
    config = _configured_probe(monkeypatch, tmp_path)
    cancel = threading.Event()
    timeouts = []

    def fake_run_process(_argv, *, timeout_seconds, **_kwargs):
        timeouts.append(timeout_seconds)
        cancel.set()
        return _result(reason='timeout', returncode=-1)

    monkeypatch.setattr(backend, 'run_process', fake_run_process)

    assert backend._java_version(config, cancel) == 'unknown'
    assert timeouts == [15]


def test_java_version_does_not_retry_oserror(monkeypatch, tmp_path):
    config = _configured_probe(monkeypatch, tmp_path)
    timeouts = []

    def fake_run_process(_argv, *, timeout_seconds, **_kwargs):
        timeouts.append(timeout_seconds)
        raise OSError('unavailable')

    monkeypatch.setattr(backend, 'run_process', fake_run_process)

    assert backend._java_version(config) == 'unknown'
    assert timeouts == [15]


def test_java_version_never_spawns_when_java_is_missing(monkeypatch, tmp_path):
    config = _configured_probe(monkeypatch, tmp_path)
    monkeypatch.setattr(backend, '_java_executable', lambda _config: None)

    def unexpected_run(*_args, **_kwargs):
        raise AssertionError('Java was absent; process must not be spawned')

    monkeypatch.setattr(backend, 'run_process', unexpected_run)

    assert backend._java_version(config) == 'unknown'
