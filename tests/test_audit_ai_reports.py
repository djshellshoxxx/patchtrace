import threading

import pytest

from patchtrace import providers
from patchtrace.reports import _redact


def test_redacts_windows_path_with_spaces():
    out = _redact(r'loaded C:\Users\John Smith\cases\secret.dll ok')
    assert 'Smith' not in out and 'secret.dll' not in out and out.endswith(' ok')


class _Drip:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read1(self, n):
        return b' '

    read = read1


class _Opener:
    def open(self, *a, **k):
        return _Drip()


def test_total_deadline_bounds_slow_drip(monkeypatch):
    monkeypatch.setattr(providers.urllib.request, 'build_opener', lambda *a: _Opener())
    clock = iter(range(0, 10_000, 10))
    monkeypatch.setattr(providers.time, 'monotonic', lambda: next(clock))
    config = providers.ProviderConfig('ollama', 'http://127.0.0.1:11434', 'm')
    with pytest.raises(providers.ProviderError, match='timed out'):
        providers.request_completion(config, 's', 'c', threading.Event())


def test_markdown_ranking_cell_cannot_break_row():
    from patchtrace.reports import _cell
    assert '\n' not in _cell('evil\n## heading\r\n| x |')
    assert _cell('a | b').count('|') == _cell('a | b').count('\\|')
