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


def _override_export(tmp_path, include_code):
    import json

    from patchtrace.reports import export_project
    from patchtrace.sample import create_sample
    service = create_sample(tmp_path / 'p')
    match = next(m for m in service.project.matches if m.category == 'modified' and m.newer[0].name == 'read_item')
    service.correct_match(match.id, [match.older[0].id], [match.newer[0].id], 'modified', 'test reason')
    out = tmp_path / 'r.json'
    export_project(service.project, 'json', out, include_code=include_code)
    return json.loads(out.read_text()), service


def test_code_free_export_omits_code_embedded_in_match_override(tmp_path):
    data, service = _override_export(tmp_path, False)
    text = str(data)
    assert 'return buffer[index]' not in text and 'previous_matches' not in text
    assert 'test reason' in text
    assert 'previous_matches' in service.project.annotations[-1].text  # revert data stays in the project


def test_code_export_keeps_code_text_verbatim(tmp_path):
    from patchtrace.reports import _clean, _Verbatim
    source = 'x = a /b; /* note */ // c:/foo http://h/p'
    assert _clean({'code': _Verbatim(source)})['code'] == source
    assert '[PATH REDACTED]' in _clean({'name': source})['name']
    assert _clean(_Verbatim('password=hunter2 ok')) == '[REDACTED] ok'


def test_redact_log_hides_whole_authorization_value():
    from patchtrace.diagnostics import redact_log
    for line in ('Authorization: Token abcdefghijk123', 'Authorization: ApiKey abc123def456'):
        assert redact_log(line) == 'Authorization: [redacted]'


@pytest.mark.parametrize('fmt', ['json', 'md', 'html'])
def test_export_neutralises_bidi_and_escape_controls(tmp_path, fmt):
    from patchtrace.reports import export_project
    from patchtrace.sample import create_sample
    service = create_sample(tmp_path / 'p')
    project = service.project.model_copy(update={'name': 'Project\u202egnp\x1b[2J'})
    out = tmp_path / f'r.{fmt}'
    export_project(project, fmt, out)
    text = out.read_text(encoding='utf-8')
    assert not any(ch in text for ch in '\u202e\x1b') and 'gnp' in text
