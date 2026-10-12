"""Audit regressions for SPEC-07 detectors (§5) and CLI envelope/exit codes (§11)."""
from __future__ import annotations

import json

import pytest

from patchtrace import cli
from patchtrace.enrichment.signals import detect
from patchtrace.enrichment.views import match_view
from patchtrace.models import FunctionMatch, FunctionRecord
from patchtrace.service import ProjectService

HEAD = 'void f(char *b, int n, uint i) {\n'


def _detectors(old: str, new: str) -> dict[str, list[tuple[int, int]]]:
    rec = lambda side, code: FunctionRecord(artifact_id=side, run_id='r', name='f', code=code)  # noqa: E731
    match = FunctionMatch(run_id='r', category='modified', older=[rec('a-old', old)], newer=[rec('a-new', new)])
    result = detect(match_view(match, '0' * 64, {'older': 'a-old', 'newer': 'a-new'}))
    return {s.detector: [(loc.start_line, loc.end_line) for loc in s.locations] for s in result.signals}


def test_bnd_sees_ghidra_cast_pointer_arithmetic():
    old = HEAD + '  *(char *)(param_1 + param_2) = 0;\n}'
    new = HEAD + '  if (param_2 < 0x41) {\n    *(char *)(param_1 + param_2) = 0;\n  }\n}'
    assert _detectors(old, new).get('BND') == [(2, 3)]


def test_bnd_cast_deref_without_arithmetic_still_negative():
    old = HEAD + '  *(char *)param_2 = 0;\n}'
    new = HEAD + '  if (param_2 < 0x41) {\n    *(char *)param_2 = 0;\n  }\n}'
    assert 'BND' not in _detectors(old, new)


@pytest.mark.parametrize('branch', ['  }\n  else if (i < n) {\n', '  } else if (i < n) {\n'])
def test_bnd_added_else_if_predicate(branch):
    old = HEAD + '  b[i] = 0;\n}'
    new = HEAD + '  if (n == 0) {\n    return;\n' + branch + '    b[i] = 0;\n  }\n}'
    assert 'BND' in _detectors(old, new)


@pytest.fixture
def project(tmp_path):
    service = ProjectService.sample(tmp_path / 'case')
    root = service.root
    service.close()
    return root


def test_correlate_cancelled_exits_5_with_cancelled_envelope(project, capsys, monkeypatch):
    from patchtrace.enrichment import pipeline
    real = pipeline.run

    def cancelled_run(project_, options, cancel, progress=None):
        cancel.set()
        return real(project_, options, cancel, progress)
    monkeypatch.setattr(pipeline, 'run', cancelled_run)
    code = cli.main(['correlate', str(project), '--cve', 'CVE-2024-0001', '--json', '--dry-run'])
    out, _ = capsys.readouterr()
    assert code == 5
    assert json.loads(out)['status'] == 'cancelled'


def test_keyboard_interrupt_json_emits_one_document(project, capsys, monkeypatch):
    def interrupt(*_a, **_k):
        raise KeyboardInterrupt
    monkeypatch.setitem(cli.HANDLERS, 'rank', interrupt)
    code = cli.main(['rank', str(project), '--json'])
    out, _ = capsys.readouterr()
    assert code == 5
    doc = json.loads(out)
    assert (doc['contract'], doc['command'], doc['status']) == ('enrichment-cli/1', 'rank', 'cancelled')
