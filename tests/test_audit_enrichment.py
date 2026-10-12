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


# ---- SIZE: decompiler temp spill is not a size change (coordinator decision 1) ----

def test_size_ignores_temp_spill_of_same_expression():
    old = HEAD + '  p = malloc(n + i);\n}'
    new = HEAD + '  uVar1 = n + i;\n  p = malloc(uVar1);\n}'
    assert 'SIZE' not in _detectors(old, new)


def test_size_still_fires_when_spilled_value_differs():
    old = HEAD + '  p = malloc(n + i);\n}'
    new = HEAD + '  uVar1 = n + i + 1;\n  p = malloc(uVar1);\n}'
    assert _detectors(old, new).get('SIZE') == [(2, 2), (3, 3)]


def test_size_spill_negative_requires_decompiler_temporary():
    old = HEAD + '  p = malloc(n + i);\n}'
    new = HEAD + '  len = n + i;\n  p = malloc(len);\n}'
    assert 'SIZE' in _detectors(old, new)  # a named variable is a real source change


# ---- BND co-fires with OVF on a wrapped-sum guard (coordinator decision 2) ----

def test_bnd_and_ovf_share_one_group_on_wrapped_sum_guard():
    from patchtrace.enrichment import ranking
    from patchtrace.enrichment.contracts import RankingConfig
    old = HEAD + '  p = malloc(n + i);\n}'
    new = HEAD + '  uVar1 = n + i;\n  if (uVar1 < n) {\n    return;\n  }\n  p = malloc(uVar1);\n}'
    rec = lambda side, code: FunctionRecord(artifact_id=side, run_id='r', name='f', code=code)  # noqa: E731
    match = FunctionMatch(run_id='r', category='modified', older=[rec('a-old', old)], newer=[rec('a-new', new)])
    result = detect(match_view(match, '0' * 64, {'older': 'a-old', 'newer': 'a-new'}))
    pair = [s for s in result.signals if s.detector in ('BND', 'OVF')]
    assert sorted(s.detector for s in pair) == ['BND', 'OVF']
    assert len({s.group_key for s in pair}) == 1
    _, _, groups = ranking.score_signals(pair, RankingConfig())
    assert len(groups) == 1 and groups[0].points == min(40, groups[0].a + min(12, groups[0].b // 4))


# ---- WIL: noise hunks never qualify ----

def _wil(old: str, new: str):
    from patchtrace.enrichment import wil
    rec = lambda side, code: FunctionRecord(artifact_id=side, run_id='r', name='f', code=code)  # noqa: E731
    match = FunctionMatch(run_id='r', category='modified', older=[rec('a-old', old)], newer=[rec('a-new', new)])
    view = match_view(match, '0' * 64, {'older': 'a-old', 'newer': 'a-new'})
    transitions = wil.analyze(view)
    return [(t.kind, t.qualifies) for t in transitions], wil.wil_signals(view, transitions)


GATE = 'Feature_7__private_IsEnabledDeviceUsage()'


def test_wil_rename_only_hunk_is_not_condition_change():
    old = f'void f(void) {{\n  iVar1 = g();\n  if ({GATE} && iVar1 > 0) {{\n    h(iVar1);\n  }}\n}}'
    new = old.replace('iVar1', 'iVar2')
    kinds, sigs = _wil(old, new)
    assert kinds == [('unchanged-around-change', False)] and sigs == ()


def test_wil_whitespace_only_hunk_does_not_qualify():
    old = f'void f(void) {{\n  if ({GATE}) {{\n    h(1);\n  }}\n}}'
    kinds, sigs = _wil(old, old.replace('h(1)', 'h( 1 )'))
    assert not any(q for _, q in kinds) and sigs == ()


def test_wil_real_guarded_change_still_qualifies():
    old = f'void f(void) {{\n  if ({GATE}) {{\n    h(1);\n  }}\n}}'
    kinds, sigs = _wil(old, old.replace('h(1)', 'h(2)'))
    assert kinds == [('guarded-behavior-changed', True)] and len(sigs) == 1


# ---- cache: quarantine re-verifies under the lock ----

def test_quarantine_never_moves_a_valid_entry(tmp_path):
    from patchtrace.enrichment.cache import CacheConfig, DerivedCache
    from patchtrace.enrichment.identity import stage_id
    cache = DerivedCache(CacheConfig(root=tmp_path / 'cache'))
    key = stage_id('signals', 1, {'x': '1'})
    assert cache.put('signals', key, b'payload', {})
    assert cache._quarantine('signals', key) is False  # a writer republished a valid entry
    assert cache.get('signals', key) == b'payload'


# ---- pipeline: zero pairings is an empty complete ranking ----

def test_zero_pairings_rank_complete_and_cli_exits_4(project, capsys, monkeypatch):
    from patchtrace.enrichment import pipeline
    service = ProjectService.open(project)
    try:
        empty = service.project.model_copy(update={'matches': []})
        result = pipeline.run(empty)
    finally:
        service.close()
    assert result.ranking is not None and result.ranking.entries == ()
    assert result.ranking.status == 'complete' and result.status.status == 'complete'
    real = pipeline.run
    monkeypatch.setattr(pipeline, 'run', lambda p, *a, **k: real(p.model_copy(update={'matches': []}), *a, **k))
    code = cli.main(['rank', str(project), '--json', '--dry-run'])
    assert code == 4 and json.loads(capsys.readouterr()[0])['status'] == 'complete'


def test_non_default_profile_only_is_not_reported_stale(project, capsys):
    from patchtrace.enrichment import pipeline
    from patchtrace.enrichment.storage import EnrichmentStore
    assert cli.main(['rank', str(project), '--disable', 'BND']) == 0
    capsys.readouterr()
    service = ProjectService.open(project)
    try:
        ranking, _, note = pipeline.load_default(EnrichmentStore(service.store), service.project)
    finally:
        service.close()
    assert ranking is None and 'stale' not in note.lower()


# ---- ranking ties and dedup (§6) ----

def test_ranking_dedups_signal_ids_and_breaks_ties_by_pairing_id():
    from patchtrace.enrichment import ranking
    from patchtrace.enrichment.contracts import RankingConfig
    old = HEAD + '  b[i] = 0;\n}'
    new = HEAD + '  if (0x40 < i) {\n    b[i] = 0;\n  }\n}'
    sets = []
    for name in ('f', 'g'):
        rec = lambda side, code, n=name: FunctionRecord(artifact_id=side, run_id='r', name=n, code=code)  # noqa: E731
        m = FunctionMatch(run_id='r', category='modified', older=[rec('a-old', old)], newer=[rec('a-new', new)])
        sets.append(detect(match_view(m, '0' * 64, {'older': 'a-old', 'newer': 'a-new'})))
    sets[0] = sets[0].model_copy(update={'signals': sets[0].signals * 2})  # duplicated signal ids
    result = ranking.rank(sets, RankingConfig())
    first, second = result.entries
    assert first.score == second.score and first.raw == second.raw
    assert first.pairing_id < second.pairing_id  # tie → pairing id ascending
    assert all(len(g.signal_ids) == len(set(g.signal_ids)) for e in result.entries for g in e.groups)


# ---- CLI / GUI loader / export agreement ----

def test_cli_gui_export_agree_on_default_ranking(project, capsys):
    from patchtrace import reports
    from patchtrace.enrichment import pipeline
    from patchtrace.enrichment.storage import EnrichmentStore
    assert cli.main(['rank', str(project), '--json']) == 0
    doc = json.loads(capsys.readouterr()[0])
    service = ProjectService.open(project)
    try:
        ranking, _, note = pipeline.load_default(EnrichmentStore(service.store), service.project)
        assert ranking is not None, note
        section = reports._ranking_section(service.project, {'ranking': ranking.model_dump(mode='json'),
                                                             'stale': False},
                                           {m.id for m in service.project.matches})
    finally:
        service.close()
    key = lambda e: (e['rank'], e['match_id'], e['score'], e['raw'], e['evidence'])  # noqa: E731
    cli_rows = [key(e) for e in doc['result']['entries']]
    gui_rows = [(e.rank, e.match_id, e.score, e.raw, e.evidence) for e in ranking.entries]
    export_rows = [key(e) for e in section['entries']]
    assert cli_rows == gui_rows == export_rows
    assert doc['result']['status'] == ranking.status == section['status']
    assert doc['result']['config_digest'] == section['config_digest']
