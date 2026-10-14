"""SPEC-07h hardening backlog regressions (H3-H6). Fixtures are synthetic."""
from __future__ import annotations

import pytest
from test_enrichment_signals import BND_NEW, BND_OLD, view

from patchtrace.enrichment import identity, pipeline, signals
from patchtrace.enrichment.contracts import DetectorOutcome, RankingConfig, SignalSet
from patchtrace.enrichment.ranking import rank
from patchtrace.enrichment.signals import detect
from patchtrace.service import ProjectService


@pytest.fixture
def service(tmp_path):
    svc = ProjectService.sample(tmp_path / 'case')
    yield svc
    if not svc.store.closed:
        svc.close()


# --- H3: partial only for real partials ---------------------------------------

def test_reason_prefixes_are_declared_and_used():
    assert signals.NOT_APPLICABLE and signals.LIMIT and signals.NOT_APPLICABLE != signals.LIMIT
    for old, new, cat in ((False, BND_NEW, 'added'), (BND_OLD, False, 'removed'), (None, BND_NEW, 'modified')):
        for o in detect(view(old, new, cat)).outcomes:
            assert o.reason.startswith(signals.REASON_PREFIXES), o.reason


def test_one_sided_pairing_is_unavailable_and_missing_code_is_partial():
    assert detect(view(False, BND_NEW, 'added')).status == 'unavailable'
    assert detect(view(BND_OLD, False, 'removed')).status == 'unavailable'
    assert detect(view(None, BND_NEW)).status == 'partial'
    assert detect(view(BND_OLD, None)).status == 'partial'


def test_not_applicable_outcomes_do_not_degrade_a_complete_set():
    pid = identity.domain_id('t', 1, 'p')
    outcomes = (DetectorOutcome(pairing_id=pid, detector='BND', status='complete'),
                DetectorOutcome(pairing_id=pid, detector='OVF', status='unavailable',
                                reason=signals.NOT_APPLICABLE + ' category'),
                DetectorOutcome(pairing_id=pid, detector='ERR', status='unavailable', reason=signals.LIMIT + ' x'))
    assert signals.aggregate_status(outcomes[:2]) == 'complete'
    assert signals.aggregate_status(outcomes) == 'partial'
    assert signals.aggregate_status(outcomes[1:2]) == 'unavailable'
    failed = (outcomes[0], DetectorOutcome(pairing_id=pid, detector='WIL', status='failed'))
    assert signals.aggregate_status(failed) == 'partial'


def test_run_with_added_and_removed_functions_is_complete(service):
    result = pipeline.run(service.project)
    assert [c.category for c in {s.match_id: s for s in result.signal_sets}.values()].count('added') == 1
    assert {s.stage: s.status for s in result.status.stages}['signals'] == 'complete'
    assert result.status.status == 'complete'
    by_match = {s.match_id: s for s in result.signal_sets}
    for entry in result.ranking.entries:
        category = by_match[entry.match_id].category
        assert entry.evidence == ('unavailable' if category in {'added', 'removed'} else 'complete'), category
    assert result.ranking.status == 'complete'  # structural unavailability does not degrade the ranking


def test_wil_outcome_is_per_pairing_and_failure_is_global(service, monkeypatch):
    result = pipeline.run(service.project)
    for s in result.signal_sets:
        wil = next(o for o in s.outcomes if o.detector == 'WIL')
        assert wil.status == ('unavailable' if s.category in {'added', 'removed'} else 'complete')
        if wil.status == 'unavailable':
            assert wil.reason.startswith(signals.NOT_APPLICABLE)
    from patchtrace.enrichment import wil as wil_mod

    def boom(*_a, **_k):
        from patchtrace.enrichment.contracts import EnrichmentError
        raise EnrichmentError('PT-ENRICH-INPUT', 'boom')
    monkeypatch.setattr(wil_mod, 'analyze', boom)
    failed = pipeline.run(service.project)
    assert all(next(o for o in s.outcomes if o.detector == 'WIL').status == 'failed' for s in failed.signal_sets)
    assert failed.status.status == 'partial'


def test_golden_ranking_arithmetic_unchanged_by_status_rules():
    pid = identity.domain_id('t', 1, 'p')
    s = SignalSet(pairing_id=pid, match_id='m', category='modified', signals=(),
                  outcomes=(DetectorOutcome(pairing_id=pid, detector='BND', status='complete'),), status='complete')
    assert rank([s], RankingConfig()).entries[0].score == 0


# --- H6: _TEMP only collapses real Ghidra temporaries ---------------------------

NAMED = ['myVar1', 'tmpVar2', 'idxVar1', 'in_len', 'in_buf', 'local_buffer', 'local_x', 'param_count', 'param_',
         'stack_size', 'DAT_table', 'FUN_main', 'extraout_value']
TEMPS = ['uVar1', 'iVar12', 'pcVar3', 'ppvVar4', 'auVar5', 'uStack_c', 'local_18', 'local_res10', 'param_3',
         'in_RAX', 'in_stack_00000010', 'extraout_RAX', 'extraout_var_00', 'unaff_RBX', 'DAT_180012345',
         'LAB_18001a2b0', 'FUN_1800010a0', 'PTR_DAT_180034560', 'switchD_180001234', 'caseD_3',
         'joined_r0x180001abc', 'stack0x00000008']


@pytest.mark.parametrize('name', NAMED)
def test_real_names_are_not_temporaries(name):
    assert not signals._TEMP.fullmatch(name) and signals._norm_token(name) == name


@pytest.mark.parametrize('name', TEMPS)
def test_ghidra_temporaries_collapse(name):
    assert signals._TEMP.fullmatch(name) and signals._norm_token(name) == '$v'


def test_renaming_a_real_variable_is_a_change_but_temp_swap_is_not():
    def code(var):
        return '\n'.join(['int f(char *buf, int len, int idx, char *dst) {', f'  int {var};',
                          f'  {var} = len + 1;', f'  if ({var} > 8) {{ return {var}; }}', '  return 0;', '}'])
    assert signals.normalized_text(code('iVar1')) == signals.normalized_text(code('iVar2'))
    assert signals.normalized_text(code('myVar1')) != signals.normalized_text(code('count'))


from hypothesis import given  # noqa: E402
from hypothesis import strategies as st  # noqa: E402


@given(st.text(alphabet=st.characters(min_codepoint=33, max_codepoint=126), min_size=1, max_size=24))
def test_norm_token_is_idempotent_and_never_invents_dollar(token):
    once = signals._norm_token(token)
    assert signals._norm_token(once) == once
    if '$' not in token:
        assert once == token or once == '$v'


# --- H5: SIZE cast-only and BND added-loop false positives ----------------------

def _size_found(old_arg, new_arg, call='memcpy(dst, buf, {})', extra_new=()):
    from test_enrichment_signals import fn, found
    old = fn('  ' + call.format(old_arg) + ';', '  return 0;')
    new = fn(*extra_new, '  ' + call.format(new_arg) + ';', '  return 0;')
    return found(old, new, 'SIZE')


@pytest.mark.parametrize('old,new', [
    ('n', '(ulonglong)n'), ('(uint)n', '(ulong)n'), ('n', '(n)'), ('0x10', '0x10U'), ('16', '0x10'),
    ('(longlong)(int)n', 'n'), ('(uint)n', '(ushort)n'), ('16', '16UL'), ('sizeof(int)', 'sizeof(int)')])
def test_size_cast_only_changes_do_not_fire(old, new):
    assert _size_found(old, new) == []


def test_size_spill_still_forgiven():
    from test_enrichment_signals import fn, found
    old = fn('  malloc(n);', '  return 0;')
    new = fn('  uVar1 = n;', '  malloc(uVar1);', '  return 0;')
    assert found(old, new, 'SIZE') == []
    new = fn('  uVar1 = (ulonglong)n;', '  malloc(uVar1);', '  return 0;')
    assert found(old, new, 'SIZE') == []


@pytest.mark.parametrize('old,new', [
    ('n', 'n - 1'), ('n', '(ulonglong)n - 1'), ('n', 'm'), ('sizeof(struct A)', 'sizeof(struct B)'),
    ('sizeof(int)', 'sizeof(char)'), ('0x10', '0x20')])
def test_size_real_changes_fire(old, new):
    assert len(_size_found(old, new)) == 1


def test_size_canon_is_exposed_and_deterministic():
    toks = signals._TOKEN.findall('(ulonglong)(n)')
    assert signals.size_canon(toks) == signals.size_canon(['n'])


def _bnd(old_lines, new_lines):
    from test_enrichment_signals import fn, found
    return found(fn(*old_lines), fn(*new_lines), 'BND')


def test_bnd_new_loop_header_is_not_a_guard():
    old = ['  return 0;']
    assert _bnd(old, ['  for (i = 0; i < count; i++) { buf[i] = x; }', '  return 0;']) == []
    assert _bnd(old, ['  while (i < len) { dst[i++] = 0; }', '  return 0;']) == []
    assert _bnd(['  i = 0;', '  return 0;'], ['  i = 0;', '  while (i < len) {', '    dst[i++] = 0;', '  }',
                                              '  return 0;']) == []


def test_bnd_changed_existing_loop_bound_fires():
    old = ['  for (i = 0; i < len; i++) buf[i] = x;', '  return 0;']
    new = ['  for (i = 0; i < len && i < idx; i++) buf[i] = x;', '  return 0;']
    assert len(_bnd(old, new)) == 1
    old = ['  while (i < len) {', '    buf[i++] = x;', '  }', '  return 0;']
    new = ['  while (i < min(len, idx)) {', '    buf[i++] = x;', '  }', '  return 0;']
    assert len(_bnd(old, new)) == 1


def test_bnd_guard_inside_added_loop_and_plain_guard_still_count():
    old = ['  buf[idx] = 1;', '  return 0;']
    assert len(_bnd(old, ['  if (idx >= len) return -1;', '  buf[idx] = 1;', '  return 0;'])) == 1
    new = ['  for (i = 0; i < 4; i++) {', '    if (idx >= len) return -1;', '    buf[idx] = 1;', '  }',
           '  return 0;']
    assert len(_bnd(old, new)) == 1


def test_bnd_detector_version_bumped():
    assert {d.id: d.version for d in signals.DETECTORS}['BND'] == 2
