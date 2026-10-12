"""B1 detector tests (SPEC-07 §5). All decompiled snippets here are SYNTHETIC fixtures."""
from __future__ import annotations

import doctest
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from patchtrace.enrichment import identity, signals
from patchtrace.enrichment.contracts import RankingConfig
from patchtrace.enrichment.ranking import rank
from patchtrace.enrichment.signals import DETECTORS, detect
from patchtrace.enrichment.views import match_view
from patchtrace.models import FunctionMatch, FunctionRecord

DIFF = '1' * 64
ARTIFACTS = {'older': 'art-old', 'newer': 'art-new'}


def rec(side, code, name='f'):
    return FunctionRecord(artifact_id=ARTIFACTS[side], run_id='run', name=name, code=code, address='180001000')


def view(old, new, category='modified'):
    older = [rec('older', old)] if old is not False else []
    newer = [rec('newer', new)] if new is not False else []
    return match_view(FunctionMatch(run_id='run', category=category, older=older, newer=newer), DIFF, ARTIFACTS)


def fn(*body):
    return '\n'.join(['int f(char *buf, int len, int idx, char *dst) {', *body, '}'])


def found(old, new, detector=None):
    result = detect(view(old, new), [detector] if detector else None)
    return [s for s in result.signals if detector is None or s.detector == detector]


def ids(old, new):
    return sorted(s.detector for s in detect(view(old, new)).signals)


# --- BND ------------------------------------------------------------------

BND_OLD = fn('  int iVar1;', '  iVar1 = (int)buf[idx];', '  return iVar1;')
BND_NEW = fn('  int iVar1;', '  if (len <= idx) {', '    return 0;', '  }', '  iVar1 = (int)buf[idx];',
             '  return iVar1;')


def test_bnd_positive_guard_before_subscript():
    sig = found(BND_OLD, BND_NEW, 'BND')
    assert len(sig) == 1 and sig[0].confidence == 'moderate' and not sig[0].typed_evidence
    loc = sig[0].locations[0]
    assert loc.side == 'newer' and loc.start_line == 3 and loc.end_line == 6
    code = view(BND_OLD, BND_NEW).newer[0].code
    assert loc.excerpt_sha256 == identity.excerpt_sha256(code[2:6])


def test_bnd_positive_memcpy_size_linkage():
    old = fn('  memcpy(dst, buf, len);', '  return 0;')
    new = fn('  if (0x40 < len) {', '    return 0;', '  }', '  memcpy(dst, buf, len);', '  return 0;')
    assert len(found(old, new, 'BND')) == 1


def test_bnd_negative_comparison_without_index_use():
    old = fn('  return len;')
    new = fn('  if (len < 5) {', '    len = 5;', '  }', '  return len;')
    assert found(old, new, 'BND') == []


def test_bnd_negative_sign_test_is_not_a_bound():
    old = fn('  return buf[idx];')
    new = fn('  if (idx < 0) {', '    idx = 0;', '  }', '  return buf[idx];')
    assert found(old, new, 'BND') == []


def test_bnd_negative_unchanged_guard_moved_by_optimizer():
    old = fn('  if (idx < len) {', '    len = len + 1;', '    return buf[idx];', '  }', '  return 0;')
    new = fn('  len = len + 1;', '  if (idx < len) {', '    return buf[idx];', '  }', '  return 0;')
    assert found(old, new) == []


def test_bnd_negative_mirrored_comparison_is_same_guard():
    old = fn('  if (idx < len) {', '    return buf[idx];', '  }', '  return 0;')
    new = fn('  if (len > idx) {', '    return buf[idx];', '  }', '  return 0;')
    assert found(old, new) == []


# --- INT ------------------------------------------------------------------

def test_int_strictness_change_same_operands_is_moderate():
    old = fn('  if (idx < len) {', '    return buf[idx];', '  }', '  return 0;')
    new = fn('  if (idx <= len) {', '    return buf[idx];', '  }', '  return 0;')
    sig = found(old, new, 'INT')
    assert len(sig) == 1 and sig[0].confidence == 'moderate'
    assert [loc.side for loc in sig[0].locations] == ['older', 'newer']


def test_int_strictness_change_through_renamed_temp_is_weak():
    old = fn('  if (iVar1 < len) {', '    return 1;', '  }', '  return 0;')
    new = fn('  if (iVar2 <= len) {', '    return 1;', '  }', '  return 0;')
    assert [s.confidence for s in found(old, new, 'INT')] == ['weak']


def test_int_signedness_cast_change():
    old = fn('  if ((int)idx < len) {', '    return 1;', '  }', '  return 0;')
    new = fn('  if ((uint)idx < (uint)len) {', '    return 1;', '  }', '  return 0;')
    assert len(found(old, new, 'INT')) == 1


def test_int_negatives():
    base = ['    return 1;', '  }', '  return 0;']
    # equivalent rewrite with different operands
    assert found(fn('  if (idx < len) {', *base), fn('  if (idx <= len - 1) {', *base), 'INT') == []
    # direction flip is not a strictness change
    assert found(fn('  if (idx < len) {', *base), fn('  if (idx > len) {', *base), 'INT') == []
    # identical casts, renamed temporaries only
    assert found(fn('  if ((uint)iVar1 < (uint)len) {', *base),
                 fn('  if ((uint)iVar3 < (uint)len) {', *base)) == []
    # cast change on different operands
    assert found(fn('  if ((int)idx < len) {', *base), fn('  if ((uint)len < 7) {', *base), 'INT') == []


# --- OVF ------------------------------------------------------------------

def test_ovf_wrapped_sum_guard_linked_to_alloc():
    old = fn('  uVar1 = len + idx;', '  p = malloc(uVar1);', '  return 0;')
    new = fn('  uVar1 = len + idx;', '  if (uVar1 < len) {', '    return -1;', '  }', '  p = malloc(uVar1);',
             '  return 0;')
    assert len(found(old, new, 'OVF')) == 1


def test_ovf_max_minus_guard_and_checked_call():
    old = fn('  memcpy(dst, buf, len + idx);', '  return 0;')
    new = fn('  if (0xffffffff - idx < len) {', '    return -1;', '  }', '  memcpy(dst, buf, len + idx);',
             '  return 0;')
    assert len(found(old, new, 'OVF')) == 1
    new2 = fn('  iVar1 = RtlULongAdd(len, idx, &total);', '  if (iVar1 < 0) {', '    return iVar1;', '  }',
              '  p = ExAllocatePool2(0x40, total, 0x74615074);', '  return 0;')
    old2 = fn('  total = len + idx;', '  p = ExAllocatePool2(0x40, total, 0x74615074);', '  return 0;')
    assert len(found(old2, new2, 'OVF')) == 1


def test_ovf_negative_guard_not_linked_to_size():
    old = fn('  return len + idx;')
    new = fn('  if (len + idx < len) {', '    return -1;', '  }', '  return len + idx;')
    assert found(old, new, 'OVF') == []


# --- VAL ------------------------------------------------------------------

def test_val_added_probe_and_checked_validator():
    old = fn('  memcpy(dst, buf, 8);', '  return 0;')
    assert len(found(old, fn('  ProbeForRead(buf, 8, 1);', '  memcpy(dst, buf, 8);', '  return 0;'), 'VAL')) == 1
    new = fn('  iVar1 = ValidateHeader(buf);', '  if (iVar1 != 0) {', '    return iVar1;', '  }',
             '  memcpy(dst, buf, 8);', '  return 0;')
    assert len(found(old, new, 'VAL')) == 1


def test_val_newly_checked_return_of_existing_call():
    old = fn('  Initialize(buf);', '  return 0;')
    new = fn('  iVar1 = Initialize(buf);', '  if (iVar1 < 0) {', '    return iVar1;', '  }', '  return 0;')
    assert len(found(old, new, 'VAL')) == 1


def test_val_negative_api_name_alone():
    old = fn('  return 0;')
    # validator name with discarded result, and inside a comment/string
    new = fn('  CheckState(buf);', '  /* ValidateHeader(buf) */', '  puts("CheckThis(x)");', '  return 0;')
    assert found(old, new, 'VAL') == []


# --- ERR ------------------------------------------------------------------

@pytest.mark.parametrize('value', ['0xc000000d', '-1', 'STATUS_INVALID_PARAMETER', '(NTSTATUS)0xC0000023'])
def test_err_positive(value):
    old = fn('  return 0;')
    new = fn('  if (len == 0) {', f'    return {value};', '  }', '  return 0;')
    assert len(found(old, new, 'ERR')) == 1


def test_err_goto_with_assigned_status():
    old = fn('  iVar1 = 0;', 'LAB_1:', '  return iVar1;')
    new = fn('  iVar1 = 0;', '  if (len == 0) {', '    iVar1 = -0x3ffffff3;', '    goto LAB_1;', '  }', 'LAB_1:',
             '  return iVar1;')
    assert len(found(old, new, 'ERR')) == 1


def test_err_negatives():
    old = fn('  return 0;')
    assert found(old, fn('  if (len == 0) {', '    return 0;', '  }', '  return 0;'), 'ERR') == []
    assert found(old, fn('  if (len == 0) {', '    return STATUS_SUCCESS;', '  }', '  return 0;'), 'ERR') == []
    assert found(old, fn('  return -1;'), 'ERR') == []  # no predicate


# --- SIZE -----------------------------------------------------------------

def test_size_changed_at_same_ordinal():
    old = fn('  memcpy(dst, buf, len);', '  memcpy(dst + 8, buf, 4);', '  return 0;')
    new = fn('  memcpy(dst, buf, len);', '  memcpy(dst + 8, buf, 2);', '  return 0;')
    sig = found(old, new, 'SIZE')
    assert len(sig) == 1 and sig[0].locations[0].start_line == 3 and sig[0].locations[1].start_line == 3


def test_size_negatives():
    old = fn('  memcpy(dst, buf, uVar1);', '  return 0;')
    assert found(old, fn('  memcpy(dst, buf, uVar2);', '  return 0;'), 'SIZE') == []  # rename
    assert found(old, fn('  memcpy(dst, buf, 4);', '  memcpy(dst, buf, uVar1);', '  return 0;'), 'SIZE') == []
    assert found(old, fn('  memmove(dst, buf, 4);', '  return 0;'), 'SIZE') == []  # different callee


# --- SCRUB ----------------------------------------------------------------

SCRUB_OLD = fn('  undefined local_38 [32];', '  fill(local_38);', '  memcpy(dst, local_38, 0x20);', '  return 0;')


def test_scrub_positive_zero_before_copy_of_same_object():
    new = fn('  undefined local_38 [32];', '  memset(local_38, 0, 0x20);', '  fill(local_38);',
             '  memcpy(dst, local_38, 0x20);', '  return 0;')
    sig = found(SCRUB_OLD, new, 'SCRUB')
    assert len(sig) == 1 and sig[0].locations[0].start_line == 3 and sig[0].locations[0].end_line == 5


def test_scrub_positive_rtlzero_with_address_of():
    old = fn('  S local_48;', '  RtlCopyMemory(dst, &local_48, 0x10);', '  return 0;')
    new = fn('  S local_48;', '  RtlZeroMemory(&local_48, 0x10);', '  RtlCopyMemory(dst, &local_48, 0x10);',
             '  return 0;')
    assert len(found(old, new, 'SCRUB')) == 1


def test_scrub_negatives():
    # zeroing a different object near the copy
    other = fn('  undefined local_38 [32];', '  memset(local_58, 0, 0x20);', '  fill(local_38);',
               '  memcpy(dst, local_38, 0x20);', '  return 0;')
    assert found(SCRUB_OLD, other, 'SCRUB') == []
    # zeroing after the copy
    after = fn('  undefined local_38 [32];', '  fill(local_38);', '  memcpy(dst, local_38, 0x20);',
               '  memset(local_38, 0, 0x20);', '  return 0;')
    assert found(SCRUB_OLD, after, 'SCRUB') == []
    # zeroed object is the copy destination, not the source
    dest = fn('  undefined local_38 [32];', '  fill(local_38);', '  memset(dst, 0, 0x20);',
              '  memcpy(dst, local_38, 0x20);', '  return 0;')
    assert found(SCRUB_OLD, dest, 'SCRUB') == []
    # zeroing already present on the older side
    both = fn('  memset(local_38, 0, 0x20);', '  memcpy(dst, local_38, 0x20);', '  return 0;')
    assert found(both, both.replace('return 0', 'return 1'), 'SCRUB') == []


# --- cross-cutting negatives -----------------------------------------------

def test_variable_renames_only_yield_no_signal():
    old = fn('  int iVar1;', '  if (iVar1 < len) {', '    memset(local_38, 0, 8);', '    memcpy(dst, local_38, iVar1);',
             '    return -1;', '  }', '  return buf[iVar1];')
    new = old.replace('iVar1', 'iVar2').replace('local_38', 'local_40')
    result = detect(view(old, new))
    assert result.status == 'complete' and result.signals == ()


def test_whitespace_and_comment_only_hunks_yield_no_signal():
    new = BND_NEW.replace('if (len <= idx)', 'if (len  <=   idx)').replace('return 0;', 'return 0; /* x */')
    result = detect(view(BND_NEW, new))
    assert result.status == 'complete' and result.signals == ()
    assert all(o.status == 'complete' for o in result.outcomes)


@pytest.mark.parametrize('category', ['added', 'removed'])
def test_one_sided_categories_are_unavailable(category):
    v = view(False, BND_NEW, category) if category == 'added' else view(BND_OLD, False, category)
    result = detect(v)
    assert result.status == 'unavailable' and result.signals == ()
    assert {o.status for o in result.outcomes} == {'unavailable'}
    assert {o.detector for o in result.outcomes} == {d.id for d in DETECTORS}


def test_missing_code_is_unavailable_not_zero():
    result = detect(view(None, BND_NEW))
    assert result.status == 'unavailable' and all('missing' in o.reason for o in result.outcomes)


def test_split_with_two_functions_is_unavailable():
    m = FunctionMatch(run_id='run', category='split', older=[rec('older', BND_OLD)],
                      newer=[rec('newer', BND_NEW, 'f1'), rec('newer', BND_NEW, 'f2')])
    result = detect(match_view(m, DIFF, ARTIFACTS))
    assert result.status == 'unavailable' and all('1:1' in o.reason for o in result.outcomes)


def test_ambiguous_one_to_one_runs_and_records_ambiguity():
    result = detect(view(BND_OLD, BND_NEW, 'ambiguous'))
    assert result.signals and all('ambiguous-match' in s.limitations for s in result.signals)


def test_side_reversal_does_not_claim_added_guard():
    assert 'BND' in ids(BND_OLD, BND_NEW)
    assert ids(BND_NEW, BND_OLD) == []


def test_detectors_on_same_edit_share_group_and_distinct_edits_do_not():
    old = fn('  return buf[idx];')
    new = fn('  if (len <= idx) {', '    return -1;', '  }', '  return buf[idx];')
    sig = found(old, new)
    assert sorted(s.detector for s in sig) == ['BND', 'ERR'] and len({s.group_key for s in sig}) == 1
    two = fn('  if (len <= idx) {', '    return -1;', '  }', '  x = 1;', '  if (idx < 0x100) {', '    return -2;',
             '  }', '  return buf[idx];')
    groups = {s.group_key for s in found(fn('  x = 0;', '  return buf[idx];'), two)}
    assert len(groups) == 2


def test_determinism_and_disabled_detectors():
    v = view(BND_OLD, BND_NEW)
    m = FunctionMatch(run_id='run', category='modified', older=[rec('older', BND_OLD)], newer=[rec('newer', BND_NEW)])
    assert detect(match_view(m, DIFF, ARTIFACTS)) == detect(match_view(m, DIFF, ARTIFACTS))
    only = detect(v, ['ERR'])
    assert [o.detector for o in only.outcomes] == ['ERR']
    with pytest.raises(ValueError):
        detect(v, ['WIL'])


def test_detector_run_matches_detect_and_declares_metadata():
    v = view(BND_OLD, BND_NEW)
    assert [d.id for d in DETECTORS] == ['BND', 'INT', 'OVF', 'VAL', 'ERR', 'SIZE', 'SCRUB']
    combined = detect(v)
    for d in DETECTORS:
        assert d.version >= 1 and d.prerequisites and d.limitations and 'added' not in d.categories
        outcome, sigs = d.run(v)
        assert outcome in combined.outcomes
        assert set(sigs) == {s for s in combined.signals if s.detector == d.id}


def test_cancel_preset_and_during_scan():
    event = threading.Event()
    event.set()
    assert detect(view(BND_OLD, BND_NEW), cancel=event).status == 'cancelled'
    big = fn(*([f'  x{i} = {i};' for i in range(600)]))
    assert detect(view(big, big.replace('x5 = 5', 'x5 = 6')), cancel=event).status == 'cancelled'


def test_long_line_input_is_bounded():
    # nested parentheses / repeated operators must not explode regex or scan cost
    nasty = '  if (' + '(' * 5000 + 'idx' + ')' * 5000 + ' < ' + '<' * 5000 + ') {'
    result = detect(view(fn('  return 0;'), fn(nasty, '    return -1;', '  }', '  return 0;')))
    assert result.status == 'complete'


@settings(max_examples=40, deadline=None)
@given(st.lists(st.sampled_from(['  x = 1;', '  if (idx < len) {', '  }', '  return buf[idx];',
                                 '  memset(local_38, 0, 8);', '  memcpy(dst, local_38, len);', '  return -1;']),
                max_size=12))
def test_identical_sides_never_signal(body):
    code = fn(*body)
    assert detect(view(code, code)).signals == ()


# --- sample + ranking ------------------------------------------------------

def test_sample_signals_and_ranking_are_stable(tmp_path):
    from patchtrace.enrichment.views import build_views
    from patchtrace.service import ProjectService
    service = ProjectService.sample(tmp_path / 'sample')
    try:
        run = build_views(service.project)
        sets = [detect(m) for m in run.matches]
        again = [detect(m) for m in build_views(service.project).matches]
        assert sets == again
        read_item = next(s for s, m in zip(sets, run.matches, strict=True)
                         if m.category == 'modified' and m.newer[0].name == 'read_item')
        assert [s.detector for s in read_item.signals] == ['BND']
        config = RankingConfig()
        first, second = rank(sets, config), rank(list(reversed(again)), config)
        assert first == second
        assert first.entries[0].pairing_id == read_item.pairing_id and first.entries[0].score > 0
    finally:
        service.close()


def test_module_docstring_example_runs():
    assert doctest.testmod(signals).failed == 0


def test_signals_module_imports_no_qt_or_network():
    code = ('import sys\nimport patchtrace.enrichment.signals\n'
            "bad = [m for m in ('PySide6', 'subprocess', 'ssl', 'http.client', 'urllib.request') if m in sys.modules]\n"
            'print(bad)\nraise SystemExit(1 if bad else 0)\n')
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, check=False,
                            env={'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')})
    assert result.returncode == 0, result.stdout + result.stderr
