"""B2 WIL feature-gate evidence. All code fixtures are SYNTHETIC decompiler-like text."""
from __future__ import annotations

import subprocess
import sys

from hypothesis import given
from hypothesis import strategies as st

from patchtrace.alignment import diff_hunks
from patchtrace.enrichment import identity
from patchtrace.enrichment.views import FunctionView, Hunk, MatchView
from patchtrace.enrichment.wil import analyze, find_sites, wil_signals


def fn(code, side='newer', fid=None):
    lines = None if code is None else tuple(code.splitlines())
    return FunctionView(fid or f'f-{side}', f'a-{side}', 'r', side, 'FUN_1', 0, lines, None, False)


def mv(old, new, manual=False, older=None, newer=None):
    o = older if older is not None else (fn(old, 'older'),)
    n = newer if newer is not None else (fn(new, 'newer'),)
    hunks = ()
    if len(o) == 1 and len(n) == 1 and o[0].code is not None and n[0].code is not None:
        hunks = tuple(Hunk(h.operation, h.old_start, h.old_end, h.new_start, h.new_end)
                      for h in diff_hunks('\n'.join(o[0].code), '\n'.join(n[0].code), 'm'))
    pid = identity.domain_id('test-pairing', 1, [old, new, manual, len(o), len(n)])
    return MatchView(pid, 'm', 'r', 'modified', manual, 'high', o, n, hunks)


def ids(code):
    return [(s.identifier, s.feature_id) for s in find_sites(fn(code))]


# --- recognition ------------------------------------------------------------

def test_exact_identifier_recognition_and_rejections():
    assert ids('x = Feature_12345678;') == [('Feature_12345678', 12345678)]
    for bad in ('Feature_', 'Feature_12a', 'MyFeature_1', 'Feature_1x', 'Feature_4294967296',
                'Feature_99999999999', 'Feature_-1', 'feature_1'):
        assert ids(f'x = {bad};') == [], bad


def test_feature_zero_leading_zeros_and_max():
    assert ids('Feature_0;') == [('Feature_0', 0)]
    assert ids('Feature_0042;') == [('Feature_0042', 42)]
    assert ids('Feature_4294967295;') == [('Feature_4294967295', 4294967295)]


def test_public_wrappers_and_underivable_number():
    sites = find_sites(fn('a = Feature_7__private_IsEnabledDeviceUsage();\n'
                          'b = wil::details::FeatureImpl<__WilFeatureTraits_Feature_8>::__private_IsEnabled();\n'
                          'c = Feature_9::IsEnabled();\n'
                          'd = wil::details::FeatureImpl<NamedTraits>::__private_IsEnabled();\n'))
    assert [(s.feature_id, s.wrapper) for s in sites] == [
        (7, 'Feature_7__private_IsEnabledDeviceUsage'),
        (8, 'wil::details::FeatureImpl<__WilFeatureTraits_Feature_8>::__private_IsEnabled'),
        (9, 'Feature_9::IsEnabled'),
        (None, 'wil::details::FeatureImpl<NamedTraits>::__private_IsEnabled')]
    assert sites[3].identifier == 'NamedTraits'
    overflow = 'wil::details::FeatureImpl<__WilFeatureTraits_Feature_4294967296>::__private_IsEnabled();'
    assert find_sites(fn(overflow)) == ()


def test_unsupported_mangling_and_absent_symbols_yield_no_sites():
    assert ids('?IsEnabled@?$FeatureImpl@U__WilFeatureTraits_Feature_123@@@details@wil@@SA_NXZ();') == []
    assert ids('if (FUN_140001000() != 0) {\n  x = 1;\n}') == []
    assert find_sites(fn(None)) == ()


def test_control_classification_never_cfg():
    code = ('if (Feature_1 != 0) {\n  a();\n}\n'
            'b = Feature_2;\nif (b) {\n  c();\n}\n'
            'if (Feature_3) ;\n'
            '\n\n\n\n\nz = Feature_4;\n\n\n\n\n'
            'if (Feature_5)\n    d();\n')
    got = {s.feature_id: s.control for s in find_sites(fn(code))}
    assert got == {1: 'lexical-enclosure', 2: 'adjacent', 3: 'unknown', 4: 'unknown', 5: 'lexical-enclosure'}


def test_multiple_ids_and_duplicate_sites_preserved():
    code = 'if (Feature_1) {\n  a();\n}\nif (Feature_1) {\n  b();\n}\nx = Feature_2 + Feature_3;'
    sites = find_sites(fn(code))
    assert [s.feature_id for s in sites] == [1, 1, 2, 3]
    assert sites[0].location.start_line == 1 and sites[1].location.start_line == 4


# --- transitions ------------------------------------------------------------

OLD = 'int f(int n) {\n  x = 1;\n  return 0;\n}'
NEW_GATED = 'int f(int n) {\n  x = 1;\n  if (Feature_42 != 0) {\n    if (n > 8) {\n      return -1;\n    }\n  }\n  return 0;\n}'


def by_id(transitions):
    return {t.feature_id: t for t in transitions}


def test_introduced_gate_qualifies_and_signal_emitted():
    view = mv(OLD, NEW_GATED)
    (t,) = analyze(view, 'unverified')
    assert (t.kind, t.qualifies, t.confidence, t.symbol_status) == ('introduced', True, 'weak', 'unverified')
    (s,) = wil_signals(view, (t,))
    assert s.detector == 'WIL' and s.detector_version == 1 and s.confidence == 'weak'
    assert 'heuristic' in s.rationale and 'no-cfg-evidence' in s.limitations


def test_side_reversal_swaps_introduced_and_removed():
    assert analyze(mv(OLD, NEW_GATED))[0].kind == 'introduced'
    rev = analyze(mv(NEW_GATED, OLD))
    assert rev[0].kind == 'removed' and rev[0].qualifies


def test_guarded_behavior_changed_both_sides_moderate():
    old = 'void f() {\n  if (Feature_5) {\n    a(1);\n  }\n  z();\n}'
    new = 'void f() {\n  if (Feature_5) {\n    a(2);\n  }\n  z();\n}'
    view = mv(old, new)
    (t,) = analyze(view)
    assert (t.kind, t.qualifies, t.confidence) == ('guarded-behavior-changed', True, 'moderate')
    (s,) = wil_signals(view, (t,))
    assert s.confidence == 'moderate'
    assert s.group_key == identity.domain_id('edit', 1, {'pairing_id': view.pairing_id, 'hunk_ordinal': 0,
                                                         'side': 'newer', 'text': 'a(2);'})


def test_condition_changed():
    old = 'void f() {\n  if (Feature_5 && a) {\n    b();\n  }\n}'
    new = 'void f() {\n  if (Feature_5 && c) {\n    b();\n  }\n}'
    (t,) = analyze(mv(old, new))
    assert t.kind == 'condition-changed' and t.qualifies


def test_unchanged_gate_around_unrelated_change_does_not_qualify():
    old = 'void f() {\n  if (Feature_5) {\n    a();\n  }\n  z(1);\n}'
    new = 'void f() {\n  if (Feature_5) {\n    a();\n  }\n  z(2);\n}'
    view = mv(old, new)
    (t,) = analyze(view)
    assert (t.kind, t.qualifies) == ('unchanged-around-change', False)
    assert wil_signals(view, (t,)) == ()


def test_nearby_unrelated_guard_is_adjacent_note_only():
    old = 'void f() {\n  b = 0;\n  if (b) {\n    c();\n  }\n}'
    new = 'void f() {\n  b = Feature_9;\n  if (b) {\n    c();\n  }\n}'
    view = mv(old, new)
    (t,) = analyze(view)
    assert t.kind == 'introduced' and not t.qualifies and 'adjacent-only' in t.notes
    assert wil_signals(view, (t,)) == ()


def test_nested_gates_both_enclose_change():
    old = 'void f() {\n  if (Feature_1) {\n    if (Feature_2) {\n      a(1);\n    }\n  }\n}'
    new = old.replace('a(1)', 'a(2)')
    got = by_id(analyze(mv(old, new)))
    assert got[1].kind == got[2].kind == 'guarded-behavior-changed'
    assert got[1].qualifies and got[2].qualifies


def test_conflicting_mappings_noted():
    old = 'void f() {\n  if (Feature_1 && Feature_2) {\n    a(1);\n  }\n}'
    new = 'void f() {\n  if (Feature_01 && Feature_2) {\n    a(2);\n  }\n}'
    got = by_id(analyze(mv(old, new)))
    assert 'shared-condition' in got[1].notes and 'shared-condition' in got[2].notes
    assert 'identifier-spellings-differ' in got[1].notes


def test_underivable_id_never_qualifies():
    new = 'void f() {\n  if (wil::details::FeatureImpl<T>::__private_IsEnabled()) {\n    a();\n  }\n}'
    (t,) = analyze(mv('void f() {\n}', new))
    assert t.feature_id is None and t.kind == 'unknown' and not t.qualifies


def test_split_merged_and_manual_ambiguity():
    a, b = fn(NEW_GATED, 'newer', 'n1'), fn(NEW_GATED.replace('42', '43'), 'newer', 'n2')
    split = by_id(analyze(mv(OLD, None, older=(fn(NEW_GATED, 'older'),), newer=(a, b))))
    assert split[42].kind == 'unknown' and not split[42].qualifies and 'pairing-ambiguous' in split[42].notes
    assert split[43].kind == 'introduced' and split[43].confidence == 'weak' and not split[43].qualifies
    merged = analyze(mv(None, None, older=(fn(OLD, 'older', 'o1'), fn(OLD, 'older', 'o2')),
                        newer=(fn(NEW_GATED),)))
    assert merged[0].kind == 'introduced' and not merged[0].qualifies
    manual = analyze(mv(OLD, NEW_GATED, manual=True))
    assert not manual[0].qualifies and 'manual-match' in manual[0].notes
    added = analyze(mv(None, NEW_GATED, older=()))
    assert added[0].kind == 'introduced' and 'one-sided-pairing' in added[0].notes and not added[0].qualifies


def test_missing_code_is_unknown_not_qualified():
    view = mv(None, NEW_GATED, older=(fn(None, 'older'),))
    (t,) = analyze(view)
    assert not t.qualifies and 'code-unavailable' in t.notes
    assert wil_signals(view, (t,)) == ()


def test_site_limit_note():
    code = '\n'.join(f'x = Feature_{i};' for i in range(4100))
    assert len(find_sites(fn(code))) == 4096
    assert any('site-limit' in t.notes for t in analyze(mv('', code)))


def test_determinism():
    old = 'void f() {\n  if (Feature_1) {\n    a(1);\n  }\n}'
    new = old.replace('a(1)', 'a(2)')
    v = mv(old, new)
    first = analyze(v)
    assert first == analyze(v) and wil_signals(v, first) == wil_signals(v, analyze(v))
    assert first[0].transition_id == analyze(mv(old, new))[0].transition_id


def test_wil_module_is_pure():
    code = ('import sys, patchtrace.enrichment.wil\n'
            "bad = {'PySide6', 'subprocess', 'ssl', 'http.client', 'urllib.request'} & set(sys.modules)\n"
            'assert not bad, bad\n')
    import os

    import patchtrace
    src = os.path.dirname(os.path.dirname(patchtrace.__file__))
    subprocess.run([sys.executable, '-c', code], check=True, env=os.environ | {'PYTHONPATH': src})


@given(st.integers(min_value=0, max_value=4294967295))
def test_uint32_round_trips(n):
    assert ids(f'Feature_{n}') == [(f'Feature_{n}', n)]


@given(st.integers(min_value=4294967296, max_value=10**30))
def test_above_uint32_rejected(n):
    assert ids(f'Feature_{n}') == []


def test_wil_and_b1_signals_on_same_hunk_share_group_key():
    """Coordinator contract: B1 and B2 use signals.edit_group_key for the same edit."""
    from patchtrace.enrichment.signals import edit_group_key
    from patchtrace.enrichment.views import FunctionView, Hunk, MatchView
    old = ('int f(int n) {', '  return g(n);', '}')
    new = ('int f(int n) {', '  if (Feature_42__private_IsEnabledDeviceUsage()) {', '    if (n > 8) return -1;',
           '  }', '  return g(n);', '}')
    def fv(side, code):
        return FunctionView(side[0], 'a-' + side, 'r', side, 'f', 0x1000, code, None, False)
    view = MatchView('1' * 64, 'm', 'r', 'modified', False, 'high', (fv('older', old),), (fv('newer', new),),
                     (Hunk('equal', 0, 1, 0, 1), Hunk('insert', 1, 1, 1, 4), Hunk('equal', 1, 3, 4, 6)))
    transitions = analyze(view)
    signals = wil_signals(view, transitions)
    assert signals, transitions
    assert signals[0].group_key == edit_group_key(view, 0, 'newer', new[1:4])


def test_flag_names_in_strings_and_comments_are_not_sites():
    from patchtrace.enrichment import wil as wil_mod
    from patchtrace.enrichment.views import match_view
    from patchtrace.models import FunctionMatch, FunctionRecord
    code = ('void f(void) {\n  log("Feature_9 enabled");\n  /* Feature_10 */ g(); // Feature_11\n'
            '  if (Feature_12__private_IsEnabledDeviceUsage()) {\n    h();\n  }\n}')
    rec = FunctionRecord(artifact_id='a-new', run_id='r', name='f', code=code)
    view = match_view(FunctionMatch(run_id='r', category='added', newer=[rec]), '0' * 64,
                      {'older': 'a-old', 'newer': 'a-new'})
    sites = wil_mod.find_sites(view.newer[0])
    assert [s.feature_id for s in sites] == [12] and sites[0].control == 'lexical-enclosure'
    assert sites[0].location.start_line == 4
