"""CAP-2: capability changes on matched function pairs (`capa-pairs/1`): groups, cell states, gained/lost/moved,
noise, unattributed matches, comparability, properties and bounds. Hermetic; no Qt."""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from intel_tools_support import golden, image_getter

from patchtrace.intelligence.tools import capa, capa_pairs
from patchtrace.intelligence.tools.capa_pairs import PairGroup, compute_pairs, groups_from_project
from patchtrace.intelligence.tools.common import (
    DEFAULT_LIMITS,
    CapabilityEvidence,
    EvidenceLink,
    FunctionCoverage,
    TaxonomyLabel,
    ToolEvidenceSet,
    ToolManifest,
    ToolRun,
)
from patchtrace.models import FunctionMatch, FunctionRecord

BASE = 0x140000000
MANIFEST = ToolManifest(engine='capa', version='9.4.0', executable_sha256='e' * 64, license='Apache-2.0',
                        rules_source='embedded', supported=True)
SRC = Path(__file__).resolve().parents[1] / 'src'


def run_for(side: str, evidence: ToolEvidenceSet, manifest: ToolManifest = MANIFEST) -> ToolRun:
    return ToolRun(run_id=evidence.run_id, engine='capa', side=side, input_artifact_hash=evidence.artifact_sha256,
                   config_digest='d' * 64, cache_key=evidence.cache_key, started_at='2026-10-14T00:00:00+00:00',
                   elapsed=1, status='ok', evidence_count=evidence.evidence_count(), profile='basic', manifest=manifest)


def pairs(older: ToolEvidenceSet, newer: ToolEvidenceSet, groups, **kw):
    return compute_pairs(run_for('older', older), older, run_for('newer', newer), newer, groups, **kw)


def group(gid: str, category: str, older=(), newer=(), **kw) -> PairGroup:
    return PairGroup(group_id=gid, match_id=gid[2:] if gid.startswith('m:') else None, category=category,
                     older_rvas=tuple(older), newer_rvas=tuple(newer), **kw)


def rows(delta, **want):
    return {(c.rule_id, c.group_id): c for c in delta.changes
            if all(getattr(c, k) == v for k, v in want.items())}


def changes(delta) -> dict[tuple[str, str], str]:
    return {(c.rule_id, c.group_id): c.change for c in delta.changes}


# ---- synthetic evidence ---------------------------------------------------------------------------------------

def cap(side: str, rule: str, rva: int | None, *, scope='function', kind='capability', namespace='host-interaction/x',
        labels=(), owned=False) -> CapabilityEvidence:
    """`owned`: a basic-block match that capa's layout assigns to the function at `rva`."""
    attribution = ('function-start' if scope == 'function' else 'basic-block-in-function' if owned else 'none') \
        if rva is not None else 'none'
    link = EvidenceLink(tool_run_id=f'run-{side}', artifact_sha256=('1' if side == 'older' else '2') * 64,
                        function_id=f'rva:0x{rva:x}' if attribution != 'none' else None,
                        rva=rva, attribution=attribution)
    return CapabilityEvidence(rule_id=rule, rule_sha256='f' * 64, namespace=namespace, scope=scope,
                              address_space='relative', address=rva, location=link, kind=kind,
                              source_run_id=f'run-{side}', labels=tuple(labels))


def evidence(side: str, caps=(), evaluated=(), library=(), truncated=False) -> ToolEvidenceSet:
    return ToolEvidenceSet(
        run_id=f'run-{side}', engine='capa', side=side, artifact_sha256=('1' if side == 'older' else '2') * 64,
        cache_key='c' * 64, config_digest='d' * 64, capabilities=tuple(cap(side, c[0], c[1], **c[2]) for c in caps),
        coverage=FunctionCoverage(evaluated=tuple(sorted(set(evaluated))), library=tuple(sorted(set(library)))),
        truncated=truncated)


def both(older_caps, newer_caps, groups, old_eval=(1, 2, 3, 4), new_eval=(1, 2, 3, 4), **kw):
    return pairs(evidence('older', older_caps, old_eval), evidence('newer', newer_caps, new_eval), groups, **kw)


# ---- groups -------------------------------------------------------------------------------------------------

def record(address: str | None, name='f', space='virtual') -> FunctionRecord:
    return FunctionRecord(id=f'fn-{address}-{name}', artifact_id='a', run_id='r', name=name, address=address,
                          address_space=space)


def match(mid: str, category: str, older=(), newer=()) -> FunctionMatch:
    return FunctionMatch(id=mid, run_id='r', category=category, older=[record(a, f'o{a}') for a in older],
                         newer=[record(a, f'n{a}') for a in newer])


def test_groups_use_the_pairing_rva_rules_and_keep_names():
    matches = [match('a', 'modified', ['140001000'], ['140001010']), match('b', 'added', newer=['140001030']),
               match('c', 'split', ['140001050'], ['140001070', '140001060'])]
    result = {g.group_id: g for g in groups_from_project(matches, None, (BASE, BASE))}
    assert result['m:a'].older_rvas == (0x1000,) and result['m:a'].newer_rvas == (0x1010,)
    assert result['m:b'].older_rvas == () and result['m:b'].newer_names == ('n140001030',)
    assert result['m:c'].newer_rvas == (0x1060, 0x1070) and result['m:c'].match_id == 'c'
    assert [g.group_id for g in groups_from_project(matches, None, (BASE, BASE))] == ['m:a', 'm:b', 'm:c']


def test_raw_unchanged_pairs_fill_gaps_but_never_override_normalised_matches():
    raw = {'address_matches': {'140001030': [['140001053', ['x']]], '140001000': [['140001000', ['x']]],
                               '140001065': [['140001070', ['x']], ['140001080', ['x']]],
                               'EXTERNAL:0000': [['140001090', ['x']]]}}
    matches = [match('a', 'modified', ['140001000'], ['140001000'])]
    result = {g.group_id: g for g in groups_from_project(matches, raw, (BASE, BASE))}
    assert set(result) == {'m:a', 'u:4144:4179', 'u:4197:4208'}
    assert result['u:4144:4179'].category == 'unchanged' and result['u:4144:4179'].newer_rvas == (0x1053,)
    assert result['u:4197:4208'].category == 'ambiguous' and result['u:4197:4208'].newer_rvas == (0x1070, 0x1080)


def test_a_side_without_a_usable_address_is_unresolved_not_a_missing_function():
    result = groups_from_project([match('a', 'modified', ['140001000'], [None])], None, (BASE, BASE))
    assert result[0].unresolved and result[0].newer_rvas == ()


# ---- cells and classification ------------------------------------------------------------------------------------

def test_gained_lost_unchanged_and_no_function_sides():
    groups = [group('m:mod', 'modified', [1], [1]), group('m:add', 'added', newer=[2]),
              group('m:rem', 'removed', older=[3]), group('m:same', 'modified', [4], [4])]
    delta = both([('gone', 3, {}), ('keep', 4, {})], [('new', 1, {}), ('born', 2, {}), ('keep', 4, {})], groups,
                 include_unchanged=True)
    assert changes(delta) == {('new', 'm:mod'): 'gained', ('born', 'm:add'): 'gained', ('gone', 'm:rem'): 'lost',
                              ('keep', 'm:same'): 'unchanged'}
    assert rows(delta)[('born', 'm:add')].older.state == 'no-function'
    assert delta.counts == {'gained': 2, 'lost': 1, 'moved': 0, 'unchanged': 1, 'not-compared': 0,
                            'detection-difference': 0}


def test_unchanged_rows_are_materialised_only_on_request_but_always_counted():
    groups = [group('m:a', 'modified', [1], [1])]
    delta = both([('keep', 1, {})], [('keep', 1, {})], groups)
    assert delta.changes == () and delta.counts['unchanged'] == 1
    assert len(both([('keep', 1, {})], [('keep', 1, {})], groups, include_unchanged=True).changes) == 1


def test_a_library_function_is_not_a_lost_capability():
    groups = [group('m:a', 'modified', [1], [1])]
    older = evidence('older', [], evaluated=[2], library=[1])
    newer = evidence('newer', [('keep', 1, {})], evaluated=[1, 2])
    delta = pairs(older, newer, groups)
    row = rows(delta)[('keep', 'm:a')]
    assert row.change == 'not-compared' and (row.older.state, row.older.reason) == ('not-evaluated',
                                                                                    'library-function')
    assert delta.counts['gained'] == 0 and delta.coverage.older_library == 1


def test_an_unrecovered_function_is_not_compared():
    older = evidence('older', [], evaluated=[2])    # function 1 is in neither list
    newer = evidence('newer', [('open', 1, {})], evaluated=[1])
    delta = pairs(older, newer, [group('m:a', 'modified', [1], [1])])
    row = rows(delta)[('open', 'm:a')]
    assert row.change == 'not-compared' and row.older.reason == 'function-not-recovered'
    assert delta.coverage.older_not_recovered == 1 and delta.coverage.both_evaluated == 0


def test_a_union_with_an_unevaluated_function_cannot_prove_absence():
    older = evidence('older', [('open', 1, {})], evaluated=[1])
    newer = evidence('newer', [], evaluated=[1])   # newer has two functions; one is not recovered
    delta = pairs(older, newer, [group('m:a', 'merged', [1], [1, 2])])
    assert rows(delta)[('open', 'm:a')].change == 'not-compared'


def test_truncated_evidence_cannot_prove_absence():
    older = evidence('older', [('open', 1, {})], evaluated=[1])
    newer = evidence('newer', [], evaluated=[1], truncated=True)
    delta = pairs(older, newer, [group('m:a', 'modified', [1], [1])])
    row = rows(delta)[('open', 'm:a')]
    assert row.change == 'not-compared' and row.newer.reason == 'evidence-truncated' and delta.truncated
    assert any('truncated' in note for note in delta.notes)


def test_n_to_m_groups_compare_side_unions():
    groups = [group('m:split', 'split', [1], [2, 3])]
    delta = both([('a', 1, {}), ('b', 1, {})], [('a', 3, {}), ('c', 2, {})], groups)
    assert changes(delta) == {('b', 'm:split'): 'lost', ('c', 'm:split'): 'gained'}


def test_ambiguous_unmatched_and_unresolved_groups_give_no_rows():
    groups = [group('m:amb', 'ambiguous', [1], [1]), group('m:un', 'unmatched', [2], [2]),
              group('m:bad', 'modified', [3], [3], unresolved=True)]
    delta = both([], [('a', 1, {}), ('b', 2, {}), ('c', 3, {})], groups)
    assert delta.changes == () and delta.coverage.ambiguous_groups == 1 and delta.coverage.matched_groups == 0
    assert any('no usable counterpart' in note for note in delta.notes)


def test_a_function_in_two_groups_reports_in_both():
    groups = [group('m:a', 'modified', [1], [1]), group('m:b', 'modified', [1], [2])]
    delta = both([], [('a', 2, {})], groups)
    assert changes(delta) == {('a', 'm:b'): 'gained'}


# ---- moved and noise -------------------------------------------------------------------------------------------

def test_a_gain_and_a_loss_of_the_same_rule_in_different_pairs_is_a_moved_candidate():
    groups = [group('m:host', 'modified', [1], [1]), group('m:helper', 'added', newer=[2])]
    delta = both([('name', 1, {})], [('name', 2, {})], groups)
    assert changes(delta) == {('name', 'm:host'): 'moved', ('name', 'm:helper'): 'moved'}
    assert {c.relocation for c in delta.changes} == {'candidate'}
    assert delta.counts['moved'] == 1 and delta.counts['gained'] == delta.counts['lost'] == 0


def test_the_same_rule_at_another_scope_is_not_a_move():
    groups = [group('m:host', 'modified', [1], [1]), group('m:helper', 'added', newer=[2])]
    delta = both([('name', 1, {})], [('name', 2, {'scope': 'basic block', 'owned': True})],
                groups)
    assert sorted(changes(delta).values()) == ['gained', 'lost'] and delta.counts['moved'] == 0


def test_a_gain_in_an_unchanged_pair_is_detection_noise_and_never_moves():
    groups = [group('m:a', 'unchanged', [1], [1]), group('m:b', 'unchanged', [2], [2]),
              group('m:c', 'modified', [3], [3])]
    delta = both([('name', 1, {})], [('name', 2, {})], groups)
    assert {c.noise for c in delta.changes} == {'detection-difference'}
    assert {c.change for c in delta.changes} == {'gained', 'lost'} and delta.counts['detection-difference'] == 2
    assert delta.counts['gained'] == delta.counts['lost'] == delta.counts['moved'] == 0


def test_a_noise_row_does_not_pair_up_with_a_real_change():
    groups = [group('m:a', 'unchanged', [1], [1]), group('m:b', 'modified', [2], [2])]
    delta = both([('name', 1, {})], [('name', 2, {})], groups)
    assert rows(delta, noise='none')[('name', 'm:b')].change == 'gained'
    assert delta.counts['moved'] == 0


# ---- unattributed -------------------------------------------------------------------------------------------

def test_matches_without_a_function_are_listed_apart_with_a_reason():
    older = [('link', None, {'scope': 'instruction'}), ('tls', None, {'scope': 'file'})]
    newer = [('link', None, {'scope': 'instruction'}), ('bb', 1, {'scope': 'basic block'}),
             ('lonely', 9, {}), ('lib', 1, {'kind': 'library'})]
    delta = both(older, newer, [group('m:a', 'modified', [1], [1])])
    got = {(u.rule_id, u.reason): u.change for u in delta.unattributed}
    assert got == {('link', 'instruction-scope'): 'unchanged', ('tls', 'file-scope'): 'lost',
                   ('bb', 'basic-block-without-layout'): 'gained', ('lonely', 'function-not-paired'): 'gained'}
    assert [c.rule_id for c in delta.changes] == ['lib']
    assert delta.coverage.total_matches == 5 and delta.coverage.attributed_matches == 0


def test_library_rules_are_rows_of_kind_library_and_do_not_count():
    delta = both([], [('loop', 1, {'kind': 'library'})], [group('m:a', 'modified', [1], [1])])
    assert [c.kind for c in delta.changes] == ['library'] and delta.counts['gained'] == 0


def test_limitation_rules_are_flags_not_rows():
    delta = both([], [('limit', 1, {'kind': 'limitation'})], [group('m:a', 'modified', [1], [1])])
    assert delta.changes == () and delta.unattributed == ()


# ---- comparability --------------------------------------------------------------------------------------------

def test_different_tool_setups_are_refused_with_reasons():
    older, newer = evidence('older', [], [1]), evidence('newer', [], [1])
    other = MANIFEST.model_copy(update={'executable_sha256': 'f' * 64})
    changed = run_for('newer', newer, other).model_copy(update={'config_digest': 'e' * 64})
    delta = compute_pairs(run_for('older', older), older, changed, newer, [])
    assert not delta.comparable and any('configuration differs' in r for r in delta.reasons) and not delta.changes


def test_evidence_without_coverage_asks_for_a_refresh():
    older = evidence('older', [], [1]).model_copy(update={'coverage': None})
    newer = evidence('newer', [], [1])
    delta = pairs(older, newer, [])
    assert not delta.comparable and any('no function coverage' in r for r in delta.reasons)


def test_missing_run_or_evidence_is_not_comparable():
    newer = evidence('newer', [], [1])
    assert not compute_pairs(None, None, run_for('newer', newer), newer, []).comparable
    older = evidence('older', [], [1])
    assert 'older evidence is missing' in compute_pairs(run_for('older', older), None, run_for('newer', newer),
                                                        newer, []).reasons


def test_without_pairs_only_per_side_totals_are_reported():
    delta = both([('a', 1, {}), ('b', 1, {})], [('a', 1, {})], None)
    assert delta.comparable and delta.pairing == 'unavailable' and delta.changes == ()
    assert delta.counts == {'older_capabilities': 2, 'newer_capabilities': 1}
    assert any('function pairs are unavailable' in n for n in delta.notes)


def test_rows_are_ordered_by_namespace_and_rule_never_by_count():
    groups = [group('m:a', 'added', newer=[1]), group('m:b', 'added', newer=[2])]
    delta = both([], [('zeta', 1, {'namespace': 'a/b'}), ('alpha', 2, {'namespace': 'z/y'}),
                      ('beta', 2, {'namespace': 'a/b'}), ('beta', 1, {'namespace': 'a/b'})], groups)
    assert [(c.namespace, c.rule_id, c.group_id) for c in delta.changes] == [
        ('a/b', 'beta', 'm:a'), ('a/b', 'beta', 'm:b'), ('a/b', 'zeta', 'm:a'), ('z/y', 'alpha', 'm:b')]


def test_the_contract_has_no_score_rank_or_contradiction_fields():
    names = set(capa_pairs.PairCapabilityDelta.model_fields) | set(capa_pairs.PairChange.model_fields)
    assert not {n for n in names if any(w in n for w in ('score', 'rank', 'confidence', 'contradict', 'risk'))}
    assert capa_pairs.PairCapabilityDelta(comparable=False, older_run_id=None, newer_run_id=None).value_gate \
        == 'unvalidated'


def test_observation_keys_are_stable_and_pair_scoped():
    groups = [group('m:a', 'added', newer=[1]), group('m:b', 'added', newer=[2])]
    delta = both([], [('x', 1, {}), ('x', 2, {})], groups)
    keys = [c.observation_key for c in delta.changes]
    assert len(set(keys)) == 2 and keys == [c.observation_key for c in both([], [('x', 1, {}), ('x', 2, {})],
                                                                            groups).changes]


def test_labels_never_change_classification_or_order():
    label = TaxonomyLabel(scheme='attack', group='Execution', name='Shared Modules', ident='T1129')
    groups = [group('m:a', 'added', newer=[1]), group('m:b', 'removed', older=[2])]
    plain = both([('y', 2, {})], [('x', 1, {})], groups)
    labelled = both([('y', 2, {'labels': [label]})], [('x', 1, {'labels': [label]})], groups)
    assert [(c.rule_id, c.group_id, c.change) for c in plain.changes] == [
        (c.rule_id, c.group_id, c.change) for c in labelled.changes]
    assert labelled.changes[0].labels == (label,) and plain.changes[0].labels == ()


# ---- properties ---------------------------------------------------------------------------------------------

RULES = ('r0', 'r1', 'r2')
FUNCS = (1, 2, 3, 4)


@st.composite
def scenarios(draw):
    def side_caps():
        picks = draw(st.sets(st.tuples(st.sampled_from(RULES), st.sampled_from(FUNCS))))
        return sorted(picks)
    categories = draw(st.lists(st.sampled_from(['modified', 'unchanged', 'split', 'merged']), min_size=1, max_size=4))
    groups = []
    for index, category in enumerate(categories):
        groups.append(group(f'm:g{index}', category, draw(st.sets(st.sampled_from(FUNCS), min_size=1, max_size=2)),
                            draw(st.sets(st.sampled_from(FUNCS), min_size=1, max_size=2))))
    skipped = draw(st.sets(st.sampled_from(FUNCS), max_size=2))
    return side_caps(), side_caps(), groups, skipped


def scenario_delta(older_caps, newer_caps, groups, skipped=frozenset(), swap=False, shuffle=False):
    evaluated_old = [f for f in FUNCS if f not in skipped]
    old = [(r, f, {}) for r, f in older_caps]
    new = [(r, f, {}) for r, f in newer_caps]
    if swap:
        groups = [group(g.group_id, g.category, g.newer_rvas, g.older_rvas) for g in groups]
        old, new = new, old
    if shuffle:
        groups, old, new = groups[::-1], old[::-1], new[::-1]
    return both(old, new, groups, old_eval=evaluated_old if not swap else FUNCS,
                new_eval=FUNCS if not swap else evaluated_old, include_unchanged=True)


def reduced(delta):
    return sorted((c.rule_id, c.group_id, c.change, c.noise) for c in delta.changes)


@settings(max_examples=60, deadline=None)
@given(scenarios())
def test_swapping_orientation_swaps_gained_and_lost(case):
    older_caps, newer_caps, groups, skipped = case
    straight = scenario_delta(older_caps, newer_caps, groups, skipped)
    swapped = scenario_delta(older_caps, newer_caps, groups, skipped, swap=True)
    flip = {'gained': 'lost', 'lost': 'gained'}
    assert reduced(swapped) == sorted((r, g, flip.get(c, c), n) for r, g, c, n in reduced(straight))
    assert {k: v for k, v in swapped.counts.items() if k not in ('gained', 'lost')} == \
        {k: v for k, v in straight.counts.items() if k not in ('gained', 'lost')}


@settings(max_examples=60, deadline=None)
@given(scenarios())
def test_pair_and_match_order_is_irrelevant(case):
    older_caps, newer_caps, groups, skipped = case
    assert scenario_delta(older_caps, newer_caps, groups, skipped) == \
        scenario_delta(older_caps, newer_caps, groups, skipped, shuffle=True)


@settings(max_examples=60, deadline=None)
@given(scenarios())
def test_identical_evidence_gives_only_unchanged_rows(case):
    older_caps, _newer, groups, _skipped = case
    same = [group(g.group_id, g.category, g.older_rvas, g.older_rvas) for g in groups]
    delta = scenario_delta(older_caps, older_caps, same)
    assert {c.change for c in delta.changes} <= {'unchanged'}
    assert not delta.counts['gained'] and not delta.counts['lost'] and not delta.counts['moved']


@settings(max_examples=60, deadline=None)
@given(scenarios())
def test_not_compared_is_never_counted_and_moved_needs_a_gain_and_a_loss(case):
    older_caps, newer_caps, groups, skipped = case
    delta = scenario_delta(older_caps, newer_caps, groups, skipped)
    visible = [c for c in delta.changes if c.kind == 'capability' and c.noise == 'none']
    assert delta.counts['not-compared'] == sum(c.change == 'not-compared' for c in visible)
    assert delta.counts['gained'] + delta.counts['lost'] == sum(c.change in ('gained', 'lost') for c in visible)
    for moved in (c for c in visible if c.change == 'moved'):
        peers = [c for c in visible if (c.rule_id, c.scope) == (moved.rule_id, moved.scope) and c.change == 'moved']
        direction = {(c.older.state == 'present') for c in peers}
        assert direction == {True, False}


# ---- bounds and imports ----------------------------------------------------------------------------------------

def test_20000_items_per_side_compute_inside_the_time_budget():
    groups = [group(f'm:{i}', 'modified', [i], [i]) for i in range(1, 4001)]
    matches = [(f'rule{i % 50}', i, {}) for i in range(1, 4001) for _ in range(5)]
    old_ev, new_ev = evidence('older', matches, range(1, 4001)), evidence('newer', matches, range(1, 4001))
    start = time.perf_counter()
    delta = pairs(old_ev, new_ev, groups)
    assert time.perf_counter() - start < 5 and delta.coverage.total_matches == 40_000
    assert delta.counts['unchanged'] == 4000


def test_group_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(capa_pairs, 'MAX_GROUPS', 2)
    with pytest.raises(capa_pairs.ToolError) as caught:
        both([], [], [group(f'm:{i}', 'added', newer=[1]) for i in range(3)])
    assert caught.value.code == 'PT-TOOL-LIMIT'


def test_module_imports_no_qt():
    code = (f'import sys; sys.path.insert(0, {str(SRC)!r}); import patchtrace.intelligence.tools.capa_pairs; '
            "assert not [m for m in sys.modules if m.startswith(('PySide6', 'PyQt'))]")
    subprocess.run([sys.executable, '-I', '-c', code], check=True, timeout=120)


def test_real_parse_feeds_the_pairs(tmp_path):
    get, close = image_getter(tmp_path)
    try:
        sides = {}
        for side in ('older', 'newer'):
            copy, _reader, pe = get('capa-api', side)
            ctx = capa.ParseContext(f'run-{side}', side, copy, 'c' * 64, 'd' * 64, pe, DEFAULT_LIMITS['capa'])
            sides[side] = capa.parse(golden(f'capa/capa-api-{side}.json'), ctx)
        delta = pairs(sides['older'], sides['newer'], [group('m:log', 'modified', [0x108b], [0x1096])])
        assert changes(delta) == {('write file on Windows', 'm:log'): 'gained'}
    finally:
        close()
