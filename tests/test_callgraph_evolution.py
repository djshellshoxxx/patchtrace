"""WB2 G7: pair_calls and the A7 N-way callee evolution (pure; no project is opened)."""
from __future__ import annotations

import pytest

from patchtrace.callgraph.contracts_evolution import NeighbourhoodEvolution
from patchtrace.callgraph.evolution import build_evolution
from patchtrace.callgraph.limits import GraphError
from patchtrace.callgraph.pair_calls import PairCalls
from patchtrace.callgraph.project_input import EmittedPair, Entry, ProjectInput
from patchtrace.callgraph.raw_matches import RawMatchesResult, parse_raw_matches

BUILDS = ['b0', 'b1', 'b2', 'b3']


def pair(older=None, newer=None, names=None, emitted=(), raw=True) -> PairCalls:
    """One adjacent pair: `older`/`newer` map function label -> stored callees; `names` is name_matches."""
    entries = [Entry(side, label, f'{side}-{label}', f'm-{label}', None, False, tuple(callees), ())
               for side, table in (('older', older or {}), ('newer', newer or {}))
               for label, callees in table.items()]
    matches = parse_raw_matches({'name_matches': {k: [[v, ['Symbols']]] for k, v in (names or {}).items()}})
    data = ProjectInput('p', 1, 'r', 'v', None, 'a' * 64, 'b' * 64, tuple(entries), tuple(emitted), 'digest',
                        RawMatchesResult(matches if raw else None, 'ok' if raw else 'absent', ()))
    return PairCalls(data)


def added(label: str) -> EmittedPair:
    return EmittedPair(f'add-{label}', 'added', (), (label,), 'ghidriff:Symbols', False)


def four_builds() -> list[PairCalls]:
    """X is called in b0 and b1, dropped in b2, back in b3. Y is new in b1 and stays."""
    same = {'F': 'F', 'X': 'X', 'Y': 'Y'}
    return [
        pair({'F': ['X']}, {'F': ['X', 'Y']}, same, emitted=[added('Y')]),
        pair({'F': ['X', 'Y']}, {'F': ['Y']}, same),
        pair({'F': ['Y']}, {'F': ['X', 'Y']}, same),
    ]


def run(pairs, focus=('F', 'F', 'F', 'F')) -> NeighbourhoodEvolution:
    return build_evolution('series', 'chain', BUILDS, focus, pairs)


def lineage(result: NeighbourhoodEvolution, label: str):
    return next(item for item in result.lineages if label in item.labels_by_ordinal)


def events(item) -> list[tuple[str, int]]:
    return [(e.kind, e.ordinal) for e in item.events]


def test_lineage_matrix_on_four_builds():
    result = run(four_builds())
    x, y = lineage(result, 'X'), lineage(result, 'Y')
    assert x.cells == ('present', 'present', 'absent', 'present')
    assert events(x) == [('dropped', 2), ('reverted', 3)]
    assert y.cells == ('absent', 'present', 'present', 'present')
    assert events(y) == [('appeared', 1)]
    assert len(result.lineages) == 2 and not result.inconsistencies and not result.limitations
    assert [d.ordinal for d in result.digest_by_ordinal] == [0, 1, 2, 3]


def test_renamed_callee_is_one_lineage_across_builds():
    pairs = [pair({'F': ['FUN_a']}, {'F': ['FUN_a']}, {'F': 'F', 'FUN_a': 'FUN_a'}),
             pair({'F': ['FUN_a']}, {'F': ['FUN_b']}, {'F': 'F', 'FUN_a': 'FUN_b'}),
             pair({'F': ['FUN_b']}, {'F': ['FUN_b']}, {'F': 'F', 'FUN_b': 'FUN_b'})]
    result = run(pairs)
    assert len(result.lineages) == 1
    assert result.lineages[0].labels_by_ordinal == ('FUN_a', 'FUN_a', 'FUN_b', 'FUN_b')
    assert result.lineages[0].cells == ('present',) * 4 and not result.lineages[0].events


def test_missing_pair_project_is_unknown_not_absent():
    pairs = four_builds()
    pairs[2] = None
    result = run(pairs)
    x = lineage(result, 'X')
    assert x.cells == ('present', 'present', 'absent', 'unknown')
    assert events(x) == [('dropped', 2)]
    assert any('pair project(s) 2 unavailable' in note for note in result.limitations)


def test_build_without_a_record_is_unknown():
    pairs = four_builds()
    pairs[2] = pair({'G': []}, {'G': []}, {'F': 'F', 'X': 'X', 'Y': 'Y'})  # F unchanged here: no record
    result = run(pairs)
    assert lineage(result, 'X').cells == ('present', 'present', 'absent', 'unknown')
    assert [d.ordinal for d in result.digest_by_ordinal] == [0, 1, 2]
    assert any('build(s) 3 have no stored record' in note for note in result.limitations)


def test_same_build_inconsistency_is_flagged_and_cells_unknown():
    pairs = four_builds()
    pairs[1] = pair({'F': ['X']}, {'F': ['Y']}, {'F': 'F', 'X': 'X', 'Y': 'Y'})  # b1 as older lacks Y
    result = run(pairs)
    assert [(i.kind, i.ordinal) for i in result.inconsistencies] == [('same-build-callees-differ', 1)]
    assert lineage(result, 'Y').cells[1] == 'unknown'
    assert lineage(result, 'X').cells[1] == 'present'
    assert not [e for e in lineage(result, 'Y').events if e.ordinal == 1]


def test_deleted_callee_is_absent_from_then_on():
    deleted = EmittedPair('del-X', 'removed', ('X',), (), 'ghidriff:Symbols', False)
    pairs = [pair({'F': ['X']}, {'F': ['X']}, {'F': 'F', 'X': 'X'}),
             pair({'F': ['X']}, {'F': []}, {'F': 'F'}, emitted=[deleted]),
             pair({'F': []}, {'F': []}, {'F': 'F'})]
    x = lineage(run(pairs), 'X')
    assert x.cells == ('present', 'present', 'absent', 'absent')
    assert x.labels_by_ordinal == ('X', 'X', None, None)
    assert events(x) == [('dropped', 2)]


def test_without_raw_matches_unchanged_callees_cannot_cross_builds():
    pairs = [pair({'F': ['X']}, {'F': ['X']}, raw=False), pair({'F': ['X']}, {'F': ['X']}, raw=False),
             pair({'F': ['X']}, {'F': ['X']}, raw=False)]
    result = run(pairs)
    assert [item.cells[0] for item in result.lineages] == ['present', 'unknown', 'unknown', 'unknown']
    assert any('no raw matches' in note for note in result.limitations)


def test_hostile_labels_are_sanitized_and_ids_are_stable():
    evil = 'F\x1b[31m‮\nrm'
    pairs = [pair({evil: ['X\x00']}, {evil: ['X\x00']}, {evil: evil, 'X\x00': 'X\x00'}) for _ in range(3)]
    first = build_evolution('s', 'c', BUILDS[:4], (evil,) * 4, [*pairs, pair()][:3])
    again = build_evolution('s', 'c', BUILDS[:4], (evil,) * 4, [*pairs, pair()][:3])
    assert first == again and first.model_dump_json() == again.model_dump_json()
    assert '\x1b' not in first.model_dump_json() and '‮' not in first.focus_labels[0]


@pytest.mark.parametrize('builds,focus,pair_count', [
    (2, 2, 1), (9, 9, 8), (4, 3, 3), (4, 4, 2),
], ids=['too-few', 'too-many', 'focus-length', 'pair-length'])
def test_input_shape_is_validated(builds, focus, pair_count):
    with pytest.raises(GraphError) as caught:
        build_evolution('s', 'c', ['b'] * builds, ['F'] * focus, [None] * pair_count)
    assert caught.value.code in {'PT-GRAPH-LIMIT', 'PT-GRAPH-INPUT'}


def test_cancel_raises_graph_cancel():
    with pytest.raises(GraphError) as caught:
        build_evolution('s', 'c', BUILDS, ('F',) * 4, four_builds(), cancel=lambda: True)
    assert caught.value.code == 'PT-GRAPH-CANCEL'


def test_lineage_cap_truncates_and_says_so(monkeypatch):
    monkeypatch.setattr('patchtrace.callgraph.evolution.MAX_LINEAGES', 1)
    result = run(four_builds())
    assert result.truncated and len(result.lineages) == 1
    assert any('cut' in note for note in result.limitations)


@pytest.mark.parametrize('direction,label,expected', [
    ('forward', 'A', ('B', 'mapped')),
    ('backward', 'B', ('A', 'mapped')),
    ('forward', 'R', (None, 'gone')),
    ('forward', 'M', (None, 'unknown')),
    ('forward', 'S', (None, 'unknown')),
    ('forward', 'nope', (None, 'unknown')),
], ids=['one', 'reverse', 'removed', 'one-to-many', 'not-reciprocal', 'unlisted'])
def test_step_follows_only_agreed_one_to_one_pairs(direction, label, expected):
    removed = EmittedPair('rm', 'removed', ('R',), (), 'ghidriff:Symbols', False)
    table = parse_raw_matches({'name_matches': {'A': [['B', ['x']]], 'S': [['T', ['x']]], 'U': [['T', ['x']]],
                                                'M': [['P', ['x']], ['Q', ['x']]]}})
    data = ProjectInput('p', 1, 'r', 'v', None, 'a' * 64, 'b' * 64, (), (removed,), 'd',
                        RawMatchesResult(table, 'ok', ()))
    assert tuple(PairCalls(data).step(direction, label)) == expected


def test_callees_distinguishes_no_record_from_empty():
    calls = pair({'F': [], 'D': ['x']}, {})
    assert calls.callees('older', 'F') == frozenset()
    assert calls.callees('older', 'missing') is None
    assert calls.callees('newer', 'F') is None
