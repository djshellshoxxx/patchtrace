"""GUI core (slice F1): ProjectKey and MatchIndex, the projection of a project that panels navigate by (plan 7, 8.2)."""
from __future__ import annotations

from types import SimpleNamespace

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.gui.projection import FunctionHit, MatchIndex, MatchIndexCache, ProjectKey
from patchtrace.service import ProjectService

PROPS = settings(max_examples=200, deadline=None, derandomize=True, database=None,
                 suppress_health_check=[HealthCheck.too_slow])
SHA_A, SHA_B = 'a' * 64, 'b' * 64
KEY = ProjectKey('/p', 'proj-1', 3, 'run-1', SHA_A, SHA_B)


def match(match_id, run_id, older=(), newer=()):
    return SimpleNamespace(id=match_id, run_id=run_id, older=[SimpleNamespace(id=f) for f in older],
                           newer=[SimpleNamespace(id=f) for f in newer])


def test_project_key_has_the_layout_of_the_c6_window_port_key():
    assert KEY == ('/p', 'proj-1', 3, 'run-1', SHA_A, SHA_B)  # C6 consumers index it: key[4], key[:2]
    assert (KEY.root, KEY.project_id, KEY.revision, KEY.run_id, KEY.older_sha256, KEY.newer_sha256) == tuple(KEY)
    assert KEY.identity() == ('/p', 'proj-1') == KEY[:2]
    assert hash(KEY) == hash(('/p', 'proj-1', 3, 'run-1', SHA_A, SHA_B))


def test_a_new_revision_or_run_or_orientation_is_a_different_key():
    assert KEY._replace(revision=4) != KEY
    assert KEY._replace(run_id='run-2') != KEY
    assert KEY._replace(older_sha256=SHA_B, newer_sha256=SHA_A) != KEY
    assert KEY._replace(revision=4).identity() == KEY.identity()


def test_functions_resolve_to_their_match_and_side():
    index = MatchIndex(KEY, [match('m1', 'run-1', older=['f1'], newer=['f2', 'f3']), match('m2', 'run-1', newer=['f4'])])
    assert index.functions_for('f1') == (FunctionHit('m1', 'older'),)
    assert index.functions_for('f3') == (FunctionHit('m1', 'newer'),)
    assert index.functions_for('f4') == (FunctionHit('m2', 'newer'),)
    assert index.functions_for('nope') == ()
    assert index.has_match('m1') and index.has_match('m2') and not index.has_match('m3')
    assert len(index) == 4


def test_matches_of_another_run_are_not_in_the_index():
    index = MatchIndex(KEY, [match('old', 'run-0', older=['f1']), match('now', 'run-1', older=['f2'])])
    assert index.functions_for('f1') == () and not index.has_match('old')
    assert index.functions_for('f2') == (FunctionHit('now', 'older'),)


def test_a_function_in_two_matches_is_ambiguous_and_never_resolves_to_the_first():
    index = MatchIndex(KEY, [match('m1', 'run-1', older=['f1'], newer=['g1']),
                             match('m2', 'run-1', older=['f1'], newer=['g2'])])
    assert index.functions_for('f1') == (FunctionHit('m1', 'older'), FunctionHit('m2', 'older'))


def test_a_function_listed_twice_in_one_match_side_is_one_hit():
    assert MatchIndex(KEY, [match('m1', 'run-1', older=['f1', 'f1'])]).functions_for('f1') == (
        FunctionHit('m1', 'older'),)


def test_no_project_or_no_run_gives_an_empty_index():
    matches = [match('m1', 'run-1', older=['f1'])]
    for key in (None, KEY._replace(run_id=None)):
        index = MatchIndex(key, matches)
        assert len(index) == 0 and index.functions_for('f1') == () and not index.has_match('m1')


@PROPS
@given(st.lists(st.tuples(st.sampled_from(['run-1', 'run-2']),
                          st.lists(st.sampled_from(['f1', 'f2', 'f3', 'f4']), max_size=3),
                          st.lists(st.sampled_from(['f1', 'f2', 'f3', 'f4']), max_size=3)), max_size=8))
def test_index_equals_a_brute_force_scan(rows):
    matches = [match(f'm{i}', run, older, newer) for i, (run, older, newer) in enumerate(rows)]
    index = MatchIndex(KEY, matches)
    for function in ['f1', 'f2', 'f3', 'f4', 'f5']:
        expected = []
        for m in matches:
            if m.run_id != 'run-1':
                continue
            for side in ('older', 'newer'):
                if any(f.id == function for f in getattr(m, side)) and FunctionHit(m.id, side) not in expected:
                    expected.append(FunctionHit(m.id, side))
        assert list(index.functions_for(function)) == expected


def test_cache_builds_one_index_per_key():
    reads = []

    class Matches(list):
        def __iter__(self):
            reads.append(1)
            return super().__iter__()

    matches = Matches([match('m1', 'run-1', older=['f1'])])
    cache = MatchIndexCache()
    first = cache.get(KEY, matches)
    assert cache.get(KEY, matches) is first and len(reads) == 1
    rebuilt = cache.get(KEY._replace(revision=4), matches)
    assert rebuilt is not first and len(reads) == 2 and rebuilt.key.revision == 4
    assert cache.get(None, matches).functions_for('f1') == ()
    assert len(reads) == 2  # a missing project needs no scan


def test_the_sample_project_is_indexed_by_function_id(tmp_path):
    service = ProjectService.sample(tmp_path / 'case')
    try:
        project = service.project
        run = next(r for r in reversed(project.runs) if r.status == 'completed' and r.raw_sha256)
        sides = {a.side: a.sha256 for a in project.artifacts}
        key = ProjectKey(str(service.root), project.id, project.revision, run.id, sides['older'], sides['newer'])
        index = MatchIndex(key, project.matches)
        expected = {(f.id, m.id, side) for m in project.matches for side in ('older', 'newer')
                    for f in getattr(m, side)}
        assert len(expected) == 6 == len(index)
        for function_id, match_id, side in expected:
            assert index.functions_for(function_id) == (FunctionHit(match_id, side),)
        assert all(index.has_match(m.id) for m in project.matches)
    finally:
        service.close()
