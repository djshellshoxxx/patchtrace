"""GUI core (slice F1): AnchorRef, NavResult, the stale rule, match resolution, history and the router (plan 7, 8.2)."""
from __future__ import annotations

import dataclasses
from types import SimpleNamespace

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.gui.anchors import (
    ANCHOR_KINDS,
    MAX_CANDIDATES,
    NAV_HISTORY,
    AnchorRef,
    AnchorRouter,
    NavHistory,
    NavResult,
    is_stale,
    locate_match,
)
from patchtrace.gui.projection import MatchIndex, ProjectKey

PROPS = settings(max_examples=250, deadline=None, derandomize=True, database=None,
                 suppress_health_check=[HealthCheck.too_slow])
KEY = ProjectKey('/p', 'proj-1', 3, 'run-1', 'a' * 64, 'b' * 64)
STALE_TEXT = 'The project changed after this link was created. Open it again from the source panel.'
KINDS = st.sampled_from(ANCHOR_KINDS)
SIDES = st.sampled_from([None, 'older', 'newer', 'both'])
KEYS = st.text(min_size=1, max_size=256)


def test_the_anchor_kinds_are_the_closed_set_of_the_plan():
    assert ANCHOR_KINDS == ('function', 'match', 'string', 'import', 'address', 'capability', 'rule', 'build_fact',
                            'advisory_phrase', 'cve', 'kb', 'cwe')
    assert (MAX_CANDIDATES, NAV_HISTORY) == (20, 50)


# ---- AnchorRef --------------------------------------------------------------------------------------------------


def test_anchor_defaults_and_immutability():
    anchor = AnchorRef('string', 's:7f3a', side='newer', run_id='run-1')
    assert (anchor.label, anchor.origin, anchor.revision) == ('', None, None)
    with pytest.raises(dataclasses.FrozenInstanceError):
        anchor.key = 'other'
    assert not hasattr(anchor, '__dict__')


def test_equality_and_hash_use_kind_key_side_and_run_only():
    base = AnchorRef('string', 's:7f3a', 'newer', 'run-1')
    same = AnchorRef('string', 's:7f3a', 'newer', 'run-1', label='Different label', origin='leads', revision=9)
    assert base == same and hash(base) == hash(same)
    for other in (AnchorRef('string', 's:7f3b', 'newer', 'run-1'), AnchorRef('string', 's:7f3a', 'older', 'run-1'),
                  AnchorRef('string', 's:7f3a', 'newer', 'run-2'), AnchorRef('import', 's:7f3a', 'newer', 'run-1'),
                  AnchorRef('string', 's:7f3a', None, 'run-1')):
        assert other != base


@PROPS
@given(KINDS, KEYS, SIDES, st.none() | st.text(min_size=1, max_size=40), st.text(max_size=400))
def test_valid_anchors_construct_and_keep_the_label_bounded_and_plain(kind, key, side, run_id, label):
    anchor = AnchorRef(kind, key, side, run_id, label)
    assert len(anchor.label) <= 200 and '\n' not in anchor.label and '\x00' not in anchor.label
    assert (anchor.kind, anchor.key, anchor.side, anchor.run_id) == (kind, key, side, run_id)


@pytest.mark.parametrize('kwargs', [
    dict(kind='nope', key='k'), dict(kind='', key='k'), dict(kind=None, key='k'),
    dict(kind='string', key=''), dict(kind='string', key='k' * 257), dict(kind='string', key=None),
    dict(kind='string', key='k', side='left'), dict(kind='string', key='k', side='Newer'),
], ids=['unknown-kind', 'empty-kind', 'none-kind', 'empty-key', 'long-key', 'none-key', 'bad-side', 'bad-case'])
def test_invalid_anchors_are_refused(kwargs):
    with pytest.raises(ValueError):
        AnchorRef(**kwargs)


def test_the_key_limit_is_inclusive_and_the_key_is_never_altered():
    assert AnchorRef('string', 'k' * 256).key == 'k' * 256
    assert AnchorRef('string', ' <b>\n').key == ' <b>\n'  # opaque: only the label is for display


def test_hostile_labels_become_literal_plain_text():
    anchor = AnchorRef('function', 'f1', label='<img src=x onerror=1>{0}' + chr(0x202e) + '\nVerdict: agree')
    assert anchor.label == '<img src=x onerror=1>{0} Verdict: agree'


def test_pinning_stamps_the_run_and_revision_of_a_key():
    pinned = AnchorRef('string', 's1', 'newer', label='L', origin='leads').pinned(KEY)
    assert (pinned.run_id, pinned.revision, pinned.label, pinned.origin) == ('run-1', 3, 'L', 'leads')
    unpinned = AnchorRef('string', 's1')
    assert unpinned.pinned(None) is unpinned


# ---- NavResult --------------------------------------------------------------------------------------------------


def test_navigation_results_carry_the_plans_copy_and_codes():
    shown = NavResult.shown()
    assert (shown.status, shown.message, shown.candidates, shown.code) == ('shown', '', (), None)
    stale = NavResult.stale()
    assert (stale.status, stale.message, stale.code) == ('stale', STALE_TEXT, 'PT-GUI-NAV-STALE')
    missing = NavResult.not_found('sub_1000', 'run-1')
    assert (missing.status, missing.message, missing.code) == (
        'not-found', 'Not found in run run-1: sub_1000.', 'PT-GUI-NAV-NOTFOUND')
    assert NavResult.not_found('sub_1000', None).message == 'Not found: sub_1000.'
    blocked = NavResult.blocked('Search', 'capa was not found.')
    assert (blocked.status, blocked.message, blocked.code) == (
        'blocked', 'Search is unavailable: capa was not found.', 'PT-GUI-NAV-BLOCKED')


def test_ambiguity_lists_candidates_up_to_twenty_but_counts_them_all():
    candidates = [AnchorRef('match', f'm{i}') for i in range(25)]
    result = NavResult.ambiguous('sub_1000', candidates)
    assert result.status == 'ambiguous' and result.code == 'PT-GUI-NAV-AMBIGUOUS'
    assert result.message == '25 candidates match sub_1000. Choose one.'
    assert result.candidates == tuple(candidates[:20])
    assert NavResult.ambiguous('x', candidates[:2]).message == '2 candidates match x. Choose one.'


def test_ambiguity_accepts_an_empty_iterator():
    result = NavResult.ambiguous('missing', iter(()))
    assert result.status == 'ambiguous'
    assert result.message == '0 candidates match missing. Choose one.'
    assert result.candidates == ()


def test_ambiguity_consumes_one_shot_generator_in_order():
    visited = []

    def generate():
        for i in range(25):
            visited.append(i)
            yield AnchorRef('match', f'm{i}')

    result = NavResult.ambiguous('function', generate())
    assert visited == list(range(25))
    assert result.message == '25 candidates match function. Choose one.'
    assert [item.key for item in result.candidates] == [f'm{i}' for i in range(MAX_CANDIDATES)]


def test_ambiguity_bounds_peak_memory_for_large_stream():
    from itertools import repeat
    import tracemalloc

    candidate = AnchorRef('match', 'repeated')
    tracemalloc.start()
    try:
        result = NavResult.ambiguous('function', repeat(candidate, 100_000))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()

    assert result.message == '100000 candidates match function. Choose one.'
    assert result.candidates == (candidate,) * MAX_CANDIDATES
    assert peak < 500_000, f'candidate iterator was materialized: {peak} bytes peak'


def test_nav_result_messages_sanitize_untrusted_labels():
    result = NavResult.not_found('a\nb' + chr(0x202e), 'r\n1')
    assert '\n' not in result.message and chr(0x202e) not in result.message


def test_nav_result_validation():
    with pytest.raises(ValueError):
        NavResult('maybe')
    with pytest.raises(ValueError):
        NavResult('ambiguous', candidates=tuple(AnchorRef('match', f'm{i}') for i in range(21)))


# ---- staleness and resolution -----------------------------------------------------------------------------------


@pytest.mark.parametrize('anchor,key,stale', [
    (AnchorRef('string', 's', run_id='run-1', revision=3), KEY, False),
    (AnchorRef('string', 's'), KEY, False),
    (AnchorRef('string', 's', run_id='run-1'), KEY, False),
    (AnchorRef('string', 's', revision=3), KEY, False),
    (AnchorRef('string', 's', run_id='run-2', revision=3), KEY, True),
    (AnchorRef('string', 's', run_id='run-1', revision=2), KEY, True),
    (AnchorRef('string', 's', revision=4), KEY, True),
    (AnchorRef('string', 's', run_id='run-1'), KEY._replace(run_id=None), True),
    (AnchorRef('string', 's'), None, True),
], ids=['pinned', 'unpinned', 'run-only', 'revision-only', 'other-run', 'older-revision', 'newer-revision',
        'run-gone', 'no-project'])
def test_is_stale(anchor, key, stale):
    assert is_stale(anchor, key) is stale


def index_of(*rows):
    matches = [SimpleNamespace(id=mid, run_id='run-1', older=[SimpleNamespace(id=f) for f in older],
                               newer=[SimpleNamespace(id=f) for f in newer]) for mid, older, newer in rows]
    return MatchIndex(KEY, matches)


def test_a_match_anchor_resolves_to_its_own_key_or_is_not_found():
    index = index_of(('m1', ['f1'], ['g1']))
    assert locate_match(AnchorRef('match', 'm1'), index) == 'm1'
    result = locate_match(AnchorRef('match', 'm9', label='sub_9'), index)
    assert isinstance(result, NavResult) and result.status == 'not-found'
    assert result.message == 'Not found in run run-1: sub_9.'


def test_a_function_anchor_resolves_through_the_index():
    index = index_of(('m1', ['f1'], ['g1']), ('m2', [], ['g2']))
    assert locate_match(AnchorRef('function', 'g2', 'newer'), index) == 'm2'
    assert locate_match(AnchorRef('function', 'f1', None), index) == 'm1'
    assert locate_match(AnchorRef('function', 'f1', 'both'), index) == 'm1'


def test_a_function_missing_from_the_run_or_on_the_wrong_side_is_not_found():
    index = index_of(('m1', ['f1'], ['g1']))
    assert locate_match(AnchorRef('function', 'zzz', label='zzz'), index).status == 'not-found'
    wrong_side = locate_match(AnchorRef('function', 'f1', 'newer', label='sub_1'), index)
    assert wrong_side.status == 'not-found'  # f1 is an older function: orientation is explicit, never guessed


def test_the_run_named_in_not_found_is_the_anchors_else_the_current_one():
    index = index_of(('m1', ['f1'], []))
    assert 'run-9' in locate_match(AnchorRef('function', 'x', run_id='run-9', label='x'), index).message
    assert 'run-1' in locate_match(AnchorRef('function', 'x', label='x'), index).message
    assert locate_match(AnchorRef('function', 'x', label='x'), MatchIndex(None, [])).message == 'Not found: x.'


def test_an_ambiguous_function_returns_match_candidates_never_the_first():
    index = index_of(('m1', ['f1'], ['g1']), ('m2', ['f1'], ['g2']), ('m3', ['f1'], []))
    anchor = AnchorRef('function', 'f1', 'older', 'run-1', 'sub_1', 'search', 3)
    result = locate_match(anchor, index)
    assert result.status == 'ambiguous' and result.message == '3 candidates match sub_1. Choose one.'
    assert [(c.kind, c.key, c.side, c.run_id, c.label, c.origin, c.revision) for c in result.candidates] == [
        ('match', f'm{i}', 'older', 'run-1', 'sub_1', 'search', 3) for i in (1, 2, 3)]


def test_a_candidate_match_keeps_the_first_side_that_lists_the_function():
    index = index_of(('m1', ['f1'], ['f1']), ('m2', [], ['f1']))
    result = locate_match(AnchorRef('function', 'f1', label='sub_1'), index)
    assert [(c.key, c.side) for c in result.candidates] == [('m1', 'older'), ('m2', 'newer')]


def test_only_code_anchors_resolve_to_matches():
    with pytest.raises(ValueError):
        locate_match(AnchorRef('string', 's1'), index_of())


# ---- history ----------------------------------------------------------------------------------------------------


def anchors(count):
    return [AnchorRef('string', f's{i}') for i in range(count)]


def test_history_goes_back_and_forward_and_stops_at_the_ends():
    history = NavHistory()
    assert history.back() is None and history.forward() is None and len(history) == 0
    first, second, third = anchors(3)
    for anchor in (first, second, third):
        history.push(anchor)
    assert (len(history), history.current) == (3, third)
    assert (history.back(), history.back(), history.back()) == (second, first, None)
    assert history.current == first
    assert (history.forward(), history.forward(), history.forward()) == (second, third, None)


def test_pushing_after_going_back_drops_the_forward_entries():
    history = NavHistory()
    first, second, third, fourth = anchors(4)
    for anchor in (first, second, third):
        history.push(anchor)
    history.back()
    history.push(fourth)
    assert len(history) == 3 and history.forward() is None
    assert [history.back(), history.back()] == [second, first]


def test_pushing_the_current_anchor_again_changes_nothing():
    history = NavHistory()
    first, second = anchors(2)
    history.push(first)
    history.push(first)
    history.push(second)
    history.push(AnchorRef('string', 's1', label='same anchor, new label'))
    assert len(history) == 2


def test_a_degenerate_limit_still_keeps_the_current_entry():
    history = NavHistory(0)
    first, second = anchors(2)
    history.push(first)
    history.push(second)
    assert len(history) == 1 and history.current == second


def test_history_keeps_the_newest_fifty_entries():
    history = NavHistory()
    pushed = anchors(NAV_HISTORY + 7)
    for anchor in pushed:
        history.push(anchor)
    assert len(history) == NAV_HISTORY and history.current == pushed[-1]
    seen = [history.back() for _ in range(NAV_HISTORY - 1)]
    assert seen == list(reversed(pushed[7:-1])) and history.back() is None


@PROPS
@given(st.lists(st.one_of(st.integers(0, 6).map(lambda n: ('push', n)), st.just(('back', 0)),
                          st.just(('forward', 0))), max_size=120), st.integers(1, 8))
def test_history_invariants_under_any_sequence(operations, limit):
    history = NavHistory(limit)
    for name, number in operations:
        if name == 'push':
            history.push(AnchorRef('string', f's{number}'))
        elif name == 'back':
            before = history.current
            moved = history.back()
            assert (moved is None and history.current == before) or history.current == moved
        else:
            before = history.current
            moved = history.forward()
            assert (moved is None and history.current == before) or history.current == moved
        assert len(history) <= limit
        assert (history.current is None) == (len(history) == 0)


# ---- router -----------------------------------------------------------------------------------------------------


class Harness:
    """A router wired to a mutable key, a handler table and a recording `show`."""

    def __init__(self, handlers=None, results=None):
        self.key = KEY
        self.handlers = {'string': 'strings', 'function': None} if handlers is None else handlers
        self.results = results or {}
        self.shown: list[tuple[str, AnchorRef]] = []
        self.router = AnchorRouter(lambda: self.key, self.handlers.get, self.show)

    def show(self, panel_id, anchor):
        self.shown.append((panel_id, anchor))
        return self.results.get(anchor.key, NavResult.shown())


def pinned(key='s1', kind='string'):
    return AnchorRef(kind, key).pinned(KEY)


def test_a_current_anchor_is_shown_by_its_handler_and_recorded():
    harness = Harness()
    result = harness.router.navigate(pinned())
    assert result.status == 'shown'
    assert harness.shown == [('strings', pinned())] and len(harness.router.history) == 1


def test_a_stale_anchor_navigates_nowhere():
    harness = Harness()
    anchor = pinned()
    harness.key = KEY._replace(revision=4)  # a manual correction bumped the revision
    result = harness.router.navigate(anchor)
    assert (result.status, result.message) == ('stale', STALE_TEXT)
    assert harness.shown == [] and len(harness.router.history) == 0


def test_swapping_orientation_makes_pinned_anchors_stale():
    harness = Harness()
    anchor = pinned()
    harness.key = KEY._replace(revision=4, older_sha256=KEY.newer_sha256, newer_sha256=KEY.older_sha256)
    assert harness.router.navigate(anchor).status == 'stale'


def test_a_kind_nobody_handles_is_blocked_and_there_is_no_fallback_target():
    harness = Harness(handlers={})
    result = harness.router.navigate(pinned())
    assert result.status == 'blocked' and result.code == 'PT-GUI-NAV-BLOCKED' and harness.shown == []


def test_only_shown_results_enter_the_history():
    harness = Harness(results={'missing': NavResult.not_found('x', 'run-1'), 'two': NavResult.ambiguous('x', [])})
    for key in ('missing', 'two'):
        assert harness.router.navigate(pinned(key)).status != 'shown'
    assert len(harness.router.history) == 0
    harness.router.navigate(pinned('s1'))
    assert len(harness.router.history) == 1


def test_back_and_forward_reopen_earlier_anchors_without_growing_the_history():
    harness = Harness()
    first, second = pinned('s1'), pinned('s2')
    harness.router.navigate(first)
    harness.router.navigate(second)
    assert harness.router.back().status == 'shown' and harness.shown[-1] == ('strings', first)
    assert harness.router.forward().status == 'shown' and harness.shown[-1] == ('strings', second)
    assert harness.router.forward() is None and len(harness.router.history) == 2
    assert harness.router.back() is not None and harness.router.back() is None


def test_back_to_an_anchor_that_went_stale_reports_it_and_moves_on():
    harness = Harness()
    harness.router.navigate(pinned('s1'))
    harness.key = KEY._replace(revision=4)
    harness.router.navigate(AnchorRef('string', 's2').pinned(harness.key))
    result = harness.router.back()
    assert result.status == 'stale' and len(harness.shown) == 2
    assert harness.router.history.current == pinned('s1')
