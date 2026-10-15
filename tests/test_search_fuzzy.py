"""WB1 S4: name suggestions and rename hints (RapidFuzz optional)."""
from __future__ import annotations

import pytest

from patchtrace import optional_deps
from patchtrace.search import fuzzy
from patchtrace.search.contracts import FunctionRef

pytestmark = pytest.mark.skipif(not optional_deps.available('rapidfuzz'), reason='needs the search extra')


def ref(name: str, side: str = 'older', ident: str | None = None) -> FunctionRef:
    return FunctionRef(function_id=ident or f'{side}-{name}', name=name, side=side)


@pytest.mark.parametrize('length, edits', [(1, 0), (2, 0), (3, 1), (4, 1), (5, 2), (9, 2), (10, 3), (40, 3)],
                         ids=lambda v: str(v))
def test_max_edits_by_length(length, edits):
    assert fuzzy.max_edits(length) == edits


def test_suggestions_are_closest_first_without_exact_or_auto_names():
    names = ['ValidateAccount', 'ValidateAccounts', 'FUN_140001000', 'ValdateAccount', 'Unrelated']
    rows = fuzzy.suggest('ValdateAcount', names)
    assert [(names[i], e) for i, e in rows] == [('ValdateAccount', 1), ('ValidateAccount', 2),
                                                  ('ValidateAccounts', 3)]
    assert 'ValidateAccount' not in [names[i] for i, _ in fuzzy.suggest('ValidateAccount', names)]


def test_short_names_never_get_suggestions():
    assert fuzzy.suggest('ab', ['ac', 'ab']) == []


def test_suggestion_count_is_limited():
    names = [f'Handler{chr(97 + i)}x' for i in range(20)]
    assert len(fuzzy.suggest('Handlerzx', names)) == fuzzy.DEFAULT_LIMITS.suggestions


def test_counterpart_hint_needs_a_mutual_unique_nearest():
    older = [ref('ParseHeaderBlock'), ref('FUN_140001000')]
    newer = [ref('ParseHeaderBlocks', 'newer'), ref('FUN_140002000', 'newer')]
    (hint,) = fuzzy.counterpart_hints(older, newer)
    assert (hint.older.name, hint.newer.name, hint.edits) == ('ParseHeaderBlock', 'ParseHeaderBlocks', 1)
    assert hint.shared_words == ('header', 'parse')


def test_a_tie_or_a_one_sided_nearest_gives_no_hint():
    tie_new = [ref('ParseHeaderBlocka', 'newer'), ref('ParseHeaderBlockb', 'newer')]
    assert fuzzy.counterpart_hints([ref('ParseHeaderBlock')], tie_new) == ()
    one_sided_old = [ref('ParseHeaderBlock'), ref('ParseHeaderBlocka')]
    hints = fuzzy.counterpart_hints(one_sided_old, [ref('ParseHeaderBlockb', 'newer')])
    assert hints == ()


def test_unrelated_names_give_no_hint():
    assert fuzzy.counterpart_hints([ref('AlphaBeta')], [ref('ZetaOmegaXyz', 'newer')]) == ()


def test_hundred_thousand_names_fit_the_query_budget():
    import time
    names = [f'Module{i % 997}Handler{i}' for i in range(100_000)]
    started = time.perf_counter()
    rows = fuzzy.suggest('Modle5Handler5', names)
    assert time.perf_counter() - started < fuzzy.DEFAULT_LIMITS.query_timeout_s
    assert rows[0] == (5, 1)
