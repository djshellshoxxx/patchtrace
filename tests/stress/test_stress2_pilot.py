"""QA-S2 pilot leads pipeline: 10k to 100k synthetic anchors through the ranking tie-breaker, the CVE universe bound and
the typed error envelope, with hostile text. Deterministic (seeded), synthetic only, each test well under 20 s at scale 1.
"""
from __future__ import annotations

import os
import random

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.pilot.collect import universe
from patchtrace.pilot.limits import DEFAULT_LIMITS, ERROR_CODES, PilotError
from patchtrace.pilot.ranking import CLASS_RANK, MECHANISM_INDEX, advisory_key, place

SCALE = int(os.environ.get('PATCHTRACE_STRESS_SCALE', '1'))
CLASSES = tuple(CLASS_RANK)
MECHANISMS = tuple(MECHANISM_INDEX)
HOSTILE = '\x1b[31mCVE‮\x00\n\r​' + 'A' * 300


def _rows(count: int, seed: int) -> list[tuple[tuple[int, ...], str]]:
    rng = random.Random(seed)
    rows = []
    for index in range(count):
        key = advisory_key(lead_class=rng.choice(CLASSES), mechanism=rng.choice(MECHANISMS),
                           contested=rng.random() < 0.5, met=rng.randint(0, 3), components=rng.randint(0, 3),
                           basis=rng.randint(0, 2), local_hits=rng.randint(0, 2), anchored=rng.random() < 0.5,
                           severity=rng.randint(0, 3), nuisance=rng.randint(0, 1))
        rows.append((key, f'cand-{index:07d}'))
    return rows


@pytest.mark.parametrize('count', [10_000 * SCALE, 100_000 * SCALE], ids=['10k', '100k'])
def test_place_ranks_every_anchor_uniquely_and_contiguously(count):
    rows = _rows(count, seed=count)
    placed = place(rows)
    assert [item.rank for item in placed] == list(range(1, count + 1))
    assert len({item.candidate_key for item in placed}) == count
    keys = [item.key for item in placed]
    assert keys == sorted(keys)


def test_place_tie_groups_span_exactly_their_equal_keys():
    rows = _rows(50_000 * SCALE, seed=7)
    placed = place(rows)
    by_key: dict[tuple, list[int]] = {}
    for item in placed:
        by_key.setdefault(item.key, []).append(item.rank)
    for ranks in by_key.values():
        assert min(ranks) == ranks[0] and max(ranks) == ranks[-1]
        assert ranks == list(range(ranks[0], ranks[-1] + 1))
    for item in placed:
        assert item.first <= item.rank <= item.last
        assert item.last - item.first + 1 == len(by_key[item.key])


def test_place_is_independent_of_input_order():
    rows = _rows(20_000 * SCALE, seed=11)
    shuffled = list(rows)
    random.Random(3).shuffle(shuffled)
    assert place(rows) == place(shuffled)


@settings(max_examples=25, deadline=None, database=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(st.tuples(st.lists(st.integers(-5, 5), min_size=1, max_size=4).map(tuple),
                          st.text(max_size=12)), max_size=60))
def test_place_handles_arbitrary_keys_without_gaps(rows):
    placed = place(rows)
    assert [item.rank for item in placed] == list(range(1, len(rows) + 1))


def test_universe_bounds_the_stored_cves_at_scale():
    cap = DEFAULT_LIMITS.p03_cves
    stored = [f'CVE-2099-{index:07d}' for index in range(100_000 * SCALE)]
    named = stored[:cap]
    computed, shown = universe(stored, named)
    assert computed == shown == tuple(sorted(named))
    small = stored[:cap]
    assert universe(small, [])[0] == tuple(sorted(small))
    with pytest.raises(PilotError) as info:
        universe(stored, stored[:cap + 1])
    assert info.value.code == 'PT-PILOT-INPUT' and info.value.reason == 'too-many-cves'
    with pytest.raises(PilotError) as info:
        universe(stored, [])
    assert info.value.reason == 'too-many-cves'


def test_universe_message_never_echoes_hostile_input():
    stored = ['CVE-2099-0001']
    with pytest.raises(PilotError) as info:
        universe(stored, [HOSTILE])
    message = info.value.message
    assert info.value.code == 'PT-PILOT-NOTFOUND'
    assert not any(ord(char) < 32 or ord(char) == 0x202E for char in message)


@pytest.mark.parametrize('code', ERROR_CODES, ids=list(ERROR_CODES))
def test_error_codes_map_to_exit_codes_in_range(code):
    assert PilotError(code, 'fixed template').exit_code in {2, 3, 4, 5}


@pytest.mark.parametrize('reason', ['', 'UPPER', 'space here', 'x' * 49, 'new\nline'],
                         ids=['empty', 'upper', 'space', 'too-long', 'newline'])
def test_error_reason_must_be_a_slug(reason):
    with pytest.raises(ValueError):
        PilotError('PT-PILOT-INPUT', 'template', reason=reason)


def test_error_message_is_truncated_to_the_envelope():
    error = PilotError('PT-PILOT-INPUT', 'A' * 100_000)
    assert len(error.message) == 400
