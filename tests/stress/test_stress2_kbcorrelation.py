"""QA-S2 KB correlation identifiers at 100k scale and hostile id text: token extraction over large documents, edge
normalisers, the pydantic KB contract agreeing with the pure predicate, and the id sort order. Synthetic only.
"""
from __future__ import annotations

import os
import random
import time

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import TypeAdapter, ValidationError

from patchtrace.kbcorrelation.contracts import KbId
from patchtrace.kbcorrelation.ids import (
    KbSyntaxError,
    canonical_kb,
    cve_sort_key,
    find_kb_tokens,
    is_canonical_kb,
    is_cve,
    kb_sort_key,
    normalise_cve,
    normalise_kb_edge,
)

SCALE = int(os.environ.get('PATCHTRACE_STRESS_SCALE', '1'))
SETTINGS = settings(max_examples=300, deadline=None, database=None, suppress_health_check=[HealthCheck.too_slow])
KB_ADAPTER = TypeAdapter(KbId)
HOSTILE_TEXT = st.text(alphabet=st.characters(blacklist_categories=('Cs',)), max_size=40)


def _ids(count: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    return [f'KB{rng.randint(0, 10**10 - 1):0{rng.randint(4, 10)}d}' for _ in range(count)]


def test_token_extraction_over_a_hundred_thousand_mentions_is_exact_and_fast():
    rng = random.Random(9)
    mentions = [f'KB{rng.randint(1000, 9999):07d}' for _ in range(100_000 * SCALE)]
    text = '\n'.join(f'patch {mention} fixes; see xKB{i}y and KB{i}z' for i, mention in enumerate(mentions))
    started = time.monotonic()
    tokens = find_kb_tokens(text)
    assert time.monotonic() - started < 20
    assert tokens == tuple(sorted(set(mentions), key=kb_sort_key))


@pytest.mark.parametrize('text', ['XKB1234', 'KB1234x', 'kb1234', 'KB 1234', 'KB123', 'KB12345678901'],
                         ids=['prefix-glue', 'suffix-glue', 'lower', 'spaced', 'short', 'long'])
def test_token_extraction_rejects_glued_or_nonstandard_forms(text):
    assert find_kb_tokens(text) == ()


@SETTINGS
@given(HOSTILE_TEXT)
def test_find_kb_tokens_is_total_and_returns_only_canonical_ids(text):
    tokens = find_kb_tokens(text)
    assert all(is_canonical_kb(token) for token in tokens)
    assert list(tokens) == sorted(tokens, key=kb_sort_key)


@SETTINGS
@given(HOSTILE_TEXT)
def test_edge_normaliser_raises_only_its_own_error(raw):
    try:
        result = normalise_kb_edge(raw)
    except KbSyntaxError:
        return
    assert is_canonical_kb(result) and KB_ADAPTER.validate_python(result) == result


@SETTINGS
@given(st.text(alphabet='0123456789', min_size=4, max_size=10))
def test_edge_normaliser_keeps_leading_zeros_and_is_idempotent(digits):
    once = normalise_kb_edge(digits)
    assert once == 'KB' + digits
    assert normalise_kb_edge(once) == once == canonical_kb(once)


@SETTINGS
@given(HOSTILE_TEXT)
def test_pydantic_kb_contract_agrees_with_the_pure_predicate(candidate):
    try:
        KB_ADAPTER.validate_python(candidate)
        accepted = True
    except Exception:  # noqa: BLE001 - any rejection is a rejection
        accepted = False
    assert accepted == is_canonical_kb(candidate)


@pytest.mark.parametrize('candidate', ['KB1234\n', 'KB1234٠', 'KB12345678901', ' KB1234', 'KB1234\x00'],
                         ids=['trailing-newline', 'arabic-digit', 'eleven-digits', 'leading-space', 'nul'])
def test_kb_contract_rejects_hostile_near_misses(candidate):
    assert not is_canonical_kb(candidate)
    with pytest.raises(ValidationError):
        KB_ADAPTER.validate_python(candidate)


def test_kb_sort_key_orders_a_hundred_thousand_ids_without_numeric_cast():
    ids = _ids(100_000 * SCALE, seed=4)
    ordered = sorted(set(ids), key=kb_sort_key)
    assert all(kb_sort_key(a) < kb_sort_key(b) for a, b in zip(ordered, ordered[1:], strict=False))
    assert all(len(a) <= len(b) for a, b in zip(ordered, ordered[1:], strict=False))


@SETTINGS
@given(st.integers(min_value=1000, max_value=10**19 - 1))
def test_cve_sort_key_orders_by_year_then_numeric_sequence(sequence):
    text = f'CVE-2024-{sequence}'
    assert is_cve(text)
    assert cve_sort_key(text) == (2024, len(str(sequence)), str(sequence))


@SETTINGS
@given(HOSTILE_TEXT)
def test_normalise_cve_is_idempotent_or_refused(raw):
    try:
        once = normalise_cve(raw)
    except KbSyntaxError:
        return
    assert normalise_cve(once) == once and is_cve(once)
