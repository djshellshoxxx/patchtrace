"""WB3-S6 search rows: changed and linked strings only, secrets by kind and hash, bounded fields."""
from __future__ import annotations

import pytest
from test_strings_delta import PAIRING, sha, table

from patchtrace.strings.contracts import StringsDelta
from patchtrace.strings.delta import compute_delta
from patchtrace.strings.search_rows import search_rows


@pytest.fixture(scope='module')
def rows():
    older = table('older', ['kept string one', 'Old message here'])
    newer = table('newer', ['kept string one', 'index %u exceeds length %u', 'AKIAIOSFODNN7EXAMPLE'])
    delta = compute_delta(older, newer, pairing=PAIRING)
    return delta, search_rows(delta)


def test_one_row_per_changed_string_and_none_for_unchanged(rows):
    delta, found = rows
    assert len(found) == len(delta.changes) == 3
    assert 'kept string one' not in {r.text for r in found}


def test_side_status_and_offsets_follow_the_observed_side(rows):
    by_text = {r.text: r for r in rows[1]}
    older, newer = by_text['Old message here'], by_text['index %u exceeds length %u']
    assert (older.side, older.status, newer.side, newer.status) == ('older', 'only-older', 'newer', 'only-newer')
    assert newer.offsets and newer.field == 'strings' and newer.title.startswith('Only in newer string')


def test_secret_is_indexed_by_kind_and_hash_only(rows):
    texts = [r.text for r in rows[1]]
    assert not any('AKIAIOSFODNN7EXAMPLE' in t for t in texts)
    assert f'[redacted secret-like {sha("AKIAIOSFODNN7EXAMPLE").hex()[:12]}]' in texts


def test_coverage_line_says_the_inventory_is_not_indexed(rows):
    assert all('inventory is not indexed' in r.coverage for r in rows[1])


def test_doc_keys_are_unique_and_stable(rows):
    keys = [r.doc_key for r in rows[1]]
    assert len(set(keys)) == len(keys)
    delta = compute_delta(table('older', ['Old message here']), table('newer', ['index %u exceeds length %u']),
                          pairing=PAIRING)
    assert [r.doc_key for r in search_rows(delta)] == [r.doc_key for r in search_rows(delta)]


def test_a_delta_that_is_not_comparable_indexes_nothing():
    refused = StringsDelta(older_basis_digest='a' * 64, newer_basis_digest='b' * 64, comparable=False)
    assert search_rows(refused) == ()
