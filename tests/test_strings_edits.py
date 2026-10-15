"""WB3-S5 edited-string pairing."""
from __future__ import annotations

import hashlib

import pytest

from patchtrace.strings import edits
from patchtrace.strings.edits import Candidate, pair_edits


def cand(text, *functions):
    return Candidate(hashlib.sha256(text.encode()).digest(), text, frozenset(functions))


@pytest.mark.parametrize('older, newer, kind', [
    ('bad header (%s)', 'bad header (%.64s)', 'insert'),
    ('bad header (%.64s)', 'bad header (%s)', 'delete'),
    ('open file', 'try open file', 'prefix'),
    ('open file', 'open file now', 'suffix'),
    ('build one', 'build two', 'replace'),
], ids=['insert', 'delete', 'prefix', 'suffix', 'replace'])
def test_edit_kind(older, newer, kind):
    assert edits.edit_kind(older, newer) == kind


def test_format_edit_pairs_inside_one_function_and_flags_the_specifier():
    result = pair_edits([cand('bad header (%s)', 'm1'), cand('debug dump of internal state', 'm1')],
                        [cand('bad header (%.64s)', 'm1'), cand('index %u exceeds length %u', 'm1')])
    (pair,) = result.pairs
    assert pair.older == cand('bad header (%s)').key and pair.newer == cand('bad header (%.64s)').key
    assert (pair.kind, pair.format_spec, pair.lookalike) == ('insert', True, False)


def test_edit_in_different_functions_does_not_pair():
    assert pair_edits([cand('bad header (%s)', 'm1')], [cand('bad header (%.64s)', 'm2')]).pairs == ()


def test_tie_pairs_nothing():
    result = pair_edits([cand('config value a', 'm1')], [cand('config value b', 'm1'), cand('config value c', 'm1')])
    assert result.pairs == ()


def test_dissimilar_strings_do_not_pair():
    assert pair_edits([cand('alpha beta gamma', 'm1')], [cand('zzzz yyyy xxxx', 'm1')]).pairs == ()


def test_lookalike_pairs_without_a_function():
    result = pair_edits([cand('Error')], [cand('Еrror')])
    (pair,) = result.pairs
    assert pair.lookalike and pair.kind == 'replace'


def test_oversized_function_group_is_skipped_with_a_note():
    olds = [cand(f'old message number {i}', 'm1') for i in range(edits.MAX_EDIT_PAIRS + 1)]
    result = pair_edits(olds, [cand('old message number 1x', 'm1')])
    assert result.pairs == () and result.notes


def test_pairs_are_one_to_one_and_order_independent():
    older = [cand('first message here', 'm1'), cand('second message there', 'm1')]
    newer = [cand('first message here!', 'm1'), cand('second message there!', 'm1')]
    forward = pair_edits(older, newer)
    backward = pair_edits(older[::-1], newer[::-1])
    assert forward.pairs == backward.pairs and len(forward.pairs) == 2
    assert len({p.older for p in forward.pairs}) == len({p.newer for p in forward.pairs}) == 2
