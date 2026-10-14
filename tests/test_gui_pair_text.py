"""PairText and align_pair (GUI plan 8.4, slice F6a). Pure: no Qt."""
from __future__ import annotations

from difflib import SequenceMatcher

import pytest

from patchtrace.alignment import diff_hunks
from patchtrace.gui.pair_text import PairHunk, PairText, align_pair


def build(old: str, new: str) -> PairText:
    ops = SequenceMatcher(None, old.splitlines(), new.splitlines(), autojunk=False).get_opcodes()
    return align_pair(old.splitlines(), new.splitlines(), ops)


def test_replace_and_insert_pad_the_shorter_side_with_empty_rows():
    pair = build('a\nb\nc', 'a\nX\nY\nc')
    assert pair.older.split('\n') == ['a', 'b', '', 'c'] and pair.newer.split('\n') == ['a', 'X', 'Y', 'c']
    assert pair.hunks == (PairHunk(1, 2, 'replace'),)
    assert pair.older_map == (0, 1, 3) and pair.newer_map == (0, 1, 2, 3)


def test_identical_text_has_no_hunks_and_identity_maps():
    pair = build('a\nb', 'a\nb')
    assert pair.hunks == () and pair.older_map == pair.newer_map == (0, 1)


def test_an_empty_side_is_all_empty_rows_not_invented_code():
    pair = build('', 'x\ny')
    assert pair.older == '\n' and pair.older_map == () and pair.hunks == (PairHunk(0, 2, 'insert'),)


def test_it_accepts_the_repository_hunks():
    old, new = 'one\ntwo\nthree', 'one\n2\nthree'
    ops = [(h.operation, h.old_start, h.old_end, h.new_start, h.new_end) for h in diff_hunks(old, new, 'm')]
    assert align_pair(old.splitlines(), new.splitlines(), ops) == build(old, new)


@pytest.mark.parametrize('opcode', [pytest.param(('weird', 0, 1, 0, 1), id='op'),
                                    pytest.param(('replace', 0, 5, 0, 1), id='range'),
                                    pytest.param(('replace', 1, 0, 0, 1), id='order')])
def test_bad_opcodes_are_rejected(opcode):
    with pytest.raises(ValueError):
        align_pair(['a'], ['b'], [opcode])


def test_line_map_rejects_an_unknown_side():
    with pytest.raises(ValueError):
        PairText().line_map('left')
