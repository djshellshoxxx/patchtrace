"""SPEC-31 S3 alignment (05 s2.3): patience + LCS primitives, block pairing and the block-wise instruction alignment.
Functions are hand-assembled (tests/unified_facts_builder.py) and go through the real ingest."""
from __future__ import annotations

import dataclasses

import pytest
from unified_facts_builder import build_pair, function

from patchtrace.unified.facts import align as aligner
from patchtrace.unified.facts.fnview import load_view
from patchtrace.unified.limits import DEFAULT_LIMITS, Budget, BudgetExhausted

SYM = {'g_a': 0x3000, 'helper': 0x1400}


def views(tmp_path, old_items, new_items, *, old_rva=0x1000, new_rva=0x1000):
    old, new = build_pair(tmp_path, [function(old_rva, old_items, sym=SYM)], [function(new_rva, new_items, sym=SYM)])
    return (load_view(old, 'older', old.functions.rva_to_fid[old_rva]),
            load_view(new, 'newer', new.functions.rva_to_fid[new_rva]))


def mnemonics(view, indexes):
    return [view.insns[i].mnem for i in indexes]


# --- primitives ---------------------------------------------------------------------------------------------------------

def test_patience_anchors_take_the_longest_unique_chain():
    a = ['x', 'a', 'b', 'c', 'x', 'd']
    b = ['a', 'b', 'x', 'c', 'd']
    assert aligner.patience_anchors(a, b) == [(1, 0), (2, 1), (3, 3), (5, 4)]
    assert aligner.patience_anchors(['a', 'a'], ['a']) == []        # not unique on both sides


def test_lcs_pairs_is_a_longest_common_subsequence_and_deterministic():
    a, b = list('ABCBDAB'), list('BDCABA')
    pairs = aligner.lcs_pairs(a, b)
    assert len(pairs) == 4 and all(a[i] == b[j] for i, j in pairs)
    assert pairs == sorted(pairs) and pairs == aligner.lcs_pairs(a, b)
    assert aligner.lcs_pairs(list('ab'), list('xy')) == []
    assert aligner.lcs_pairs(list('abc' * 40), list('bca' * 40), cap=100) is None      # beyond the cell cap


def test_diff_tokens_reports_a_capped_gap_and_keeps_the_rest():
    a = ['p'] + ['a'] * 50 + ['q']
    b = ['p'] + ['b'] * 50 + ['q']
    pairs, capped = aligner.diff_tokens(a, b, a, b, cap=10)
    assert capped and pairs == [(0, 0), (51, 51)]


def test_family_groups_condition_code_variants():
    assert aligner.family('JZ') == aligner.family('JLE') == 'Jcc'
    assert aligner.family('SETL') == aligner.family('SETZ') == 'SETcc'
    assert aligner.family('CMOVG') == 'CMOVcc'
    assert aligner.family('JMP') == 'JMP' and aligner.family('MOV') == 'MOV'


# --- block pairing --------------------------------------------------------------------------------------------------------

BODY = [('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'), ('mov_ri', 'EAX', 1), ('add_ri', 'EAX', 3), ('label', 'done'),
        ('mov_rr', 'EDX', 'EAX'), ('ret',)]


def test_identical_functions_pair_every_block_by_key_and_every_instruction(tmp_path):
    old, new = views(tmp_path, BODY, BODY)
    result = aligner.align(old, new)
    assert result.by_key and not result.capped and result.old_only == result.new_only == ()
    assert result.block_pairs == ((0, 0), (1, 1), (2, 2))
    assert [old.insns[i].mnem for i, _ in result.pairs] == ['CMP', 'MOV', 'ADD', 'MOV', 'RET']
    assert result.terminators[(0, 0)] == (1, 1)                 # the JA of the entry block is not aligned here


def test_moved_function_aligns_identically(tmp_path):
    old, new = views(tmp_path, BODY, BODY, new_rva=0x1200)
    assert aligner.align(old, new).pairs == aligner.align(old, old).pairs


def test_a_changed_constant_keeps_the_instruction_paired(tmp_path):
    changed = [('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'), ('mov_ri', 'EAX', 1), ('add_ri', 'EAX', 4), ('label', 'done'),
               ('mov_rr', 'EDX', 'EAX'), ('ret',)]
    old, new = views(tmp_path, BODY, changed)
    result = aligner.align(old, new)
    assert not result.by_key                                    # block 1 differs, so not every key is unique-equal
    assert result.block_pairs == ((0, 0), (1, 1), (2, 2))       # ... but the CFG position pairs it
    assert [old.insns[i].mnem for i, _ in result.pairs] == ['CMP', 'MOV', 'ADD', 'MOV', 'RET']
    assert result.old_only == result.new_only == ()


def test_inserted_and_deleted_instructions_stay_unmatched(tmp_path):
    longer = [('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'), ('mov_ri', 'EAX', 1), ('call', 'helper'), ('add_ri', 'EAX', 3),
              ('label', 'done'), ('mov_rr', 'EDX', 'EAX'), ('ret',)]
    old, new = views(tmp_path, BODY, longer)
    result = aligner.align(old, new)
    assert mnemonics(new, result.new_only) == ['CALL'] and result.old_only == ()
    assert len(result.pairs) == 5


def test_a_changed_condition_code_is_a_substitution_not_an_insert_and_delete(tmp_path):
    cmov_old = [('cmp_ri', 'ECX', 6), ('cmov', 'L', 'EAX', 'EDX'), ('ret',)]
    cmov_new = [('cmp_ri', 'ECX', 6), ('cmov', 'LE', 'EAX', 'EDX'), ('ret',)]
    old, new = views(tmp_path, cmov_old, cmov_new)
    result = aligner.align(old, new)
    assert [(old.insns[i].mnem, new.insns[j].mnem) for i, j in result.replaced] == [('CMOVL', 'CMOVLE')]
    assert result.old_only == result.new_only == ()


def test_unrelated_replacement_is_not_paired(tmp_path):
    old, new = views(tmp_path, [('cmp_ri', 'ECX', 6), ('xor_rr', 'EAX', 'EAX'), ('ret',)],
                     [('cmp_ri', 'ECX', 6), ('call', 'helper'), ('ret',)])
    result = aligner.align(old, new)
    assert result.replaced == () and mnemonics(old, result.old_only) == ['XOR'] and mnemonics(new, result.new_only) == ['CALL']


LAYOUT_OLD = [('cmp_ri', 'ECX', 1), ('jcc', 'Z', 'then'), ('mov_ri', 'EAX', 2), ('jmp', 'end'), ('label', 'then'),
              ('mov_ri', 'EAX', 3), ('label', 'end'), ('ret',)]
LAYOUT_NEW = [('cmp_ri', 'ECX', 1), ('jcc', 'NZ', 'else'), ('mov_ri', 'EAX', 3), ('jmp', 'end'), ('label', 'else'),
              ('mov_ri', 'EAX', 2), ('label', 'end'), ('ret',)]


def test_reordered_blocks_are_paired_by_their_unique_body_key(tmp_path):
    old, new = views(tmp_path, LAYOUT_OLD, LAYOUT_NEW)
    result = aligner.align(old, new)
    assert result.by_key and len(result.block_pairs) == 4
    # old `then` (mov 3) sits where the new `else` is, and the other way round: mov 2 pairs with mov 2 wherever it is
    paired = {(old.insns[i].mnem, old.insns[i].ops[1].value, new.insns[j].ops[1].value) for i, j in result.pairs
              if old.insns[i].mnem == 'MOV'}
    assert paired == {('MOV', 2, 2), ('MOV', 3, 3)} and result.old_only == result.new_only == ()
    assert [old.insns[i].mnem for i, _ in result.pairs].count('CMP') == 1 and len(result.pairs) == 4


def test_blocks_with_an_equal_body_are_not_paired_by_key_but_by_their_place_in_the_cfg(tmp_path):
    """Two bodies `mov eax, 5` have no unique key: they pair through the branch they hang off, not by listing order."""
    def program(first, second):
        blocks = {'x': [('label', 'L1'), ('mov_ri', 'EAX', 5), ('jmp', 'end')],
                  'y': [('label', 'L2'), ('mov_ri', 'EAX', 5), ('jmp', 'end')]}
        return [('cmp_ri', 'ECX', 1), ('jcc', 'Z', 'L1'), ('cmp_ri', 'EDX', 2), ('jcc', 'Z', 'L2'),
                ('xor_rr', 'EAX', 'EAX'), ('ret',), *blocks[first], *blocks[second], ('label', 'end'), ('ret',)]
    old, new = views(tmp_path, program('x', 'y'), program('y', 'x'))
    result = aligner.align(old, new)
    assert not result.by_key
    assert result.block_map == {0: 0, 1: 1, 2: 2, 3: 4, 4: 3, 5: 5}      # the listing order of the twins is swapped


def test_unmatched_blocks_are_reported_as_added_and_removed(tmp_path):
    guarded = [('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'), ('mov_ri', 'EAX', 1), ('add_ri', 'EAX', 3), ('label', 'done'),
               ('mov_rr', 'EDX', 'EAX'), ('ret',)]
    extra = [('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'), ('cmp_ri', 'EDX', 9), ('jcc', 'Z', 'done'), ('mov_ri', 'EAX', 1),
             ('add_ri', 'EAX', 3), ('label', 'done'), ('mov_rr', 'EDX', 'EAX'), ('ret',)]
    old, new = views(tmp_path, guarded, extra)
    result = aligner.align(old, new)
    assert result.old_blocks_only == () and len(result.new_blocks_only) == 1
    assert result.by_key is False


def test_the_alignment_cap_leaves_only_prefix_and_suffix(tmp_path):
    edited = [*BODY[:3], ('sub_ri', 'EAX', 3), *BODY[4:]]
    old, new = views(tmp_path, BODY, edited)
    tight = dataclasses.replace(DEFAULT_LIMITS, l27_align_instructions=3)
    result = aligner.align(old, new, limits=tight)
    assert result.capped and result.block_pairs == () and not result.by_key
    assert [old.insns[i].mnem for i, _ in result.pairs] == ['CMP', 'MOV', 'MOV', 'RET']      # the other opcode stays out
    assert mnemonics(old, result.old_only) == ['ADD'] and mnemonics(new, result.new_only) == ['SUB']


def test_equal_masked_bytes_align_positionally_whatever_the_cap(tmp_path):
    """05 s2.3, first rule: equal `h1` and a positionally equal CFG align k with k in linear time, so the cap on the
    diff never applies to them; twin blocks (equal bodies, no unique key) pair by ordinal."""
    twin = [('cmp_ri', 'ECX', 1), ('jcc', 'Z', 'L1'), ('cmp_ri', 'EDX', 2), ('jcc', 'Z', 'L2'), ('xor_rr', 'EAX', 'EAX'),
            ('ret',), ('label', 'L1'), ('mov_ri', 'EAX', 5), ('jmp', 'end'), ('label', 'L2'), ('mov_ri', 'EAX', 5),
            ('jmp', 'end'), ('label', 'end'), ('ret',)]
    old, new = views(tmp_path, twin, twin, new_rva=0x1200)
    tight = dataclasses.replace(DEFAULT_LIMITS, l27_align_instructions=3)
    result = aligner.align(old, new, limits=tight)
    assert not result.capped and result.block_pairs == tuple((b, b) for b in range(6))
    assert not result.by_key                                    # the twins have no unique key
    assert len(result.pairs) == len(old.kept) - 4 and result.old_only == result.new_only == ()   # 4 terminating jumps


def test_alignment_honours_the_budget(tmp_path):
    old, new = views(tmp_path, BODY, BODY)
    budget = Budget(check_every=1)
    budget.cancel = type('Set', (), {'is_set': staticmethod(lambda: True)})()
    with pytest.raises(BudgetExhausted):
        aligner.align(old, new, budget=budget)
