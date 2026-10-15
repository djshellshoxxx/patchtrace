"""SPEC-31 S3 CFG edge logic (05 s2.5 COS-LAYOUT/1, review R-04) and EH-EQ (R-16) in isolation."""
from __future__ import annotations

import pytest
from test_unified_ir_facts import image
from unified_facts_builder import build_pair, eh_json, function, run_facts

from patchtrace.unified.facts import layout
from patchtrace.unified.facts.align import align
from patchtrace.unified.facts.datamap import TargetMap
from patchtrace.unified.facts.eh import eh_state
from patchtrace.unified.facts.fnview import load_view

SYM = {'helper': 0x1200, 'other': 0x1300}
OLD_EH = {0x1000: eh_json(handler=0x1200, scopes=[[0x10, 0x20, 1, 0x30]])}


def views(tmp_path, old_items, new_items, *, old_eh=None, new_eh=None, pairs=((0x1200, 0x1200), (0x1300, 0x1300))):
    helpers = [function(0x1200, [('mov_ri', 'EAX', 1), ('ret',)], name='helper'),
               function(0x1300, [('mov_ri', 'EAX', 2), ('ret',)], name='other')]
    old, new = build_pair(tmp_path, [function(0x1000, old_items, name='f', sym=SYM), *helpers],
                          [function(0x1000, new_items, name='f', sym=SYM), *helpers], old_eh=old_eh, new_eh=new_eh)
    targets = TargetMap(old, new, list(pairs))
    return (load_view(old, 'older', old.functions.rva_to_fid[0x1000]),
            load_view(new, 'newer', new.functions.rva_to_fid[0x1000]), targets)


def cfg(tmp_path, old_items, new_items):
    old, new, targets = views(tmp_path, old_items, new_items)
    alignment = align(old, new)
    return old, new, alignment, layout.compare_cfg(old, new, alignment, targets)


GUARD = [('cmp_ri', 'ECX', 1), ('jcc', 'Z', 'then'), ('mov_ri', 'EAX', 2), ('jmp', 'end'), ('label', 'then'),
         ('mov_ri', 'EAX', 3), ('label', 'end'), ('ret',)]


# --- the inversion table ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('a,b', [('JZ', 'JNZ'), ('JC', 'JNC'), ('JBE', 'JA'), ('JL', 'JGE'), ('JLE', 'JG'),
                                 ('JS', 'JNS'), ('JO', 'JNO'), ('JP', 'JNP'), ('JB', 'JAE'), ('JE', 'JNE')],
                         ids=['z', 'b', 'be', 'l', 'le', 's', 'o', 'p', 'alias-b', 'alias-e'])
def test_the_closed_inversion_table_is_symmetric(a, b):
    assert layout.inverted(a, b) and layout.inverted(b, a)


@pytest.mark.parametrize('a,b', [('JZ', 'JZ'), ('JZ', 'JA'), ('JL', 'JG'), ('JL', 'JLE'), ('JMP', 'JNZ'), ('JMP', 'JMP'),
                                 ('JC', 'JA'), ('CALL', 'JZ'), ('JXX', 'JNZ')],
                         ids=['same', 'z-a', 'l-g', 'l-le', 'jmp', 'jmp-jmp', 'c-a', 'call', 'junk'])
def test_other_pairs_are_not_inversions(a, b):
    assert not layout.inverted(a, b)


# --- the bijection ---------------------------------------------------------------------------------------------------------

def test_an_inverted_branch_with_swapped_successors_is_a_layout_change_only(tmp_path):
    swapped = [('cmp_ri', 'ECX', 1), ('jcc', 'NZ', 'else'), ('mov_ri', 'EAX', 3), ('jmp', 'end'), ('label', 'else'),
               ('mov_ri', 'EAX', 2), ('label', 'end'), ('ret',)]
    _o, _n, _a, result = cfg(tmp_path, GUARD, swapped)
    assert result.layout_ok and result.deltas == []


def test_an_inverted_condition_with_the_same_successors_is_a_semantic_condition_change(tmp_path):
    """JZ -> JNZ while the blocks stay where they are inverts the program: the closed table needs the swap too."""
    inverted_only = [('cmp_ri', 'ECX', 1), ('jcc', 'NZ', 'then'), ('mov_ri', 'EAX', 2), ('jmp', 'end'), ('label', 'then'),
                     ('mov_ri', 'EAX', 3), ('label', 'end'), ('ret',)]
    _o, _n, _a, result = cfg(tmp_path, GUARD, inverted_only)
    assert not result.layout_ok and [d.cls for d, _ in result.deltas] == ['condition']


def test_a_swapped_branch_condition_that_is_not_an_inversion_is_a_condition_change(tmp_path):
    other = [('cmp_ri', 'ECX', 1), ('jcc', 'A', 'then'), *GUARD[2:]]
    _o, _n, _a, result = cfg(tmp_path, GUARD, other)
    assert not result.layout_ok and [d.cls for d, _ in result.deltas] == ['condition']


def test_a_non_inverse_condition_with_swapped_successors_is_a_condition_change(tmp_path):
    """JZ -> JL with the two successors swapped looks like an inversion but is none: the closed table is exact."""
    swapped_l = [('cmp_ri', 'ECX', 1), ('jcc', 'L', 'els'), ('mov_ri', 'EAX', 3), ('jmp', 'end'), ('label', 'els'),
                 ('mov_ri', 'EAX', 2), ('label', 'end'), ('ret',)]
    _o, _n, _a, result = cfg(tmp_path, GUARD, swapped_l)
    assert not result.layout_ok and 'condition' in [d.cls for d, _ in result.deltas]
    swapped_nz = [*swapped_l[:1], ('jcc', 'NZ', 'els'), *swapped_l[2:]]                # the real inversion of the layout
    assert cfg(tmp_path, GUARD, swapped_nz)[3].layout_ok


def test_a_jmp_replaced_by_a_fall_into_another_block_is_not_a_layout_change(tmp_path):
    """The jump went to `end`; the fall-through block is `then`: another path whatever the block bodies say."""
    shared = [('mov_ri', 'EAX', 3), ('cmp_ri', 'EDX', 5), ('jcc', 'Z', 'end'), ('mov_ri', 'EAX', 4), ('label', 'end'),
              ('ret',)]
    old = [('cmp_ri', 'ECX', 1), ('jcc', 'Z', 'then'), ('mov_ri', 'EAX', 2), ('jmp', 'end'), ('label', 'then'), *shared]
    new = [('cmp_ri', 'ECX', 1), ('jcc', 'Z', 'then'), ('mov_ri', 'EAX', 2), ('label', 'then'), *shared]
    _o, _n, _a, result = cfg(tmp_path, old, new)
    assert not result.layout_ok and 'cfg' in [d.cls for d, _ in result.deltas]


def test_an_added_or_removed_jmp_to_the_fall_through_block_is_a_layout_change(tmp_path):
    with_jump = [('cmp_ri', 'ECX', 1), ('jcc', 'Z', 'then'), ('mov_ri', 'EAX', 2), ('jmp', 'then'), ('label', 'then'),
                 ('mov_ri', 'EAX', 3), ('ret',)]
    without = [('cmp_ri', 'ECX', 1), ('jcc', 'Z', 'then'), ('mov_ri', 'EAX', 2), ('label', 'then'), ('mov_ri', 'EAX', 3),
               ('ret',)]
    _o, _n, _a, result = cfg(tmp_path, with_jump, without)
    assert result.layout_ok and result.deltas == []
    _o, _n, _a, back = cfg(tmp_path, without, with_jump)
    assert back.layout_ok and back.deltas == []


def test_a_jmp_to_somewhere_else_is_not_a_fall_through(tmp_path):
    jump_to_end = [('cmp_ri', 'ECX', 1), ('jcc', 'Z', 'then'), ('mov_ri', 'EAX', 2), ('jmp', 'end'), ('label', 'then'),
                   ('mov_ri', 'EAX', 3), ('label', 'end'), ('ret',)]
    fall = [('cmp_ri', 'ECX', 1), ('jcc', 'Z', 'then'), ('mov_ri', 'EAX', 2), ('label', 'then'), ('mov_ri', 'EAX', 3),
            ('label', 'end'), ('ret',)]
    _o, _n, _a, result = cfg(tmp_path, jump_to_end, fall)
    assert not result.layout_ok


def test_unpaired_blocks_are_added_and_removed_blocks_and_break_the_bijection(tmp_path):
    guarded = [('cmp_ri', 'ECX', 1), ('jcc', 'Z', 'done'), ('call', 'helper'), ('label', 'done'), ('ret',)]
    bare = [('cmp_ri', 'ECX', 1), ('ret',)]
    _o, _n, _a, result = cfg(tmp_path, guarded, bare)
    assert not result.layout_ok
    removed = [(d.cls, info.effect) for d, info in result.deltas if d.cls.startswith('block')]
    assert ('block-removed', True) in removed                    # the removed block held a call


def test_a_tail_jump_out_of_the_function_is_judged_as_a_function_target(tmp_path):
    old = [('cmp_ri', 'ECX', 1), ('jcc', 'Z', 'out'), ('ret',), ('label', 'out'), ('jmp', 0x1200)]
    same = cfg(tmp_path, old, old)
    assert same[3].cons.mapped == 2 and same[3].layout_ok
    moved = [*old[:4], ('jmp', 0x1300)]
    _o, _n, _a, conflict = cfg(tmp_path, old, moved)
    assert conflict.cons.conflict == 1 and [d.cls for d, _ in conflict.deltas] == ['callee']


def test_positional_equality_compares_successors_terminators_and_lengths(tmp_path):
    old, new, _t = views(tmp_path, GUARD, GUARD)
    assert layout.positional_cfg_equal(old, new)
    for other in ([('cmp_ri', 'ECX', 1), ('jcc', 'NZ', 'then'), *GUARD[2:]],
                  [*GUARD[:3], ('nop',), *GUARD[3:]] if False else [*GUARD[:6], ('add_ri', 'EAX', 1), *GUARD[6:]]):
        left, right, _t = views(tmp_path, GUARD, other)
        assert not layout.positional_cfg_equal(left, right)


def test_a_padding_nop_does_not_change_the_positional_cfg(tmp_path):
    padded = [*GUARD[:6], ('nop',), *GUARD[6:]]
    old, new, _t = views(tmp_path, GUARD, padded)
    assert layout.positional_cfg_equal(old, new)


# --- EH-EQ -----------------------------------------------------------------------------------------------------------------

def state(tmp_path, old_eh, new_eh, **kwargs):
    old, new, targets = views(tmp_path, GUARD, GUARD, old_eh=old_eh, new_eh=new_eh)
    return eh_state(old, new, targets, **kwargs)


def doc(**kwargs):
    return {0x1000: eh_json(**kwargs)}


def test_no_unwind_data_on_either_side_is_absent_and_one_sided_unwind_data_differs(tmp_path):
    assert state(tmp_path, None, None) == 'absent'
    assert state(tmp_path, OLD_EH, None) == 'differs' and state(tmp_path, None, OLD_EH) == 'differs'


def test_equal_unwind_data_is_equal(tmp_path):
    assert state(tmp_path, OLD_EH, OLD_EH) == 'equal'


@pytest.mark.parametrize('field,value', [('version', 2), ('flags', 8), ('prolog', 6), ('codes', '010401')],
                         ids=['version', 'flags', 'prolog', 'codes'])
def test_a_changed_unwind_header_or_code_differs(tmp_path, field, value):
    assert state(tmp_path, doc(handler=0x1200, scopes=[[1, 2, 1, 3]]),
                 doc(handler=0x1200, scopes=[[1, 2, 1, 3]], **{field: value})) == 'differs'


def test_the_scope_table_is_compared_record_by_record(tmp_path):
    base = doc(handler=0x1200, scopes=[[0x10, 0x20, 1, 0x30]])
    assert state(tmp_path, base, doc(handler=0x1200, scopes=[[0x10, 0x28, 1, 0x30]])) == 'differs'
    assert state(tmp_path, base, doc(handler=0x1200, scopes=[[0x10, 0x20, 1, 0x38]])) == 'differs'
    assert state(tmp_path, base, doc(handler=0x1200, scopes=[[0x10, 0x20, 1, 0x30], [0x40, 0x50, 0, 0x60]])) == 'differs'
    assert state(tmp_path, base, doc(handler=0x1200)) == 'differs'


def test_filters_are_plain_values_or_function_relative_or_mapped_targets(tmp_path):
    assert state(tmp_path, doc(handler=0x1200, scopes=[[0x10, 0x20, 0, 0x30]]),
                 doc(handler=0x1200, scopes=[[0x10, 0x20, 1, 0x30]])) == 'differs'                # __finally -> catch-all
    inside = doc(handler=0x1200, scopes=[[0x10, 0x20, 0x1008, 0x30]])
    assert state(tmp_path, inside, inside) == 'equal'                                               # same offset in f
    assert state(tmp_path, inside, doc(handler=0x1200, scopes=[[0x10, 0x20, 0x100c, 0x30]])) == 'differs'


def test_the_handler_must_be_the_counterpart(tmp_path):
    assert state(tmp_path, doc(handler=0x1200), doc(handler=0x1300)) == 'differs'               # maps elsewhere
    old, new, targets = views(tmp_path, GUARD, GUARD, old_eh=doc(handler=0x1700), new_eh=doc(handler=0x1700), pairs=())
    assert eh_state(old, new, targets) == 'unavailable'                                          # no evidence either way
    assert state(tmp_path, doc(handler=0x1200), doc()) == 'differs'


def test_a_truncated_signature_or_unreadable_tables_are_unavailable_never_equal(tmp_path):
    truncated = {0x1000: '{"trunc":true,"v":1}'}
    assert state(tmp_path, truncated, truncated) == 'unavailable'
    assert state(tmp_path, None, None, unreadable=True) == 'unavailable'
    assert state(tmp_path, {0x1000: 'not json'}, OLD_EH) == 'unavailable'


def test_unreadable_pdata_in_the_manifest_makes_the_channel_unavailable(tmp_path):
    from unified_facts_builder import NEW_SHA, OLD_SHA, build_reader

    from patchtrace.unified.facts.irchannels import IrFacts, IrSides
    fns = image([('ret',)])
    old = build_reader(tmp_path, 'o', fns, sha=OLD_SHA, warnings=('pdata-unreadable',))
    new = build_reader(tmp_path, 'n', fns, sha=NEW_SHA)
    pair = IrFacts(IrSides(old, new), [(0x1000, 0x1000)]).analyze(0x1000, 0x1000)
    assert pair.eh == 'unavailable'
    assert run_facts(tmp_path, fns, fns).facts('f').eh == 'absent'
