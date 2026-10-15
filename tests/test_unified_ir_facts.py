"""SPEC-31 S3: IR channels C0-C5, the target-consistency classifier, DATA-MAP/1 in use, the proofs UNCH/1, COS-ADDR/1
and COS-LAYOUT/1 with EH-EQ, and MAT-ANCHOR (05 s2.1-s2.7). Hand-assembled x86-64 through the real ingest; the
functions of every image are matched by name with tier-A rows. Synthetic: nothing here is live Ghidra evidence."""
from __future__ import annotations

import pytest
from unified_facts_builder import eh_json, function, run_facts

SYM = {'g_a': 0x3000, 'g_b': 0x3040, 'g_c': 0x3080, 'helper': 0x1200, 'other': 0x1300, 'report': 0x1500}


def image(f_items, *, shift=0, shift_c=None, f_rva=0x1000, with_report=False, f_kwargs=None, users=True):
    """`f` plus a callee, two spare callees and four users of two globals (they vote for the data mapping)."""
    sym = {**SYM, **{name: SYM[name] + shift for name in ('g_a', 'g_b')}, 'g_c': SYM['g_c'] + (shift if shift_c is None else shift_c)}
    out = [function(f_rva, f_items, name='f', sym=sym, **(f_kwargs or {})),
           function(0x1200, [('mov_ri', 'EAX', 1), ('ret',)], name='helper', sym=sym),
           function(0x1300, [('mov_ri', 'EAX', 2), ('ret',)], name='other', sym=sym)]
    if with_report:
        out.append(function(0x1500, [('mov_ri', 'EAX', 3), ('ret',)], name='report', sym=sym))
    if users:
        out += [function(0x1400, [('load_g', 'EAX', 'g_a'), ('ret',)], name='u1', sym=sym),
                function(0x1440, [('load_g', 'ECX', 'g_a'), ('ret',)], name='u2', sym=sym),
                function(0x1480, [('load_g', 'EAX', 'g_b'), ('ret',)], name='u3', sym=sym),
                function(0x14c0, [('load_g', 'EDX', 'g_b'), ('ret',)], name='u4', sym=sym)]
    return sorted(out, key=lambda fn: fn['rva'])


PLAIN = [('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'), ('mov_ri', 'EAX', 1), ('add_ri', 'EAX', 3), ('label', 'done'),
         ('mov_rr', 'EDX', 'EAX'), ('ret',)]
USES_GLOBAL = [('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'), ('load_g', 'EAX', 'g_a'), ('call', 'helper'),
               ('label', 'done'), ('ret',)]


def run(tmp_path, old_items, new_items, *, shift=0, new_rva=0x1000, old_kwargs=None, new_kwargs=None, **kwargs):
    return run_facts(tmp_path, image(old_items, f_kwargs=old_kwargs), image(new_items, shift=shift, f_rva=new_rva,
                                                                            with_report=kwargs.pop('with_report', False),
                                                                            f_kwargs=new_kwargs), **kwargs)


def classes(run_, name='f'):
    return {d.cls for d in run_.facts(name).deltas}


# --- unchanged / cosmetic ------------------------------------------------------------------------------------------------

def test_identical_function_at_a_moved_rva_is_unchanged_when_nothing_it_references_moved(tmp_path):
    r = run(tmp_path, PLAIN, PLAIN, new_rva=0x1100)
    assert r.verdict('f') == ('unchanged', 'UNCH/1')
    facts = r.facts('f')
    assert dict(facts.channels)['C0'] == 'equal' and facts.targets[1:] == (0, 0) and facts.eh == 'absent'


def test_moved_global_is_cosmetic_via_other_function_votes(tmp_path):
    r = run(tmp_path, USES_GLOBAL, USES_GLOBAL, shift=0x40)
    assert r.verdict('f') == ('cosmetic', 'COS-ADDR/1')
    facts = r.facts('f')
    assert dict(facts.channels)['C0'] == 'differs' and dict(facts.channels)['C1'] == 'equal'
    assert facts.targets[1:] == (0, 0) and facts.deltas == ()
    assert [r.verdict(name)[0] for name in ('u1', 'u2', 'u3', 'u4')] == ['cosmetic'] * 4


def test_cos_addr_requires_tier_a_targets(tmp_path):
    """05 s2.7: only a `matched` row with a tier A or M support maps a target. The callee moved by 0x40; its row is
    tier A (the caller is cosmetic) or tier B (the row maps nothing: no address proof, the row is `review`)."""
    sym_old, sym_new = {'helper': 0x1200}, {'helper': 0x1240}
    body, caller = [('mov_ri', 'EAX', 1), ('ret',)], [('mov_ri', 'EAX', 1), ('call', 'helper'), ('ret',)]
    old = [function(0x1000, caller, name='f', sym=sym_old), function(0x1200, body, name='helper', sym=sym_old)]
    new = [function(0x1000, caller, name='f', sym=sym_new), function(0x1240, body, name='helper', sym=sym_new)]
    assert run_facts(tmp_path, old, new).verdict('f') == ('cosmetic', 'COS-ADDR/1')
    facts = run_facts(tmp_path, old, new, tentative=('helper',)).facts('f')
    assert dict(facts.channels)['C1'] == 'equal' and facts.targets[1] == 1      # the bytes still say "same shape"
    assert facts.verdict == 'review' and facts.proof is None


def test_unchanged_requires_target_consistency(tmp_path):
    """Equal bytes at a moved RVA re-target every relative operand (R-03): the call now reaches `other`."""
    old = [('mov_ri', 'EAX', 1), ('call', 'helper'), ('ret',)]
    new = [('mov_ri', 'EAX', 1), ('call', 'other'), ('ret',)]
    r = run(tmp_path, old, new, new_rva=0x1100)
    facts = r.facts('f')
    assert dict(facts.channels)['C0'] == 'equal'                # the bytes ARE equal ...
    assert facts.verdict != 'unchanged' and facts.proof is None  # ... and still no proof
    assert facts.targets[2] == 1 and 'callee' in classes(r)


def test_a_callee_swapped_to_another_matched_function_is_material_with_c4_as_the_second_channel(tmp_path):
    old = [('mov_ri', 'EAX', 1), ('call', 'helper'), ('ret',)]
    new = [('mov_ri', 'EAX', 1), ('call', 'other'), ('ret',)]
    facts = run(tmp_path, old, new).facts('f')
    assert (facts.verdict, facts.second_channel) == ('material', 'C4')
    assert dict(facts.channels)['C4'] == 'differs'
    assert [(d.cls, d.channel) for d in facts.deltas] == [('callee', 'C2')]


def test_swapped_global_same_shape_is_not_cosmetic(tmp_path):
    """R-01: g_a -> g_b with the same instruction shape (equal masked bytes) conflicts with the votes of the others."""
    old = [('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'), ('load_g', 'EAX', 'g_a'), ('label', 'done'), ('ret',)]
    new = [('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'), ('load_g', 'EAX', 'g_b'), ('label', 'done'), ('ret',)]
    r = run(tmp_path, old, new)
    facts = r.facts('f')
    assert dict(facts.channels)['C1'] == 'equal'                # masked bytes are equal: the old draft's blind spot
    assert facts.verdict == 'review' and facts.proof is None and facts.targets[2] == 1
    assert [d.cls for d in facts.deltas] == ['data-ref']
    assert r.verdict('u1') == ('unchanged', 'UNCH/1')           # the innocent users keep their mapping


def test_innocent_functions_keep_mapping_beside_a_dissenter(tmp_path):
    old = [('load_g', 'EAX', 'g_a'), ('ret',)]
    new = [('load_g', 'EAX', 'g_b'), ('ret',)]
    r = run(tmp_path, old, new, shift=0x40)
    assert r.facts('f').targets[2] == 1
    assert {r.verdict(name)[0] for name in ('u1', 'u2', 'u3', 'u4')} == {'cosmetic'}


def test_unmapped_target_blocks_cosmetic(tmp_path):
    """No other function references the global and there is no region evidence: `unmapped`, never a proof."""
    old = [('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'), ('load_g', 'EAX', 'g_c'), ('label', 'done'), ('ret',)]
    r = run(tmp_path, old, old, shift=0x40, sections=())
    facts = r.facts('f')
    assert facts.verdict == 'review' and facts.proof is None and facts.targets[1] == 1
    assert 'address-only' in r['f'].classes


def test_single_use_global_needs_region_shift(tmp_path):
    old = [('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'), ('load_g', 'EAX', 'g_c'), ('label', 'done'), ('ret',)]
    assert run(tmp_path, old, old, shift=0x40).verdict('f') == ('cosmetic', 'COS-ADDR/1')   # g_b below it moved too
    odd = run_facts(tmp_path, image(old), image(old, shift=0x40, shift_c=0x80))               # but g_c moved by 0x80
    assert odd.facts('f').verdict == 'review' and odd.facts('f').targets[1] == 1


def test_function_never_votes_for_itself(tmp_path):
    only = [('load_g', 'EAX', 'g_c'), ('ret',)]
    r = run_facts(tmp_path, image(only, users=False), image(only, shift=0x40, users=False))
    assert r.facts('f').targets[1] == 1 and r.facts('f').verdict == 'review'      # one voter, however sure it is


# --- the constant, the condition and the structure ----------------------------------------------------------------------

def test_constant_only_patch_is_review_ranked_first_not_material(tmp_path):
    edited = [('cmp_ri', 'ECX', 7), *PLAIN[1:]]
    facts = run(tmp_path, PLAIN, edited).facts('f')
    assert facts.verdict == 'review' and facts.second_channel is None
    assert [(d.cls, d.channel, d.old, d.new) for d in facts.deltas] == [
        ('constant', 'C2', 'CMP ECX,0x6', 'CMP ECX,0x7')]
    assert dict(facts.channels)['C5'] == 'differs'


def test_small_constant_bound_change_detected(tmp_path):
    """F14: a bound fix uses a small constant; facts keep every constant (only the matching keys are rarity filtered)."""
    assert run(tmp_path, [('cmp_ri', 'EDX', 0x40), ('ret',)], [('cmp_ri', 'EDX', 0x41), ('ret',)]
               ).facts('f').deltas[0].cls == 'constant'


@pytest.mark.parametrize('old_cc,new_cc', [('A', 'NC'), ('L', 'LE'), ('L', 'C')], ids=['A-NC', 'L-LE', 'L-C'])
def test_a_changed_branch_condition_is_a_semantic_condition_delta(tmp_path, old_cc, new_cc):
    """Bound (<, <=) and signedness (jl, jb) mutants: never cosmetic."""
    old = [('cmp_ri', 'ECX', 6), ('jcc', old_cc, 'done'), ('mov_ri', 'EAX', 1), ('label', 'done'), ('ret',)]
    new = [('cmp_ri', 'ECX', 6), ('jcc', new_cc, 'done'), ('mov_ri', 'EAX', 1), ('label', 'done'), ('ret',)]
    r = run(tmp_path, old, new)
    assert r.facts('f').verdict == 'review' and 'condition' in classes(r)


def test_a_changed_setcc_is_a_comparison_delta(tmp_path):
    old = [('cmp_ri', 'ECX', 6), ('setcc', 'L', 'AL'), ('ret',)]
    new = [('cmp_ri', 'ECX', 6), ('setcc', 'LE', 'AL'), ('ret',)]
    facts = run(tmp_path, old, new).facts('f')
    assert facts.verdict == 'review' and [d.cls for d in facts.deltas] == ['comparison']


def test_block_reorder_is_cos_layout(tmp_path):
    old = [('cmp_ri', 'ECX', 1), ('jcc', 'Z', 'then'), ('mov_ri', 'EAX', 2), ('jmp', 'end'), ('label', 'then'),
           ('mov_ri', 'EAX', 3), ('label', 'end'), ('ret',)]
    new = [('cmp_ri', 'ECX', 1), ('jcc', 'NZ', 'else'), ('mov_ri', 'EAX', 3), ('jmp', 'end'), ('label', 'else'),
           ('mov_ri', 'EAX', 2), ('label', 'end'), ('ret',)]
    facts = run(tmp_path, old, new).facts('f')
    assert (facts.verdict, facts.proof) == ('cosmetic', 'COS-LAYOUT/1') and facts.deltas == ()


def test_then_else_swap_not_cosmetic(tmp_path):
    """R-04: the polarity is kept (JZ stays JZ) but the bodies swapped places: counts, MD and multisets all agree."""
    old = [('cmp_ri', 'ECX', 1), ('jcc', 'Z', 'then'), ('mov_ri', 'EAX', 2), ('jmp', 'end'), ('label', 'then'),
           ('mov_ri', 'EAX', 3), ('label', 'end'), ('ret',)]
    new = [('cmp_ri', 'ECX', 1), ('jcc', 'Z', 'then'), ('mov_ri', 'EAX', 3), ('jmp', 'end'), ('label', 'then'),
           ('mov_ri', 'EAX', 2), ('label', 'end'), ('ret',)]
    r = run(tmp_path, old, new)
    facts = r.facts('f')
    assert facts.proof is None and facts.verdict == 'review'
    assert dict(facts.channels)['C3'] == 'equal'                # the equal CFG filter is NOT a proof
    assert 'cfg' in classes(r)


def test_unmatched_callee_is_material_candidate(tmp_path):
    """F6: the new function calls a function that exists only in the newer image."""
    new = [*USES_GLOBAL[:-1], ('call', 'report'), ('ret',)]
    facts = run(tmp_path, USES_GLOBAL, new, with_report=True).facts('f')
    assert (facts.verdict, facts.second_channel) == ('material', 'C4')
    assert [d.cls for d in facts.deltas if d.cls == 'call-added'] == ['call-added']


def test_an_added_guard_block_with_a_call_is_material_anchored_by_the_cfg_counts(tmp_path):
    guarded = [('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'), ('cmp_ri', 'EDX', 9), ('jcc', 'NZ', 'ok'),
               ('call', 'report'), ('label', 'ok'), ('mov_ri', 'EAX', 1), ('label', 'done'), ('ret',)]
    plain = [('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'), ('mov_ri', 'EAX', 1), ('label', 'done'), ('ret',)]
    facts = run(tmp_path, plain, guarded, with_report=True).facts('f')
    assert facts.verdict == 'material' and facts.second_channel in ('C3', 'C4')
    assert {'block-added', 'call-added'} <= {d.cls for d in facts.deltas}


def test_frame_only_change_is_review_not_material(tmp_path):
    old = [('sub_rsp', 0x28), ('store_s', 0x20, 'EAX'), ('add_rsp', 0x28), ('ret',)]
    new = [('sub_rsp', 0x48), ('store_s', 0x40, 'EAX'), ('add_rsp', 0x48), ('ret',)]
    facts = run(tmp_path, old, new).facts('f')
    assert facts.verdict == 'review' and {d.cls for d in facts.deltas} == {'frame'}


def test_a_register_rename_is_review(tmp_path):
    facts = run(tmp_path, [('mov_rr', 'EAX', 'ECX'), ('ret',)], [('mov_rr', 'EAX', 'EDX'), ('ret',)]).facts('f')
    assert facts.verdict == 'review' and [d.cls for d in facts.deltas] == ['register-only']


def test_index_register_swap_inside_an_address_operand_is_review(tmp_path):
    old = [('load_tab', 'EAX', 'RDX', 'RAX', 'g_a'), ('ret',)]
    new = [('load_tab', 'EAX', 'RDX', 'RCX', 'g_a'), ('ret',)]
    facts = run(tmp_path, old, new).facts('f')
    assert facts.verdict == 'review' and 'register-only' in {d.cls for d in facts.deltas}


def test_struct_offset_change_is_semantic(tmp_path):
    facts = run(tmp_path, [('load_m', 'EAX', 'RBX', 0x10), ('ret',)], [('load_m', 'EAX', 'RBX', 0x14), ('ret',)]).facts('f')
    assert facts.verdict == 'review' and [d.cls for d in facts.deltas] == ['struct-offset']


# --- unwind data (EH-EQ) -------------------------------------------------------------------------------------------------

def test_scope_table_change_blocks_unchanged(tmp_path):
    old_eh = {0x1000: eh_json(handler=0x1200, scopes=[[0x10, 0x20, 1, 0x30]])}
    same = run(tmp_path, PLAIN, PLAIN, old_eh=old_eh, new_eh=old_eh)
    assert same.verdict('f') == ('unchanged', 'UNCH/1') and same.facts('f').eh == 'equal'
    added = {0x1000: eh_json(handler=0x1200, scopes=[[0x10, 0x20, 1, 0x30], [0x40, 0x50, 1, 0x60]])}
    changed = run(tmp_path, PLAIN, PLAIN, old_eh=old_eh, new_eh=added)
    facts = changed.facts('f')
    assert dict(facts.channels)['C0'] == 'equal'                # bytes and masked bytes cannot see a scope table
    assert facts.verdict == 'review' and facts.proof is None and facts.eh == 'differs'
    assert 'eh' in changed['f'].classes
