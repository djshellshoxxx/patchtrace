"""SPEC-31 S3 DATA-MAP/1 and function target mapping (05 s2.7): votes with leave-one-out, consensus, region shift,
strings, thunks and imports, identical artifacts. Hand-assembled images through the real ingest."""
from __future__ import annotations

import pytest
from unified_facts_builder import DATA_SECTIONS, NEW_SHA, OLD_SHA, build_reader, function

from patchtrace.unified.facts.datamap import CONFLICT, MAPPED, STRING, UNMAPPED, TargetMap
from patchtrace.unified.limits import DEFAULT_LIMITS, UnifiedLimits

RET = ('ret',)


def users(prefix, data, reg='EAX', *, count, base):
    """`count` tiny functions that each load the global `data` (they vote for its mapping)."""
    return [(f'{prefix}{i}', base + 0x40 * i, [('load_g', reg, data), RET]) for i in range(count)]


def image(tmp_path, label, specs, sym, sha):
    fns = [function(rva, items, name=name, sym=sym) for name, rva, items in specs]
    return build_reader(tmp_path, label, sorted(fns, key=lambda f: f['rva']), sha=sha)


def targets_of(tmp_path, old_specs, new_specs, old_sym, new_sym, *, by_name=True, sections=DATA_SECTIONS, **kwargs):
    old = image(tmp_path, 'old', old_specs, old_sym, OLD_SHA)
    new = image(tmp_path, 'new', new_specs, new_sym, NEW_SHA)
    names_new = {name: rva for name, rva, _ in new_specs}
    pairs = [(rva, names_new[name]) for name, rva, _ in old_specs if name in names_new] if by_name else []
    return TargetMap(old, new, pairs, older_sections=sections, newer_sections=sections, **kwargs)


def test_a_matched_row_maps_its_pair_and_conflicts_with_any_other_partner(tmp_path):
    specs = [('a', 0x1000, [('mov_ri', 'EAX', 1), RET]), ('b', 0x1100, [('mov_ri', 'EAX', 2), RET]),
             ('c', 0x1200, [('mov_ri', 'EAX', 3), RET])]
    tm = targets_of(tmp_path, specs, specs, {}, {})
    assert tm.function_state(0x1000, 0x1000) == MAPPED
    assert tm.function_state(0x1000, 0x1100) == CONFLICT and tm.function_state(0x1100, 0x1000) == CONFLICT
    only = TargetMap(tm.older, tm.newer, [(0x1000, 0x1000)])
    assert only.function_state(0x1100, 0x1200) == UNMAPPED          # neither is in a matched row: no evidence


def test_tentative_rows_never_map_anything(tmp_path):
    old = [('a', 0x1000, [('mov_ri', 'EAX', 1), RET])]
    new = [('a', 0x1000, [('mov_ri', 'EAX', 2), RET])]
    tm = targets_of(tmp_path, old, new, {}, {}, by_name=False)
    assert tm.function_state(0x1000, 0x1000) == UNMAPPED         # different bodies, no matched row: no evidence
    assert targets_of(tmp_path, old, new, {}, {}).function_state(0x1000, 0x1000) == MAPPED


def test_two_imports_with_one_key_map_and_different_keys_conflict(tmp_path):
    def stub(rva, name, key):
        return function(rva, [('jmp_iat', 0x2000, key)], name=name, kind='thunk',
                        imp={'dll': 'KERNEL32.DLL', 'name': name, 'ordinal': None})
    old = build_reader(tmp_path, 'old', [stub(0x1000, 'Sleep', 'kernel32.dll!Sleep'),
                                         stub(0x1100, 'GetTickCount', 'kernel32.dll!GetTickCount')], sha=OLD_SHA)
    new = build_reader(tmp_path, 'new', [stub(0x1000, 'Sleep', 'kernel32.dll!Sleep'),
                                         stub(0x1100, 'GetTickCount', 'kernel32.dll!GetTickCount')], sha=NEW_SHA)
    tm = TargetMap(old, new, [])
    assert tm.function_state(0x1000, 0x1000) == MAPPED
    assert tm.function_state(0x1000, 0x1100) == CONFLICT


def test_a_pure_jump_thunk_stands_for_its_target(tmp_path):
    real = [('mov_ri', 'EAX', 1), ('mov_ri', 'ECX', 2), RET]
    old = [function(0x1000, real, name='target'),
           function(0x1100, [('jmp', 'target')], name='thunk', kind='thunk', thunk_target=0x1000, sym={'target': 0x1000})]
    new = [function(0x1000, real, name='target')]
    tm = TargetMap(build_reader(tmp_path, 'old', old, sha=OLD_SHA), build_reader(tmp_path, 'new', new, sha=NEW_SHA),
                   [(0x1000, 0x1000)])
    assert tm.function_state(0x1100, 0x1000) == MAPPED               # a call through the thunk reaches the same target


def test_equal_bodies_at_the_same_rva_map_without_a_row_but_equal_bodies_elsewhere_need_other_callers(tmp_path):
    body = [('xor_rr', 'EAX', 'EAX'), RET]
    old_specs = [('tiny', 0x1000, body), ('mover', 0x1100, body)]
    new_specs = [('tiny', 0x1000, body), ('mover', 0x1200, body)]
    tm = targets_of(tmp_path, old_specs, new_specs, {}, {}, by_name=False)
    assert tm.function_state(0x1000, 0x1000) == MAPPED               # rule (iv): equal h0, same RVA
    assert tm.function_state(0x1100, 0x1200) == UNMAPPED             # moved: nobody else calls it


def test_a_moved_equal_body_is_mapped_by_the_calls_of_other_matched_pairs(tmp_path):
    body = [('xor_rr', 'EAX', 'EAX'), RET]
    callers_old = [(f'c{i}', 0x1400 + 0x40 * i, [('call', 'tiny'), RET]) for i in range(3)]
    callers_new = [(f'c{i}', 0x1400 + 0x40 * i, [('call', 'tiny'), RET]) for i in range(3)]
    old_specs = [('tiny', 0x1100, body), *callers_old]
    new_specs = [('tiny', 0x1200, body), *callers_new]
    tm = targets_of(tmp_path, old_specs, new_specs, {'tiny': 0x1100}, {'tiny': 0x1200}, by_name=False)
    tm2 = TargetMap(tm.older, tm.newer, [(0x1400 + 0x40 * i, 0x1400 + 0x40 * i) for i in range(3)])
    assert tm2.function_state(0x1100, 0x1200, voter=(0x1400, 0x1400)) == MAPPED   # two other callers still vote for it
    assert tm2.function_state(0x1100, 0x1300) == UNMAPPED


def test_votes_build_a_consensus_and_the_dissenter_conflicts(tmp_path):
    old_specs = users('u', 'g_a', count=3, base=0x1400) + [('r', 0x1000, [('load_g', 'EAX', 'g_a'), RET])]
    new_specs = users('u', 'g_a', count=3, base=0x1400) + [('r', 0x1000, [('load_g', 'EAX', 'g_b'), RET])]
    tm = targets_of(tmp_path, old_specs, new_specs, {'g_a': 0x3000, 'g_b': 0x3040}, {'g_a': 0x3100, 'g_b': 0x3040})
    voter = (0x1000, 0x1000)
    assert tm.data_state(0x3000, 0x3100, (0x1400, 0x1400)) == MAPPED  # the innocent users: g_a moved to 0x3100
    assert tm.data_state(0x3000, 0x3040, voter) == CONFLICT            # r reads another datum: g_a has a consensus
    assert tm.data_state(0x3040, 0x3100, voter) == CONFLICT            # the new datum belongs to g_a


def test_a_function_never_proves_its_own_reference(tmp_path):
    specs = [('r', 0x1000, [('load_g', 'EAX', 'g_a'), RET])]
    shifted = {'g_a': 0x3040}
    tm = targets_of(tmp_path, specs, specs, {'g_a': 0x3000}, shifted)
    assert tm.data_state(0x3000, 0x3040, (0x1000, 0x1000)) == UNMAPPED       # one voter is no consensus ...
    two = [('r', 0x1000, [('load_g', 'EAX', 'g_a'), RET]), ('s', 0x1100, [('load_g', 'ECX', 'g_a'), RET])]
    tm2 = targets_of(tmp_path, two, two, {'g_a': 0x3000}, shifted)
    assert tm2.data_state(0x3000, 0x3040, (0x1000, 0x1000)) == MAPPED        # ... two are, and each has the other
    only_self = TargetMap(tm2.older, tm2.newer, [(0x1000, 0x1000)])
    assert only_self.data_state(0x3000, 0x3040, (0x1000, 0x1000)) == UNMAPPED


def test_two_way_tie_is_unmapped(tmp_path):
    old_specs = users('u', 'g_a', count=4, base=0x1400)
    new_specs = [(name, rva, [('load_g', 'EAX', 'g_x' if i < 2 else 'g_y'), RET])
                 for i, (name, rva, _items) in enumerate(old_specs)]
    tm = targets_of(tmp_path, old_specs, new_specs, {'g_a': 0x3000}, {'g_x': 0x3040, 'g_y': 0x3080})
    assert tm.data_state(0x3000, 0x3040, (0x1000, 0x1000)) == UNMAPPED


def test_a_swap_to_an_existing_global_is_not_mapped_by_the_region_shift(tmp_path):
    old_specs = users('a', 'g_a', count=2, base=0x1400) + users('b', 'g_b', count=2, base=0x1500)
    sym = {'g_a': 0x3000, 'g_b': 0x3040}
    tm = targets_of(tmp_path, old_specs, old_specs, sym, sym)
    assert tm.data_state(0x3000, 0x3040, (0x1000, 0x1000)) == CONFLICT       # g_b has its own consensus


def test_single_use_global_needs_region_shift(tmp_path):
    shared = users('a', 'g_a', count=2, base=0x1400) + users('b', 'g_b', count=2, base=0x1500)
    single = [('s', 0x1000, [('load_g', 'EAX', 'g_s'), RET])]
    old_sym = {'g_a': 0x3000, 'g_b': 0x3040, 'g_s': 0x3080}
    shifted = {'g_a': 0x3040, 'g_b': 0x3080, 'g_s': 0x30c0}                  # everything moved by 0x40
    tm = targets_of(tmp_path, shared + single, shared + single, old_sym, shifted)
    assert tm.data_state(0x3080, 0x30c0, (0x1000, 0x1000)) == MAPPED          # the neighbour below shifted by 0x40
    assert tm.data_state(0x3080, 0x3100, (0x1000, 0x1000)) == UNMAPPED        # a different displacement
    assert tm.data_state(0x3080, 0x3000, (0x1000, 0x1000)) == UNMAPPED        # ... or one that breaks the order


def test_region_shift_needs_neighbours_in_the_same_section(tmp_path):
    shared = users('a', 'g_a', count=2, base=0x1400)
    single = [('s', 0x1000, [('load_g', 'EAX', 'g_s'), RET])]
    old_sym, new_sym = {'g_a': 0x3000, 'g_s': 0x2800}, {'g_a': 0x3040, 'g_s': 0x2840}   # g_s sits in .rdata, g_a in .data
    tm = targets_of(tmp_path, shared + single, shared + single, old_sym, new_sym)
    assert tm.data_state(0x2800, 0x2840, (0x1000, 0x1000)) == UNMAPPED
    assert targets_of(tmp_path, shared + single, shared + single, old_sym, new_sym, sections=()
                      ).data_state(0x3000, 0x3040, (0x1000, 0x1000)) == MAPPED     # votes alone still map the shared one


def test_defined_strings_map_by_content_when_unique_and_differ_as_a_string_delta(tmp_path):
    old_specs = [('p', 0x1000, [('lea_g', 'RDX', 'str_a', 'hello world'), RET]),
                 ('q', 0x1100, [('lea_g', 'RDX', 'str_b', 'other text!'), RET])]
    new_specs = [('p', 0x1000, [('lea_g', 'RDX', 'str_a', 'hello world'), RET]),
                 ('q', 0x1100, [('lea_g', 'RDX', 'str_b', 'other text?'), RET])]
    tm = targets_of(tmp_path, old_specs, new_specs, {'str_a': 0x2000, 'str_b': 0x2040}, {'str_a': 0x2100, 'str_b': 0x2140})
    from patchtrace.unified.facts.datamap import string_sha
    from patchtrace.unified.facts.fnview import load_view
    view = lambda reader, rva: load_view(reader, 'older', reader.functions.rva_to_fid[rva])  # noqa: E731
    sha = lambda reader, rva: string_sha(view(reader, rva), 0)  # noqa: E731
    assert tm.data_state(0x2000, 0x2100, None, (sha(tm.older, 0x1000), sha(tm.newer, 0x1000))) == MAPPED
    assert tm.data_state(0x2040, 0x2140, None, (sha(tm.older, 0x1100), sha(tm.newer, 0x1100))) == STRING


def test_duplicate_strings_are_not_unique_and_fall_back_to_the_votes(tmp_path):
    old_specs = [('p', 0x1000, [('lea_g', 'RDX', 'str_a', 'same text'), RET]),
                 ('q', 0x1100, [('lea_g', 'RDX', 'str_b', 'same text'), RET])]
    tm = targets_of(tmp_path, old_specs, old_specs, {'str_a': 0x2000, 'str_b': 0x2040}, {'str_a': 0x2000, 'str_b': 0x2040})
    from patchtrace.unified.facts.datamap import string_sha
    from patchtrace.unified.facts.fnview import load_view
    sha = string_sha(load_view(tm.older, 'older', 0), 0)
    assert tm.data_state(0x2000, 0x2000, (0x1000, 0x1000), (sha, sha)) == UNMAPPED   # two addresses carry that content


def test_the_header_region_does_not_shift(tmp_path):
    specs = [('p', 0x1000, [('mov_ri', 'EAX', 1), RET])]
    tm = targets_of(tmp_path, specs, specs, {}, {}, sections=((0x1000, 0x2000),))
    assert tm.data_state(0x3c, 0x3c, None) == MAPPED and tm.data_state(0x3c, 0x40, None) == UNMAPPED


def test_identical_artifacts_map_every_address_to_itself(tmp_path):
    specs = [('p', 0x1000, [('mov_ri', 'EAX', 1), RET])]
    tm = targets_of(tmp_path, specs, specs, {}, {}, identical=True)
    assert tm.data_state(0x3000, 0x3000) == MAPPED and tm.data_state(0x3000, 0x3040) == CONFLICT
    assert tm.function_state(0x1000, 0x1000) == MAPPED and tm.function_state(0x1000, 0x1100) == CONFLICT


def test_data_tokens_are_shared_by_both_sides_of_a_mapped_pair(tmp_path):
    old_specs = users('u', 'g_a', count=2, base=0x1400)
    tm = targets_of(tmp_path, old_specs, old_specs, {'g_a': 0x3000}, {'g_a': 0x3040})
    assert tm.data_token('older', 0x3000) == tm.data_token('newer', 0x3040) and tm.data_token('older', 0x3000)
    assert tm.data_token('older', 0x3100) is None


def test_the_vote_table_is_capped_and_says_so(tmp_path):
    old_specs = users('u', 'g_a', count=2, base=0x1400) + users('v', 'g_b', count=2, base=0x1500)
    sym = {'g_a': 0x3000, 'g_b': 0x3040}
    tiny = UnifiedLimits(l40_data_pairs=1)
    tm = targets_of(tmp_path, old_specs, old_specs, sym, sym, limits=tiny)
    assert 'datamap-cap' in tm.limits_hit


def test_results_do_not_depend_on_the_order_of_the_pairs(tmp_path):
    old_specs = users('u', 'g_a', count=3, base=0x1400) + users('v', 'g_b', count=3, base=0x1500)
    sym = {'g_a': 0x3000, 'g_b': 0x3040}
    shifted = {'g_a': 0x3100, 'g_b': 0x3140}
    base = targets_of(tmp_path, old_specs, old_specs, sym, shifted)
    pairs = [(rva, rva) for _n, rva, _i in old_specs]
    reordered = TargetMap(base.older, base.newer, list(reversed(pairs)), older_sections=DATA_SECTIONS,
                          newer_sections=DATA_SECTIONS)
    for t, u in ((0x3000, 0x3100), (0x3040, 0x3140), (0x3000, 0x3140)):
        assert base.data_state(t, u) == reordered.data_state(t, u)


@pytest.mark.parametrize('limit', [UnifiedLimits().l40_votes_kept], ids=['default-cap'])
def test_the_default_vote_cap_is_the_spec_number(limit):
    assert limit == DEFAULT_LIMITS.l40_votes_kept == 8
