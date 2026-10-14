"""Groups and leftovers (SPEC-31 04 s7, 05 s3 F11): duplicates, ICF alias groups, inline/outline hints, reasons.
SYNTHETIC IR only."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from unified_ir_builder import SyntheticIr, assert_partition, make_body, tag_pairs  # noqa: E402

from patchtrace.unified.ladder.engine import run_ladder  # noqa: E402


def blk(seed: int, n: int = 6):
    return make_body(seed, n)


def group_tags(corr, older, newer):
    return [(g.kind, tuple(older.tag_of(f) for f in g.older_fids), tuple(newer.tag_of(f) for f in g.newer_fids),
             g.reason) for g in corr.groups]


placed = assert_partition


def test_duplicates_are_one_group_never_cross_multiplied():
    older, newer = SyntheticIr(), SyntheticIr()
    for tag in ('d1', 'd2'):
        older.add(tag, seed=900)
    for tag in ('e1', 'e2', 'e3'):
        newer.add(tag, seed=900)
    older.add('u', seed=1)
    newer.add('u', seed=1)
    corr = run_ladder(older, newer)
    assert tag_pairs(corr, older, newer) == {('u', 'u')}
    assert group_tags(corr, older, newer) == [('duplicate', ('d1', 'd2'), ('e1', 'e2', 'e3'), 'h0')]
    placed(corr, 3, 4)


def test_duplicate_group_reason_h1_when_only_addresses_differ():
    older, newer = SyntheticIr(), SyntheticIr()
    body_a = make_body(901, 12)
    shifted = tuple(i._replace(addr=(i.addr or 0) + 64) if i.addr is not None else i for i in body_a)
    older.add('d1', body=body_a)
    older.add('d2', body=body_a)
    newer.add('e1', body=shifted)
    newer.add('e2', body=shifted)
    corr = run_ladder(older, newer)
    assert [(k, r) for k, _, _, r in group_tags(corr, older, newer)] == [('duplicate', 'h1')]


def test_icf_alias_group_not_added_removed():
    """Old: one folded function with two names. New: the fold was undone and one half changed, so the folded
    function has a unique byte-identical partner that must NOT be paired 1:1 (the other half would read as added)."""
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('folded', seed=7, name='Alpha', aliases=('Beta',))
    newer.add('alpha', seed=7, name='Alpha')
    newer.add('beta', seed=8, name='Beta')
    older.add('stable', seed=1)
    newer.add('stable', seed=1)
    corr = run_ladder(older, newer)
    assert tag_pairs(corr, older, newer) == {('stable', 'stable')}
    assert group_tags(corr, older, newer) == [('icf', ('folded',), ('alpha', 'beta'), 'alias-fold-changed')]
    assert not corr.older_only and not corr.newer_only                       # neither added nor removed
    placed(corr, 2, 3)


def test_icf_fold_set_merge_is_the_mirror_case():
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('alpha', seed=7, name='Alpha')
    older.add('beta', seed=8, name='Beta')
    newer.add('folded', seed=7, name='Alpha', aliases=('Beta',))
    corr = run_ladder(older, newer)
    assert not corr.pairs
    assert group_tags(corr, older, newer) == [('icf', ('alpha', 'beta'), ('folded',), 'alias-fold-changed')]


def test_identical_fold_sets_pair_normally():
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        ir.add('folded', seed=7, name='Alpha', aliases=('Beta',))
    corr = run_ladder(older, newer)
    assert tag_pairs(corr, older, newer) == {('folded', 'folded')}
    assert corr.pairs[0].pass_id == 'P03' and not corr.groups


def _inline_world(contained_count: int, container_extra: int):
    """Old `host` (matched) and an unmatched `helper` made of 3 rare blocks; the new `host` contains
    `contained_count` of helper's blocks plus `container_extra` unrelated blocks."""
    helper_blocks = (blk(701), blk(702), blk(703))
    host_blocks = (blk(710), blk(711))
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        ir.add('lib', kind='external', import_key='k32!Lib')
    older.add('host', blocks=host_blocks, name='HostName', calls=('lib',))
    older.add('helper', blocks=helper_blocks)
    newer.add('host', blocks=(*host_blocks, *helper_blocks[:contained_count],
                              *(blk(720 + i) for i in range(container_extra))), name='HostName', calls=('lib',))
    return older, newer


def test_inlined_function_not_reported_removed():
    older, newer = _inline_world(3, 0)
    corr = run_ladder(older, newer)
    assert ('host', 'host') in tag_pairs(corr, older, newer)
    assert group_tags(corr, older, newer) == [('inlined-into', ('helper',), ('host',), 'blocks:3')]
    assert 'helper' not in {older.tag_of(i.fid) for i in corr.older_only}        # not "removed"
    placed(corr, 3, 2)


def test_partial_containment_adds_a_hint_only():
    older, newer = _inline_world(2, 1)
    corr = run_ladder(older, newer)
    assert not corr.groups
    helper = {older.tag_of(i.fid): i for i in corr.older_only}['helper']
    assert helper.reason == 'no-unique-evidence' and 'moved-or-inlined' in helper.hints


def test_outlined_function_is_the_symmetric_case():
    newer, older = _inline_world(3, 0)                  # roles swapped: the OLD build holds the container
    corr = run_ladder(older, newer)
    assert group_tags(corr, older, newer) == [('outlined-from', ('host',), ('helper',), 'blocks:3')]


def test_blocks_shared_with_other_functions_are_not_rare():
    older, newer = _inline_world(3, 0)
    older.add('copy', blocks=(blk(701), blk(702), blk(703)))          # the blocks exist in a second old function
    corr = run_ladder(older, newer)
    assert not [g for g in corr.groups if g.kind == 'inlined-into']


def test_leftover_reasons_are_distinct():
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('plain', seed=1)
    older.add('tiny', seed=2, n_insn=3)
    older.add('big', seed=3, oversize=True)
    older.add('target', seed=4)
    older.add('jmp', kind='thunk', thunk_target='target')
    older.add('lib', kind='external', import_key='k32!Gone')
    corr = run_ladder(older, newer)
    reasons = {older.tag_of(i.fid): i.reason for i in corr.older_only}
    assert reasons == {'plain': 'no-unique-evidence', 'tiny': 'tiny', 'big': 'oversize', 'target': 'no-unique-evidence',
                       'jmp': 'thunk-unresolved', 'lib': 'no-unique-evidence'}
    assert not corr.newer_only and not corr.pairs
    placed(corr, 6, 0)


def test_tiny_change_is_reported_one_sided_with_reason_tiny_never_dropped():
    """F9 at ladder level: a tiny function that changed cannot be content-matched; both versions stay visible."""
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('small', seed=1, n_insn=4)
    newer.add('small', seed=2, n_insn=4)
    corr = run_ladder(older, newer)
    assert not corr.pairs
    assert [i.reason for i in corr.older_only] == ['tiny'] and [i.reason for i in corr.newer_only] == ['tiny']
