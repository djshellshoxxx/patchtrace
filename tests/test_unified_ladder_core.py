"""L1 ladder core (SPEC-31 04 s3-s4, s9): pass table, global passes, drill-down, gates, anchors, soft candidates.

SYNTHETIC IR only (tests/unified_ir_builder.py): these prove the algorithm, not live behaviour on Ghidra output.
"""
from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from unified_ir_builder import SyntheticIr, pairs_by_tag, tag_pairs  # noqa: E402

from patchtrace.unified.contracts import Atom  # noqa: E402
from patchtrace.unified.ladder.engine import run_ladder, run_ladder_data, stage_groups  # noqa: E402
from patchtrace.unified.ladder.passes import (  # noqa: E402
    PASS_BY_ID,
    PASS_TABLE_DIGEST,
    PASSES,
    PassSpec,
    pass_table_digest,
)
from patchtrace.unified.ladder.ports import BlockRow, CallRow, CstRow, IrSide, RowsIrSide, StrRow  # noqa: E402
from patchtrace.unified.ladder.side import SideData  # noqa: E402
from patchtrace.unified.ladder.types import CorrPair  # noqa: E402
from patchtrace.unified.limits import DEFAULT_LIMITS, UnifiedError  # noqa: E402


def solo(*ids: str, neighbour: bool = False):
    """A pass table of the named passes with propagation switched off (isolates one key's behaviour)."""
    return [dataclasses.replace(PASS_BY_ID[i], neighbour=neighbour, stage=0) for i in ids]


def both(older: SyntheticIr, newer: SyntheticIr, tag: str, **fields):
    older.add(tag, **fields)
    newer.add(tag, **fields)


def only(corr, older, newer):
    return tag_pairs(corr, older, newer)


# ---- the table ---------------------------------------------------------------------------------------------------------------

# (id, name, stage, tier, family, class) exactly as 04 s4 and 05 s1.1 list them
SPEC_TABLE = [
    ('P01', 'import-key', 0, 'A', 'F-PT-PE', 'E-NAME'), ('P02', 'export-key', 0, 'A', 'F-PT-PE', 'E-NAME'),
    ('P03', 'name-exact', 0, 'A', 'F-PT-NAMES', 'E-NAME'), ('P04', 'bytes-exact', 1, 'A', 'F-PT-STRUCT', 'E-BODY'),
    ('P05', 'masked-exact', 1, 'A', 'F-PT-STRUCT', 'E-BODY'), ('P06', 'operand-class', 2, 'B', 'F-PT-STRUCT', 'E-BODY'),
    ('P07', 'register-agnostic', 2, 'B', 'F-PT-STRUCT', 'E-BODY'),
    ('P08', 'mnemonic-seq', 2, 'B', 'F-PT-STRUCT', 'E-BODY'),
    ('P09', 'mnemonic-multiset', 2, 'B', 'F-PT-STRUCT', 'E-BODY'),
    ('P10', 'md-flowgraph', 2, 'B', 'F-PT-STRUCT', 'E-CFG'), ('P11', 'md-callgraph', 2, 'B', 'F-PT-STRUCT', 'E-CALL'),
    ('P12', 'string-set', 3, 'B', 'F-PT-STRUCT', 'E-DATA'), ('P13', 'import-callee-set', 3, 'B', 'F-PT-STRUCT', 'E-CALL'),
    ('P14', 'const-set', 3, 'B', 'F-PT-STRUCT', 'E-DATA'), ('P15', 'rehash-exact', 4, 'B', 'F-PT-STRUCT', 'E-CALL'),
]


def test_pass_table_matches_spec_04_s4_and_05_s1_1():
    assert [(p.id, p.name, p.stage, p.tier, p.family, p.cls) for p in PASSES] == SPEC_TABLE
    assert [p.id for p in PASSES if p.hubs] == ['P01', 'P02', 'P03', 'P04', 'P05']          # hubs match by P01-P05 only
    assert [p.id for p in PASSES if p.neighbour] == [f'P{i:02d}' for i in range(4, 15)]    # P04-P14 in neighbour sets
    assert [p.id for p in PASSES if p.bytes_family] == ['P04', 'P05', 'P06', 'P07', 'P08', 'P09', 'P14']
    assert [[p.id for p in g] for g in stage_groups(PASSES)] == [
        ['P01', 'P02', 'P03'], ['P04', 'P05'], ['P06', 'P07', 'P08', 'P09', 'P10', 'P11'], ['P12', 'P13', 'P14'],
        ['P15']]
    assert PASS_BY_ID['P00'].tier == 'M' and PASS_BY_ID['P00'].cls == 'E-MANUAL'


def test_pass_table_agrees_with_the_s0b_registry():
    """The registry (S0b) and the ladder describe the same passes: names, classes, stages, family kinds, tiers."""
    from patchtrace.unified.registry import REGISTRY
    stage_name = {0: 'T0', 1: 'T1', 2: 'T2', 3: 'T3', 4: 'T3+'}

    def family_kind(p):
        if p.family == 'F-PT-PE':
            return 'pe'
        if p.family == 'F-PT-NAMES':
            return 'names'
        return 'bytes-or-struct' if p.bytes_family else 'struct'
    for p in PASSES:
        row = REGISTRY.pass_spec(p.id)
        assert row is not None, p.id
        assert (row.name, row.cls, row.stage, row.family_kind) == (p.name, p.cls, stage_name[p.stage], family_kind(p)), p.id
        assert p.tier in row.tiers, p.id


def test_registry_family_of_agrees_with_every_pair_the_ladder_emits():
    from unified_ir_builder import random_world

    from patchtrace.unified.ladder.types import TIER_RANK
    from patchtrace.unified.registry import REGISTRY
    checked = 0
    for seed in range(12):
        older, newer = random_world(seed, 40)
        corr = run_ladder(older, newer)
        pairs = [p for p in corr.pairs if p.pass_id != 'P00']
        for pair, atom in zip(pairs, corr.atoms(), strict=True):
            assert REGISTRY.family_of(atom.source, atom.step) == pair.family, (atom.source, atom.step)
            row = REGISTRY.pass_spec(pair.pass_id)
            if row is not None:                     # PV / PT (implied, thunk) have no registry row: structural
                assert TIER_RANK[pair.tier] <= max(TIER_RANK[t] for t in row.tiers), (pair.pass_id, pair.tier)
            checked += 1
    assert checked > 300


def test_pass_table_digest_changes_with_any_rule():
    assert PASS_TABLE_DIGEST == pass_table_digest() and len(PASS_TABLE_DIGEST) == 64
    changed = [dataclasses.replace(PASSES[0], tier='B'), *PASSES[1:]]
    assert pass_table_digest(changed) != PASS_TABLE_DIGEST
    assert pass_table_digest(PASSES[:-1]) != PASS_TABLE_DIGEST


def test_stage_groups_rejects_bad_tables():
    with pytest.raises(UnifiedError) as dup:
        stage_groups([PASSES[0], PASSES[0]])
    assert dup.value.code == 'PT-UNIFIED-INPUT' and dup.value.reason == 'pass-table'
    with pytest.raises(UnifiedError):
        stage_groups([PASSES[3], PASSES[0]])                           # stages must not decrease
    with pytest.raises(UnifiedError):
        stage_groups([dataclasses.replace(PASSES[0], keys=None)])      # neither keys nor run hook


# ---- global passes -----------------------------------------------------------------------------------------------------------

def test_unique_key_matches_and_duplicate_bucket_abstains():
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        ir.add('a', seed=1)
        ir.add('b', seed=2)
        ir.add('c1', seed=900)       # byte-identical duplicates: no unique key anywhere
        ir.add('c2', seed=900)
    corr = run_ladder(older, newer)
    assert only(corr, older, newer) == {('a', 'a'), ('b', 'b')}
    assert corr.status == 'complete'
    assert [(g.kind, g.reason) for g in corr.groups] == [('duplicate', 'h0')]
    group = corr.groups[0]
    assert [older.tag_of(f) for f in group.older_fids] == ['c1', 'c2']
    assert [newer.tag_of(f) for f in group.newer_fids] == ['c1', 'c2']
    assert corr.stat('ambiguous:P05') >= 1       # P04 drilled into P05, which abstained
    assert not corr.older_only and not corr.newer_only


def test_exact_pair_provenance_and_atom():
    older, newer = SyntheticIr(), SyntheticIr()
    both(older, newer, 'f', seed=5)
    corr = run_ladder(older, newer)
    pair = corr.pairs[0]
    assert (pair.pass_id, pair.step, pair.tier, pair.round, pair.chain, pair.anchors) == (
        'P04', 'P04-bytes-exact', 'A', 2, (), ())
    assert pair.family == 'F-PT-BYTES' and pair.cls == 'E-BODY'          # both extents .pdata-confirmed
    (atom,) = corr.atoms()
    assert isinstance(atom, Atom)
    assert (atom.source, atom.step, atom.tier, atom.cardinality, atom.cls) == (
        'pt-bytes', 'P04-bytes-exact', 'A', '1:1', 'E-BODY')
    assert (atom.older_rva, atom.newer_rva, atom.ref) == (older.rva_of('f'), newer.rva_of('f'), 'r2')
    assert dict(atom.native)['round'] == '2'


def test_unconfirmed_extent_makes_structural_family_and_pt_ladder_source():
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('f', seed=5, pdata=False)
    newer.add('f', seed=5)
    corr = run_ladder(older, newer)
    assert corr.pairs[0].family == 'F-PT-STRUCT'
    assert corr.atoms()[0].source == 'pt-ladder'


@pytest.mark.parametrize('target', ['P04', 'P05', 'P06', 'P07', 'P08', 'P09', 'P10'])
def test_each_content_pass_matches_when_only_its_key_agrees(target):
    """All other keys differ, so the pair can only be found by `target` (solo table, no propagation)."""
    older, newer = SyntheticIr(), SyntheticIr()
    key_of = {'P04': 'h0', 'P05': 'h1', 'P06': 'h2', 'P07': 'h3', 'P08': 'hm', 'P09': 'hms'}

    def keys(side):
        out = {k: 1000 * (1 if side == 'o' else 2) + i for i, k in enumerate(['h0', 'h1', 'h2', 'h3', 'hm', 'hms'])}
        out.update(md_td=7000 + (side == 'o'), md_bu=8000 + (side == 'o'), n_bb=6, n_edge=7)
        if target == 'P10':
            out.update(md_td=7, md_bu=8)
        else:
            out[key_of[target]] = 555
        return out
    older.add('f', seed=1, keys=keys('o'))
    newer.add('f', seed=2, keys=keys('n'))
    corr = run_ladder(older, newer, passes=solo(*(p.id for p in PASSES if p.id <= 'P10' and p.id >= 'P04')))
    assert only(corr, older, newer) == {('f', 'f')}
    pair = corr.pairs[0]
    assert pair.pass_id == target and pair.tier == PASS_BY_ID[target].tier and pair.chain == ()


def test_drill_down_uses_next_key_inside_bucket():
    older, newer = SyntheticIr(), SyntheticIr()
    common = {'h2': 5, 'h3': 6, 'hm': 7, 'hms': 8, 'n_bb': 6, 'n_edge': 7}
    older.add('x1', seed=1, keys={**common, 'h0': 11, 'h1': 12, 'md_td': 100, 'md_bu': 101})
    older.add('x2', seed=2, keys={**common, 'h0': 21, 'h1': 22, 'md_td': 200, 'md_bu': 201})
    newer.add('y1', seed=3, keys={**common, 'h0': 31, 'h1': 32, 'md_td': 100, 'md_bu': 101})
    newer.add('y2', seed=4, keys={**common, 'h0': 41, 'h1': 42, 'md_td': 200, 'md_bu': 201})
    corr = run_ladder(older, newer, passes=solo('P06', 'P07', 'P08', 'P09', 'P10'))
    assert only(corr, older, newer) == {('x1', 'y1'), ('x2', 'y2')}
    pair = pairs_by_tag(corr, older, newer)[('x1', 'y1')]
    assert (pair.pass_id, pair.chain, pair.tier) == ('P10', ('P06', 'P07', 'P08', 'P09'), 'B')


def test_drill_down_tier_never_exceeds_chain():
    """A weak first key (tier B) followed by A-tier keys: the drill-down pair is B at every depth, not A."""
    def column(attr):
        return lambda side, limits: list(getattr(side, attr))
    weak = PassSpec('T1', 'weak-first', 0, 'B', 'F-PT-STRUCT', 'E-BODY', column('hms'))
    strong1 = PassSpec('T2', 'strong-second', 0, 'A', 'F-PT-STRUCT', 'E-BODY', column('hm'))
    strong2 = PassSpec('T3', 'strong-third', 0, 'A', 'F-PT-STRUCT', 'E-BODY', column('h0'))
    older, newer = SyntheticIr(), SyntheticIr()
    for ir, base in ((older, 10), (newer, 20)):
        ir.add('p', seed=base, keys={'hms': 1, 'hm': 2, 'h0': 500})        # the first two keys cannot split p from q
        ir.add('q', seed=base + 1, keys={'hms': 1, 'hm': 2, 'h0': 600})
    corr = run_ladder(older, newer, passes=[weak, strong1, strong2])
    assert only(corr, older, newer) == {('p', 'p'), ('q', 'q')}
    assert {(p.pass_id, p.tier, p.chain) for p in corr.pairs} == {('T3', 'B', ('T1', 'T2'))}
    alone = run_ladder(older, newer, passes=[strong1, strong2])
    assert {p.tier for p in alone.pairs} == {'A'}


def test_accepted_pair_never_reopened():
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('x', seed=5, name='Foo')
    newer.add('y', seed=5)                    # byte-identical to x but unnamed
    newer.add('y2', seed=99, name='Foo')      # same name, other body
    corr = run_ladder(older, newer)
    pairs = pairs_by_tag(corr, older, newer)
    assert set(pairs) == {('x', 'y2')} and pairs[('x', 'y2')].pass_id == 'P03'
    assert [newer.tag_of(item.fid) for item in corr.newer_only] == ['y']


def test_tiny_and_thunk_never_content_matched():
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        ir.add('tiny', seed=7, n_insn=DEFAULT_LIMITS.l10_tiny_instructions)
        ir.add('target', seed=8)
        ir.add('jmp', kind='thunk', thunk_target='target', keys={'h0': 77, 'h1': 77, 'h2': 77, 'h3': 77, 'hm': 77,
                                                                  'hms': 77, 'n_insn': 12, 'size': 48})
        ir.add('big', seed=9)
    corr = run_ladder(older, newer)
    tags = only(corr, older, newer)
    assert ('tiny', 'tiny') not in tags
    reasons = {older.tag_of(item.fid): item.reason for item in corr.older_only}
    assert reasons['tiny'] == 'tiny'
    # the thunk has equal content keys but is never matched by them; it follows its matched target instead
    assert pairs_by_tag(corr, older, newer)[('jmp', 'jmp')].pass_id == 'PT'


def test_thunk_without_matched_target_is_a_leftover():
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('target', seed=8)
    older.add('jmp', kind='thunk', thunk_target='target')
    newer.add('other', seed=9)
    newer.add('jmp', kind='thunk', thunk_target='other')
    corr = run_ladder(older, newer)
    assert {older.tag_of(i.fid): i.reason for i in corr.older_only}['jmp'] == 'thunk-unresolved'


def test_oversize_function_is_not_matched_and_reported():
    older, newer = SyntheticIr(), SyntheticIr()
    both(older, newer, 'huge', seed=1, oversize=True)
    corr = run_ladder(older, newer)
    assert not corr.pairs
    assert corr.older_only[0].reason == 'oversize' and corr.newer_only[0].reason == 'oversize'


# ---- names, imports, exports ----------------------------------------------------------------------------------------------

def test_import_key_pass_pairs_externals_and_leaves_different_imports_unmatched():
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('open', kind='external', import_key='k32!CreateFileW')
    older.add('gone', kind='external', import_key='k32!OldApi')
    newer.add('open', kind='external', import_key='k32!CreateFileW')
    newer.add('fresh', kind='external', import_key='k32!NewApi')
    corr = run_ladder(older, newer)
    assert only(corr, older, newer) == {('open', 'open')}
    pair = corr.pairs[0]
    assert (pair.pass_id, pair.tier, pair.family, pair.cls) == ('P01', 'A', 'F-PT-PE', 'E-NAME')
    assert {older.tag_of(i.fid) for i in corr.older_only} == {'gone'}
    assert {newer.tag_of(i.fid) for i in corr.newer_only} == {'fresh'}


def test_export_pass_uses_pe_export_keys():
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('e1', seed=1)
    older.add('e2', seed=2)
    newer.add('n1', seed=3)
    newer.add('n2', seed=4)
    exports = ({older.rva_of('e1'): 'ExportA', older.rva_of('e2'): '#7'},
               {newer.rva_of('n1'): 'ExportA', newer.rva_of('n2'): '#8'})
    corr = run_ladder(older, newer, exports=exports)
    assert only(corr, older, newer) == {('e1', 'n1')}
    assert corr.pairs[0].pass_id == 'P02'
    assert run_ladder(older, newer).pairs == ()                      # no export input: P02 contributes nothing


def test_name_pass_requires_trusted_nondefault_names_and_uniqueness():
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        ir.add('good', seed=1, name='Module::Parse')
        ir.add('auto', seed=2, name='FUN_140001000', name_src='USER_DEFINED')     # default-looking name
        ir.add('dflt', seed=3, name='Real', name_src='DEFAULT')                    # untrusted source
        ir.add('short', seed=4, name='ab')                                         # shorter than 3
        ir.add('dup1', seed=5, name='Twice')
        ir.add('dup2', seed=6, name='Twice')
    corr = run_ladder(older, newer, passes=solo('P03'))
    assert only(corr, older, newer) == {('good', 'good')}
    assert corr.pairs[0].pass_id == 'P03' and corr.pairs[0].family == 'F-PT-NAMES'


def test_name_pass_body_mismatch_becomes_tier_c_hint():
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('f', seed=1, n_insn=10, name='Reuse')
    newer.add('f', seed=2, n_insn=100, name='Reuse')          # same name, 10x the size, no shared callee
    corr = run_ladder(older, newer)
    (pair,) = corr.pairs
    assert (pair.pass_id, pair.tier, pair.hints) == ('P03', 'C', ('name-body-mismatch',))
    assert corr.atoms()[0].tier == 'C'


def test_name_pass_accepts_size_mismatch_when_a_callee_is_mapped():
    older, newer = SyntheticIr(), SyntheticIr()
    for ir, n in ((older, 10), (newer, 100)):
        ir.add('lib', kind='external', import_key='k32!Open')
        ir.add('f', seed=n, n_insn=n, name='Reuse', calls=('lib',))
    corr = run_ladder(older, newer)
    pair = pairs_by_tag(corr, older, newer)[('f', 'f')]
    assert (pair.pass_id, pair.tier, pair.hints) == ('P03', 'A', ())


def test_weak_candidate_never_blocks_later_exact_pass():
    """Tier C is held back until the end: the name-reuse candidate must not steal the byte-identical successor."""
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('foo', seed=5, n_insn=10, name='Foo')
    newer.add('bar', seed=5, n_insn=10, name='Bar')            # same bytes, renamed
    newer.add('foo2', seed=77, n_insn=100, name='Foo')         # name reused for an unrelated big function
    corr = run_ladder(older, newer)
    assert only(corr, older, newer) == {('foo', 'bar')}
    assert corr.pairs[0].pass_id == 'P04'
    assert {newer.tag_of(i.fid) for i in corr.newer_only} == {'foo2'}


def test_rival_soft_candidates_cancel_each_other():
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('a', seed=1, n_insn=10, name='Alpha')
    older.add('b', seed=2, n_insn=10, name='Beta')
    newer.add('x', seed=3, n_insn=100, name='Alpha')      # both candidates are name-body mismatches ...
    newer.add('y', seed=4, n_insn=100, name='Beta')
    corr = run_ladder(older, newer)
    assert only(corr, older, newer) == {('a', 'x'), ('b', 'y')}      # ... but they do not share endpoints
    older2, newer2 = SyntheticIr(), SyntheticIr()
    older2.add('a', seed=1, n_insn=10, name='Alpha', aliases=('Beta',))      # one function carrying both names (ICF)
    newer2.add('x', seed=3, n_insn=100, name='Alpha')
    newer2.add('y', seed=4, n_insn=100, name='Beta')
    assert run_ladder(older2, newer2).pairs == ()                    # ICF suspect: groups, never 1:1


def test_p10_requires_the_minimum_block_count():
    """L-11: a flow-graph MD key below 5 blocks is too weak to match on, even if present and equal."""
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('few', seed=1, keys={'n_bb': 4, 'n_edge': 3, 'md_td': 9, 'md_bu': 9})
    newer.add('few', seed=2, keys={'n_bb': 4, 'n_edge': 3, 'md_td': 9, 'md_bu': 9})
    older.add('enough', seed=3, keys={'n_bb': 5, 'n_edge': 4, 'md_td': 8, 'md_bu': 8})
    newer.add('enough', seed=4, keys={'n_bb': 5, 'n_edge': 4, 'md_td': 8, 'md_bu': 8})
    corr = run_ladder(older, newer, passes=solo('P10'))
    assert only(corr, older, newer) == {('enough', 'enough')}


# ---- sets: strings, imports, constants ----------------------------------------------------------------------------------------

def _set_world(attr, shared, other):
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('f', seed=1, **{attr: shared})
    newer.add('f', seed=2, **{attr: shared})
    older.add('g', seed=3, **{attr: other})
    newer.add('g', seed=4, **{attr: other})
    return older, newer


def test_string_set_pass_matches_rare_string_sets():
    older, newer = _set_world('strings', ('disk full', 'cannot open'), ('out of memory', 'bad handle'))
    corr = run_ladder(older, newer, passes=solo('P12'))
    assert only(corr, older, newer) == {('f', 'f'), ('g', 'g')}
    assert corr.pairs[0].pass_id == 'P12' and corr.pairs[0].cls == 'E-DATA'


def test_string_set_ignores_short_and_common_strings():
    older, newer = SyntheticIr(), SyntheticIr()
    for ir, base in ((older, 0), (newer, 100)):
        for i in range(DEFAULT_LIMITS.l14_string_rare_functions + 1):
            ir.add(f'c{i}', seed=base + i, strings=('shared everywhere', 'also shared'))   # not rare: 5 functions
        ir.add('short', seed=base + 50, strings=('ab', 'cd'))                              # below L-13
    assert run_ladder(older, newer, passes=solo('P12')).pairs == ()


def test_single_element_set_needs_the_size_ratio_guard():
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('f', seed=1, n_insn=10, strings=('only one string',))
    newer.add('f', seed=2, n_insn=11, strings=('only one string',))
    older.add('g', seed=3, n_insn=10, strings=('another lone string',))
    newer.add('g', seed=4, n_insn=100, strings=('another lone string',))       # ratio 10: guard vetoes
    corr = run_ladder(older, newer, passes=solo('P12'))
    assert only(corr, older, newer) == {('f', 'f')}
    assert corr.stat('guard-rejected:P12') == 1


def test_import_callee_set_pass():
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('f', seed=1, calls=('imp:k32!A', 'imp:k32!B'))
    newer.add('f', seed=2, calls=('imp:k32!B', 'imp:k32!A'))               # order does not matter: it is a set
    older.add('g', seed=3, calls=('imp:k32!C', 'imp:k32!D'))
    newer.add('g', seed=4, calls=('imp:k32!C', 'imp:k32!E'))
    corr = run_ladder(older, newer, passes=solo('P13'))
    assert only(corr, older, newer) == {('f', 'f')}


def test_constant_set_pass_applies_the_l15_filter():
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('f', seed=1, consts=(0x12345, 0x6789A, 0x3, 0xFF00, 0x1000))   # only the first two are usable
    newer.add('f', seed=2, consts=(0x12345, 0x6789A, 0x5, 0x00FF00, 0x2000))
    corr = run_ladder(older, newer, passes=solo('P14'))
    assert only(corr, older, newer) == {('f', 'f')}
    older2, newer2 = SyntheticIr(), SyntheticIr()
    older2.add('f', seed=1, consts=(0x3, 0xFF00, 0x1000, 0xFFFF))             # small, mask, single bit, mask
    newer2.add('f', seed=2, consts=(0x3, 0xFF00, 0x1000, 0xFFFF))
    assert run_ladder(older2, newer2, passes=solo('P14')).pairs == ()


def test_call_graph_md_separates_functions_with_identical_bodies():
    """Two byte-identical functions that differ only in their call-graph position (P11)."""
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        ir.add('p1', seed=50, calls=('c1', 'c2', 'c3'))     # three callees
        ir.add('p2', seed=50, calls=('c1', 'c2'))           # two callees, same body
        ir.add('c1', seed=60)
        ir.add('c2', seed=61)
        ir.add('c3', seed=62)
    corr = run_ladder(older, newer, passes=solo('P11'))
    assert only(corr, older, newer) >= {('p1', 'p1'), ('p2', 'p2')}
    pair = pairs_by_tag(corr, older, newer)[('p1', 'p1')]
    assert pair.pass_id == 'P11' and pair.cls == 'E-CALL' and pair.tier == 'B'


def test_hubs_match_only_by_the_first_five_passes():
    older, newer = SyntheticIr(), SyntheticIr()
    fan = DEFAULT_LIMITS.l17_hub_fan_in + 1
    for ir in (older, newer):
        for i in range(fan):
            ir.add(f'c{i}', seed=1000 + i, calls=('hub',))
        ir.add('hub', seed=1)
    keys = {'h0': 1, 'h1': 2, 'h2': 3, 'h3': 4, 'hm': 5, 'hms': 6}
    older.specs[-1].keys.update(keys)
    newer.specs[-1].keys.update({**keys, 'h0': 11, 'h1': 12})          # exact keys differ, h2 on equal
    corr = run_ladder(older, newer, passes=solo('P06'))
    assert ('hub', 'hub') not in only(corr, older, newer)
    assert older.fid('hub') in corr.older_hubs
    older.specs[-1].keys.update({'h1': 12})
    exact = run_ladder(older, newer, passes=solo('P05'))
    assert ('hub', 'hub') in only(corr, older, newer) | only(exact, older, newer)


# ---- anchors -----------------------------------------------------------------------------------------------------------------------

def test_anchor_wins_over_every_pass():
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('x', seed=5)
    newer.add('same_bytes', seed=5)
    newer.add('chosen', seed=77)
    anchor = CorrPair(older.fid('x'), newer.fid('chosen'), 'P00', 'P00-manual', 'M', 'F-MANUAL', 'E-MANUAL', 0)
    corr = run_ladder(older, newer, anchors=[anchor])
    pairs = pairs_by_tag(corr, older, newer)
    assert set(pairs) == {('x', 'chosen')}
    assert (pairs[('x', 'chosen')].pass_id, pairs[('x', 'chosen')].tier) == ('P00', 'M')
    assert corr.atoms() == ()                                   # anchors are inputs: the manual atom already exists
    assert len(corr.atoms(include_anchors=True)) == 1


def test_contradictory_anchors_are_an_input_error():
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('x', seed=1)
    older.add('y', seed=2)
    newer.add('a', seed=3)
    newer.add('b', seed=4)
    with pytest.raises(UnifiedError) as err:
        run_ladder(older, newer, anchors=[(0, 0), (0, 1)])
    assert (err.value.code, err.value.reason) == ('PT-UNIFIED-INPUT', 'anchor-conflict')
    with pytest.raises(UnifiedError) as err:
        run_ladder(older, newer, anchors=[(0, 5)])
    assert err.value.reason == 'anchor-range'
    assert len(run_ladder(older, newer, anchors=[(0, 0), (0, 0)]).pairs) >= 1      # an identical repeat is harmless


# ---- port validation -----------------------------------------------------------------------------------------------------------

def _rows_with(**changes):
    """A one-function IR whose port rows are patched; returns the object `SideData.from_ir` reads."""
    ir = SyntheticIr()
    ir.add('a', seed=1)
    ir.add('b', seed=2)
    fn_rows = [r._replace(**changes.get('fn', {})) if i == changes.get('fn_index', 0) else r
               for i, r in enumerate(sorted(ir.function_rows()))]
    if 'fn_swap_rva' in changes:
        fn_rows = [fn_rows[0]._replace(rva=fn_rows[1].rva), fn_rows[1]]

    class Patched:
        def function_rows(self):
            return fn_rows

        def call_rows(self):
            return changes.get('calls', [])

        def string_rows(self):
            return changes.get('strings', [])

        def constant_rows(self):
            return changes.get('consts', [])

        def block_rows(self):
            return changes.get('blocks', [])
    return Patched()


@pytest.mark.parametrize('case, reason', [
    ({'fn': {'fid': 1}}, 'fid-range'),                                  # fid 1 twice
    ({'fn': {'kind': 'bogus'}}, 'fn-enum'),
    ({'fn': {'name_src': 'LOUD'}}, 'fn-enum'),
    ({'fn': {'aliases': tuple(f'n{i}' for i in range(17))}}, 'alias-cap'),
    ({'fn': {'thunk_target': 9}}, 'thunk-range'),
    ({'fn_swap_rva': True}, 'fn-order'),                                # fid is the rank by rva
    ({'calls': [CallRow(0, 1, 7, None, False)]}, 'call-range'),
    ({'calls': [CallRow(5, 1, None, None, False)]}, 'call-range'),
    ({'strings': [StrRow(0, 'zz' * 32, 12)]}, 'string-sha'),
    ({'strings': [StrRow(9, 'a' * 64, 12)]}, 'string-range'),
    ({'consts': [CstRow(9, 5)]}, 'const-range'),
    ({'blocks': [BlockRow(9, 0, 1, 5)]}, 'block-range'),
], ids=lambda v: v if isinstance(v, str) else '')
def test_side_data_rejects_inconsistent_rows(case, reason):
    with pytest.raises(UnifiedError) as err:
        SideData.from_ir(_rows_with(**case))
    assert (err.value.code, err.value.reason) == ('PT-UNIFIED-IR', reason)


def test_side_data_function_cap():
    from patchtrace.unified.limits import UnifiedLimits
    ir = SyntheticIr()
    for i in range(3):
        ir.add(f'f{i}', seed=i)
    with pytest.raises(UnifiedError) as err:
        SideData.from_ir(ir, UnifiedLimits(l01_functions_per_side=2))
    assert (err.value.code, err.value.reason) == ('PT-UNIFIED-LIMIT', 'functions-cap')


def test_state_never_reopens_an_accepted_pair():
    from patchtrace.unified.ladder.state import State
    from patchtrace.unified.limits import Budget
    ir = SyntheticIr()
    ir.add('a', seed=1)
    ir.add('b', seed=2)
    side = SideData.from_ir(ir)
    st = State(side, side, DEFAULT_LIMITS, Budget(), PASSES)
    st.accept(0, 0, pass_id='P04', step='s', tier='A', family='f', cls='c', rnd=1)
    with pytest.raises(AssertionError):
        st.accept(0, 1, pass_id='P04', step='s', tier='A', family='f', cls='c', rnd=1)
    mark = st.begin()
    st.accept(1, 1, pass_id='P05', step='s', tier='A', family='f', cls='c', rnd=1)
    st.rollback(mark)                                  # the only legal undo: an interrupted pass
    assert st.mate_a == [0, -1] and len(st.pairs) == 1


def test_finalize_cancels_rival_soft_candidates():
    from patchtrace.unified.ladder.engine import finalize_soft
    from patchtrace.unified.ladder.state import SoftCand, State
    from patchtrace.unified.limits import Budget
    older, newer = SyntheticIr(), SyntheticIr()
    for tag in ('x', 'y'):
        older.add(tag, seed=ord(tag))
    for tag in ('p', 'q', 'r'):
        newer.add(tag, seed=ord(tag) + 100)
    st = State(SideData.from_ir(older), SideData.from_ir(newer), DEFAULT_LIMITS, Budget(), PASSES)

    def soft(x, y):
        return SoftCand(x, y, 'P06', 'P06-operand-class', 'F-PT-STRUCT', 'E-BODY', 1)
    for cand in (soft(0, 0), soft(0, 1), soft(1, 2)):         # x pairs with p AND q (rivals); y only with r
        st.add_soft(cand)
    finalize_soft(st, 9)
    assert [(p.older_fid, p.newer_fid, p.tier) for p in st.pairs] == [(1, 2, 'C')]
    assert st.stats['soft-conflicts'] == 2
    assert 'candidate-conflict' in st.hints_a[0]


def test_run_ladder_data_reuses_prepared_sides():
    older, newer = SyntheticIr(), SyntheticIr()
    both(older, newer, 'f', seed=5)
    a, b = SideData.from_ir(older), SideData.from_ir(newer)
    assert run_ladder_data(a, b).digest() == run_ladder(older, newer).digest()


def test_rows_ir_side_is_an_ir_side_equivalent_to_the_builder():
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        ir.add('a', seed=1, calls=('b',), strings=('some string',), consts=(0x12345,))
        ir.add('b', seed=2)
        ir.add('c1', seed=900)
        ir.add('c2', seed=900)

    def rows_of(ir):
        return RowsIrSide(list(ir.function_rows()), list(ir.call_rows()), list(ir.string_rows()),
                          list(ir.constant_rows()), list(ir.block_rows()))
    ro, rn = rows_of(older), rows_of(newer)
    assert isinstance(ro, IrSide)
    corr = run_ladder(ro, rn)
    assert corr.digest() == run_ladder(older, newer).digest()
    # fusion only sees rvas: the helpers translate groups and leftovers
    (group,) = corr.groups
    assert corr.group_rvas(group) == ((older.rva_of('c1'), older.rva_of('c2')), (newer.rva_of('c1'), newer.rva_of('c2')))
    assert corr.leftover_rvas('older') == () and corr.leftover_rvas('newer') == ()
