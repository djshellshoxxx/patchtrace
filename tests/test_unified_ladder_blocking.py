"""Blocked candidate generation of the residual stage (SPEC-31 04 s6.1). SYNTHETIC IR only.

Candidate pairs = share >= 1 MinHash band OR >= 2 non-size tokens; top L-22 per function per direction by shared-token
count (ties: lower rva); a bucket above L-23 is split by the size bucket, then the n_bb bucket, then abstains.
"""
from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from unified_ir_builder import SyntheticIr, make_body  # noqa: E402
from unified_residual_support import BodyMnemonics, edited, make_state  # noqa: E402

from patchtrace.unified.ladder.blocking import (  # noqa: E402
    BANDS,
    MinHasher,
    Signatures,
    block,
    eligible,
    rare_constants,
    rare_strings,
    references,
)
from patchtrace.unified.ladder.side import SideData  # noqa: E402
from patchtrace.unified.limits import DEFAULT_LIMITS  # noqa: E402

CAP = DEFAULT_LIMITS.l06_fn_instructions


def tags(blocked, older, newer):
    return {(older.tag_of(x), newer.tag_of(y)) for x, ys in blocked.older.items() for y in ys}


def signatures(older, newer):
    hasher = MinHasher()
    return Signatures(BodyMnemonics(older), hasher, CAP), Signatures(BodyMnemonics(newer), hasher, CAP)


# ---- the candidate rule -------------------------------------------------------------------------------------------------------

def test_two_shared_rare_tokens_make_a_candidate_a_single_one_does_not():
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('X', seed=1, strings=('alpha-string', 'beta-string'))
    older.add('W', seed=2, strings=('alpha-string',))
    newer.add('Y', seed=3, strings=('alpha-string', 'beta-string'))
    newer.add('V', seed=4, strings=('alpha-string',))
    blocked = block(make_state(older, newer), None, None)
    assert tags(blocked, older, newer) == {('X', 'Y')}
    assert {older.tag_of(x): [newer.tag_of(y) for y in ys] for x, ys in blocked.older.items()} == {'X': ['Y']}
    assert {newer.tag_of(y): [older.tag_of(x) for x in xs] for y, xs in blocked.newer.items()} == {'Y': ['X']}
    assert blocked.pairs == 1 and blocked.caps == 0


def test_size_buckets_alone_never_make_a_candidate():
    older, newer = SyntheticIr(), SyntheticIr()
    for i in range(6):
        older.add(f'o{i}', seed=10 + i, n_insn=12, n_bb=6)
        newer.add(f'n{i}', seed=30 + i, n_insn=12, n_bb=6)          # same size bucket and n_bb bucket everywhere
    blocked = block(make_state(older, newer), None, None)
    assert blocked.pairs == 0 and not blocked.older and not blocked.newer


def test_rare_constants_called_imports_and_matched_neighbours_are_tokens():
    older, newer = SyntheticIr(), SyntheticIr()
    for ir, seed in ((older, 1), (newer, 2)):
        ir.add('n1', seed=100)
        ir.add('F', seed=seed, consts=(0x2468, 0x1357), calls=('imp:lib!one', 'n1'))
    plain = block(make_state(older, newer), None, None)
    assert tags(plain, older, newer) == {('F', 'F')}                  # two constants + one import: three shared tokens
    anchored = block(make_state(older, newer, anchors=[('n1', 'n1')]), None, None)
    tokens = anchored.tokens('a', older.fid('F'))
    assert ('c', older.fid('n1')) in tokens and ('i', 'lib!one') in tokens and ('k', 0x2468) in tokens


def test_one_shared_band_is_enough_and_unrelated_bodies_share_none():
    older, newer = SyntheticIr(), SyntheticIr()
    body = make_body(7, 60)
    older.add('X', body=body, n_bb=6)
    newer.add('Y', body=edited(body, extra=1), n_bb=7)
    older.add('Z', seed=999, n_insn=60, n_bb=6)
    newer.add('Q', seed=555, n_insn=60, n_bb=7)
    blocked = block(make_state(older, newer), *signatures(older, newer))
    assert tags(blocked, older, newer) == {('X', 'Y')}
    assert any(token[0] == 'm' for token in blocked.tokens('a', older.fid('X')))


def test_without_a_mnemonic_source_the_other_tokens_still_work():
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('X', seed=1, strings=('alpha-string', 'beta-string'))
    newer.add('Y', seed=3, strings=('alpha-string', 'beta-string'))
    blocked = block(make_state(older, newer), None, None)
    assert tags(blocked, older, newer) == {('X', 'Y')}
    assert not any(token[0] == 'm' for token in blocked.tokens('a', 0))


# ---- bucket caps: split by size bucket, then n_bb bucket, then abstain ---------------------------------------------------------

SMALL_CAP = dataclasses.replace(DEFAULT_LIMITS, l23_bucket_cap=6, l24_assign_bucket_cap=6)


def common_import_world(size_of, nbb_of=lambda i: 6):
    """10 functions per side that all call one import; twin i shares one rare string with its twin."""
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        for i in range(10):
            ir.add(f'f{i}', seed=i, n_insn=size_of(i), n_bb=nbb_of(i), calls=('imp:lib!common',),
                   strings=(f'rare-string-{i}',))
    return older, newer


def test_an_oversized_bucket_is_split_by_the_size_bucket():
    older, newer = common_import_world(lambda i: 8 if i < 5 else 40)
    blocked = block(make_state(older, newer, limits=SMALL_CAP), None, None)
    assert blocked.caps == 0
    assert tags(blocked, older, newer) == {(f'f{i}', f'f{i}') for i in range(10)}     # import + own string
    unsplit = block(make_state(older, newer), None, None)
    assert unsplit.work > blocked.work                       # the split enumerates 2 x 5x5 pairs instead of 10x10


def test_the_split_continues_with_the_n_bb_bucket():
    older, newer = common_import_world(lambda i: 12, nbb_of=lambda i: 4 if i < 5 else 9)
    blocked = block(make_state(older, newer, limits=SMALL_CAP), None, None)
    assert blocked.caps == 0
    assert tags(blocked, older, newer) == {(f'f{i}', f'f{i}') for i in range(10)}


def test_a_bucket_too_large_after_both_splits_abstains_and_is_counted():
    older, newer = common_import_world(lambda i: 12)
    blocked = block(make_state(older, newer, limits=SMALL_CAP), None, None)
    assert blocked.caps == 1                                  # one abstained (token, size, n_bb) bucket
    assert blocked.pairs == 0                                 # the rare string alone is a single shared token


@pytest.mark.parametrize(('size', 'cross_pair_kept'), [(6, True), (7, False)], ids=['at-the-cap', 'over-the-cap'])
def test_a_bucket_of_exactly_the_cap_is_not_split(size, cross_pair_kept):
    """Small and big functions share two imports. Unsplit, they pair across the size buckets; split, they cannot."""
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        for i in range(size):
            ir.add(f'f{i}', seed=i, n_insn=8 if i < size // 2 else 40, n_bb=6, calls=('imp:lib!A', 'imp:lib!B'))
    blocked = block(make_state(older, newer, limits=SMALL_CAP), None, None)       # L-23 = 6
    assert (('f0', f'f{size - 1}') in tags(blocked, older, newer)) is cross_pair_kept
    assert blocked.caps == 0


# ---- top-K per function per direction ------------------------------------------------------------------------------------------

def test_top_k_keeps_the_highest_shared_count_with_ties_to_the_lower_rva():
    older, newer = SyntheticIr(), SyntheticIr()
    shared = {'Y1': ('a1', 'a2'), 'Y2': ('b1', 'b2', 'b3'), 'Y3': ('c1', 'c2', 'c3'), 'Y4': ('d1', 'd2')}
    older.add('X', seed=1, n_bb=6, strings=tuple(f'{s}-xx' for names in shared.values() for s in names))
    for i, (tag, names) in enumerate(shared.items(), start=1):
        twin = tuple(f'twin{i}-{k}' for k in range(4))
        older.add(f'W{i}', seed=10 + i, n_bb=6, strings=twin)
        newer.add(tag, seed=20 + i, n_bb=6, strings=(*(f'{s}-xx' for s in names), *twin))
    limits = dataclasses.replace(DEFAULT_LIMITS, l22_candidates_per_function=1)
    blocked = block(make_state(older, newer, limits=limits), None, None)
    assert [newer.tag_of(y) for y in blocked.older[older.fid('X')]] == ['Y2']      # 3 shared, tie with Y3 -> lower rva
    for i in (1, 3, 4):                                                          # these keep their twin only
        assert [older.tag_of(x) for x in blocked.newer[newer.fid(f'Y{i}')]] == [f'W{i}']
    # the union of both directions: Y2 also sees X, which listed it, so a rival can never hide from a margin test
    assert [older.tag_of(x) for x in blocked.newer[newer.fid('Y2')]] == ['X', 'W2']


def test_a_matching_n_bb_bucket_ranks_a_candidate_above_an_otherwise_equal_one():
    older, newer = SyntheticIr(), SyntheticIr()
    shared = ('aa-text', 'bb-text')
    older.add('X', seed=1, n_bb=6, strings=shared)                       # n_bb bucket 2
    older.add('W1', seed=2, n_bb=9, strings=tuple(f'w1-text-{k}' for k in range(4)))
    newer.add('Y1', seed=3, n_bb=9, strings=(*shared, *(f'w1-text-{k}' for k in range(4))))   # bucket 3: no match
    newer.add('Y2', seed=4, n_bb=6, strings=shared)                      # bucket 2: matches X
    limits = dataclasses.replace(DEFAULT_LIMITS, l22_candidates_per_function=1)
    blocked = block(make_state(older, newer, limits=limits), None, None)
    # X shares the same two strings with both; Y2 also shares the n_bb bucket, so it outranks the lower rva Y1
    assert [newer.tag_of(y) for y in blocked.older[older.fid('X')]] == ['Y2']


def test_a_pair_that_only_the_newer_function_lists_is_kept():
    older, newer = SyntheticIr(), SyntheticIr()
    names = ('aa-text', 'bb-text', 'cc-text', 'dd-text', 'ee-text')
    older.add('X', seed=1, n_bb=6, strings=names)
    newer.add('Y1', seed=2, n_bb=6, strings=names)                         # X's best (5 shared)
    newer.add('Y2', seed=3, n_bb=6, strings=names[:3])                     # 3 shared: only Y2's own list names X
    limits = dataclasses.replace(DEFAULT_LIMITS, l22_candidates_per_function=1)
    blocked = block(make_state(older, newer, limits=limits), None, None)
    assert [newer.tag_of(y) for y in blocked.older[older.fid('X')]] == ['Y1', 'Y2']
    assert [older.tag_of(x) for x in blocked.newer[newer.fid('Y2')]] == ['X']


def test_the_kept_pairs_are_bounded_by_k_per_function_per_direction_not_the_matrix():
    n = 240
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        for i in range(n):
            ir.add(f'f{i}', seed=i, n_insn=12, n_bb=6, calls=('imp:lib!A', 'imp:lib!B'),
                   strings=tuple(f'own-{i}-{k}' for k in range(3)))
    blocked = block(make_state(older, newer), None, None)
    k = DEFAULT_LIMITS.l22_candidates_per_function
    assert {(f'f{i}', f'f{i}') for i in range(n)} <= tags(blocked, older, newer)        # every twin is kept
    assert blocked.pairs <= k * 2 * n                       # the union of both directions' top-K lists
    assert blocked.pairs < n * n // 4                       # every cross pair qualifies (two shared imports)


def test_adjacency_is_sorted_and_symmetric():
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        for i in range(8):
            ir.add(f'f{i}', seed=i, n_bb=6, calls=('imp:lib!A', 'imp:lib!B'))
    blocked = block(make_state(older, newer), None, None)
    for x, ys in blocked.older.items():
        assert list(ys) == sorted(ys) and all(x in blocked.newer[y] for y in ys)
    for y, xs in blocked.newer.items():
        assert list(xs) == sorted(xs) and all(y in blocked.older[x] for x in xs)
    assert blocked.pairs == sum(len(v) for v in blocked.older.values()) == 64


# ---- eligibility and on-demand reading -----------------------------------------------------------------------------------------

def eligibility_world():
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        ir.add('ok', seed=1, n_insn=12)
        ir.add('tiny', seed=2, n_insn=4)                               # <= L-10 instructions
        ir.add('big', seed=3, oversize=True)                           # oversize: keys NULL
        ir.add('anchor', seed=4, n_insn=12)
        ir.add('thunk', kind='thunk', thunk_target='ok')
        ir.add('imp', kind='external', import_key='lib!x')
        ir.add('hub', seed=5, n_insn=12)
        for i in range(3):
            ir.add(f'caller{i}', seed=60 + i, n_insn=12, calls=('hub',))
    return older, newer


def test_only_unmatched_content_eligible_non_hub_functions_are_candidates_and_read():
    older, newer = eligibility_world()
    limits = dataclasses.replace(DEFAULT_LIMITS, l17_hub_fan_in=2)           # `hub` has 3 callers
    st = make_state(older, newer, anchors=[('anchor', 'anchor')], limits=limits)
    got = [older.tag_of(f) for f in eligible(st, 'a')]
    assert got == ['ok', 'caller0', 'caller1', 'caller2']                       # not tiny/oversize/thunk/ext/hub/matched
    source_a, source_b = BodyMnemonics(older), BodyMnemonics(newer)
    hasher = MinHasher()
    sigs = (Signatures(source_a, hasher, CAP), Signatures(source_b, hasher, CAP))
    block(st, *sigs)
    assert sorted(source_a.reads) == sorted(older.fid(t) for t in got)
    before = len(source_a.reads)
    block(st, *sigs)                                                           # signatures are cached per function
    assert len(source_a.reads) == before


def test_icf_suspects_are_not_eligible():
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('fold', seed=1, name='Alpha', name_src='IMPORTED', aliases=('Beta',))
    newer.add('one', seed=2, name='Alpha', name_src='IMPORTED')
    newer.add('two', seed=3, name='Beta', name_src='IMPORTED')              # the alias names map to two functions
    st = make_state(older, newer)
    assert st.icf_a[older.fid('fold')] and eligible(st, 'a') == []


def test_strings_and_constants_are_rare_up_to_exactly_their_limits():
    """L-14: a string is rare when at most 4 functions per side reference it; L-15: a constant, at most 2."""
    for functions, string_rare, const_rare in ((2, True, True), (3, True, False), (4, True, False), (5, False, False)):
        ir = SyntheticIr()
        for i in range(functions):
            ir.add(f'f{i}', seed=i, strings=('shared-text',), consts=(0x2468,))
        side = SideData.from_ir(ir)
        assert bool(rare_strings(side, DEFAULT_LIMITS)[0]) is string_rare, functions
        assert bool(rare_constants(side, DEFAULT_LIMITS)[0]) is const_rare, functions


# ---- references ---------------------------------------------------------------------------------------------------------------

def references_world():
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        ir.add('E', kind='external', import_key='lib!imp')
        ir.add('A', seed=1)                                    # matched callee
        ir.add('B', seed=2)                                    # unmatched callee
        ir.add('H', seed=3)                                    # matched hub callee (three callers)
        ir.add('F', seed=5, strings=('rare-text-one',), calls=('A', 'B', 'H', 'E', 'imp:lib!other'))
        ir.add('P', seed=4, calls=('F',))                      # matched caller of F
        ir.add('R', seed=8, calls=('F',))                      # unmatched caller of F
        ir.add('G', seed=6, calls=('H',))
        ir.add('Q', seed=7, calls=('H',))
    return older, newer


def test_references_split_matched_unmatched_imports_strings_and_hubs():
    older, newer = references_world()
    limits = dataclasses.replace(DEFAULT_LIMITS, l17_hub_fan_in=2)
    st = make_state(older, newer, anchors=[('A', 'A'), ('H', 'H'), ('E', 'E'), ('P', 'P')], limits=limits)
    f = older.fid('F')
    with_hubs = references(st, 'a', f, hubs=True)
    assert with_hubs.pairs == (('c', older.fid('A')), ('c', older.fid('H')), ('r', older.fid('P')))
    assert with_hubs.unmatched == 2                              # callee B and caller R
    assert with_hubs.imports == ('lib!imp', 'lib!other')         # the external callee E carries its import key
    assert len(with_hubs.strings) == 1
    without_hubs = references(st, 'a', f, hubs=False)
    assert without_hubs.pairs == (('c', older.fid('A')), ('r', older.fid('P')))
    assert without_hubs.unmatched == 2
    # the newer side names a pair by the OLDER member, so equal relations compare equal across sides
    assert references(st, 'b', newer.fid('F'), hubs=True).pairs == with_hubs.pairs


# ---- MinHash ------------------------------------------------------------------------------------------------------------------

SEQUENCE = ['mov', 'add', 'sub', 'mov', 'cmp', 'jne', 'mov', 'lea', 'call', 'test', 'je', 'xor', 'ret']
# verified once against a naive loop that shares no code with MinHasher (one blake2b per shingle, one min per row)
GOLDEN = (264491622574983714, 137243124933485355, 5666901865997701, 54262450393366894, 104460676130585310,
          187917923013690732, 108152962472108347, 254381165519140917, 153457700134715348, 106971035203332328,
          116695081316139956, 90754687586808378, 168415968456179087, 297024834360232013, 120050686410123088,
          124209354224904042)


def mnemonics_of(seed, n):
    return [insn.mnem for insn in make_body(seed, n)]


def bands_of(hasher, sequence):
    sig = hasher.signature(sequence, CAP)
    return {(i, sig[4 * i:4 * i + 4]) for i in range(BANDS)}


def test_minhash_signature_golden_vector():
    """Platform independent: blake2b and integer arithmetic only. A change here is a rule change (RESIDUAL_VERSION)."""
    sig = MinHasher().signature(SEQUENCE, CAP)
    assert len(sig) == 16 and all(type(v) is int for v in sig)
    assert sig == GOLDEN


def test_similar_sequences_share_a_band_unrelated_sequences_do_not():
    hasher = MinHasher()
    base = mnemonics_of(11, 80)
    close = [*base[:40], 'xor', *base[41:], 'imul']
    assert bands_of(hasher, base) & bands_of(hasher, close)
    assert not bands_of(hasher, base) & bands_of(hasher, mnemonics_of(12, 80))


def test_the_bands_are_four_consecutive_rows_of_four_values_each():
    class Fixed:
        def mnemonics(self, fid):
            return SEQUENCE

    bands = Signatures(Fixed(), MinHasher(), CAP).bands(0)
    assert bands == tuple(('m', band, GOLDEN[4 * band:4 * band + 4]) for band in range(4))


def test_padding_instructions_do_not_change_the_signature():
    hasher = MinHasher()
    padded = [*SEQUENCE[:6], 'NOP', 'int3', *SEQUENCE[6:], 'INT3']
    assert hasher.signature(padded, CAP) == hasher.signature(SEQUENCE, CAP)


def test_the_shingle_cache_is_bounded_and_never_changes_a_signature():
    """Untrusted IR can hold millions of distinct shingles: the cache is cleared above its cap, results stay equal."""
    bounded, unbounded = MinHasher(max_cached=50), MinHasher()
    sequences = [mnemonics_of(seed, 120) for seed in range(30)]
    for sequence in sequences:
        assert bounded.signature(sequence, CAP) == unbounded.signature(sequence, CAP)
        assert bounded.cached_shingles <= 50 + 120
    assert unbounded.cached_shingles > 50 + 120


def test_too_short_streams_have_no_signature():
    hasher = MinHasher()
    assert hasher.signature(['mov', 'ret'], CAP) is None and hasher.signature([], CAP) is None


def test_hostile_mnemonics_are_bounded_and_never_raise():
    hostile = ['\ud800', 'x' * 100_000, 'mov', '\x00', 'ret', 'ret']
    assert MinHasher().signature(hostile, CAP) is not None


def test_the_stream_is_cut_at_the_instruction_limit():
    endless = iter(lambda: 'mov', None)                      # an unbounded source must not hang the signature
    assert MinHasher().signature(endless, 50) is not None


@pytest.mark.parametrize('fid', [0, 1], ids=['first', 'second'])
def test_signatures_are_read_once_per_function(fid):
    older = SyntheticIr()
    older.add('X', seed=1, n_insn=20)
    older.add('Y', seed=2, n_insn=20)
    source = BodyMnemonics(older)
    sigs = Signatures(source, MinHasher(), CAP)
    first = sigs.bands(fid)
    assert sigs.bands(fid) == first and source.reads == [fid]
    assert len(first) == BANDS and all(t[0] == 'm' and t[1] == i for i, t in enumerate(first))
