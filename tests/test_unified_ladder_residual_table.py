"""The residual stage inside the whole ladder (SPEC-31 04 s4, s6, s9; backup B-07): table, fallback, invariants.

Random worlds from `random_residual_world` leave the stage real work; every property is checked with the residual passes
ON and compared with the plain S2 table where that is the claim. SYNTHETIC IR only.
"""
from __future__ import annotations

import dataclasses
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
sys.path.insert(0, str(TESTS))
from unified_ir_builder import SyntheticIr, assert_partition  # noqa: E402
from unified_residual_support import BodyMnemonics, random_residual_world  # noqa: E402

from patchtrace.unified.keys import config_digest  # noqa: E402
from patchtrace.unified.ladder import residual  # noqa: E402
from patchtrace.unified.ladder.engine import run_ladder, stage_groups  # noqa: E402
from patchtrace.unified.ladder.passes import PASS_TABLE_DIGEST, PASSES, pass_table_digest  # noqa: E402
from patchtrace.unified.ladder.residual import (  # noqa: E402
    RESIDUAL_IDS,
    RESIDUAL_VERSION,
    pass_table,
    residual_passes,
    table_digest,
)
from patchtrace.unified.ladder.types import TIER_RANK  # noqa: E402
from patchtrace.unified.limits import DEFAULT_LIMITS, Budget  # noqa: E402
from patchtrace.unified.registry import REGISTRY  # noqa: E402

FAST = settings(max_examples=40, deadline=None, derandomize=True, database=None,
                suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])


def full(older, newer, **kwargs):
    return run_ladder(older, newer, passes=pass_table(older=BodyMnemonics(older), newer=BodyMnemonics(newer)), **kwargs)


def plain(older, newer, **kwargs):
    return run_ladder(older, newer, **kwargs)


def accepted_pairs(corr, tiers='MAB'):
    return {(p.older_fid, p.newer_fid) for p in corr.pairs if p.tier in tiers}


# ---- the table ------------------------------------------------------------------------------------------------------------------

def test_the_residual_rows_are_the_04_s4_rows():
    rows = [(p.id, p.name, p.stage, p.tier, p.family, p.cls) for p in residual_passes()]
    assert rows == [('P16', 'ref-vector', 5, 'B', 'F-PT-STRUCT', 'E-RESID'),
                    ('P17', 'bb-vote', 5, 'C', 'F-PT-STRUCT', 'E-RESID'),
                    ('P18', 'layout-gap', 5, 'C', 'F-PT-STRUCT', 'E-LAYOUT'),
                    ('P19', 'assignment', 6, 'C', 'F-PT-STRUCT', 'E-RESID')]
    for spec in residual_passes():
        assert spec.run is not None and spec.keys is None and spec.guard is None
        assert not (spec.hubs or spec.neighbour or spec.bytes_family)       # never matches hubs, never a neighbour key
        assert spec.step == f'{spec.id}-{spec.name}'


def test_the_residual_rows_agree_with_the_s0b_registry():
    for spec in residual_passes():
        row = REGISTRY.pass_spec(spec.id)
        assert row is not None
        assert (row.name, row.cls, row.family_kind, row.stage) == (spec.name, spec.cls, 'struct', 'T4-T5')
        assert spec.tier in row.tiers


def test_the_full_table_runs_p15_then_the_two_residual_stages():
    groups = [[p.id for p in group] for group in stage_groups(pass_table())]
    assert groups[-3:] == [['P15'], ['P16', 'P17', 'P18'], ['P19']]
    assert [p.id for p in pass_table()] == [p.id for p in PASSES] + list(RESIDUAL_IDS)


def test_the_table_digest_is_the_s2_digest_without_residual_passes_and_covers_them_with():
    assert table_digest(pass_table(residual=False)) == table_digest() == PASS_TABLE_DIGEST      # B-07 keeps the keys
    with_residual = table_digest(pass_table())
    assert re.fullmatch(r'[0-9a-f]{64}', with_residual) and with_residual != PASS_TABLE_DIGEST
    tweaked = [dataclasses.replace(p, tier='B') if p.id == 'P19' else p for p in pass_table()]
    assert table_digest(tweaked) != with_residual
    assert pass_table_digest(pass_table()) != PASS_TABLE_DIGEST                  # S2's own digest sees the rows too
    assert re.fullmatch(r'residual/\d+', RESIDUAL_VERSION)


def test_the_table_digest_tracks_the_residual_rule_version(monkeypatch):
    before = table_digest(pass_table())
    monkeypatch.setattr(residual, 'RESIDUAL_VERSION', 'residual/next')
    assert table_digest(pass_table()) != before
    assert table_digest(PASSES) == PASS_TABLE_DIGEST                             # no residual pass: the version is moot


def test_the_table_digest_is_a_valid_config_digest_input():
    kwargs = {'registry_digest': REGISTRY.digest(), 'channel_versions': dict(REGISTRY.channel_versions),
              'proof_versions': dict(REGISTRY.proof_versions), 'limits_digest': 'a' * 64}
    assert config_digest(pass_table_digest=table_digest(pass_table()), **kwargs) != config_digest(
        pass_table_digest=table_digest(PASSES), **kwargs)


# ---- B-07: skip residual ------------------------------------------------------------------------------------------------------

def test_skipping_the_residual_is_exactly_the_s2_table():
    assert pass_table(residual=False) == PASSES


@pytest.mark.parametrize('seed', range(6), ids=lambda s: f'world{s}')
def test_skip_residual_gives_the_byte_identical_s2_result(seed):
    older, newer = random_residual_world(seed, 40)
    skipped = run_ladder(older, newer, passes=pass_table(residual=False))
    assert skipped.digest() == plain(older, newer).digest()
    assert not any(p.pass_id in RESIDUAL_IDS for p in skipped.pairs)


def test_every_residual_pass_has_work_in_the_random_worlds():
    """Guard for the property tests below: they would prove little if a pass never produced a pair."""
    produced = {pass_id: 0 for pass_id in RESIDUAL_IDS}
    gained = 0
    for seed in range(12):
        older, newer = random_residual_world(seed, 50)
        corr = full(older, newer)
        gained += len(corr.pairs) - len(plain(older, newer).pairs)
        for pair in corr.pairs:
            if pair.pass_id in produced:
                produced[pair.pass_id] += 1
    assert all(count > 0 for count in produced.values()), produced
    assert gained >= sum(produced.values()) // 2          # the residual pairs are mostly NEW pairs, not renamed ones


# ---- invariants with the residual stage on ---------------------------------------------------------------------------------------

@FAST
@given(seed=st.integers(0, 10 ** 6), n=st.integers(5, 45))
def test_every_function_has_exactly_one_place_and_pairs_are_one_to_one(seed, n):
    older, newer = random_residual_world(seed, n)
    corr = full(older, newer)
    assert_partition(corr, len(older.specs), len(newer.specs))
    assert len({p.older_fid for p in corr.pairs}) == len(corr.pairs) == len({p.newer_fid for p in corr.pairs})
    assert all(p.tier in 'MABC' for p in corr.pairs)


@FAST
@given(seed=st.integers(0, 10 ** 6), n=st.integers(5, 45))
def test_the_residual_stage_never_removes_a_tier_m_a_or_b_pair_of_the_s2_ladder(seed, n):
    older, newer = random_residual_world(seed, n)
    assert accepted_pairs(plain(older, newer)) <= accepted_pairs(full(older, newer))


@FAST
@given(seed=st.integers(0, 10 ** 6), n=st.integers(5, 45))
def test_residual_pairs_obey_i6_no_tiny_thunk_import_or_oversize_function(seed, n):
    older, newer = random_residual_world(seed, n)
    corr = full(older, newer)
    for pair in corr.pairs:
        if pair.pass_id not in RESIDUAL_IDS:
            continue
        for ir, fid in ((older, pair.older_fid), (newer, pair.newer_fid)):
            spec = ir.layout()[1][fid]
            assert spec.kind == 'normal' and not spec.oversize
            if pair.pass_id != 'P18':                       # a layout slot needs no content gate, only a real function
                assert len(spec.resolved_body()) > DEFAULT_LIMITS.l10_tiny_instructions


@FAST
@given(seed=st.integers(0, 10 ** 6), n=st.integers(5, 45), order_old=st.integers(0, 50), order_new=st.integers(0, 50))
def test_permutation_of_input_order_is_invisible(seed, n, order_old, order_new):
    base = full(*random_residual_world(seed, n))
    shuffled = full(*random_residual_world(seed, n, row_order_old=order_old, row_order_new=order_new))
    assert base.digest() == shuffled.digest()


@FAST
@given(seed=st.integers(0, 10 ** 6), n=st.integers(5, 45))
def test_swapping_sides_mirrors_the_correspondence(seed, n):
    older, newer = random_residual_world(seed, n)
    forward = full(older, newer)
    backward = full(newer, older)

    def key(p):
        return (p.older_fid, p.newer_fid, p.pass_id, p.tier, p.family, p.cls, p.round, p.votes, p.chain, p.hints)
    assert sorted(key(p) for p in forward.pairs) == sorted((p.newer_fid, p.older_fid, *key(p)[2:]) for p in backward.pairs)
    assert [(i.fid, i.reason, i.hints) for i in forward.older_only] == [
        (i.fid, i.reason, i.hints) for i in backward.newer_only]


class Countdown:
    """A cancel event that fires after `limit` polls."""

    def __init__(self, limit):
        self.limit, self.polls = limit, 0

    def is_set(self):
        self.polls += 1
        return self.polls > self.limit


@FAST
@given(seed=st.integers(0, 10 ** 6), n=st.integers(5, 40), limit=st.integers(0, 4000))
def test_budget_expiry_yields_a_prefix_of_the_full_run(seed, n, limit):
    older, newer = random_residual_world(seed, n)
    whole = full(older, newer)
    cut = full(older, newer, budget=Budget(cancel=Countdown(limit), check_every=1))
    if cut.status == 'complete':
        assert cut.digest() == whole.digest()
        return
    assert cut.status == 'partial' and not cut.groups
    order = [(p.older_fid, p.newer_fid, p.pass_id, p.tier, p.round, p.seq) for p in sorted(whole.pairs, key=lambda p: p.seq)]
    got = [(p.older_fid, p.newer_fid, p.pass_id, p.tier, p.round, p.seq) for p in sorted(cut.pairs, key=lambda p: p.seq)]
    assert got == order[:len(got)]
    assert set(cut.passes_completed) <= set(whole.passes_completed)


def test_a_stop_inside_the_residual_stage_keeps_the_s2_result_up_to_p15():
    older, newer = random_residual_world(3, 40)
    reference = plain(older, newer)
    ticks_before_residual = dict(reference.stats)['ticks']
    cut = full(older, newer, budget=Budget(cancel=Countdown(ticks_before_residual + 40), check_every=1))
    assert cut.status == 'partial'
    assert 'P15' in cut.passes_completed and 'P19' not in cut.passes_completed


@pytest.mark.parametrize('shape', ['both-empty', 'older-empty', 'newer-empty'])
def test_empty_and_one_sided_inputs_are_fine(shape):
    older, newer = SyntheticIr(), SyntheticIr()
    if shape == 'newer-empty':
        older.add('f', seed=1)
    if shape == 'older-empty':
        newer.add('f', seed=1)
    corr = full(older, newer)
    assert corr.status == 'complete' and not corr.pairs
    assert len(corr.older_only) == len(older.specs) and len(corr.newer_only) == len(newer.specs)


def test_a_table_can_be_reused_for_another_run():
    older, newer = random_residual_world(2, 40)
    source_a, source_b = BodyMnemonics(older), BodyMnemonics(newer)
    table = pass_table(older=source_a, newer=source_b)
    first = run_ladder(older, newer, passes=table)
    reads = len(source_a.reads)
    second = run_ladder(older, newer, passes=table)
    assert first.digest() == second.digest()
    assert len(source_a.reads) == 2 * reads                  # signatures never leak from one run into the next


# ---- atoms ------------------------------------------------------------------------------------------------------------------------

@FAST
@given(seed=st.integers(0, 10 ** 6), n=st.integers(5, 45))
def test_residual_atoms_are_valid_and_agree_with_the_registry(seed, n):
    corr = full(*random_residual_world(seed, n))
    pairs = [p for p in corr.pairs if p.pass_id != 'P00']
    for pair, atom in zip(pairs, corr.atoms(), strict=True):
        assert REGISTRY.family_of(atom.source, atom.step) == pair.family
        row = REGISTRY.pass_spec(pair.pass_id)
        if row is not None:
            assert TIER_RANK[pair.tier] <= max(TIER_RANK[t] for t in row.tiers)
        if pair.pass_id in RESIDUAL_IDS:
            assert atom.source == 'pt-ladder' and atom.cardinality == '1:1'


# ---- never the full matrix -----------------------------------------------------------------------------------------------------------

def common_import_world(n):
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        for i in range(n):
            ir.add(f'f{i}', seed=i, n_insn=12, n_bb=6, calls=('imp:lib!A', 'imp:lib!B'),
                   strings=tuple(f'own-{i}-{k}' for k in range(3)))
    return older, newer


@pytest.mark.parametrize('k', [DEFAULT_LIMITS.l22_candidates_per_function, 3], ids=['L-22', 'k3'])
def test_blocking_never_builds_full_matrix(k):
    """Counter on pair evaluations <= K x n (04 s9): 300 unmatched functions per side, every cross pair shares two
    imports, yet at most K candidates per function and direction are ever evaluated."""
    n = 300
    older, newer = common_import_world(n)
    limits = dataclasses.replace(DEFAULT_LIMITS, l22_candidates_per_function=k)
    corr = run_ladder(older, newer, passes=residual_passes(BodyMnemonics(older), BodyMnemonics(newer)), limits=limits)
    blocked, evaluated = corr.stat('blocked-pairs:P16'), corr.stat('evaluated:P16')
    assert 0 < evaluated == blocked <= k * 2 * n
    assert blocked < n * n // 4
    assert corr.stat('accepted:P16') == n                    # every twin shares three rare strings: all n pairs found
    assert not corr.stat('evaluated:P19')                    # nothing was left for the assignment


# ---- determinism across processes ------------------------------------------------------------------------------------------------------

def test_the_result_digest_is_stable_across_hash_seeds_and_processes():
    script = textwrap.dedent('''
        import sys
        sys.path[:0] = [sys.argv[1], sys.argv[2]]
        from unified_residual_support import BodyMnemonics, random_residual_world
        from patchtrace.unified.ladder.engine import run_ladder
        from patchtrace.unified.ladder.residual import pass_table
        older, newer = random_residual_world(7, 60)
        table = pass_table(older=BodyMnemonics(older), newer=BodyMnemonics(newer))
        corr = run_ladder(older, newer, passes=table)
        print(corr.digest(), len([p for p in corr.pairs if p.pass_id.startswith('P1') and p.pass_id >= 'P16']))
    ''')
    outputs = set()
    for hash_seed in ('0', '1', '4242'):
        env = {**os.environ, 'PYTHONHASHSEED': hash_seed, 'PYTHONDONTWRITEBYTECODE': '1'}
        done = subprocess.run([sys.executable, '-c', script, str(ROOT / 'src'), str(TESTS)], capture_output=True,
                              text=True, timeout=180, env=env, cwd=str(ROOT), check=True)
        outputs.add(done.stdout.strip())
    assert len(outputs) == 1
    digest, residual_pairs = outputs.pop().split()
    assert re.fullmatch(r'[0-9a-f]{64}', digest) and int(residual_pairs) > 0
