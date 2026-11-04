"""Audit regressions of the L1 ladder (card `lad`, 2026-11-04). SYNTHETIC IR only."""
from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from unified_ir_builder import SyntheticIr, pairs_by_tag  # noqa: E402

from patchtrace.unified.ladder import blocking, passes, propagate  # noqa: E402
from patchtrace.unified.ladder.blocking import MinHasher, Signatures  # noqa: E402
from patchtrace.unified.ladder.engine import run_ladder  # noqa: E402
from patchtrace.unified.ladder.passes import PASS_TABLE_DIGEST, PASSES, pass_table_digest  # noqa: E402
from patchtrace.unified.ladder.residual import pass_table, table_digest  # noqa: E402
from patchtrace.unified.limits import Budget, UnifiedError  # noqa: E402

# ---- (f) U7-12: an unresolved callee never reaches tier A through P15 ------------------------------------------------------


def _wrappers(extra_call):
    """Two wrappers of one shape that differ only in WHICH matched callee they call first (so only P15 can split them)."""
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        ir.add('w1', seed=5, calls=('f1', 'f2', *extra_call))
        ir.add('w2', seed=5, calls=('f2', 'f1', *extra_call))
        ir.add('f1', seed=11)
        ir.add('f2', seed=12)
    newer.specs[2].rva = 0x9000                      # f1 moved: h0 differs, h1 stays equal
    return older, newer


def test_control_p15_matches_wrappers_whose_callees_are_all_resolved():
    older, newer = _wrappers(())
    pairs = pairs_by_tag(run_ladder(older, newer), older, newer)
    assert (pairs[('w1', 'w1')].pass_id, pairs[('w1', 'w1')].tier) == ('P15', 'A')


def test_unresolved_callee_keeps_a_wrapper_out_of_p15_and_out_of_tier_a():
    older, newer = _wrappers((None,))              # an indirect call with no import key: callee is unknown
    corr = run_ladder(older, newer)
    pairs = pairs_by_tag(corr, older, newer)
    assert not any(p.pass_id == 'P15' for p in corr.pairs)
    assert ('w1', 'w1') not in pairs and ('w2', 'w2') not in pairs
    assert not any(p.tier == 'A' and older.tag_of(p.older_fid).startswith('w') for p in corr.pairs)


# ---- manual anchors are validated with a typed error ----------------------------------------------------------------------------

@pytest.mark.parametrize('bad', [[(0,)], [(0, 0, 0)], [None], [5]], ids=['short', 'long', 'none', 'int'])
def test_malformed_anchor_is_an_input_error_not_a_crash(bad):
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('a', seed=1)
    newer.add('a', seed=1)
    with pytest.raises(UnifiedError) as caught:
        run_ladder(older, newer, anchors=bad)
    assert caught.value.code == 'PT-UNIFIED-INPUT'


# ---- (g) the pass-table digest covers what the rows cannot show ----------------------------------------------------------------

def test_digest_changes_when_a_pass_swaps_its_key_guard_or_run_function():
    base = pass_table_digest()
    assert base == PASS_TABLE_DIGEST

    def other(*args, **kwargs):               # a different function object with a different qualified name
        return None
    for index, attr in ((3, 'keys'), (2, 'guard'), (14, 'run'), (11, 'guard')):
        swapped = list(PASSES)
        swapped[index] = dataclasses.replace(swapped[index], **{attr: other})
        assert pass_table_digest(swapped) != base, (PASSES[index].id, attr)


@pytest.mark.parametrize('field,value', [('tier', 'C'), ('stage', 9), ('family', 'F-X'), ('cls', 'E-X'), ('hubs', True),
                                         ('neighbour', False), ('bytes_family', False), ('name', 'renamed')])
def test_digest_changes_with_every_row_field(field, value):
    rows = list(PASSES)
    current = getattr(rows[3], field)
    value = (not current) if isinstance(current, bool) else value
    rows[3] = dataclasses.replace(rows[3], **{field: value})
    assert pass_table_digest(rows) != PASS_TABLE_DIGEST


@pytest.mark.parametrize('module,name,value', [
    (passes, 'P15_MAX_WAVES', 3), (passes, 'MAX_CALL_SITES', 100),
    (blocking, 'SHINGLE', 4), (blocking, 'BANDS', 2), (blocking, 'MIN_SHARED', 3), (blocking, 'MNEMONIC_CHARS', 16),
], ids=['p15-waves', 'callsites', 'shingle', 'bands', 'min-shared', 'mnemonic-chars'])
def test_digest_changes_with_the_tuning_constants_that_are_not_pass_rows(monkeypatch, module, name, value):
    assert propagate.MAX_CALL_SITES == passes.MAX_CALL_SITES      # one definition: the engine and the digest agree
    before_s2, before_all = pass_table_digest(), table_digest(pass_table())
    monkeypatch.setattr(module, name, value)
    if module is passes:
        assert pass_table_digest() != before_s2
    assert table_digest(pass_table()) != before_all


# ---- I7: the MinHash stream is metered by its length, not by the function count ------------------------------------------------

def test_reading_a_long_instruction_stream_costs_budget_proportionally():
    class Stream:
        def mnemonics(self, fid):
            return ('mov', 'add', 'xor', 'cmp') * 2048          # 8192 instructions

    budget = Budget(check_every=10 ** 9)
    Signatures(Stream(), MinHasher(), 100_000, tick=budget.tick).bands(0)
    assert budget.used >= 8192 // 64
