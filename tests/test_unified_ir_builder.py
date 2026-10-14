"""Self-tests of the synthetic IR builder (tests/unified_ir_builder.py). SYNTHETIC data only: these tests prove the
fixture generator behaves as documented, they are not evidence about Ghidra, MSVC output or BinDiff."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from unified_ir_builder import (  # noqa: E402
    Insn,
    SyntheticIr,
    body_keys,
    cfg_keys,
    generate_pair,
    make_body,
    md_index,
    md_key,
    plain_sum,
    twin,
)

from patchtrace.unified.ladder.ports import IrSide  # noqa: E402


def test_md_index_diamond_vector():
    """04 s9 vector for the BUILDER's reference md_index (test support). Slice S1 owns `ir/mdindex.py` and ships
    the same three test names (diamond vector, plain loop, NULL below L-11 blocks) against that module."""
    value = md_index(4, [(0, 1), (0, 2), (1, 3), (2, 3)])
    assert abs(value - 0.277559753195558) < 1e-12
    assert md_key(value) == 277559753196


def test_md_index_plain_loop_not_compensated_sum():
    planted = [1e16, 1.0, -1e16]
    assert plain_sum(planted) == 0.0                       # the C++ loop loses the 1.0 ...
    assert sum(planted) == 1.0                             # ... Python 3.12+ sum() keeps it: the two differ
    assert plain_sum([0.1] * 10) == pytest.approx(1.0) and plain_sum([0.1] * 10) != 1.0


def test_md_null_below_min_blocks():
    """The builder emits md keys for any CFG with edges; the ladder's P10 gate (L-11 = 5 blocks) ignores shorter ones."""
    assert cfg_keys(((1,), (2,), (3,), ())) != {'md_td': None, 'md_bu': None}
    assert cfg_keys(((), (), ())) == {'md_td': None, 'md_bu': None}          # no edges -> NULL


def test_builder_md_is_isomorphism_invariant():
    a = md_index(4, [(0, 1), (0, 2), (1, 3), (2, 3)])
    b = md_index(4, [(0, 2), (0, 1), (2, 3), (1, 3)])          # same shape, successors listed in another order
    c = md_index(4, [(0, 3), (0, 1), (1, 2), (3, 2)])          # relabelled diamond
    assert a == b == c


def test_builder_key_levels_are_nested():
    base = make_body(7, 10)
    keys = body_keys(base)

    def changed(body):
        other = body_keys(body)
        return {name for name in keys if keys[name] != other[name]}

    moved = tuple(i._replace(addr=(i.addr or 0) + 64) if i.addr is not None else i for i in base)
    assert changed(moved) == {'h0'}                                      # address shift only
    const = tuple(i._replace(imm=i.imm + 1) if i.imm is not None else i for i in base)
    assert changed(const) == {'h0', 'h1'}                                # immediates survive h2
    renamed = tuple(i._replace(regs=tuple('r15' for _ in i.regs)) for i in base)
    assert changed(renamed) == {'h0', 'h1', 'h2'}                        # register names survive h3
    swapped = list(base)
    swapped[2], swapped[3] = swapped[3], swapped[2]
    assert changed(tuple(swapped)) <= {'h0', 'h1', 'h2', 'h3', 'hm'}
    assert 'hms' not in changed(tuple(swapped))                           # multiset ignores order
    assert 'hms' in changed((*base, Insn('push', ('rax',))))


def test_builder_distinct_seeds_do_not_collide():
    seen = {body_keys(make_body(s, 12))['h0'] for s in range(300)}
    assert len(seen) == 300


def test_builder_rows_satisfy_port_and_fid_is_rank_by_rva():
    ir = SyntheticIr()
    ir.add('b', seed=2, rva=0x3000, calls=('a', 'imp:k32!Open', None, ('jump', 'a')), strings=('hello world',),
           consts=(0x12345,))
    ir.add('a', seed=1, rva=0x2000)
    ir.add('open', kind='external', import_key='k32!Open')
    assert isinstance(ir, IrSide)
    rows = list(ir.function_rows())
    assert [r.fid for r in sorted(rows)] == [0, 1, 2]
    assert [r.rva for r in sorted(rows)] == sorted(r.rva for r in rows)       # rank by rva
    assert ir.tag_of(0) == 'open' and ir.fid('a') == 1 and ir.fid('b') == 2     # externals get low synthetic rvas
    calls = sorted(ir.call_rows(), key=lambda c: c.site)
    assert [(c.callee, c.import_key, c.jump) for c in calls] == [(1, None, False), (None, 'k32!Open', False),
                                                                (None, None, False), (1, None, True)]
    assert list(ir.string_rows())[0].length == len('hello world')
    assert [c.value for c in ir.constant_rows()] == [0x12345]


def test_builder_row_order_option_only_permutes_emission():
    plain = SyntheticIr()
    shuffled = SyntheticIr(row_order=5)
    for ir in (plain, shuffled):
        for i in range(12):
            ir.add(f'f{i}', seed=i, calls=(f'f{(i + 1) % 12}',), strings=(f'string-{i}',))
    assert sorted(plain.function_rows()) == sorted(shuffled.function_rows())
    assert sorted(plain.call_rows()) == sorted(shuffled.call_rows())
    assert list(plain.function_rows()) != list(shuffled.function_rows())


def test_builder_twin_and_overrides():
    older, newer = twin(['a', 'b'], n_insn=10)
    assert sorted(older.function_rows()) == sorted(newer.function_rows())
    newer.specs[0].keys['h2'] = 12345
    assert {r.h2 for r in newer.function_rows()} >= {12345}


def test_builder_generated_pair_is_deterministic_with_truth():
    one = generate_pair(400, seed=3)
    two = generate_pair(400, seed=3)
    assert list(one.older.function_rows()) == list(two.older.function_rows())
    assert one.truth == two.truth and one.stats == two.stats
    assert len(one.truth) == one.stats['functions'] - one.stats['kind_removed']
    older_rvas = {r.rva for r in one.older.function_rows()}
    newer_rvas = {r.rva for r in one.newer.function_rows()}
    assert set(one.truth) <= older_rvas and set(one.truth.values()) <= newer_rvas
    other = generate_pair(400, seed=4)
    assert list(other.older.function_rows()) != list(one.older.function_rows())


@pytest.mark.parametrize('n', [50, 2000])
def test_builder_generated_side_passes_port_validation(n):
    from patchtrace.unified.ladder.side import SideData
    pair = generate_pair(n, seed=11)
    older = SideData.from_ir(pair.older)
    newer = SideData.from_ir(pair.newer)
    assert older.n == n and newer.n >= n * 0.9
