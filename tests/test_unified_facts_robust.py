"""SPEC-31 S3 robustness: whatever two functions look like, the IR facts are computed, valid, deterministic and never
more optimistic than the evidence. Real Ghidra instruction shapes (every ordered pair of the recorded mingw image is
judged as if a matcher had paired the two) plus generated programs with planted edits."""
from __future__ import annotations

import random

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from test_unified_gu_mutants import judge_by_name, recorded
from test_unified_ir_facts import SYM, image
from unified_facts_builder import decided, run_facts

from patchtrace.unified import keys
from patchtrace.unified.addressing import AddressMap, PeLayout
from patchtrace.unified.facts import verdict
from patchtrace.unified.facts.channels import FactsContext
from patchtrace.unified.facts.irchannels import IrSides

GLOBALS = ('g_a', 'g_b', 'g_c')
CALLEES = ('helper', 'other')
REGISTERS = ('EAX', 'ECX', 'EDX', 'EBX')
CONDITIONS = ('Z', 'NZ', 'L', 'GE', 'A', 'NC')


def simple(rng: random.Random):
    kind = rng.choice(['mov_ri', 'add_ri', 'cmp_ri', 'mov_rr', 'load_g', 'store_g', 'call', 'load_m', 'xor_rr', 'nop',
                       'setcc', 'sub_ri'])
    reg, reg2 = rng.choice(REGISTERS), rng.choice(REGISTERS)
    if kind in ('mov_ri', 'add_ri', 'cmp_ri', 'sub_ri'):
        return (kind, reg, rng.choice([0, 1, 5, 6, 0x40, 0x7f, -3]))
    if kind == 'mov_rr' or kind == 'xor_rr':
        return (kind, reg, reg2)
    if kind == 'load_g':
        return (kind, reg, rng.choice(GLOBALS))
    if kind == 'store_g':
        return (kind, rng.choice(GLOBALS), reg)
    if kind == 'call':
        return (kind, rng.choice(CALLEES))
    if kind == 'load_m':
        return (kind, reg, rng.choice(['RBX', 'RSI']), rng.choice([0x8, 0x10, 0x14]))
    if kind == 'setcc':
        return (kind, rng.choice(CONDITIONS), 'AL')
    return (kind,)


def program(seed: int) -> list:
    rng = random.Random(seed)
    items: list = []
    for number in range(rng.randint(1, 4)):
        items.append(simple(rng))
        if rng.random() < 0.6:
            label = f'L{number}'
            items += [('cmp_ri', 'ECX', rng.randint(0, 9)), ('jcc', rng.choice(CONDITIONS), label)]
            items += [simple(rng) for _ in range(rng.randint(1, 3))]
            items.append(('label', label))
    items.append(('ret',))
    return items


def mutate(items: list, seed: int) -> list:
    rng = random.Random(seed)
    out = list(items)
    for _ in range(rng.randint(1, 3)):
        movable = [i for i, item in enumerate(out) if item[0] not in ('label', 'ret', 'jcc', 'jmp')]
        choice = rng.choice(['edit', 'delete', 'insert', 'swap', 'condition'])
        if choice == 'delete' and movable:
            del out[rng.choice(movable)]
        elif choice == 'insert':
            out.insert(rng.randint(0, len(out) - 1), simple(rng))
        elif choice == 'swap' and len(movable) > 1:
            a, b = rng.sample(movable, 2)
            out[a], out[b] = out[b], out[a]
        elif choice == 'condition':
            branches = [i for i, item in enumerate(out) if item[0] == 'jcc']
            if branches:
                at = rng.choice(branches)
                out[at] = ('jcc', rng.choice(CONDITIONS), out[at][2])
        elif movable:
            at = rng.choice(movable)
            out[at] = simple(rng)
    return out


@settings(max_examples=120, deadline=None, derandomize=True, suppress_health_check=[HealthCheck.too_slow])
@given(st.integers(0, 10 ** 6), st.integers(0, 10 ** 6), st.booleans())
def test_generated_programs_with_planted_edits_never_crash_and_stay_deterministic(tmp_path_factory, seed, edit, moved):
    tmp = tmp_path_factory.mktemp('gen')
    old = program(seed)
    new = mutate(old, edit)
    first = run_facts(tmp, image(old), image(new, f_rva=0x1100 if moved else 0x1000, shift=0x40 if moved else 0))
    again = run_facts(tmp, image(old), image(new, f_rva=0x1100 if moved else 0x1000, shift=0x40 if moved else 0))
    assert first.facts('f') == again.facts('f') and first['f'].classes == again['f'].classes
    facts = first.facts('f')
    if facts.verdict in ('unchanged', 'cosmetic'):
        assert facts.targets[1] == facts.targets[2] == 0 and not facts.deltas
    same = run_facts(tmp, image(old), image(old), identical=True)
    assert {j.facts.verdict for j in same.judged.values()} == {'unchanged'}


@settings(max_examples=100, deadline=None, derandomize=True, suppress_health_check=[HealthCheck.too_slow])
@given(st.integers(0, 10 ** 6), st.integers(0, 10 ** 6), st.booleans())
def test_swapping_the_two_sides_gives_the_same_verdict_and_proof(tmp_path_factory, seed, edit, moved):
    """G-U4 (08 s1) at the facts level: the verdict and the proof do not depend on which build is called older. The
    delta classes are mirrored only up to the (non-unique) alignment, so they are not compared."""
    tmp = tmp_path_factory.mktemp('swap')
    old = program(seed)
    new = mutate(old, edit)
    moved_new = image(new, f_rva=0x1100 if moved else 0x1000, shift=0x40 if moved else 0)
    forward = run_facts(tmp, image(old), moved_new).facts('f')
    backward = run_facts(tmp, moved_new, image(old)).facts('f')
    assert (forward.verdict, forward.proof) == (backward.verdict, backward.proof)


def test_every_ordered_pair_of_real_functions_is_judged_without_error_and_never_hidden_by_mistake(tmp_path):
    """The recorded mingw image has 61 functions of every shape the CRT has: judge each against each (a hostile
    matcher): no exception, and a pair of different functions is never `unchanged`."""
    reader, tables, data = recorded(tmp_path, 'mingw_old')
    n = reader.functions.n
    rvas = [reader.functions.get('rva', i) for i in range(n)]
    layout = PeLayout(image_base=reader.manifest.image_base, size_of_image=reader.manifest.size_of_image)
    sides = IrSides(reader, reader, tuple((s.start, s.end) for s in tables.sections),
                    tuple((s.start, s.end) for s in tables.sections), identical=False)
    rows = [decided(a, b, decision='candidate', tier='C') for a in rvas for b in rvas]
    context = FactsContext.build(older_sha256=data['sha256'], newer_sha256='f' * 64, addr=AddressMap(layout, layout),
                                 matches=[], rows=[decided(r, r) for r in rvas], bindiff_flags={}, ir_sides=sides)
    different_but_unchanged = []
    for row in rows:
        judged = verdict.judge(keys.row_id(data['sha256'], 'f' * 64, row.older, row.newer), row.decision,
                               context.collect(row))
        if judged.facts.verdict == 'unchanged':
            same_bytes = reader.functions.get('h0', reader.functions.rva_to_fid[row.pair[0]]) == \
                reader.functions.get('h0', reader.functions.rva_to_fid[row.pair[1]])
            if not same_bytes:
                different_but_unchanged.append(row.pair)
    assert different_but_unchanged == []


def test_real_functions_judged_twice_give_the_same_facts(tmp_path):
    reader, tables, data = recorded(tmp_path, 'probe_old')
    first = judge_by_name(reader, reader, tables, tables, data['sha256'], data['sha256'], identical=False)
    second = judge_by_name(reader, reader, tables, tables, data['sha256'], data['sha256'], identical=False)
    assert {n: j.facts for n, j in first.items()} == {n: j.facts for n, j in second.items()}


@pytest.mark.parametrize('symbols', [SYM], ids=['sym'])
def test_the_generated_world_uses_known_symbols(symbols):
    assert set(GLOBALS) <= set(symbols) and set(CALLEES) <= set(symbols)
