"""SPEC-31 gates G-U1 (X vs X) and G-U2 (planted mutations, leakage = 0) at unit level (08 s1).

Every mutant of the table in 08 s1, including the review's additions R-01..R-04, R-07 and R-16, is planted into a
hand-assembled function; none may ever be `unchanged` or `cosmetic` (every hit would be a normaliser bug and becomes
a fixture), and every one must land in `material` or `review`. The recorded real-Ghidra fixtures run X vs X.
Synthetic functions: this is not the corpus evidence of G-U2 (that is S6), it is the leakage regression test."""
from __future__ import annotations

import json
import random
from array import array
from pathlib import Path

import pytest
from test_unified_ir_facts import SYM, image
from unified_facts_builder import eh_json, function, run_facts

from patchtrace.unified import keys
from patchtrace.unified.addressing import AddressMap, PeLayout
from patchtrace.unified.facts import verdict
from patchtrace.unified.facts.channels import FactsContext
from patchtrace.unified.facts.irchannels import IrSides
from patchtrace.unified.ir.ingest import ExpectedSide, ingest
from patchtrace.unified.ir.pe_tables import PeTables, Primary, Section
from patchtrace.unified.ir.reader import IrReader

FIXTURES = Path(__file__).parent / 'fixtures' / 'unified'
SAFE = ('material', 'review')
IAT = 0x2100

BASE = [('sub_rsp', 0x28), ('cmp_ri', 'ECX', 6), ('jcc', 'A', 'fail'), ('load_g', 'EAX', 'g_a'), ('call', 'helper'),
        ('load_m', 'EDX', 'RBX', 0x10), ('add_ri', 'EAX', 3), ('store_g', 'g_b', 'EAX'), ('label', 'fail'),
        ('add_rsp', 0x28), ('ret',)]
THEN_ELSE = [('cmp_ri', 'ECX', 1), ('jcc', 'Z', 'then'), ('mov_ri', 'EAX', 2), ('jmp', 'end'), ('label', 'then'),
             ('mov_ri', 'EAX', 3), ('label', 'end'), ('ret',)]
TRACE = [('mov_ri', 'ECX', 0x100), ('call_iat', IAT, 'ntdll.dll!EtwWriteTransfer'), ('ret',)]


def swap(items, index, replacement):
    return [*items[:index], replacement, *items[index + 1:]]


def mutated(base, **edits):
    out = list(base)
    for position, replacement in sorted(edits.items(), key=lambda item: -int(item[0][1:])):
        out = swap(out, int(position[1:]), replacement)
    return out


def without(items, *positions):
    return [item for number, item in enumerate(items) if number not in positions]


MUTANTS = {
    'constant': (BASE, mutated(BASE, i6=('add_ri', 'EAX', 4)), {}),
    'bound-lt-le': (BASE, mutated(BASE, i2=('jcc', 'NC', 'fail')), {}),
    'comparison': ([('cmp_ri', 'ECX', 6), ('setcc', 'L', 'AL'), ('ret',)], [('cmp_ri', 'ECX', 6), ('setcc', 'LE', 'AL'),
                                                                            ('ret',)], {}),
    'signedness': (BASE, mutated(BASE, i2=('jcc', 'G', 'fail')), {}),
    'removed-check': (BASE, without(BASE, 1, 2), {}),
    'swapped-callee': (BASE, mutated(BASE, i4=('call', 'other')), {}),
    'struct-offset': (BASE, mutated(BASE, i5=('load_m', 'EDX', 'RBX', 0x14)), {}),
    'added-block': (BASE, [*BASE[:3], ('cmp_ri', 'EDX', 9), ('jcc', 'NZ', 'ok'), ('call', 'report'), ('label', 'ok'),
                           *BASE[3:]], {'with_report': True}),
    'swap-to-existing-global': (BASE, mutated(BASE, i3=('load_g', 'EAX', 'g_b')), {}),
    'index-register-swap': ([('load_tab', 'EAX', 'RDX', 'RAX', 'g_a'), ('ret',)],
                            [('load_tab', 'EAX', 'RDX', 'RCX', 'g_a'), ('ret',)], {}),
    'then-else-swap': (THEN_ELSE, [('cmp_ri', 'ECX', 1), ('jcc', 'Z', 'then'), ('mov_ri', 'EAX', 3), ('jmp', 'end'),
                                   ('label', 'then'), ('mov_ri', 'EAX', 2), ('label', 'end'), ('ret',)], {}),
    'buffer-resize': ([('sub_rsp', 0x28), ('store_s', 0x20, 'EAX'), ('add_rsp', 0x28), ('ret',)],
                      [('sub_rsp', 0x48), ('store_s', 0x40, 'EAX'), ('add_rsp', 0x48), ('ret',)], {}),
    'trace-arg': (TRACE, mutated(TRACE, i0=('mov_ri', 'ECX', 0x101)), {}),
}


def judged(tmp_path, old, new, extra):
    return run_facts_pair(tmp_path, old, new, **extra)


def run_facts_pair(tmp_path, old, new, **extra):
    with_report = extra.pop('with_report', False)
    return run_facts(tmp_path, image(old, with_report=False), image(new, with_report=with_report), **extra)


@pytest.mark.parametrize('name', sorted(MUTANTS))
def test_no_planted_mutant_leaks_into_cosmetic_or_unchanged(tmp_path, name):
    old, new, extra = MUTANTS[name]
    facts = judged(tmp_path, old, new, dict(extra)).facts('f')
    assert facts.verdict in SAFE and facts.proof is None, (name, facts.verdict, facts.proof)


def test_identical_bytes_at_a_moved_rva_whose_call_reaches_another_function_never_leak(tmp_path):
    old = [('mov_ri', 'EAX', 1), ('call', 'helper'), ('ret',)]
    new = [('mov_ri', 'EAX', 1), ('call', 'other'), ('ret',)]
    r = run_facts(tmp_path, image(old), image(new, f_rva=0x1100))
    assert dict(r.facts('f').channels)['C0'] == 'equal' and r.facts('f').verdict in SAFE


def test_an_added_try_scope_that_only_the_scope_table_shows_never_leaks(tmp_path):
    scopes_old = {0x1000: eh_json(handler=0x1200, scopes=[[0x10, 0x20, 1, 0x30]])}
    scopes_new = {0x1000: eh_json(handler=0x1200, scopes=[[0x10, 0x20, 1, 0x30], [0x40, 0x50, 1, 0x60]])}
    r = run_facts(tmp_path, image(BASE), image(BASE), old_eh=scopes_old, new_eh=scopes_new)
    assert dict(r.facts('f').channels)['C0'] == 'equal' and r.facts('f').verdict in SAFE


def test_trace_arg_constant_ordered_last_not_hidden(tmp_path):
    """F17: a constant that only feeds a tracing call is `review` with the hint `trace-arg` (the read model sorts it last
    inside its verdict); a plain constant edit in the same image has no hint; neither row loses its delta."""
    old, new, _extra = MUTANTS['trace-arg']

    def with_others(f_items, value):
        sleeping = [('mov_ri', 'ECX', value), ('call_iat', IAT + 8, 'kernel32.dll!Sleep'), ('ret',)]
        return sorted([*image(f_items), function(0x1600, [('mov_ri', 'EAX', value), ('ret',)], name='g', sym=SYM),
                       function(0x1700, sleeping, name='h', sym=SYM)], key=lambda fn: fn['rva'])
    r = run_facts(tmp_path, with_others(old, 1), with_others(new, 2))
    traced, plain, sleeping = r['f'], r['g'], r['h']
    assert traced.facts.verdict == plain.facts.verdict == sleeping.facts.verdict == 'review'
    assert 'trace-arg' in traced.hints
    assert 'trace-arg' not in plain.hints and 'trace-arg' not in sleeping.hints      # only a tracing callee counts
    assert traced.facts.deltas and plain.facts.deltas and sleeping.facts.deltas


@pytest.mark.parametrize('name', ['constant', 'struct-offset', 'swapped-callee'])
def test_a_planted_mutant_is_seen(tmp_path, name):
    """Recall at unit level: the delta exists and its class is the planted one."""
    old, new, extra = MUTANTS[name]
    deltas = judged(tmp_path, old, new, dict(extra)).facts('f').deltas
    assert {'constant': 'constant', 'struct-offset': 'struct-offset', 'swapped-callee': 'callee'}[name] in \
        {d.cls for d in deltas}


# --- G-U2 over many variants per class (08 s1: >= 20 mutants per class) ---------------------------------------------------

REGS = ('EAX', 'ECX', 'EDX', 'EBX')
VARIANTS = 20


def head(rng):
    return [('mov_ri', rng.choice(REGS), rng.randint(0, 9)) for _ in range(rng.randint(0, 3))]


def pick_other(rng, values, current):
    return rng.choice([value for value in values if value != current])


def plant_constant(rng):
    kind, reg, h = rng.choice(['add_ri', 'mov_ri', 'cmp_ri', 'sub_ri']), rng.choice(REGS), head(rng)
    a = rng.randint(2, 0x70)
    b = pick_other(rng, range(2, 0x71), a)
    return ([*h, (kind, reg, a), ('store_g', 'g_b', reg), ('ret',)], [*h, (kind, reg, b), ('store_g', 'g_b', reg), ('ret',)],
            {})


def plant_branch(pairs):
    def plant(rng):
        before, after = rng.choice(pairs)
        h, reg, n = head(rng), rng.choice(REGS), rng.randint(1, 0x70)
        body = [('load_g', 'EAX', 'g_a'), ('call', rng.choice(['helper', 'other']))]
        def shape(cc):
            return [*h, ('cmp_ri', reg, n), ('jcc', cc, 'out'), *body, ('label', 'out'), ('ret',)]
        return shape(before), shape(after), {}
    return plant


def plant_setcc(rng):
    before, after = rng.choice([('L', 'LE'), ('LE', 'L'), ('A', 'NC'), ('G', 'GE'), ('Z', 'NZ'), ('C', 'BE')])
    maker = rng.choice(['setcc', 'cmov'])
    h, n = head(rng), rng.randint(1, 0x70)

    def shape(cc):
        mid = ('setcc', cc, 'AL') if maker == 'setcc' else ('cmov', cc, 'EAX', 'EDX')
        return [*h, ('cmp_ri', 'ECX', n), mid, ('ret',)]
    return shape(before), shape(after), {}


def plant_removed_check(rng):
    h, reg, n, cc = head(rng), rng.choice(REGS), rng.randint(1, 0x70), rng.choice(['A', 'NC', 'L', 'Z', 'NZ', 'GE'])
    body = [('load_g', 'EAX', 'g_a'), ('call', rng.choice(['helper', 'other'])), ('store_g', 'g_b', 'EAX')]
    return ([*h, ('cmp_ri', reg, n), ('jcc', cc, 'out'), *body, ('label', 'out'), ('ret',)], [*h, *body, ('ret',)], {})


def plant_callee(rng):
    h, before = head(rng), rng.choice(['helper', 'other'])
    after = pick_other(rng, ['helper', 'other'], before)
    tail = [('mov_rr', 'EDX', 'EAX'), ('ret',)]
    return [*h, ('call', before), *tail], [*h, ('call', after), *tail], {}


def plant_struct_offset(rng):
    h, reg, base = head(rng), rng.choice(REGS), rng.choice(['RBX', 'RSI', 'RDI'])
    a = rng.choice([0x8, 0x10, 0x14, 0x18, 0x20, 0x28])
    b = pick_other(rng, [0x8, 0x10, 0x14, 0x18, 0x20, 0x28, 0x30], a)
    shape = rng.choice(['load_m', 'store_m'])
    def at(disp):
        return ('load_m', reg, base, disp) if shape == 'load_m' else ('store_m', base, disp, reg)
    return [*h, at(a), ('ret',)], [*h, at(b), ('ret',)], {}


def plant_added_block(rng):
    h, reg, n, cc = head(rng), rng.choice(REGS), rng.randint(1, 0x70), rng.choice(['A', 'NC', 'L', 'Z', 'NZ', 'GE'])
    rest = [('load_g', 'EAX', 'g_a'), ('add_ri', 'EAX', rng.randint(1, 9)), ('ret',)]
    guard = [('cmp_ri', reg, n), ('jcc', cc, 'ok'), ('call', 'report'), ('label', 'ok')]
    return [*h, *rest], [*h, *guard, *rest], {'with_report': True}


def plant_global_swap(rng):
    h, reg = head(rng), rng.choice(REGS)
    before, after = rng.choice([('g_a', 'g_b'), ('g_b', 'g_a')])
    shape = rng.choice(['load_g', 'store_g'])
    def use(name):
        return ('load_g', reg, name) if shape == 'load_g' else ('store_g', name, reg)
    return [*h, use(before), ('ret',)], [*h, use(after), ('ret',)], {}


def plant_index_swap(rng):
    h, reg, base = head(rng), rng.choice(REGS), rng.choice(['RDX', 'RBX', 'RSI'])
    a = rng.choice(['RAX', 'RCX', 'RDI'])
    b = pick_other(rng, ['RAX', 'RCX', 'RDI'], a)
    return [*h, ('load_tab', reg, base, a, 'g_a'), ('ret',)], [*h, ('load_tab', reg, base, b, 'g_a'), ('ret',)], {}


def plant_then_else(rng):
    cc, n, a = rng.choice(['Z', 'NZ', 'L', 'GE', 'A']), rng.randint(1, 0x70), rng.randint(2, 0x70)
    b = pick_other(rng, range(2, 0x71), a)

    def shape(first, second):
        return [('cmp_ri', 'ECX', n), ('jcc', cc, 'then'), ('mov_ri', 'EAX', first), ('jmp', 'end'), ('label', 'then'),
                ('mov_ri', 'EAX', second), ('label', 'end'), ('ret',)]
    return shape(a, b), shape(b, a), {}


def plant_buffer_resize(rng):
    reg, d = rng.choice(REGS), rng.choice([0x20, 0x24, 0x28])
    a = rng.choice([0x28, 0x38, 0x48])
    b = pick_other(rng, [0x28, 0x38, 0x48, 0x58, 0x68], a)

    def shape(size):
        return [('sub_rsp', size), ('store_s', d, reg), ('add_rsp', size), ('ret',)]
    return shape(a), shape(b), {}


def plant_trace_arg(rng):
    api = rng.choice(['EtwWrite', 'EtwWriteTransfer', 'EtwWriteString', 'EtwWriteEx', 'TraceMessage'])
    dll = 'advapi32.dll' if api == 'TraceMessage' else 'ntdll.dll'
    reg, a = rng.choice(['ECX', 'EDX', 'EAX']), rng.randint(2, 0x70)
    b = pick_other(rng, range(2, 0x71), a)

    def shape(value):
        return [('mov_ri', reg, value), ('call_iat', IAT, f'{dll}!{api}'), ('ret',)]
    return shape(a), shape(b), {}


PLANTERS = {
    'constant': plant_constant,
    'bound-lt-le': plant_branch([('A', 'NC'), ('NC', 'A'), ('L', 'LE'), ('LE', 'L'), ('G', 'GE'), ('GE', 'G'), ('BE', 'C'),
                                 ('C', 'BE')]),
    'comparison': plant_setcc,
    'signedness': plant_branch([('L', 'C'), ('C', 'L'), ('G', 'A'), ('A', 'G'), ('GE', 'NC'), ('NC', 'GE'), ('LE', 'BE'),
                                ('BE', 'LE')]),
    'removed-check': plant_removed_check,
    'swapped-callee': plant_callee,
    'struct-offset': plant_struct_offset,
    'added-block': plant_added_block,
    'swap-to-existing-global': plant_global_swap,
    'index-register-swap': plant_index_swap,
    'then-else-swap': plant_then_else,
    'buffer-resize': plant_buffer_resize,
    'trace-arg': plant_trace_arg,
}
SEEN_AS = {'constant': {'constant'}, 'bound-lt-le': {'condition'}, 'comparison': {'comparison'},
           'signedness': {'condition'}, 'swapped-callee': {'callee'}, 'struct-offset': {'struct-offset'},
           'swap-to-existing-global': {'data-ref'}, 'index-register-swap': {'register-only'},
           'buffer-resize': {'frame'}, 'trace-arg': {'constant'}, 'added-block': {'block-added', 'call-added'}}


def test_every_class_has_a_planter_and_the_planters_cover_the_table():
    assert set(PLANTERS) == set(MUTANTS)


@pytest.mark.parametrize('name', sorted(PLANTERS))
def test_twenty_variants_of_every_mutant_class_never_leak_and_are_always_seen(tmp_path, name):
    """Leakage 0 and recall 100 percent over VARIANTS random members of the class; frame-only and trace-arg mutants must
    be `review` (never material, never cosmetic)."""
    for seed in range(VARIANTS):
        old, new, extra = PLANTERS[name](random.Random(f'{name}:{seed}'))
        assert old != new
        facts = run_facts_pair(tmp_path, old, new, **extra).facts('f')
        where = (name, seed, facts.verdict, facts.proof, [d.cls for d in facts.deltas])
        assert facts.verdict in SAFE and facts.proof is None, where
        if name in ('buffer-resize', 'trace-arg'):
            assert facts.verdict == 'review', where
        if name in SEEN_AS:
            assert SEEN_AS[name] & {d.cls for d in facts.deltas}, where


# --- G-U1: the engine invents no change on X vs X -----------------------------------------------------------------------

def test_x_vs_x_every_function_is_unchanged(tmp_path):
    base = image(BASE)
    r = run_facts(tmp_path, base, base, identical=True)
    assert {name: r.verdict(name) for name in r.judged} == {name: ('unchanged', 'UNCH/1') for name in r.judged}


def test_a_rebuild_of_the_same_sources_is_unchanged_or_cosmetic_never_material(tmp_path):
    """P0: same sources, different artifact hash, every global used by several functions (so the votes can map it)."""
    base = image(BASE)
    r = run_facts(tmp_path, base, base)
    assert {r.verdict(name)[0] for name in r.judged} <= {'unchanged', 'cosmetic'}


def pe_from_json(path):
    data = json.loads(path.read_text(encoding='utf-8'))
    tables = PeTables(image_base=data['image_base'], size_of_image=data['size_of_image'],
                      sections=tuple(Section(n, a, b, e) for n, a, b, e in data['sections']),
                      relocs=array('I', data['relocs']), warnings=list(data['warnings']))
    for begin, item in data['primaries'].items():
        tables.primaries[int(begin)] = Primary(int(begin), item['end'], item['unwind'], [tuple(c) for c in item['chunks']])
        tables.eh[int(begin)] = item['eh']
    return tables, data


def recorded(tmp_path, stem):
    tables, data = pe_from_json(FIXTURES / f'{stem}.pe.json')
    out = tmp_path / stem
    out.mkdir()
    result = ingest(FIXTURES / f'{stem}.ir.jsonl', ExpectedSide('older', data['sha256'], tables, mode='analyze'),
                    out_dir=out)
    return IrReader.open(result.directory), tables, data


def judge_by_name(old, new, tables_old, tables_new, sha_old, sha_new, *, identical):
    from unified_facts_builder import decided
    names = lambda reader: {reader.functions.name[i]: reader.functions.get('rva', i)  # noqa: E731
                            for i in range(reader.functions.n)}
    no, nn = names(old), names(new)
    rows = [decided(no[name], nn[name]) for name in sorted(no) if name in nn]
    layout = lambda reader: PeLayout(image_base=reader.manifest.image_base,  # noqa: E731
                                     size_of_image=reader.manifest.size_of_image)
    sides = IrSides(old, new, tuple((s.start, s.end) for s in tables_old.sections),
                    tuple((s.start, s.end) for s in tables_new.sections), identical)
    context = FactsContext.build(older_sha256=sha_old, newer_sha256=sha_new, addr=AddressMap(layout(old), layout(new)),
                                 matches=[], rows=rows, bindiff_flags={}, ir_sides=sides)
    by_rva = {rva: name for name, rva in no.items()}
    return {by_rva[row.pair[0]]: verdict.judge(keys.row_id(sha_old, sha_new, row.older, row.newer), row.decision,
                                               context.collect(row)) for row in rows}


@pytest.mark.parametrize('stem', ['probe_old', 'mingw_old'])
def test_recorded_real_ghidra_images_x_vs_x_are_all_unchanged(tmp_path, stem):
    """G-U1 X vs X on REAL Ghidra 12.0.4 output (recorded fixtures, tests/fixtures/unified/PROVENANCE.json)."""
    reader, tables, data = recorded(tmp_path, stem)
    result = judge_by_name(reader, reader, tables, tables, data['sha256'], data['sha256'], identical=True)
    assert len(result) == reader.functions.n
    assert {name: (j.facts.verdict, j.facts.proof) for name, j in result.items() if j.facts.verdict != 'unchanged'} == {}


def test_recorded_probe_pair_real_ghidra_verdicts(tmp_path):
    """The recorded clang pair: untouched code is unchanged, the planted edits are seen and none is hidden."""
    old, tables_old, data_old = recorded(tmp_path, 'probe_old')
    new, tables_new, data_new = recorded(tmp_path, 'probe_new')
    result = judge_by_name(old, new, tables_old, tables_new, data_old['sha256'], data_new['sha256'], identical=False)
    got = {name: (j.facts.verdict, j.facts.proof) for name, j in result.items()}
    assert got['limit_check'] == got['loop_sum'] == ('unchanged', 'UNCH/1')       # moved, bytes equal, targets mapped
    assert got['tick'] == ('cosmetic', 'COS-ADDR/1')                               # a call to the moved add_clamped
    classes = {name: sorted({d.cls for d in j.facts.deltas}) for name, j in result.items()}
    assert classes['add_clamped'] == ['constant'] and result['add_clamped'].facts.verdict == 'review'
    assert classes['dispatch'] == ['constant'] and result['dispatch'].facts.verdict == 'review'
    assert 'string' in classes['say'] and result['say'].facts.verdict == 'review'
    assert result['use_data'].facts.verdict in SAFE
    assert not [name for name, (v, _p) in got.items() if v in ('unchanged', 'cosmetic') and name in
                ('add_clamped', 'dispatch', 'say', 'use_data')]
    back = judge_by_name(new, old, tables_new, tables_old, data_new['sha256'], data_old['sha256'], identical=False)
    assert {name: (j.facts.verdict, j.facts.proof) for name, j in back.items()} == got        # G-U4: the swap mirrors it
