"""SPEC-32 s8 planted mutations: every operator on synthetic C, compile-checked by clang -fsyntax-only (BLOCKED, never
a silent skip, without clang), deterministic site order, recorded rejections, replay."""
from __future__ import annotations

import json

import pytest

from tools.calibration.common import det_uniform
from tools.calibration.mutations import contracts as MC
from tools.calibration.mutations import engine as E
from tools.calibration.tier_r import toolchain as T
from tools.calibration.tier_r.csrc import Source, compare_spans

H = 'void note(int v);\nint mix(int a, int b);\n'
CODE = '''#include "a.h"
static int clampv(int v, int hi)
{
    if (v > hi) {
        return hi;
    }
    return v;
}

int sum(const int *p, int n)
{
    int total = 0;
    int i;
    for (i = 0; i < n; i++) {
        total += p[i];
    }
    note(total);
    return total;
}

int use(int a, int b)
{
    int r = mix(a, b);
    note(r);
    return clampv(r, 10);
}
'''
FILES = {'a.h': H, 'a.c': CODE}
BASE = MC.SourceRef(suite='_template/tiny', version='v1', license_spdx='MIT')
SEMANTIC = ('cmp-flip', 'const-change', 'bounds-check-insert', 'bounds-check-remove', 'call-add', 'call-remove',
            'arg-swap', 'loop-bound', 'off-by-one', 'int-width')
COSMETIC = ('ws-comment', 'dead-code', 'reorder-defs', 'local-rename', 'macro-rewrite', 'inline-toggle')
TARGET = {'bounds-check-remove': 'clampv', 'inline-toggle': 'clampv', 'reorder-defs': 'clampv', 'arg-swap': 'use'}


@pytest.fixture(scope='module')
def chain():
    return T.probe(names=['clang'])


@pytest.fixture
def clang(chain, record_live_status):
    if not chain.get('clang').ok:
        record_live_status('mutations-clang', 'blocked', str(chain.get('clang').reason))
        pytest.skip(f'BLOCKED (recorded, not a pass): clang: {chain.get("clang").reason}')
    return chain


def target_of(op):
    return ('a.c', TARGET.get(op, 'sum'))


@pytest.mark.parametrize('op', SEMANTIC + COSMETIC)
def test_plan_has_sites_and_is_det_uniform_ordered(op):
    plan = E.plan_mutants(FILES, op, seed=5)
    assert plan, op
    assert [c.key for c in plan] == sorted(c.key for c in plan)
    for c in plan:
        assert c.key == det_uniform(5, op, c.file, c.function, c.site)
    assert plan == E.plan_mutants(FILES, op, seed=5)
    assert all(c.operator == op for c in plan)


def test_other_seed_reorders_and_target_filters():
    a = E.plan_mutants(FILES, 'cmp-flip', seed=1)
    b = E.plan_mutants(FILES, 'cmp-flip', seed=2)
    assert {(c.function, c.site) for c in a} == {(c.function, c.site) for c in b}
    only = E.plan_mutants(FILES, 'cmp-flip', seed=1, target=('a.c', 'sum'))
    assert only and {c.function for c in only} == {'sum'}


def test_hostile_c_comments_and_strings_are_not_sites():
    hostile = {'b.c': '/* if (a < b) {} */\nconst char *s = "a < b";\nint f(void)\n{\n    return 3; // x < 4\n}\n'}
    assert E.plan_mutants(hostile, 'cmp-flip', seed=1) == []
    consts = E.plan_mutants(hostile, 'const-change', seed=1)
    assert [c.before for c in consts] == ['3']


@pytest.mark.parametrize('op', SEMANTIC + COSMETIC)
def test_apply_compiles_records_and_is_deterministic(clang, op):
    out = E.apply_case(FILES, op, seed=3, base=BASE, tools=clang, target=target_of(op))
    again = E.apply_case(FILES, op, seed=3, base=BASE, tools=clang, target=target_of(op))
    assert out.files == again.files and out.case == again.case
    case = out.case
    assert case.operator == op and case.target_function == target_of(op)[1] and case.attempts == 1
    assert case.kind == ('semantic' if op in SEMANTIC else 'cosmetic')
    assert out.files != FILES and out.changed == ('a.c',)
    assert case.patch_sha256 == MC.patch_digest(FILES, out.files)
    assert MC.load_case(MC.dump_case(case)) == case
    old, new = Source(CODE), Source(out.files['a.c'])
    name = target_of(op)[1]
    verdict = compare_spans(old, old.by_name(name)[0], new, new.by_name(name)[0])
    expected = {'ws-comment': 'layout-only', 'reorder-defs': 'same-text'}.get(op, 'token-change')
    assert verdict == expected, (op, out.files['a.c'])
    if op == 'ws-comment':
        assert [t.text for t in old.sig] == [t.text for t in new.sig]
    if op == 'reorder-defs':
        assert [f.name for f in new.functions][:2] == ['sum', 'clampv'] and case.moved_function == 'sum'
    if op == 'call-add':
        assert case.helper and new.by_name(case.helper)


@pytest.mark.parametrize('op', ('cmp-flip', 'bounds-check-insert', 'call-add', 'dead-code'))
def test_unselected_functions_are_untouched(clang, op):
    out = E.apply_case(FILES, op, seed=3, base=BASE, tools=clang, target=target_of(op))
    old, new = Source(CODE), Source(out.files['a.c'])
    for fn in ('clampv', 'use'):
        a, b = old.by_name(fn)[0], new.by_name(fn)[0]
        assert old.text[a.start:a.end] == new.text[b.start:b.end]


def test_untargeted_pick_is_first_in_plan_and_replays(clang):
    plan = E.plan_mutants(FILES, 'const-change', seed=11)
    out = E.apply_case(FILES, 'const-change', seed=11, base=BASE, tools=clang)
    assert (out.case.target_file, out.case.target_function) == (plan[0].file, plan[0].function)
    assert out.case.site.before == plan[0].before and out.case.site.after == plan[0].after
    assert E.replay_case(FILES, out.case) == out.files
    bad = out.case.model_copy(update={'patch_sha256': '0' * 64})
    with pytest.raises(ValueError, match='patch'):
        E.replay_case(FILES, bad)


def test_rejections_are_recorded_and_next_site_is_tried():
    plan = E.plan_mutants(FILES, 'dead-code', seed=4, target=('a.c', 'sum'))
    calls = []

    def checker(files, rel):
        calls.append(rel)
        return 'synthetic reject' if len(calls) <= 2 else None
    out = E.apply_case(FILES, 'dead-code', seed=4, base=BASE, checker=checker, target=('a.c', 'sum'))
    assert out.case.attempts == 3 and len(out.case.rejected) == 2
    assert [(r.line, r.column) for r in out.case.rejected] == [(c.line, c.column) for c in plan[:2]]
    assert out.case.rejected[0].reason == 'synthetic reject'
    assert (out.case.site.line, out.case.site.column) == (plan[2].line, plan[2].column)


def test_attempts_are_bounded_and_extra_check_can_reject():
    with pytest.raises(E.NoMutationSite) as err:
        E.apply_case(FILES, 'const-change', seed=1, base=BASE, checker=lambda f, r: 'no', max_attempts=2)
    assert len(err.value.rejected) == 2 and 'no' in str(err.value)
    seen = []

    def extra(cand, new):
        seen.append(cand)
        return 'masked body equal' if len(seen) < 2 else None
    out = E.apply_case(FILES, 'cmp-flip', seed=1, base=BASE, checker=lambda f, r: None, extra_check=extra)
    assert out.case.attempts == 2 and out.case.rejected[0].reason == 'masked body equal'


def test_real_compile_error_is_rejected(clang):
    files = {'s.c': 'struct S { int v; };\nint take(struct S s, int x);\n'
                    'int f(struct S s)\n{\n    return take(s, 1);\n}\n'}
    with pytest.raises(E.NoMutationSite) as err:
        E.apply_case(files, 'arg-swap', seed=1, base=BASE, tools=clang, target=('s.c', 'f'))
    assert err.value.rejected and 'error' in err.value.rejected[0].reason


def test_missing_clang_is_blocked_not_skipped():
    with pytest.raises(T.Blocked, match='clang'):
        E.apply_case(FILES, 'cmp-flip', seed=1, base=BASE, tools=T.Toolchain())
    with pytest.raises(T.Blocked):
        E.make_compile_checker(T.Toolchain())


def test_unsafe_paths_unknown_operator_and_no_site():
    with pytest.raises(ValueError, match='relative'):
        E.plan_mutants({'../x.c': 'int f(void){return 1<2;}'}, 'cmp-flip', seed=1)
    with pytest.raises(E.NoMutationSite):
        E.apply_case({'x.c': 'int f(void)\n{\n    return 3;\n}\n'}, 'cmp-flip', seed=1, base=BASE,
                     checker=lambda f, r: None)
    with pytest.raises(ValueError, match='operator'):
        E.plan_mutants(FILES, 'bogus', seed=1)


def test_case_json_is_strict_and_stable(clang):
    out = E.apply_case(FILES, 'off-by-one', seed=9, base=BASE, tools=clang, target=target_of('off-by-one'))
    data = MC.dump_case(out.case)
    assert data == MC.dump_case(MC.load_case(data)) and json.loads(data)['contract'] == 'mutation-case/1'
    with pytest.raises(MC.ContractError):
        MC.load_case(data.replace(b'"kind": "semantic"', b'"kind": "cosmetic"'))
