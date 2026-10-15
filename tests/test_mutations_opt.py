"""LBL-07: the `opt` layer. The pass table, symbol accounting and BLOCKED outcome are checked hermetically (fake process
runner, hand-written IR); the real-`opt` test runs when opt and clang are installed and otherwise asserts BLOCKED."""
from __future__ import annotations

import shutil
from types import SimpleNamespace

import pytest

from tools.calibration.mutations import contracts as MC
from tools.calibration.mutations import ir as IR
from tools.calibration.mutations import opt_transforms as O
from tools.calibration.tier_r import toolchain as T

BEFORE = '''; ModuleID = 'a.c'
define dso_local i32 @use(i32 %0) {
  ret i32 %0
}
define internal i32 @mix(i32 %0) {
  ret i32 %0
}
define internal i32 @mix2(i32 %0) {
  ret i32 %0
}
'''
AFTER_MERGE = BEFORE.replace("; ModuleID = 'a.c'", "; ModuleID = 'in.ll'").replace(
    'define internal i32 @mix2(i32 %0) {\n  ret i32 %0\n}\n', '')
AFTER_SPLIT = BEFORE + 'define internal void @use.cold.1() {\n  ret void\n}\n'


def opt_chain(path: str = '/opt/llvm/bin/opt') -> T.Toolchain:
    return T.Toolchain({'opt': T.Tool('opt', path), 'clang': T.Tool('clang', '/opt/llvm/bin/clang')})


@pytest.fixture
def fake_opt(monkeypatch):
    state = SimpleNamespace(output=BEFORE, argv=[])

    def run(argv, *, cwd, timeout):
        state.argv = list(argv)
        (cwd / 'out.ll').write_text(state.output, encoding='utf-8', newline='\n')
        return SimpleNamespace(returncode=0, stderr_tail='', log_tail='', reason=None)
    monkeypatch.setattr(IR, 'run_tool', run)
    return state


def test_pass_table_covers_exactly_the_opt_operators_with_their_n_tags():
    assert tuple(O.OPT_PASSES) == MC.COSMETIC_OPERATORS[-5:] == ('loop-extract', 'hotcoldsplit', 'mergefunc',
                                                                 'always-inline', 'partial-inliner')
    assert {k: v.n_tag for k, v in O.OPT_PASSES.items()} == {
        'loop-extract': 'N4', 'hotcoldsplit': 'N10', 'mergefunc': 'N1', 'always-inline': 'N4', 'partial-inliner': 'N4'}
    assert all(MC.kind_of(op) == 'cosmetic' for op in O.OPT_PASSES)


def test_cosmetic_target_label_and_unknown_operator():
    assert O.cosmetic_target('mergefunc') == 'cosmetic(mergefunc)'
    for call in (lambda: O.cosmetic_target('cmp-flip'), lambda: O.apply_opt(BEFORE, 'cmp-flip', opt_chain())):
        with pytest.raises(ValueError):
            call()


def test_defined_symbols_ignores_declarations_and_sorts():
    ll = 'declare i32 @g(i32)\ndefine i32 @b() {\n}\ndefine internal void @a.cold.1() {\n}\n'
    assert O.defined_symbols(ll) == ('a.cold.1', 'b')


def test_blocked_without_opt_is_reported_with_a_reason(tmp_path):
    env = {'PATH': str(tmp_path)}
    result = O.apply_opt(BEFORE, 'mergefunc', T.Toolchain(), environ=env)
    assert (result.status, result.blocked, result.ir, result.n_tag) == ('blocked', True, None, 'N1')
    assert result.reason == 'opt: not installed (not on PATH)'
    assert 'opt: not installed' in O.opt_layer_status(T.Toolchain(), env)
    assert O.opt_layer_status(opt_chain()) is None


def test_clang_missing_is_part_of_the_blocked_reason(tmp_path):
    chain = T.Toolchain({'opt': T.Tool('opt', '/opt/llvm/bin/opt')})
    assert O.opt_layer_status(chain, {'PATH': str(tmp_path)}).startswith('clang: ')


def test_bad_override_is_blocked_not_ignored(tmp_path):
    result = O.apply_opt(BEFORE, 'mergefunc', T.Toolchain(), environ={'PATCHTRACE_KA_OPT': 'opt', 'PATH': ''})
    assert result.blocked and 'not an absolute file' in result.reason


def test_merge_removes_a_symbol_and_adds_none(fake_opt):
    fake_opt.output = AFTER_MERGE
    result = O.apply_opt(BEFORE, 'mergefunc', opt_chain())
    assert (result.status, result.new_symbols, result.removed_symbols) == ('ok', (), ('mix2',))
    assert fake_opt.argv == ['/opt/llvm/bin/opt', '-passes=mergefunc', '-S', 'in.ll', '-o', 'out.ll']


def test_split_creates_a_no_counterpart_symbol_and_passes_its_flag(fake_opt):
    fake_opt.output = AFTER_SPLIT
    result = O.apply_opt(BEFORE, 'hotcoldsplit', opt_chain())
    assert (result.status, result.new_symbols, result.removed_symbols, result.n_tag) == (
        'ok', ('use.cold.1',), (), 'N10')
    assert fake_opt.argv[1:3] == ['-passes=function(mem2reg),hotcoldsplit', '-hotcoldsplit-threshold=-1']


def test_a_pass_that_changes_nothing_is_unchanged_even_if_the_header_differs(fake_opt):
    fake_opt.output = BEFORE.replace("'a.c'", "'in.ll'")
    result = O.apply_opt(BEFORE, 'always-inline', opt_chain())
    assert (result.status, result.new_symbols, result.removed_symbols) == ('unchanged', (), ())


def test_opt_failure_is_a_tool_error(monkeypatch):
    monkeypatch.setattr(IR, 'run_tool', lambda *a, **k: SimpleNamespace(
        returncode=1, stderr_tail='opt: unknown pass name', log_tail='', reason=None))
    with pytest.raises(T.ToolError, match='unknown pass name'):
        O.apply_opt(BEFORE, 'mergefunc', opt_chain())


SOURCE = '''int g(int);
struct s { int a; };
static int mix(int a, int b) { return a * 3 + b; }
static int mix2(int a, int b) { return a * 3 + b; }
__attribute__((always_inline)) static int add1(int v) { return v + 1; }
int sum(int *a, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += a[i];
    return g(s) + mix(n, 2) + mix2(n, 3);
}
int cold_path(int v) {
    if (v == 77) { g(1); g(2); g(3); g(4); g(5); g(6); __builtin_trap(); }
    return add1(v);
}
'''


def test_real_opt_or_blocked():
    status = O.opt_layer_status()
    if status:
        assert O.apply_opt(BEFORE, 'mergefunc').blocked
        if not shutil.which('clang'):  # emitting IR needs only clang; a host with clang but no opt (the Windows runner) emits
            with pytest.raises(T.Blocked):
                O.emit_opt_input({'a.c': SOURCE}, 'a.c')
        return
    ll = O.emit_opt_input({'a.c': SOURCE}, 'a.c')
    got = {op: O.apply_opt(ll, op) for op in O.OPT_PASSES}
    assert got['mergefunc'].removed_symbols == ('mix2',)
    assert got['always-inline'].removed_symbols == ('add1',)
    assert [s.split('.')[0] for s in got['loop-extract'].new_symbols] == ['sum']
    assert [s.split('.')[0] for s in got['hotcoldsplit'].new_symbols] == ['cold_path']
    assert got['partial-inliner'].status in {'ok', 'unchanged'}
    assert all(not r.blocked for r in got.values())
