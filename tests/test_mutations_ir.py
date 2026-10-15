"""LBL-07: the IR layer of the mutation factory. Sites, edits and normalisation are checked against hand-written LLVM IR
(hermetic, no clang); the clang wrappers run against a fake process runner, and one test uses the real clang when it
is installed and otherwise asserts the BLOCKED outcome (never a skip)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from tools.calibration.mutations import contracts as MC
from tools.calibration.mutations import ir as IR
from tools.calibration.tier_r import toolchain as T

MODULE = '''%struct.pair = type { i32, i32, i8 }

declare i32 @g(i32 noundef)
declare i32 @h(i32 noundef)
declare void @v(i32 noundef)

define dso_local i32 @f(ptr noundef %p, i32 noundef %n) {
entry:
  %a = getelementptr inbounds %struct.pair, ptr %p, i32 0, i32 1
  %x = load i32, ptr %a, align 4
  %c = icmp slt i32 %x, %n
  br i1 %c, label %then, label %else
then:                                             ; preds = %entry
  %y = add nsw i32 %x, 5
  %z = call i32 @g(i32 noundef %y)
  ret i32 %z
else:
  %arr = getelementptr inbounds [4 x i32], ptr %p, i64 0, i64 2
  store i32 7, ptr %arr, align 4
  ret i32 0
}
'''


def mutated(operator: str, seed: int = 0) -> str:
    return IR.mutate_ir(MODULE, 'f', operator, seed).text


def only_diff(old: str, new: str) -> tuple[list[str], list[str]]:
    a, b = old.splitlines(), new.splitlines()
    return [x for x, y in zip(a, b, strict=True) if x != y], [y for x, y in zip(a, b, strict=True) if x != y]


@pytest.mark.parametrize('operator, before, after', [
    ('cmp-flip', '  %c = icmp slt i32 %x, %n', '  %c = icmp sge i32 %x, %n'),
    ('field-offset', '  %a = getelementptr inbounds %struct.pair, ptr %p, i32 0, i32 1',
     '  %a = getelementptr inbounds %struct.pair, ptr %p, i32 0, i32 2'),
    ('index-swap', '  %arr = getelementptr inbounds [4 x i32], ptr %p, i64 0, i64 2',
     '  %arr = getelementptr inbounds [4 x i32], ptr %p, i64 0, i64 3'),
    ('branch-swap', '  br i1 %c, label %then, label %else', '  br i1 %c, label %else, label %then'),
    ('callee-swap', '  %z = call i32 @g(i32 noundef %y)', '  %z = call i32 @h(i32 noundef %y)'),
], ids=['cmp', 'field', 'index', 'branch', 'callee'])
def test_single_site_operators_edit_exactly_one_line(operator, before, after):
    assert len(IR.ir_sites(MODULE, 'f', operator)) == 1
    assert only_diff(MODULE, mutated(operator)) == ([before], [after])


def test_const_change_has_three_sites_each_bumped_by_one():
    sites = IR.ir_sites(MODULE, 'f', 'const-change')
    assert [(s.before, s.after, s.line) for s in sites] == [('5', '6', 14), ('7', '8', 19), ('0', '1', 20)]
    assert {mutated('const-change', seed) for seed in range(12)} <= {
        MODULE.replace('i32 %x, 5', 'i32 %x, 6'), MODULE.replace('store i32 7', 'store i32 8'),
        MODULE.replace('ret i32 0', 'ret i32 1')}


def test_mutation_is_deterministic_and_seed_reaches_every_site():
    assert mutated('const-change', 3) == mutated('const-change', 3)
    assert len({mutated('const-change', seed) for seed in range(40)}) == 3


def test_cmp_flip_table_is_an_involution_of_the_source_table():
    assert all(IR._FLIP[IR._FLIP[k]] == k for k in IR._FLIP)
    assert (IR._FLIP['slt'], IR._FLIP['ule'], IR._FLIP['eq']) == ('sge', 'ugt', 'ne')


@pytest.mark.parametrize('line, expected', [
    ('  %q = add nsw i8 %x, 127', []),
    ('  %q = add nsw i8 %x, 126', ['127']),
    ('  %q = mul i32 %x, -3', ['-2']),
], ids=['i8-max', 'i8-below', 'negative'])
def test_const_change_respects_the_signed_range(line, expected):
    ll = f'define i8 @k(i8 %x) {{\n{line}\n  ret i8 %q\n}}\n'
    assert [s.after for s in IR.ir_sites(ll, 'k', 'const-change')] == expected


def test_branch_swap_skips_identical_successors_and_unconditional_branches():
    ll = 'define void @k(i1 %c) {\n  br i1 %c, label %a, label %a\n  br label %a\n}\n'
    assert IR.ir_sites(ll, 'k', 'branch-swap') == []


def test_field_offset_wraps_at_the_last_field():
    ll = MODULE.replace('i32 0, i32 1', 'i32 0, i32 2')
    assert [s.after for s in IR.ir_sites(ll, 'f', 'field-offset')] == ['0']


def test_sites_stay_inside_the_named_function():
    ll = MODULE + 'define i32 @other(i32 %a) {\n  %c = icmp eq i32 %a, 1\n  ret i32 0\n}\n'
    assert [s.after for s in IR.ir_sites(ll, 'other', 'cmp-flip')] == ['ne']
    assert [s.after for s in IR.ir_sites(ll, 'f', 'cmp-flip')] == ['sge']


@pytest.mark.parametrize('call', [
    lambda: IR.ir_sites(MODULE, 'missing', 'cmp-flip'),
    lambda: IR.mutate_ir(MODULE, 'f', 'call-add', 0),
    lambda: IR.mutate_ir('define void @e() {\n  ret void\n}\n', 'e', 'cmp-flip', 0),
], ids=['no-function', 'no-ir-operator', 'no-site'])
def test_errors(call):
    with pytest.raises((IR.NoIrSite, ValueError)):
        call()


DEBUG_BUILD = '''define dso_local i32 @f(i32 noundef %0, i32 noundef %1) #0 !dbg !9 {
  %3 = alloca i32, align 4
  call void @llvm.dbg.declare(metadata ptr %3, metadata !15, metadata !DIExpression()), !dbg !16
  %4 = icmp slt i32 %0, %1, !dbg !17
  br i1 %4, label %5, label %7, !dbg !18
5:                                                ; preds = %2
  ret i32 1, !dbg !19
7:
  %8 = load i32, ptr %3, align 4, !tbaa !20
  ret i32 %8
}
'''
RENAMED = '''define dso_local i32 @f(i32 noundef %a, i32 noundef %b) {
  %slot = alloca i32, align 4
  %lt = icmp slt i32 %a, %b
  br i1 %lt, label %yes, label %no
yes:
  ret i32 1
no:
  %v = load i32, ptr %slot, align 4
  ret i32 %v
}
'''
NORMALISED = ('%v0 = alloca i32, align 4', '%v1 = icmp slt i32 %v2, %v3', 'br i1 %v1, label %v4, label %v5',
              '%v4:', 'ret i32 1', '%v5:', '%v6 = load i32, ptr %v0, align 4', 'ret i32 %v6')


def test_normalise_function_golden():
    # the parameters are first mentioned by the icmp, so they number after the alloca and the compare result
    assert IR.normalise_function(DEBUG_BUILD, 'f') == NORMALISED
    assert IR.normalise_function(RENAMED, 'f') == NORMALISED


def test_ir_changed_observations():
    assert IR.ir_changed(DEBUG_BUILD, RENAMED, 'f') is False
    assert IR.ir_changed(RENAMED, RENAMED.replace('slt', 'sge'), 'f') is True
    assert IR.ir_changed(RENAMED, RENAMED.replace('@f', '@g'), 'f') is None


def test_mutation_is_visible_to_the_comparison():
    assert all(IR.ir_changed(MODULE, mutated(op), 'f') for op in IR.IR_OPERATORS)


V = IR.LayerVerdict.for_case


def test_agreement_is_per_operator_with_unknowns_counted_apart():
    got = IR.agreement_by_operator([
        V('cmp-flip', 'a', True), V('cmp-flip', 'b', True), V('cmp-flip', 'c', False), V('cmp-flip', 'd', None),
        V('ws-comment', 'e', False), V('ws-comment', 'f', True),
        V('callee-swap', 'g', None)])
    assert list(got) == ['callee-swap', 'cmp-flip', 'ws-comment']
    assert (got['cmp-flip'].compared, got['cmp-flip'].agreed, got['cmp-flip'].unknown) == (3, 2, 1)
    assert got['cmp-flip'].rate == pytest.approx(2 / 3)
    assert got['ws-comment'].rate == 0.5
    assert got['callee-swap'].rate is None and got['callee-swap'].unknown == 1


def test_expected_label_follows_the_operator_kind():
    assert V('cmp-flip', 'x', True).expected_changed is True
    assert V('local-rename', 'x', True).expected_changed is False
    with pytest.raises(ValueError):
        V('nonsense', 'x', True)
    assert set(IR.IR_OPERATORS) <= set(MC.SEMANTIC_OPERATORS)


# ---- clang wrappers ----------------------------------------------------------------------------------------------

def fake_chain() -> T.Toolchain:
    return T.Toolchain({'clang': T.Tool('clang', '/opt/llvm/bin/clang', 'clang version 18')})


def test_blocked_without_clang():
    empty = T.Toolchain()
    assert 'clang' in IR.ir_layer_status(empty)
    assert IR.ir_layer_status(fake_chain()) is None
    for call in (lambda: IR.emit_ir({'a.c': 'int x;\n'}, 'a.c', empty), lambda: IR.optimise_ir(MODULE, empty),
                 lambda: IR.compile_ir_object(MODULE, empty)):
        with pytest.raises(T.Blocked):
            call()


@pytest.fixture
def runner(monkeypatch):
    calls = []

    def fake(argv, *, cwd, timeout):
        calls.append(list(argv))
        (cwd / argv[argv.index('-o') + 1]).write_bytes(b'IR-OR-OBJECT')
        return SimpleNamespace(returncode=0, stderr_tail='', log_tail='', reason=None)
    monkeypatch.setattr(IR, 'run_tool', fake)
    return calls


def test_emit_ir_command_line(runner):
    assert IR.emit_ir({'src/a.c': 'int x;\n'}, 'src/a.c', fake_chain()) == 'IR-OR-OBJECT'
    argv = runner[0]
    assert argv[0] == '/opt/llvm/bin/clang' and argv[-2:] == ['-o', 'out.ll']
    assert {'-S', '-emit-llvm', '-O0', '-disable-O0-optnone', '-g'} <= set(argv) and 'src/a.c' in argv


def test_optimise_and_object_command_lines(runner):
    IR.optimise_ir(MODULE, fake_chain())
    assert IR.compile_ir_object(MODULE, fake_chain()) == b'IR-OR-OBJECT'
    assert runner[0][1:] == ['-S', '-emit-llvm', '-O2', '-x', 'ir', 'x.ll', '-o', 'out.ll']
    assert runner[1][1:] == ['-c', '-O2', '-x', 'ir', 'x.ll', '-o', 'out.o']


def test_failed_clang_is_a_tool_error_and_paths_are_confined(monkeypatch):
    monkeypatch.setattr(IR, 'run_tool', lambda *a, **k: SimpleNamespace(
        returncode=1, stderr_tail='error: expected ;', log_tail='', reason=None))
    with pytest.raises(T.ToolError, match='expected ;'):
        IR.emit_ir({'a.c': 'int'}, 'a.c', fake_chain())
    with pytest.raises(ValueError):
        IR.emit_ir({'../a.c': 'int x;'}, '../a.c', fake_chain())


def test_real_clang_round_trip_or_blocked():
    src = {'a.c': 'int g(int);\nint f(int n) { if (n < 3) return g(n); return n + 1; }\n'}
    status = IR.ir_layer_status()
    if status:
        with pytest.raises(T.Blocked):
            IR.emit_ir(src, 'a.c')
        return
    old = IR.emit_ir(src, 'a.c')
    assert IR.ir_changed(old, IR.emit_ir({'a.c': src['a.c'].replace('n < 3', 'n >= 3')}, 'a.c'), 'f') is True
    assert IR.ir_changed(old, IR.emit_ir({'a.c': '/* c */\n' + src['a.c']}, 'a.c'), 'f') is False
    flipped = IR.mutate_ir(old, 'f', 'cmp-flip', 0).text
    assert IR.ir_changed(old, flipped, 'f') is True
    assert len(IR.compile_ir_object(flipped)) > 0
