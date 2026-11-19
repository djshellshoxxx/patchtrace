"""SPEC-32 optional source-checker compatibility, using an authored assembly producer.

No compiler or target is executed. Unquoted COFF-style names are compatibility
inputs here, not evidence that the configured Clang emits this spelling.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.calibration.mutations import contracts as C
from tools.calibration.mutations import engine

OLD_SYMBOL = '??_C@_05CJBACGMB@hello?$AA@'
NEW_SYMBOL = '??_C@_06GANFPHOD@hello?$CB?$AA@'
BEFORE = {'m.c': 'void emit(char*); void shout(void) { emit("hello"); }'}
AFTER = {'m.c': BEFORE['m.c'].replace('"hello"', '"hello!"')}
CHAIN = SimpleNamespace(path=lambda name: 'authored-clang')


def install(monkeypatch, before, after):
    def authored_assembly(argv, *, cwd, timeout):
        instructions = after if 'hello!' in Path(cwd, 'm.c').read_text(encoding='utf-8') else before
        Path(cwd, '_masked.s').write_text('shout:\n' + '\n'.join(instructions) + '\n.seh_endproc\n',
                                         encoding='utf-8')
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(engine, 'run_tool', authored_assembly)
    return engine.make_masked_body_check(BEFORE, CHAIN)


def operand(symbol, quoted, addend):
    return ('"' + symbol + '"' if quoted else symbol) + addend + '(%rip)'


@pytest.mark.parametrize('quoted', [False, True], ids=['unquoted', 'quoted'])
@pytest.mark.parametrize('old_addend,new_addend', [('', ''), ('+4', '+8'), ('-4', '-8')],
                         ids=['plain', 'plus', 'minus'])
def test_complete_rip_symbol_is_address_metadata(monkeypatch, quoted, old_addend, new_addend):
    before = ['movl $1, %edx', f'leaq {operand(OLD_SYMBOL, quoted, old_addend)}, %rcx', 'jmp emit']
    after = ['movl $1, %edx', f'leaq {operand(NEW_SYMBOL, quoted, new_addend)}, %rcx', 'jmp emit']
    check = install(monkeypatch, before, after)
    original = engine._masked_function_asm(BEFORE, 'm.c', 'shout', 'authored-clang', (), 1)
    changed = engine._masked_function_asm(AFTER, 'm.c', 'shout', 'authored-clang', (), 1)
    assert original == changed == ('movl $1, %edx', 'leaq SYM(%rip), %rcx', 'jmp T')
    assert check(SimpleNamespace(file='m.c', function='shout', operator='string-literal'), AFTER) == (
        'masked body unchanged')


@pytest.mark.parametrize('before,after', [
    ('movl $1, %edx', 'addl $1, %edx'),
    ('movl $1, %edx', 'movl $2, %edx'),
    ('movl $1, %edx', 'movl $1, %r8d'),
    ('movl 4(%rcx), %eax', 'movl 8(%rcx), %eax'),
    ('movl symbol(%rip), %eax', 'movl symbol(%rcx), %eax'),
    ('je .LBB0_1', 'jne .LBB0_2'),
], ids=['opcode', 'immediate', 'register', 'non-rip-offset', 'rip-base', 'branch-opcode'])
def test_instruction_and_non_address_operands_still_differ(monkeypatch, before, after):
    check = install(monkeypatch, [before], [after])
    assert check(SimpleNamespace(file='m.c', function='shout', operator='string-literal'), AFTER) is None


@pytest.mark.parametrize('before,after,expected', [
    ('jmp old_target', 'jmp new_target', 'jmp T'),
    ('callq old_target', 'callq new_target', 'callq T'),
    ('leaq .L.str1(%rip), %rcx', 'leaq .L.str2(%rip), %rcx', 'leaq SYM(%rip), %rcx'),
    ('leaq old_name+4(%rip), %rcx', 'leaq new_name-8(%rip), %rcx', 'leaq SYM(%rip), %rcx'),
], ids=['branch-target', 'call-target', 'local-rip-label', 'plain-symbol-addend'])
def test_existing_address_and_branch_policy_is_preserved(monkeypatch, before, after, expected):
    install(monkeypatch, [before], [after])
    assert engine._masked_function_asm(BEFORE, 'm.c', 'shout', 'authored-clang', (), 1) == (expected,)
    assert engine._masked_function_asm(AFTER, 'm.c', 'shout', 'authored-clang', (), 1) == (expected,)


@pytest.mark.parametrize('quoted', [False, True], ids=['unquoted', 'quoted'])
def test_cosmetic_equality_uses_the_same_normalization(monkeypatch, quoted):
    # This isolates the policy branch; it is not a claim about native cosmetic compiler output.
    check = install(monkeypatch, [f'leaq {operand(OLD_SYMBOL, quoted, "")}, %rcx'],
                    [f'leaq {operand(NEW_SYMBOL, quoted, "")}, %rcx'])
    assert check(SimpleNamespace(file='m.c', function='shout', operator='ws-comment'), AFTER) is None


@pytest.mark.parametrize('quoted', [False, True], ids=['unquoted', 'quoted'])
def test_apply_case_records_rejection_from_the_optional_check(monkeypatch, quoted):
    check = install(monkeypatch, [f'leaq {operand(OLD_SYMBOL, quoted, "")}, %rcx', 'jmp emit'],
                    [f'leaq {operand(NEW_SYMBOL, quoted, "")}, %rcx', 'jmp emit'])
    base = C.SourceRef(suite='_test/coff', version='authored-1', license_spdx='MIT')
    with pytest.raises(engine.NoMutationSite) as rejected:
        engine.apply_case(BEFORE, 'string-literal', seed=3, base=base, checker=lambda files, rel: None,
                          target=('m.c', 'shout'), extra_check=check)
    assert [item.reason for item in rejected.value.rejected] == ['masked body unchanged']


def test_unavailable_body_remains_a_rejection(monkeypatch):
    monkeypatch.setattr(engine, 'run_tool', lambda *args, **kwargs: SimpleNamespace(returncode=1))
    check = engine.make_masked_body_check(BEFORE, CHAIN)
    assert check(SimpleNamespace(file='m.c', function='shout', operator='string-literal'), AFTER) == (
        'masked body not comparable (function not emitted at -O2)')
