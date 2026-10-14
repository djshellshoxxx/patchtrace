"""SPEC-31 S1: operand typing and located address fields (03 s12.4). Instruction bytes, masks and operand facts
below are REAL Ghidra 12.0.4 output recorded from a clang-built PE (docs/specs/unified-engine/03-extraction.md
s12.1); no Ghidra runs here."""
from __future__ import annotations

import pytest

from patchtrace.unified.ir import operands as ops
from patchtrace.unified.ir.features import (
    NULL_KEY,
    h64,
    instruction_flags,
    is_nop,
    multiset_key,
    padding_start,
    sequence_key,
)

BASE = 0x180000000


class Image:
    image_base = BASE
    size_of_image = 0x5000

    def __init__(self, relocs=()):
        self.relocs = sorted(relocs)

    def reloc_in(self, low, high):
        return any(low <= r < high for r in self.relocs)


def facts(rva, raw_hex, imask, optype, omask, objs, refs, relocs=()):
    raw = bytes.fromhex(raw_hex)
    return ops.classify_operand(rva, len(raw), raw, bytes.fromhex(imask) if imask else None, optype,
                                bytes.fromhex(omask) if omask else None, objs, refs, Image(relocs))


def test_rip_relative_load_is_address_with_disp32_field():
    f = facts(0x1060, '8b059a1f0000', 'ffc700000000', 8320, '0000ffffffff', [('addr', 12288)], [('READ', 'rva:12288')])
    assert (f.vkind, f.state, f.offset, f.length, f.value) == (ops.VK_ADDRESS, 'located', 2, 4, 12288)


def test_lea_scalar_is_absolute_va_but_field_is_rip_relative():
    # LEA RDX,[0x180002000]: the scalar is the absolute VA, the encoded bytes are target - next_ip
    f = facts(0x1029, '488d15d00f0000', 'f8ffc700000000', 24576, '000000ffffffff', [('scalar', BASE + 0x2000)],
              [('DATA', 'rva:8192')])
    assert (f.vkind, f.state, f.offset, f.length) == (ops.VK_ADDRESS, 'located', 3, 4)


def test_relative_branch_targets_are_address_fields():
    f = facts(0x1023, '7723', 'ff00', 8256, '00ff', [('addr', 4168)], [('CONDITIONAL_JUMP', 'rva:4168')])
    assert (f.vkind, f.state, f.offset, f.length) == (ops.VK_ADDRESS, 'located', 1, 1)


def test_jump_table_operand_has_no_displacement_bytes_and_is_not_flagged():
    # MOVSXD RCX,dword ptr [RDX + RCX*4]: DATA reference to the table, mask = SIB only (the base is in RDX)
    f = facts(0x1030, '48630c8a', 'f8ffc700', 4202496, '000000ff', [('reg', 'RDX'), ('reg', 'RCX'), ('scalar', 4)],
              [('DATA', 'rva:8192')])
    assert f.vkind == ops.VK_ADDRESS and f.state == 'absent' and f.offset is None
    assert f.regs == ('RDX', 'RCX')


def test_rva_form_jump_table_displacement_is_address():
    # MOV EAX,[RDX + RAX*4 + 0x2000] (MSVC RVA-form table): SIB then disp32 = the RVA of the table; no scalar object
    f = facts(0x1000, '8b848200200000', 'ffc70000000000', 4202496, '0000ffffffffff',
              [('reg', 'RDX'), ('reg', 'RAX'), ('scalar', 4)], [('DATA', 'rva:8192')])
    assert (f.vkind, f.state, f.offset, f.length, f.value) == (ops.VK_ADDRESS, 'located', 3, 4, 8192)
    raw = bytes.fromhex('8b848200200000')
    assert ops.mask_instruction(raw, [f], 1) == bytes.fromhex('8b848200000000')   # SIB register bits survive


def test_immediate_and_stack_and_memory_displacements():
    imm = facts(0x1020, '83f906', 'fff800', 16384, '0000ff', [('scalar', 6)], [])
    assert (imm.vkind, imm.state, imm.offset, imm.length, imm.value) == (ops.VK_SCALAR, 'located', 2, 1, 6)
    mem = facts(0x1068, '488b4928', 'f8ffc000', 4194304, '000007ff', [('reg', 'RCX'), ('scalar', 40)], [])
    assert (mem.vkind, mem.state, mem.offset, mem.length, mem.value, mem.regs) == (
        ops.VK_MEMORY, 'located', 3, 1, 40, ('RCX',))
    stack = facts(0x10a4, '44884c1581', 'f8ffc70000', 4194304, '000000ffff',
                  [('reg', 'RBP'), ('reg', 'RDX'), ('scalar', 1), ('scalar', -127)], [])
    assert (stack.vkind, stack.state, stack.offset, stack.length, stack.value) == (ops.VK_STACK, 'located', 4, 1, -127)


def test_segment_relative_absolute_displacement_without_sib_bits_is_located():
    # MOV RAX,qword ptr GS:[0x30]: the SIB byte is fixed by the instruction mask, the operand mask is the disp32
    f = facts(0x10b5, '65488b042530000000', 'fff8ffc73f00000000', 4194304, '0000000000ffffffff',
              [('reg', 'GS'), ('scalar', 48)], [])
    assert (f.vkind, f.state, f.offset, f.length, f.value) == (ops.VK_MEMORY, 'located', 5, 4, 48)


def test_scale_factor_is_never_mistaken_for_a_displacement():
    # LEA EAX,[RAX + RAX*2]: the only scalar is the scale; the SIB byte is not a field
    f = facts(0x104b, '8d0440', 'ffc700', 4194304, '0000ff', [('reg', 'RAX'), ('reg', 'RAX'), ('scalar', 2)], [])
    assert f.vkind == ops.VK_MEMORY and f.state == 'absent' and f.value is None


def test_l1_masks_displacement_not_sib_register_bits():
    # SIB byte 0x4c holds base/index registers: it must survive L1 and L2 masking, only disp8 is cleared at L2
    raw = bytes.fromhex('44884c1581')
    fact = facts(0x10a4, '44884c1581', 'f8ffc70000', 4194304, '000000ffff',
                 [('reg', 'RBP'), ('reg', 'RDX'), ('scalar', 1), ('scalar', -127)], [])
    assert ops.mask_instruction(raw, [fact], 1) == raw
    assert ops.mask_instruction(raw, [fact], 2) == bytes.fromhex('44884c1500')


def test_l1_masks_only_positive_address_evidence():
    raw = bytes.fromhex('83f906')                 # CMP ECX,6: a small immediate is not an address
    imm = facts(0x1020, '83f906', 'fff800', 16384, '0000ff', [('scalar', 6)], [])
    assert ops.mask_instruction(raw, [imm], 1) == raw
    assert ops.mask_instruction(raw, [imm], 2) == bytes.fromhex('83f900')
    lea = bytes.fromhex('488d15d00f0000')
    addr = facts(0x1029, '488d15d00f0000', 'f8ffc700000000', 24576, '000000ffffffff', [('scalar', BASE + 0x2000)],
                 [('DATA', 'rva:8192')])
    assert ops.mask_instruction(lea, [addr], 1) == bytes.fromhex('488d1500000000')


def test_l2_masks_immediates_keeps_registers():
    raw = bytes.fromhex('4883c205')                # ADD RDX,5
    regs = facts(0x10cd, '4883c205', 'f8fff800', 512, '00000700', [('reg', 'RDX')], [])
    imm = facts(0x10cd, '4883c205', 'f8fff800', 16384, '000000ff', [('scalar', 5)], [])
    assert regs.vkind == ops.VK_REGISTER and regs.offset is None
    assert ops.mask_instruction(raw, [regs, imm], 2) == bytes.fromhex('4883c200')


def test_l3_equals_sleigh_mask():
    raw = bytes.fromhex('4883c205')
    assert ops.apply_instruction_mask(raw, bytes.fromhex('f8fff800')) == bytes.fromhex('4883c000')
    assert ops.apply_instruction_mask(raw, None) is None


def test_stack_operand_is_frame_class():
    # LEA RBP,[RSP + 0x80]: Ghidra attaches Stack[-88] to operand 0 (the register)
    f = facts(0x1088, '488dac2480000000', 'f8ffc73800000000', 8704, '0000380000000000', [('reg', 'RBP')],
              [('DATA', 'stack:-88')])
    assert (f.vkind, f.state, f.value) == (ops.VK_STACK, 'absent', -88)
    mem = facts(0x1088, '488dac2480000000', 'f8ffc73800000000', 4194304, '00000007ffffffff',
                [('reg', 'RSP'), ('scalar', 128)], [])
    assert (mem.vkind, mem.state, mem.offset, mem.length, mem.value) == (ops.VK_STACK, 'located', 4, 4, 128)


def test_imm64_covered_by_a_relocation_is_an_address():
    raw_hex = '48b88877665544332211'
    value = 0x1122334455667788
    plain = facts(0x111b, raw_hex, 'f8f80000000000000000', 16384, '0000ffffffffffffffff', [('scalar', value)], [])
    assert plain.vkind == ops.VK_SCALAR
    pointer = 0x180003000
    raw2 = '48b8' + pointer.to_bytes(8, 'little').hex()
    covered = facts(0x2000, raw2, 'f8f80000000000000000', 16384, '0000ffffffffffffffff', [('scalar', pointer)], [],
                    relocs=[0x2002])
    assert (covered.vkind, covered.state, covered.value) == (ops.VK_ADDRESS, 'located', 0x3000)


@pytest.mark.parametrize('case', ['wrong-value', 'gap-in-mask', 'partial-field', 'overlap-opcode', 'no-mask'])
def test_unverifiable_fields_are_unlocated_never_masked(case):
    kwargs = {
        'wrong-value': dict(raw='83f907', imask='fff800', omask='0000ff', objs=[('scalar', 6)]),
        'gap-in-mask': dict(raw='b8010000ff', imask='ff00000000', omask='00ff0000ff', objs=[('scalar', 1)]),
        'partial-field': dict(raw='83f906', imask='fff800', omask='0007ff', objs=[('scalar', 6)]),
        'overlap-opcode': dict(raw='83f906', imask='fff8ff', omask='0000ff', objs=[('scalar', 6)]),
        'no-mask': dict(raw='83f906', imask='fff800', omask=None, objs=[('scalar', 6)]),
    }[case]
    f = facts(0x1000, kwargs['raw'], kwargs['imask'], 16384, kwargs['omask'], kwargs['objs'], [])
    assert f.state == 'unlocated' and f.offset is None
    raw = bytes.fromhex(kwargs['raw'])
    assert ops.mask_instruction(raw, [f], 2) == raw


def test_unlocated_address_operand_is_reported_so_the_function_can_be_flagged():
    f = facts(0x1000, '8b059a1f0001', 'ffc700000000', 8320, '0000ffffffff', [('addr', 12288)], [('READ', 'rva:12288')])
    assert f.vkind == ops.VK_ADDRESS and f.state == 'unlocated'


def test_import_call_through_the_iat_carries_the_import_key():
    # CALL qword ptr [0x1800021b0]: operand reference replaced by the import key, slot RVA in the addr object
    f = facts(0x10a4, 'ff1506110000', 'ffff00000000', 8320, '0000ffffffff', [('addr', 8624)],
              [('READ', 'ext:kernel32.dll!GetTickCount')])
    assert (f.vkind, f.state, f.value, f.offset, f.length) == (ops.VK_ADDRESS, 'located', 'kernel32.dll!GetTickCount',
                                                               2, 4)


# --- features -------------------------------------------------------------------------------------------------------

def test_hash_is_signed_64_bit_and_never_the_null_sentinel(monkeypatch):
    assert -2 ** 63 < h64(b'abc') < 2 ** 63
    import hashlib

    class Fake:
        def digest(self):
            return (2 ** 63).to_bytes(8, 'big')
    monkeypatch.setattr(hashlib, 'blake2b', lambda data=b'', digest_size=8: Fake())
    assert h64(b'x') == NULL_KEY + 1


def test_instruction_sequences_with_different_boundaries_hash_differently():
    from patchtrace.unified.ir.features import KeyStream
    a, b = KeyStream(), KeyStream()
    a.add(b'\x01\x02')
    a.add(b'\x03')
    b.add(b'\x01')
    b.add(b'\x02\x03')
    assert a.value() != b.value()


def test_nop_family_skipped():
    assert is_nop('NOP') and not is_nop('MOV')
    assert padding_start(['PUSH', 'RET', 'INT3', 'INT3']) == 2
    assert padding_start(['PUSH', 'RET', 'INT3', 'MOV']) == 4
    assert padding_start(['PUSH', 'INT3']) == 2


def test_mnemonic_keys_distinguish_order_but_not_multiset_permutations():
    assert multiset_key(['MOV', 'ADD']) == multiset_key(['ADD', 'MOV'])
    assert sequence_key(['MOV', 'ADD']) != sequence_key(['ADD', 'MOV'])


def test_instruction_flags():
    assert instruction_flags('CALL', 'UNCONDITIONAL_CALL') & 1
    assert instruction_flags('JZ', 'CONDITIONAL_JUMP') & 2
    assert instruction_flags('JMP', 'UNCONDITIONAL_JUMP') & 4
    assert instruction_flags('RET', 'TERMINATOR') & 8
    assert instruction_flags('JMP', 'COMPUTED_JUMP') & 16
    assert instruction_flags('NOP', 'FALL_THROUGH') & 32
