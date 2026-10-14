"""Operand typing from positive evidence and located address fields (`norm/1`, 03 s6 and s12.4). Pure.

Rules that matter for soundness (review R-01, R-07, R-14): an operand is `address` only with positive evidence (an
image reference, the ADDRESS flag with an in-image address object, or a base relocation inside its field); only the
displacement/immediate bytes of an operand are ever cleared, never its whole value mask (which also covers
ModRM/SIB register bits); a field that cannot be located and cross-checked against an expected encoding is NOT
masked, and an unlocated `address` operand marks the function `mask-unlocated`.
"""
from __future__ import annotations

from typing import NamedTuple, Protocol

# Ghidra 12.0.4 OperandType flags (the extractor script compares its complete table with the live class).
OPTYPE_INDIRECT = 0x4
OPTYPE_REGISTER = 0x200
OPTYPE_ADDRESS = 0x2000
OPTYPE_SCALAR = 0x4000
OPTYPE_DYNAMIC = 0x400000

VK_REGISTER, VK_SCALAR, VK_MEMORY, VK_STACK, VK_ADDRESS = range(5)
VKIND_NAMES = ('register', 'scalar', 'memory', 'stack', 'address')
FRAME_REGISTERS = frozenset({'RSP', 'RBP', 'ESP', 'EBP', 'SP', 'BP'})
FIELD_LENGTHS = (1, 2, 4, 8)

STATE_NONE = 'none'            # no field is needed or possible (register operand)
STATE_LOCATED = 'located'
STATE_ABSENT = 'absent'        # the operand encodes no displacement/immediate bytes (the value comes from a register)
STATE_UNLOCATED = 'unlocated'  # bytes exist but cannot be proven to be the field: the operand is not masked


class ImageView(Protocol):
    """What operand typing needs from the PE (implemented by `pe_tables.PeTables`)."""
    image_base: int
    size_of_image: int

    def reloc_in(self, low: int, high: int) -> bool: ...


class OperandFacts(NamedTuple):
    vkind: int
    value: object                 # register name | int | displacement/offset | target RVA | import key | None
    offset: int | None            # located field: byte offset inside the instruction ...
    length: int | None            # ... and length (1, 2, 4 or 8)
    state: str
    regs: tuple[str, ...]


def _expected(rva: int, length: int, scalars: list[int], targets: list[int], image_base: int) -> list[int]:
    out = list(scalars)
    for target in targets:
        out += [target - (rva + length), target, image_base + target]
    return out


def locate_field(mask: bytes | None, imask: bytes | None, raw: bytes, dynamic: bool,
                 expected: list[int]) -> tuple[str, int | None, int | None]:
    """(state, offset, length) of the displacement/immediate field of one operand (03 s12.4 rules 1-2)."""
    if mask is None:
        return STATE_UNLOCATED, None, None
    nonzero = [i for i, byte in enumerate(mask) if byte]
    if not nonzero:
        return STATE_ABSENT, None, None
    if nonzero[-1] - nonzero[0] + 1 != len(nonzero) or len(mask) != len(raw):
        return STATE_UNLOCATED, None, None
    if imask is not None and any(m & i for m, i in zip(mask, imask, strict=False)):
        return STATE_UNLOCATED, None, None   # operand bits overlapping opcode bits: the model is not what we assumed
    rest = nonzero
    if dynamic:
        # A DYNAMIC operand starts with ONE ModRM.rm/SIB byte (03 s12.1): partial, or whole (run of 1, 2 or 5 bytes =
        # SIB, SIB + disp8, SIB + disp32). A run of 4 or 8 whole bytes is a bare displacement (SIB fixed by the
        # instruction mask, e.g. `GS:[0x30]`); any other whole-byte run cannot be split with certainty.
        if mask[nonzero[0]] != 0xFF or len(nonzero) in (1, 2, 5):
            rest = nonzero[1:]
        elif len(nonzero) not in (4, 8):
            return STATE_UNLOCATED, None, None
    if not rest or all(mask[i] != 0xFF for i in rest):
        return STATE_ABSENT, None, None          # only register/opcode bits: no displacement or immediate bytes
    if any(mask[i] != 0xFF for i in rest) or len(rest) not in FIELD_LENGTHS:
        return STATE_UNLOCATED, None, None
    offset, length = rest[0], len(rest)
    value = int.from_bytes(raw[offset:offset + length], 'little')
    modulus = 1 << (8 * length)
    if any(value == candidate % modulus for candidate in expected):
        return STATE_LOCATED, offset, length
    return STATE_UNLOCATED, None, None


def classify_operand(rva: int, length: int, raw: bytes, imask: bytes | None, optype: int, omask: bytes | None,
                     objs: list, refs: list, image: ImageView) -> OperandFacts:
    """Type one operand and locate its field. `objs` = [(kind, value)], `refs` = [(reftype, target-text)]."""
    regs = tuple(value for kind, value in objs if kind == 'reg')
    scalars = [value for kind, value in objs if kind == 'scalar']
    addr_objs = [value for kind, value in objs if kind == 'addr' and value is not None]
    image_refs = [int(text[4:]) for _, text in refs if text.startswith('rva:')]
    stack_refs = [int(text[6:]) for _, text in refs if text.startswith('stack:')]
    imports = [text[4:] for _, text in refs if text.startswith('ext:')]
    dynamic = bool(optype & OPTYPE_DYNAMIC)
    targets = list(dict.fromkeys([*addr_objs, *image_refs]))
    positive = bool(image_refs or imports or (addr_objs and optype & OPTYPE_ADDRESS))
    if positive:
        vkind = VK_ADDRESS
    elif stack_refs or (dynamic and regs and regs[0].upper() in FRAME_REGISTERS):
        vkind = VK_STACK
    elif dynamic:
        vkind = VK_MEMORY
    elif optype & OPTYPE_SCALAR and scalars:
        vkind = VK_SCALAR
    else:
        return OperandFacts(VK_REGISTER, regs[0] if regs else None, None, None, STATE_NONE, regs)
    expected = _expected(rva, length, scalars, targets, image.image_base)
    state, offset, flen = locate_field(omask, imask, raw, dynamic, expected)
    if vkind == VK_SCALAR and state == STATE_LOCATED and flen == 8 and image.reloc_in(rva + offset, rva + offset + 8):
        absolute = scalars[0] - image.image_base   # an immediate64 covered by a DIR64 relocation is an address
        return OperandFacts(VK_ADDRESS, absolute if 0 <= absolute < image.size_of_image else None, offset, flen,
                            state, regs)
    disp = int.from_bytes(raw[offset:offset + flen], 'little', signed=True) if state == STATE_LOCATED else None
    if vkind == VK_ADDRESS:
        value: object = imports[0] if imports else (image_refs[0] if image_refs else (addr_objs[0] if addr_objs else None))
    elif vkind in (VK_STACK, VK_MEMORY):
        if vkind == VK_STACK and stack_refs:
            value = stack_refs[0]
        elif state == STATE_LOCATED:
            value = disp
        else:   # absent: no displacement (the scalars are SIB scale factors); unlocated: keep every scalar visible
            value = (scalars if len(scalars) > 1 else (scalars[0] if scalars else None)) if state == STATE_UNLOCATED else None
    else:
        value = scalars[0] if scalars else None
    return OperandFacts(vkind, value, offset, flen, state, regs if dynamic else ())


def mask_instruction(raw: bytes, facts: list[OperandFacts], level: int) -> bytes:
    """L1 (level 1): clear the located fields of `address` operands; L2 (level 2): also those of scalar, stack and
    memory operands. Register fields and unlocated operands stay untouched."""
    out = bytearray(raw)
    for fact in facts:
        if fact.offset is None or fact.state != STATE_LOCATED:
            continue
        if fact.vkind == VK_ADDRESS or (level >= 2 and fact.vkind in (VK_SCALAR, VK_STACK, VK_MEMORY)):
            out[fact.offset:fact.offset + fact.length] = bytes(fact.length)
    return bytes(out)


def apply_instruction_mask(raw: bytes, imask: bytes | None) -> bytes | None:
    """L3: bytes AND the SLEIGH instruction mask (Ghidra's ExactInstructions); None when the mask is unavailable."""
    if imask is None or len(imask) != len(raw):
        return None
    return bytes(b & m for b, m in zip(raw, imask, strict=True))
