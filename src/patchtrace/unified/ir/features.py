"""Pure key functions of `norm/1` (03 s12.5): 64-bit blake2b keys, the NOP family, flow flags, constant context.

Every hash is `blake2b(digest_size=8)` read as a signed 64-bit integer; INT64_MIN is remapped to INT64_MIN + 1 so
that, inside the columnar arrays of the reader, INT64_MIN can serve as the NULL sentinel. Hashes of instruction
streams add one length byte before the bytes of every instruction, so no two different instruction sequences
share a byte string.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterable

INT64_MIN = -(2 ** 63)
NULL_KEY = INT64_MIN
NOP_MNEMONICS = frozenset({'NOP'})
RETURN_MNEMONICS = frozenset({'RET', 'RETF', 'RETN', 'IRET', 'IRETD', 'IRETQ'})
PADDING_MNEMONICS = frozenset({'INT3'})

# `ins/1` instruction flag bits (03 s12.5)
F_CALL, F_COND, F_JUMP, F_RET, F_COMPUTED, F_NOP = 1, 2, 4, 8, 16, 32
_CALL_FLOWS = frozenset({'UNCONDITIONAL_CALL', 'CONDITIONAL_CALL', 'COMPUTED_CALL', 'CONDITIONAL_COMPUTED_CALL',
                         'CALL_TERMINATOR', 'COMPUTED_CALL_TERMINATOR', 'CONDITIONAL_CALL_TERMINATOR',
                         'CONDITIONAL_COMPUTED_CALL_TERMINATOR', 'CALL_OVERRIDE_UNCONDITIONAL'})
_COND_FLOWS = frozenset({'CONDITIONAL_JUMP', 'CONDITIONAL_COMPUTED_JUMP', 'CONDITIONAL_CALL',
                         'CONDITIONAL_COMPUTED_CALL', 'CONDITIONAL_TERMINATOR', 'CONDITIONAL_CALL_TERMINATOR',
                         'CONDITIONAL_COMPUTED_CALL_TERMINATOR'})
_JUMP_FLOWS = frozenset({'UNCONDITIONAL_JUMP', 'JUMP_OVERRIDE_UNCONDITIONAL', 'COMPUTED_JUMP'})
_RET_FLOWS = frozenset({'TERMINATOR', 'CONDITIONAL_TERMINATOR', 'CALL_TERMINATOR', 'COMPUTED_CALL_TERMINATOR',
                        'CONDITIONAL_CALL_TERMINATOR', 'CONDITIONAL_COMPUTED_CALL_TERMINATOR'})
_COMPUTED_FLOWS = frozenset({'COMPUTED_JUMP', 'CONDITIONAL_COMPUTED_JUMP', 'COMPUTED_CALL',
                             'CONDITIONAL_COMPUTED_CALL', 'COMPUTED_CALL_TERMINATOR',
                             'CONDITIONAL_COMPUTED_CALL_TERMINATOR'})
_CONDITIONAL_BRANCH_FLOWS = frozenset({'CONDITIONAL_JUMP', 'CONDITIONAL_COMPUTED_JUMP'})
_DIRECT_BRANCH_FLOWS = frozenset({'UNCONDITIONAL_JUMP', 'JUMP_OVERRIDE_UNCONDITIONAL', 'CONDITIONAL_JUMP'})

_CST_CONTEXT = {}
for _code, _names in ((1, 'CMP TEST'), (2, 'AND OR XOR NOT ANDN BT BTS BTR BTC'),
                      (3, 'SHL SHR SAR SAL ROL ROR RCL RCR SHLD SHRD SHLX SHRX SARX RORX'),
                      (4, 'ADD SUB ADC SBB INC DEC NEG MUL IMUL DIV IDIV'),
                      (5, 'MOV MOVZX MOVSX MOVSXD MOVABS LEA PUSH XCHG')):
    for _name in _names.split():
        _CST_CONTEXT[_name] = _code


def h64(data: bytes) -> int:
    """Signed 64-bit blake2b key; never INT64_MIN (reserved for NULL)."""
    value = int.from_bytes(hashlib.blake2b(data, digest_size=8).digest(), 'big', signed=True)
    return INT64_MIN + 1 if value == INT64_MIN else value


class KeyStream:
    """Incremental h64 over instruction chunks (one length byte plus the bytes of each instruction)."""
    __slots__ = ('_hash',)

    def __init__(self) -> None:
        self._hash = hashlib.blake2b(digest_size=8)

    def add(self, chunk: bytes) -> None:
        self._hash.update(bytes((len(chunk),)))
        self._hash.update(chunk)

    def add_text(self, text: str) -> None:
        self._hash.update(text.encode('utf-8'))
        self._hash.update(b'\n')

    def value(self) -> int:
        value = int.from_bytes(self._hash.digest(), 'big', signed=True)
        return INT64_MIN + 1 if value == INT64_MIN else value


def multiset_key(mnemonics: Iterable[str]) -> int:
    stream = KeyStream()
    for text in sorted(mnemonics):
        stream.add_text(text)
    return stream.value()


def sequence_key(mnemonics: Iterable[str]) -> int:
    stream = KeyStream()
    for text in mnemonics:
        stream.add_text(text)
    return stream.value()


def is_nop(mnemonic: str) -> bool:
    return mnemonic in NOP_MNEMONICS


def padding_start(mnemonics: list[str]) -> int:
    """Index from which only INT3 padding follows the last RET (those instructions leave the keys); len() if none."""
    last_ret = -1
    for index, text in enumerate(mnemonics):
        if text in RETURN_MNEMONICS:
            last_ret = index
    if last_ret < 0:
        return len(mnemonics)
    tail = mnemonics[last_ret + 1:]
    return last_ret + 1 if tail and all(text in PADDING_MNEMONICS for text in tail) else len(mnemonics)


def instruction_flags(mnemonic: str, flow: str) -> int:
    flags = 0
    if flow in _CALL_FLOWS:
        flags |= F_CALL
    if flow in _COND_FLOWS:
        flags |= F_COND
    if flow in _JUMP_FLOWS:
        flags |= F_JUMP
    if flow in _RET_FLOWS or mnemonic in RETURN_MNEMONICS:
        flags |= F_RET
    if flow in _COMPUTED_FLOWS:
        flags |= F_COMPUTED
    if is_nop(mnemonic):
        flags |= F_NOP
    return flags


def is_direct_branch(flow: str) -> bool:
    """A direct JMP/Jcc: its target (and polarity) may legitimately change with the layout (COS-LAYOUT body key)."""
    return flow in _DIRECT_BRANCH_FLOWS


def is_conditional_branch(flow: str) -> bool:
    return flow in _CONDITIONAL_BRANCH_FLOWS


def constant_context(mnemonic: str) -> int:
    return _CST_CONTEXT.get(mnemonic, 0)
