"""Operand classes from the spelling of a line (WBQ S8, the text path of `codetext/1`). Pure, stdlib only.

The unified engine classes every instruction operand as `address`, `stack`, `memory`, `scalar` or `register` from
Ghidra's own facts (docs/specs/unified-engine/03-extraction.md s6). A token mark only has text, so this module applies
the same vocabulary to what the text shows, with the same rule: an operand is an `address` only on positive evidence,
because masking hides a difference and over-masking would hide an edit.

* `address`: a Ghidra address-derived name (`FUN_140001000`, `DAT_14000b000`); a number inside the image range, when
  the range is known; the target of a direct call or branch; a RIP-relative displacement; the address column of a
  listing line.
* `stack`: a number in a bracketed operand whose first register is RSP, RBP, ESP or EBP.
* `memory`: any other bracketed displacement.
* `scalar`: any other number.
* `register`: a register name.

A named operand (`->KERNEL32.DLL::CreateFileW`, a plain identifier, a callee) has no class and is never masked: a
different name is a different callee. `OperandSource` is the seam for the unified engine's instruction facts: an
IR-backed source returns the same mapping from real operand kinds when SPEC-31 delivers them.
"""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Literal, NamedTuple, Protocol

from .names import parse_auto_name
from .oracle import Target
from .tokens import Language, Token

OperandClass = Literal['address', 'stack', 'memory', 'scalar', 'register']
OPERAND_CLASSES = ('address', 'stack', 'memory', 'scalar', 'register')  # the unified engine's `vkind` strings
CONDITIONAL_JUMPS = frozenset(
    'ja jae jb jbe jc je jg jge jl jle jna jnae jnb jnbe jnc jne jng jnge jnl jnle jno jnp jns jnz jo jp jpe jpo js '
    'jz jcxz jecxz jrcxz'.split())
BRANCHES = CONDITIONAL_JUMPS | frozenset({'jmp', 'call', 'loop', 'loope', 'loopne', 'loopz', 'loopnz'})
_FRAME_REGISTERS = frozenset({'rsp', 'rbp', 'esp', 'ebp'})
# 0x.., decimal, and the `10h` form; at most a 64-bit value, so hostile digit runs never reach `int`.
_INTEGER = re.compile(r'(?:0[xX]([0-9A-Fa-f]{1,16})|([0-9]{1,18})|([0-9][0-9A-Fa-f]{0,15})[hH])[uUlL]{0,3}')


class Operand(NamedTuple):
    cls: OperandClass
    target: Target | None = None  # where an address operand points, when the text says; None when it cannot


class ImageRange(NamedTuple):
    """The loaded image of the build a line belongs to: `[base, base + size)`."""
    base: int
    size: int

    def contains(self, value: int) -> bool:
        return self.base <= value < self.base + self.size


class OperandSource(Protocol):
    def operands(self, line: str, tokens: Sequence[Token], language: Language) -> Mapping[int, Operand]:
        """Operand per token index (an index into `tokens`); a token with no entry is not an operand."""
        ...


def number_value(text: str) -> int | None:
    """The value of an integer token (`0x20`, `32`, `20h`, with an optional `U`/`L` suffix), else None."""
    match = _INTEGER.fullmatch(text)
    if match is None:
        return None
    hexadecimal, decimal, suffixed = match.groups()
    if hexadecimal:
        return int(hexadecimal, 16)
    return int(decimal) if decimal else int(suffixed, 16)


def asm_mnemonic(line: str, tokens: Sequence[Token]) -> tuple[int, str]:
    """(index of the first mnemonic token, the lower-cased real mnemonic) of an assembly line; a prefix such as `lock`
    comes first and is skipped. (-1, '') when the line has none."""
    first = last = -1
    for index, token in enumerate(tokens):
        if token.kind == 'mnemonic':
            if first < 0:
                first = index
            last = index
        elif token.kind != 'ws' and last >= 0:
            break
    if last < 0:
        return -1, ''
    return first, line[tokens[last].start:tokens[last].end].lower()


def _auto_operand(name: str) -> Operand:
    parsed = parse_auto_name(name)
    return Operand('address', Target(parsed.kind, parsed.address) if parsed else None)


class TextOperandSource:
    """Operand classes from the spelling alone. `image` (the build's loaded range) is what lets a plain number count as
    an address; without it a number is a `scalar`, so an unknown image can only make marks louder, never quieter."""

    def __init__(self, image: ImageRange | None = None) -> None:
        self.image = image

    def operands(self, line: str, tokens: Sequence[Token], language: Language) -> Mapping[int, Operand]:
        if language == 'asm':
            return self._assembly(line, tokens)
        out: dict[int, Operand] = {}
        for index, token in enumerate(tokens):
            if token.kind == 'auto_name':
                out[index] = _auto_operand(line[token.start:token.end])
            elif token.kind == 'number':
                out[index] = self._number(line[token.start:token.end], 'scalar')
        return out

    def _number(self, text: str, otherwise: OperandClass) -> Operand:
        image = self.image
        if image is not None:
            value = number_value(text)
            if value is not None and image.contains(value):
                return Operand('address', Target('data', value))
        return Operand(otherwise)

    def _assembly(self, line: str, tokens: Sequence[Token]) -> dict[int, Operand]:
        out: dict[int, Operand] = {}
        first, mnemonic = asm_mnemonic(line, tokens)
        target_kind = 'function' if mnemonic == 'call' else 'label'
        depth, base, displacements = 0, None, []  # inside [..]: nesting, first register, number token indexes
        scaled = False  # the previous significant token was `*`: a number after it is a scale, not a displacement
        for index, token in enumerate(tokens):
            kind, text = token.kind, line[token.start:token.end]
            if kind == 'ws':
                continue
            follows_star, scaled = scaled, kind == 'op' and text == '*'
            if kind == 'punct' and text == '[':
                if depth == 0:
                    base, displacements = None, []
                depth += 1
            elif kind == 'punct' and text == ']':
                if depth:
                    depth -= 1
                    if depth == 0:
                        self._bracketed(out, line, tokens, displacements, base)
            elif kind == 'register':
                out[index] = Operand('register')
                if depth and base is None:
                    base = text.lower()
            elif kind == 'auto_name':
                out[index] = _auto_operand(text)
            elif kind == 'number':
                if depth and follows_star:
                    out[index] = Operand('scalar')
                elif depth:
                    displacements.append(index)
                elif index < first:  # first is -1 without a mnemonic
                    out[index] = Operand('address')  # the address column of a listing line
                elif mnemonic in BRANCHES:
                    value = number_value(text)
                    out[index] = Operand('address', Target(target_kind, value) if value is not None else None)
                else:
                    out[index] = self._number(text, 'scalar')
        if depth:
            self._bracketed(out, line, tokens, displacements, base)
        return out

    def _bracketed(self, out: dict[int, Operand], line: str, tokens: Sequence[Token], displacements: list[int],
                   base: str | None) -> None:
        for index in displacements:
            if base in _FRAME_REGISTERS:
                out[index] = Operand('stack')
            elif base == 'rip':
                out[index] = Operand('address')  # RIP-relative: the number is a displacement, not the target
            elif base is None:
                out[index] = self._number(line[tokens[index].start:tokens[index].end], 'memory')
            else:
                out[index] = Operand('memory')
