"""Address-independent byte patterns of a function body (YRX-integration-plan s6 "Over- or under-masking", s7 step 2).

Policy = the unified engine's L1, positive evidence only. A byte is wildcarded when it is a field that holds an address
the loader or the linker chose: the displacement of a RIP-relative operand (`rip-disp`: x64 code reaches data and
imports through it and it has no relocation entry), the displacement of a branch or call whose target lies outside the
body (`branch-ext`; a branch inside the body is a distance the rebuild keeps), and any byte a base relocation covers
(`reloc`). Immediates are kept: they carry the constants of the code. An instruction the decoder did not describe is
never guessed at: the decoded instructions must tile the body exactly, or the body has no pattern (`PT-RULE-DECODE`).

Pure: the decoder is a `MaskSource` and the relocations are plain numbers, so the module never imports an extension.
"""
from __future__ import annotations

from bisect import bisect_left
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .contracts import CallPin, MaskKind
from .errors import RuleError
from .limits import DEFAULT_LIMITS
from .ports import DecodedInstruction, MaskSpan

WILDCARD = '??'
MAX_RELOCATION_WIDTH = 8


@dataclass(frozen=True)
class MaskedInstruction:
    offset: int                       # byte offset inside the body
    size: int
    tokens: tuple[str, ...]           # one hex token per byte, `??` where masked
    kinds: tuple[MaskKind, ...]       # why bytes of this instruction are wildcards (sorted, as the contract wants)
    flow: str
    target_rva: int | None
    spans: tuple[MaskSpan, ...]       # the decoder's address fields (before relocations)

    @property
    def key(self) -> str:
        """What two instructions must share to be "the same instruction" in a diff."""
        return ' '.join(self.tokens)


@dataclass(frozen=True)
class MaskedFunction:
    rva: int
    instructions: tuple[MaskedInstruction, ...]

    @property
    def size(self) -> int:
        return sum(i.size for i in self.instructions)

    def tokens(self, first: int, last: int) -> tuple[str, ...]:
        """The pattern tokens of instructions [first, last)."""
        return tuple(token for item in self.instructions[first:last] for token in item.tokens)

    def size_of(self, first: int, last: int) -> int:
        return sum(item.size for item in self.instructions[first:last])

    def kinds(self, first: int, last: int) -> tuple[MaskKind, ...]:
        return tuple(sorted({kind for item in self.instructions[first:last] for kind in item.kinds}))

    def rva_of(self, index: int) -> int:
        return self.rva + self.instructions[index].offset


def _decode_error(reason: str) -> RuleError:
    return RuleError('PT-RULE-DECODE', 'The function body could not be described instruction by instruction',
                     reason=reason)


def _check_tiling(code: bytes, decoded: Sequence[DecodedInstruction]) -> None:
    position = 0
    for item in decoded:
        if item.offset != position or item.size < 1 or item.offset + item.size > len(code):
            raise _decode_error('decoder-gap')
        for span in item.spans:
            if span.start < 0 or span.length < 1 or span.start + span.length > item.size:
                raise _decode_error('span-outside')
        position += item.size
    if position != len(code):
        raise _decode_error('decoder-short')


def _relocation_spans(rva: int, item: DecodedInstruction, relocations: tuple[Sequence[int], Sequence[int]]
                      ) -> list[MaskSpan]:
    """Parts of the instruction a base relocation covers, as spans inside it."""
    starts, widths = relocations
    begin, end = rva + item.offset, rva + item.offset + item.size
    out = []
    index = bisect_left(starts, begin - MAX_RELOCATION_WIDTH + 1)
    while index < len(starts) and starts[index] < end:
        low, high = max(starts[index], begin), min(starts[index] + widths[index], end)
        if low < high:
            out.append(MaskSpan(low - begin, high - low, 'reloc'))
        index += 1
    return out


def mask_function(code: bytes, rva: int, decoded: Sequence[DecodedInstruction],
                  relocations: tuple[Sequence[int], Sequence[int]] = ((), ())) -> MaskedFunction:
    """`code` is the whole verified body mapped at `rva`; `decoded` tiles it; `relocations` is the build's sorted
    (RVA, width) table. Raises `PT-RULE-DECODE` when the decoded instructions do not tile the body."""
    _check_tiling(code, decoded)
    out = []
    for item in decoded:
        spans = (*item.spans, *_relocation_spans(rva, item, relocations))
        tokens = [f'{byte:02X}' for byte in code[item.offset:item.offset + item.size]]
        for span in spans:
            tokens[span.start:span.start + span.length] = [WILDCARD] * span.length
        kinds = tuple(sorted({span.kind for span in spans}))
        out.append(MaskedInstruction(item.offset, item.size, tuple(tokens), kinds, item.flow, item.target_rva,
                                     item.spans))
    return MaskedFunction(rva, tuple(out))


def call_pins(function: MaskedFunction, first: int, last: int, slots: Mapping[int, tuple[str, str]],
              *, limit: int = DEFAULT_LIMITS.pins_per_feature) -> tuple[CallPin, ...]:
    """One pin per masked `call [rip+disp]` of instructions [first, last) whose target is an import address table slot of
    a NAMED import: the window then says not only "a call goes through some slot here" but "through THIS API". Offsets
    are inside the window; at most `limit` pins."""
    base = function.instructions[first].offset if first < last else 0
    pins = []
    for item in function.instructions[first:last]:
        disp = next((span for span in item.spans if span.kind == 'rip-disp' and span.length == 4), None)
        slot = slots.get(item.target_rva) if item.target_rva is not None else None
        if item.flow != 'indirect-call' or disp is None or slot is None or slot[1].startswith('#'):
            continue
        start = item.offset - base
        pins.append(CallPin(disp_offset=start + disp.start, end_offset=start + item.size, dll=slot[0], name=slot[1]))
        if len(pins) == limit:
            break
    return tuple(pins)
