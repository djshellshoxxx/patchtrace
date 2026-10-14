"""Instruction masking policy (plan s6 "Over- or under-masking"). Pure: no decoder import, no I/O.

Policy = unified L1, positive evidence only: a RIP-relative displacement, a branch displacement that leaves the
function, an operand field covered by a base relocation and a unified-IR address reference are wildcarded.
Immediates and in-function branch displacements are kept (they carry bound constants and stay stable on a rebuild).
A decoder adapter reduces each instruction to `DecodedInsn` facts; this module turns them into `MaskedInstruction`.
"""
from __future__ import annotations

from bisect import bisect_right
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .contracts import CallPin, FunctionRef, MaskKind
from .errors import RulesError
from .ports import MaskedFunction, MaskedInstruction

WILDCARD = '??'
KIND_ORDER: tuple[MaskKind, ...] = ('rip-disp', 'branch-ext', 'reloc', 'addr-ref')
MAX_RELOC_WIDTH = 8


@dataclass(frozen=True)
class DecodedInsn:
    """Decoder-neutral facts about one instruction; offsets are relative to the instruction start."""
    rva: int
    raw: bytes
    rip_disp: tuple[int, int] | None = None   # (offset, size) of the RIP-relative displacement
    rip_target: int | None = None             # RVA that displacement addresses
    branch_disp: tuple[int, int] | None = None  # (offset, size) of a near-branch displacement
    branch_target: int | None = None          # RVA of the branch target
    is_call: bool = False


class RelocIndex:
    """Sorted base-relocation RVAs with their widths, as `PeTableView.relocations()` returns them."""

    def __init__(self, starts: Sequence[int] = (), widths: Sequence[int] = ()):
        if len(starts) != len(widths):
            raise ValueError('relocation starts and widths differ in length')
        self._starts, self._widths = list(starts), list(widths)

    def covered_offsets(self, rva: int, length: int) -> frozenset[int]:
        """Offsets in [0, length) of bytes inside a relocated field."""
        end = rva + length
        found: set[int] = set()
        i = max(bisect_right(self._starts, rva - MAX_RELOC_WIDTH) - 1, 0)
        while i < len(self._starts) and self._starts[i] < end:
            lo, hi = max(self._starts[i], rva), min(self._starts[i] + self._widths[i], end)
            found.update(range(lo - rva, hi - rva))
            i += 1
        return frozenset(found)


def _token(raw: bytes, masked: set[int]) -> str:
    return ' '.join(WILDCARD if i in masked else f'{b:02X}' for i, b in enumerate(raw))


def _span(field: tuple[int, int]) -> range:
    return range(field[0], field[0] + field[1])


def mask_instruction(insn: DecodedInsn, extent: tuple[int, int], relocs: RelocIndex,
                     iat: Mapping[int, tuple[str, str]], addr_refs: Mapping[int, int] | None = None
                     ) -> MaskedInstruction:
    """Mask one instruction; a call through an IAT slot also yields a pin (offsets relative to the instruction)."""
    masked: dict[MaskKind, set[int]] = {}
    if insn.rip_disp is not None:
        masked['rip-disp'] = set(_span(insn.rip_disp))
    if insn.branch_disp is not None and insn.branch_target is not None \
            and not extent[0] <= insn.branch_target < extent[1]:
        masked['branch-ext'] = set(_span(insn.branch_disp))
    if offsets := relocs.covered_offsets(insn.rva, len(insn.raw)):
        masked['reloc'] = set(offsets)
    for at, width in (addr_refs or {}).items():
        lo, hi = max(at, insn.rva), min(at + width, insn.rva + len(insn.raw))
        if lo < hi:
            masked.setdefault('addr-ref', set()).update(range(lo - insn.rva, hi - insn.rva))
    every = set().union(*masked.values()) if masked else set()
    pin = None
    if insn.is_call and insn.rip_disp is not None and insn.rip_target in iat:
        dll, name = iat[insn.rip_target]
        pin = CallPin(disp_offset=insn.rip_disp[0], end_offset=len(insn.raw), dll=dll, name=name)
    kinds = tuple(kind for kind in KIND_ORDER if kind in masked)
    return MaskedInstruction(rva=insn.rva, length=len(insn.raw), token=_token(insn.raw, every), masks=kinds, pin=pin)


def mask_function(function: FunctionRef, mask_source: str, insns: Sequence[DecodedInsn], relocs: RelocIndex,
                  iat: Mapping[int, tuple[str, str]], addr_refs: Mapping[int, int] | None = None) -> MaskedFunction:
    """Masked body of one function; the extent is the function's own `[rva, rva + size)`."""
    if function.extent == 'unknown' or function.size == 0:
        raise RulesError('PT-RULE-MASK', 'The function size is not known (leaf functions have no exception data), '
                                         'so its bytes are unavailable.')
    extent = (function.rva, function.rva + function.size)
    masked = tuple(mask_instruction(insn, extent, relocs, iat, addr_refs) for insn in insns)
    return MaskedFunction(function=function, mask_source=mask_source, instructions=masked)
