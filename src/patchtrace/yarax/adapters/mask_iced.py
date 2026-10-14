"""`MaskSource` over iced-x86 (optional `rules` extra) and a verified PE. One of the two modules that may import the
decoder; it is reached through `patchtrace.optional_deps`, so a missing decoder is the clear state `decoder none`
(PT-RULE-UNAVAILABLE) and never an import error. Only bytes are decoded: nothing is executed or loaded."""
from __future__ import annotations

from collections.abc import Callable

from ... import optional_deps
from ...pe_overview.tables import PeTableError, PeTableView
from ..contracts import FunctionRef, Side
from ..errors import RulesError
from ..limits import LIMITS
from ..masks import DecodedInsn, RelocIndex, mask_function
from ..ports import MaskedFunction

MASK_SOURCE = 'iced-x86'


def decoder_state() -> tuple[str, str]:
    """(name, version) of the usable decoder, or ('none', 'none')."""
    if optional_deps.iced_x86 is None:
        return 'none', 'none'
    return 'iced-x86', optional_deps.probe(('iced-x86',))['iced-x86'].version or 'unknown'


def _iced():
    module = optional_deps.iced_x86
    if module is None:
        raise RulesError('PT-RULE-UNAVAILABLE', 'The instruction decoder (iced-x86) is not available in this '
                                                'installation (decoder none), so byte windows cannot be proposed.')
    return module


def decode(raw: bytes, rva: int, image_base: int) -> list[DecodedInsn]:
    """Decode `raw` (a whole function body at `rva`) into mask facts; an invalid instruction is PT-RULE-DECODE."""
    iced = _iced()
    decoder = iced.Decoder(64, raw, ip=image_base + rva)
    out: list[DecodedInsn] = []
    while decoder.can_decode:
        instr = decoder.decode()
        if instr.code == iced.Code.INVALID:
            raise RulesError('PT-RULE-DECODE', f'An invalid instruction at RVA {rva + decoder.position:#x} '
                                               'stopped the decoder.')
        offsets = decoder.get_constant_offsets(instr)
        start = instr.ip - image_base
        item = {'rva': start, 'raw': raw[start - rva:start - rva + instr.len]}
        if instr.is_ip_rel_memory_operand:
            item.update(rip_disp=(offsets.displacement_offset, offsets.displacement_size),
                        rip_target=instr.ip_rel_memory_address - image_base,
                        is_call=instr.is_call_near_indirect)
        elif instr.op0_kind == iced.OpKind.NEAR_BRANCH64 and offsets.has_immediate:
            item.update(branch_disp=(offsets.immediate_offset, offsets.immediate_size),
                        branch_target=instr.near_branch_target - image_base)
        out.append(DecodedInsn(**item))
    return out


def function_ref(view: PeTableView, rva: int, name: str = '') -> FunctionRef:
    """Function at `rva` with its `.pdata` extent; leaf code without an entry has an unknown extent (size 0)."""
    extent = view.function_extent(rva)
    if extent is None:
        return FunctionRef(name=name, rva=rva, size=0, extent='unknown')
    return FunctionRef(name=name, rva=rva, size=extent[1] - extent[0], extent='pdata')


class IcedMaskSource:
    """`open_pe(sha256)` returns the verified `PeTableView` of that build; the adapter closes it after each call."""

    def __init__(self, open_pe: Callable[[str], PeTableView]):
        self._open_pe = open_pe

    def masked_function(self, sha256: str, side: Side, function: FunctionRef) -> MaskedFunction:
        if function.extent == 'unknown' or function.size == 0:
            raise RulesError('PT-RULE-MASK', 'The function size is not known (leaf functions have no exception '
                                             'data), so its bytes are unavailable.')
        if function.size > LIMITS.function_bytes:
            raise RulesError('PT-RULE-LIMIT', 'The function is larger than the byte-window limit.')
        try:
            with self._open_pe(sha256) as view:
                raw = view.read_rva(function.rva, function.size)
                insns = decode(raw, function.rva, view.image_base)
                relocs = RelocIndex(*view.relocations())
                return mask_function(function, MASK_SOURCE, insns, relocs, view.import_slots())
        except PeTableError as exc:
            raise RulesError('PT-RULE-INTEGRITY', f'The {side} build could not be read for masking: {exc}') from None
