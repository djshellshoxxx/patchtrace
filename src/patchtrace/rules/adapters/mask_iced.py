"""`MaskSource` over iced-x86 (YRX-integration-plan s2, s7): decodes one function body and marks the bytes that depend on the
image layout. With `engine` and `worker` this is the only rules module that imports an extension; the parent process, the
GUI and the CLI import `masks` and `window`, which only see the `MaskSource` Protocol.

Decoding is static and total: nothing is executed. Every address field is reported from the decoder's own constant
offsets, never guessed from the bytes: the displacement of a RIP-relative operand (`rip-disp`) and the displacement of a
near branch or call whose target lies outside the body (`branch-ext`). Immediates and in-body branches are kept. Addresses
are module-relative: the decoder runs with `ip = rva`, so `target_rva` of a RIP-relative operand or a branch is an RVA
(`None` when it falls outside 32 bits).

An invalid instruction is `PT-RULE-DECODE` and the whole body has no pattern: a window is never cut around bytes the decoder
could not read.
"""
from __future__ import annotations

from importlib import metadata

from iced_x86 import Code, Decoder, FlowControl, OpKind

from ..contracts import DECODER_PIN, MaskSourceName
from ..errors import RuleError
from ..ports import DecodedInstruction, MaskSpan

_FLOW = {FlowControl.NEXT: 'next', FlowControl.CALL: 'call', FlowControl.INDIRECT_CALL: 'indirect-call',
         FlowControl.UNCONDITIONAL_BRANCH: 'branch', FlowControl.INDIRECT_BRANCH: 'indirect-branch',
         FlowControl.CONDITIONAL_BRANCH: 'conditional', FlowControl.RETURN: 'return'}


def _rva(address: int) -> int | None:
    return address if 0 <= address < 2**32 else None


class IcedMaskSource:
    @property
    def name(self) -> MaskSourceName:
        return 'iced-x86'

    @property
    def version(self) -> str:
        try:
            return metadata.version('iced-x86')
        except metadata.PackageNotFoundError:   # a frozen build may lack the distribution metadata
            return DECODER_PIN

    def decode(self, code: bytes, rva: int) -> tuple[DecodedInstruction, ...]:
        decoder = Decoder(64, code, ip=rva)
        out = []
        for instruction in decoder:
            if instruction.code == Code.INVALID:
                raise RuleError('PT-RULE-DECODE', 'The function contains bytes that are not a valid instruction',
                                reason='invalid-instruction')
            fields = decoder.get_constant_offsets(instruction)
            spans: list[MaskSpan] = []
            target = None
            if instruction.is_ip_rel_memory_operand:
                target = _rva(instruction.ip_rel_memory_address)
                if fields.has_displacement:
                    spans.append(MaskSpan(fields.displacement_offset, fields.displacement_size, 'rip-disp'))
            elif instruction.op0_kind == OpKind.NEAR_BRANCH64:
                target = _rva(instruction.near_branch_target)
                outside = target is None or not rva <= target < rva + len(code)
                if outside and fields.has_immediate:   # a branch displacement is the instruction's "immediate"
                    spans.append(MaskSpan(fields.immediate_offset, fields.immediate_size, 'branch-ext'))
            out.append(DecodedInstruction(instruction.ip - rva, instruction.len,
                                          _FLOW.get(instruction.flow_control, 'other'), tuple(spans), target))
        return tuple(out)
