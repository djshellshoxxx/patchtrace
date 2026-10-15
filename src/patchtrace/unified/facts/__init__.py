"""SPEC-31 L2 facts (05 s2, s6): change channels, canonical pseudo-code and verdicts. Facts never change a decision
(D-03): they read the decided rows and write `ChangeFacts` only.

`Evidence` is the hand-over between the channel collector and the verdict rules. It is plain data so the rules can
be tested without any decompiler text.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ..contracts import Delta

# 05 s2.6 severity order (never shown as a number); the classes S0 can produce come first.
SEVERITY_ORDER: tuple[str, ...] = (
    'callee', 'call-added', 'call-removed', 'condition', 'comparison', 'struct-offset', 'data-ref', 'block-added',
    'block-removed', 'eh', 'constant', 'cfg', 'string', 'frame', 'size-only', 'refcount-only', 'address-only',
    'register-only', 'layout-only', 'name-only', 'unknown')
CALL_CLASSES = ('callee', 'call-added', 'call-removed')
# A constant in a compare, test, mask, shift or size context ranks right after condition/comparison (05 s2.6); the
# context is read from the mnemonic of the instruction text, which every C2 delta carries.
CONTEXT_MNEMONICS = frozenset({'CMP', 'TEST', 'AND', 'OR', 'XOR', 'NOT', 'BT', 'BTS', 'BTR', 'BTC', 'SHL', 'SHR', 'SAR',
                               'SAL', 'ROL', 'ROR', 'RCL', 'RCR'})


def severity(delta: Delta) -> tuple:
    rank = float(SEVERITY_ORDER.index(delta.cls))
    if delta.cls == 'constant' and (delta.old or delta.new or '').split(' ', 1)[0].upper() in CONTEXT_MNEMONICS:
        rank = SEVERITY_ORDER.index('comparison') + 0.5
    return (rank, delta.channel, delta.old or '', delta.new or '')


@dataclass(frozen=True)
class IrEvidence:
    """What only the IR can tell the verdict rules (S3): the CFG proof inputs of one pair, the unmapped labels of the
    canonical pseudo-code (COS-PSEUDO needs none) and the row flags of the two functions."""
    positional_cfg: bool                # COS-ADDR/1: blocks and successors equal positionally
    layout_ok: bool                     # COS-LAYOUT/1: polarity-preserving block bijection
    mask_unlocated: bool                # an unlocated address field: no COS-ADDR possible
    pseudo_unmapped: int = 0
    trace_arg: bool = False             # F17: every constant delta feeds a tracing call (ordering hint only)


@dataclass(frozen=True)
class Evidence:
    """What the channels observed for one chosen pair. `anchors` runs parallel to `deltas`: the other-group
    channel that shows the SAME change (05 s2.5 MAT-ANCHOR), or None. `ir` is None in S0 mode (no ProgramIR)."""
    states: Mapping[str, str]           # C0..C6, C8 -> equal | differs | unavailable (S0 mode: C4, C5, C6, C8)
    deltas: tuple[Delta, ...]
    anchors: tuple[str | None, ...]
    targets: tuple[int, int, int]       # (mapped, unmapped, conflict) function/data labels
    eh: str
    change_signal: bool                 # Ghidriff lists the pair as modified, or the analyst says so
    diff_types: tuple[str, ...]
    limits_hit: tuple[str, ...]
    ir: IrEvidence | None = None
    row_flags: tuple[str, ...] = ()     # IR facts about the two functions (tiny, thunk, ..., ir-missing)
