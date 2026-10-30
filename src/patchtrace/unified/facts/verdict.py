"""Verdicts (05 s2.5, s6): proof tiers over the channels -> `ChangeFacts`. Pure, first match wins.

S0 mode (no ProgramIR): the only proof is COS-PSEUDO/1 (decompiler-relative, listed and never hidden) and `material`
needs a callee-class delta whose SAME change another data group shows (MAT-ANCHOR). IR mode (S3) adds UNCH/1, COS-ADDR/1
and COS-LAYOUT/1, each requiring target consistency of EVERY address operand (05 s2.7) and EH-EQ; `unchanged` is no
longer "raw bytes equal" alone (R-03). Absence is never evidence of sameness: no signal at all is `unknown`. Ghidriff's
diff types are hints (F4) and never decide. A cheap-tier semantic delta always beats COS-PSEUDO (cross-tier consistency).
"""
from __future__ import annotations

from dataclasses import dataclass

from ..contracts import (
    BLOCK_CLASSES,
    BYTES_GROUP,
    CHANNELS,
    SEMANTIC_CLASSES,
    UNPROVABLE_CLASSES,
    ChangeFacts,
)
from ..limits import DEFAULT_LIMITS, UnifiedLimits
from . import SEVERITY_ORDER, Evidence

NON_CODE_TYPES = {'address': 'address-only', 'refcount': 'refcount-only', 'size': 'size-only', 'name': 'name-only'}
ONE_SIDED = ('older-only', 'newer-only', 'ambiguous')
# Delta classes that no proof may carry: semantic ones, unprovable ones, block changes and the classes that stay
# `review` by rule (a frame or register change is a real change the decompiler may not show: R-14).
PROOF_BLOCKERS = frozenset({*SEMANTIC_CLASSES, *UNPROVABLE_CLASSES, *BLOCK_CLASSES, 'frame', 'register-only', 'eh'})
PSEUDO_BLOCKERS = frozenset({*SEMANTIC_CLASSES, *UNPROVABLE_CLASSES, *BLOCK_CLASSES, 'frame', 'eh'})


@dataclass(frozen=True)
class Judged:
    facts: ChangeFacts
    classes: tuple[str, ...]   # row-level change classes, in severity order (ordering hints, 05 s2.6)
    hints: tuple[str, ...]
    flags: tuple[str, ...] = ()


def judge(row_id: str, decision: str, ev: Evidence, limits: UnifiedLimits = DEFAULT_LIMITS) -> Judged:
    if decision in ONE_SIDED:
        return Judged(ChangeFacts(row_id=row_id, verdict='not-applicable',
                                  channels=tuple((c, 'not-applicable') for c in CHANNELS)), (), ())
    states = ev.states
    channels = tuple((c, states.get(c, 'unavailable')) for c in CHANNELS)
    cap = limits.l28_deltas_per_pair
    deltas, anchors = ev.deltas[:cap], ev.anchors[:cap]
    omitted = len(ev.deltas) - len(deltas)
    limits_hit = (*ev.limits_hit, *(('deltas-cap',) if omitted else ()))
    classes = {d.cls for d in deltas}
    semantic = [d for d in deltas if d.cls in SEMANTIC_CLASSES]
    targets_ok = ev.targets[1] == 0 and ev.targets[2] == 0
    proof = second = None
    if ev.ir is not None:
        proof = _ir_proof(ev, states, classes, semantic, targets_ok, omitted)
    elif _pseudo_proof(ev, states, classes, semantic, targets_ok):
        proof = 'COS-PSEUDO/1'
    if proof is not None:
        verdict = 'unchanged' if proof == 'UNCH/1' else 'cosmetic'
    else:
        second = next((a for d, a in zip(deltas, anchors, strict=True)
                       if (d.cls in SEMANTIC_CLASSES or d.cls in BLOCK_CLASSES) and a and a not in BYTES_GROUP
                       and states.get(a) == 'differs'), None)       # another data group, and it really differs
        if second is not None:
            verdict = 'material'
        elif (semantic or ev.targets[1] or ev.targets[2] or deltas or ev.change_signal or ev.eh == 'differs'
              or 'align-cap' in ev.limits_hit or any(states.get(c) == 'differs' for c in CHANNELS)):
            verdict = 'review'
        else:
            verdict = 'unknown'
    facts = ChangeFacts(row_id=row_id, verdict=verdict, proof=proof, second_channel=second, channels=channels,
                        targets=ev.targets, eh=ev.eh, deltas=deltas, deltas_omitted=omitted,
                        limits_hit=tuple(dict.fromkeys(limits_hit)))
    typed = set()
    if ev.diff_types and all(t in NON_CODE_TYPES for t in ev.diff_types):
        typed = {NON_CODE_TYPES[t] for t in ev.diff_types}
    if verdict == 'review' and ev.targets[1] and not semantic:
        typed.add('address-only')  # an unmapped target blocks every proof; never material (05 s5)
    if ev.eh == 'differs':
        typed.add('eh')
    hints = (f'ghidriff-diff-types:{",".join(ev.diff_types)}'[:200],) if ev.diff_types else ()
    if ev.ir is not None and ev.ir.trace_arg:
        hints += ('trace-arg',)
    ordered = tuple(c for c in SEVERITY_ORDER if c in classes | typed)
    return Judged(facts, ordered, hints, ev.row_flags)


def _pseudo_proof(ev: Evidence, states, classes: set[str], semantic: list, targets_ok: bool) -> bool:
    """COS-PSEUDO/1: the canonical pseudo-code is equal, nothing else says otherwise (decompiler-relative, listed)."""
    unmapped = ev.ir.pseudo_unmapped if ev.ir is not None else 0
    # IR supplies an EH-EQ state. Unreadable / unsupported unwind metadata cannot corroborate a benign change.
    # Keep the S0 (no IR) fallback decompiler-relative rather than changing its historical proof contract.
    eh_ok = ev.eh in ('equal', 'absent') if ev.ir is not None else ev.eh != 'differs'
    return (not semantic and states.get('C4') == states.get('C5') == states.get('C6') == 'equal' and targets_ok
            and eh_ok and unmapped == 0 and not classes & PSEUDO_BLOCKERS)


def _ir_proof(ev: Evidence, states, classes: set[str], semantic: list, targets_ok: bool, omitted: int) -> str | None:
    """UNCH/1, COS-ADDR/1, COS-LAYOUT/1 or COS-PSEUDO/1 in the order of 05 s2.5, or None. Capped deltas (a delta the
    cap hid could be a blocker) and alignment caps never prove anything."""
    ir = ev.ir
    structural_ok = targets_ok and ev.eh in ('equal', 'absent')
    uncapped = not omitted and 'align-cap' not in ev.limits_hit
    if states.get('C0') == 'equal' and structural_ok and uncapped and not classes:
        return 'UNCH/1'
    if semantic or not uncapped or states.get('C4') != 'equal' or states.get('C5') != 'equal':
        return None
    if structural_ok and not classes & PROOF_BLOCKERS:
        if states.get('C1') == 'equal' and ir.positional_cfg and not ir.mask_unlocated:
            return 'COS-ADDR/1'
        if ir.layout_ok:
            return 'COS-LAYOUT/1'
    return 'COS-PSEUDO/1' if _pseudo_proof(ev, states, classes, semantic, targets_ok) else None
