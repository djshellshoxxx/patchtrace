"""S0 verdicts (05 s2.5, s6): proof tiers over the S0 channels -> `ChangeFacts`. Pure, first match wins.

Without IR the only proof is COS-PSEUDO/1 (decompiler-relative, listed and never hidden) and `material` needs a
callee-class delta whose SAME change another data group shows (MAT-ANCHOR). Absence is never evidence of sameness:
no signal at all is `unknown`, never `cosmetic` or `unchanged`. Ghidriff's diff types are hints (F4) and never decide.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..contracts import CHANNELS, SEMANTIC_CLASSES, ChangeFacts
from ..limits import DEFAULT_LIMITS, UnifiedLimits
from . import SEVERITY_ORDER, Evidence

NON_CODE_TYPES = {'address': 'address-only', 'refcount': 'refcount-only', 'size': 'size-only', 'name': 'name-only'}
ONE_SIDED = ('older-only', 'newer-only', 'ambiguous')


@dataclass(frozen=True)
class Judged:
    facts: ChangeFacts
    classes: tuple[str, ...]   # row-level change classes, in severity order (ordering hints, 05 s2.6)
    hints: tuple[str, ...]


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
    semantic = [d for d in deltas if d.cls in SEMANTIC_CLASSES]
    targets_ok = ev.targets[1] == 0 and ev.targets[2] == 0
    proof = second = None
    if not semantic and states.get('C4') == states.get('C5') == states.get('C6') == 'equal' and targets_ok \
            and ev.eh != 'differs':
        verdict, proof = 'cosmetic', 'COS-PSEUDO/1'
    else:
        second = next((a for d, a in zip(deltas, anchors, strict=True) if d.cls in SEMANTIC_CLASSES and a), None)
        if second is not None:
            verdict = 'material'
        elif (semantic or ev.targets[1] or ev.targets[2] or deltas or ev.change_signal
              or any(states.get(c) == 'differs' for c in ('C4', 'C5', 'C6', 'C8'))):
            verdict = 'review'
        else:
            verdict = 'unknown'
    facts = ChangeFacts(row_id=row_id, verdict=verdict, proof=proof, second_channel=second, channels=channels,
                        targets=ev.targets, eh=ev.eh, deltas=deltas, deltas_omitted=omitted,
                        limits_hit=tuple(dict.fromkeys(limits_hit)))
    classes = {d.cls for d in deltas}
    typed = set()
    if ev.diff_types and all(t in NON_CODE_TYPES for t in ev.diff_types):
        typed = {NON_CODE_TYPES[t] for t in ev.diff_types}
    if verdict == 'review' and ev.targets[1] and not semantic:
        typed.add('address-only')  # an unmapped target blocks every proof; never material (05 s5)
    hints = (f'ghidriff-diff-types:{",".join(ev.diff_types)}'[:200],) if ev.diff_types else ()
    ordered = tuple(c for c in SEVERITY_ORDER if c in classes | typed)
    return Judged(facts, ordered, hints)
