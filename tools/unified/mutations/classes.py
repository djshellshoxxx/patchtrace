"""The G-U2 mutant classes (08-evaluation s1), one registry row per class the gate names.

A mutant is a freestanding C module in which exactly one function carries one planted edit. Truth is exact by
construction: the edited function is `changed(<class id>)`, every other function is unchanged. `verdicts` lists the
materiality values the gate accepts for a mutant of the class: `cosmetic` and `unchanged` are leakage (a normaliser
bug) and never listed; the frame-only class must land in `review` itself.

`acceptance` says how the build proves that the planted edit is real code. `masked` is the SPEC-32 rule (the address-
masked body differs). `symbolic` is for the two classes whose only change is the symbol an address operand names (a
swapped callee or global): their masked body is identical by design, so the proof is that the function's symbol
references differ.

Two review additions cannot be planted as plain C and stay `PENDING` with the exact thing each needs.
"""
from __future__ import annotations

from dataclasses import dataclass

DETECTED = ('material', 'review')


@dataclass(frozen=True)
class MutationClass:
    id: str
    spec_phrase: str            # the words 08-evaluation s1 uses; a test keeps the registry and the gate row in step
    verdicts: tuple[str, ...]
    acceptance: str             # 'masked' | 'symbolic'
    summary: str
    review_finding: str | None = None   # R-xx of 11-review-log when the class targets a hole of the first draft


@dataclass(frozen=True)
class PendingClass:
    id: str
    spec_phrase: str
    review_finding: str
    needs: str
    reason: str


CLASSES: tuple[MutationClass, ...] = (
    MutationClass('constant', 'constant', DETECTED, 'masked', 'an immediate operand changes'),
    MutationClass('comparison', 'comparison operator', DETECTED, 'masked', 'the relation of a compare is flipped'),
    MutationClass('bound', 'bound (`<`/`<=`)', DETECTED, 'masked', 'a strict bound becomes inclusive'),
    MutationClass('signedness', 'signedness (`jl`/`jb`)', DETECTED, 'masked',
                  'a compare flips between signed and unsigned'),
    MutationClass('removed-check', 'removed check', DETECTED, 'masked', 'a guard block is deleted'),
    MutationClass('callee-swap', 'swapped callee (same shape)', DETECTED, 'symbolic',
                  'a call reaches another function of the same prototype'),
    MutationClass('field-offset', 'struct offset', DETECTED, 'masked', 'a member access moves to another offset'),
    MutationClass('added-block', 'added block', DETECTED, 'masked', 'a conditional block is added'),
    MutationClass('global-swap', 'swap to an EXISTING global with the same instruction shape', DETECTED, 'symbolic',
                  'a load names another initialised global; the instruction bytes keep their shape',
                  review_finding='R-01'),
    MutationClass('index-swap', 'index-register swap inside an address operand', DETECTED, 'masked',
                  'an array index is read from another parameter register', review_finding='R-07'),
    MutationClass('branch-swap', 'then/else successor swap', DETECTED, 'masked',
                  'the two arms of an if/else trade bodies under an unchanged condition', review_finding='R-04'),
    MutationClass('buf-resize', 'buffer resize (frame only)', ('review',), 'masked',
                  'a local buffer grows; only the frame allocation changes', review_finding='R-16'),
)

PENDING: tuple[PendingClass, ...] = (
    PendingClass(
        'moved-rva-call', 'identical bytes at a moved RVA whose relative call now reaches another function', 'R-03',
        'a layout-controlled pair of same-size callees (definition order swapped) and an acceptance rule on raw bytes',
        'the caller keeps identical bytes, so neither the masked nor the symbolic acceptance sees the planted change; '
        'it needs an acceptance rule that compares raw caller bytes with the callee identity at the call target'),
    PendingClass(
        'try-scope', 'added `__try` scope (scope table only)', 'R-16',
        'the MSVC Windows leg (cl or clang-cl with a real C runtime handler)',
        'structured exception handling scope tables live in unwind data; the freestanding clang profile has no C '
        'handler to name, so the scope can only be planted on the MSVC Windows leg'),
)

BY_ID = {c.id: c for c in CLASSES}
