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


def severity(delta: Delta) -> tuple:
    return (SEVERITY_ORDER.index(delta.cls), delta.channel, delta.old or '', delta.new or '')


@dataclass(frozen=True)
class Evidence:
    """What the S0 channels observed for one chosen pair. `anchors` runs parallel to `deltas`: the other-group
    channel that shows the SAME change (05 s2.5 MAT-ANCHOR), or None."""
    states: Mapping[str, str]           # C4, C5, C6, C8 -> equal | differs | unavailable
    deltas: tuple[Delta, ...]
    anchors: tuple[str | None, ...]
    targets: tuple[int, int, int]       # (mapped, unmapped, conflict) function/data labels
    eh: str
    change_signal: bool                 # Ghidriff lists the pair as modified, or the analyst says so
    diff_types: tuple[str, ...]
    limits_hit: tuple[str, ...]
