"""EH-EQ: equality of the unwind and handler metadata of a function pair (SPEC-31 05 s2.5, review R-16, S3). Pure.

SEH scope tables and other `.pdata` unwind data are invisible to bytes and to the decompiler, so every structural
proof needs EH-EQ: both functions without unwind data, or equal normalised UNWIND_INFO (version, flags, prolog size,
frame register and offset, unwind codes), the same handler (mapped, or the same import) and the same handler-data
length; `__C_specific_handler` scope records equal after the function start was subtracted (done by the PE tables) and
the filters were mapped. States: `absent`, `equal`, `differs`, `unavailable` (a truncated or unreadable signature,
or a handler that cannot be mapped: never `equal` by absence of evidence).
"""
from __future__ import annotations

import json

from .datamap import CONFLICT, MAPPED, TargetMap, Voter
from .fnview import FnView

PLAIN_FILTERS = (0, 1)        # 0 = __finally, 1 = EXCEPTION_EXECUTE_HANDLER: not RVAs


def _parse(text: str) -> dict | None:
    try:
        document = json.loads(text)
    except ValueError:
        return None
    return document if isinstance(document, dict) and document.get('v') == 1 else None


def _within(view: FnView, rva: int) -> bool:
    return view.rva <= rva < view.rva + max(view.size, 1)


def _filter_state(old: FnView, new: FnView, a: int, b: int, targets: TargetMap, voter: Voter | None) -> str | None:
    """None = equal, else 'differs' or 'unavailable'."""
    if a in PLAIN_FILTERS or b in PLAIN_FILTERS:
        return None if a == b else 'differs'
    if _within(old, a) and _within(new, b):
        return None if a - old.rva == b - new.rva else 'differs'
    state = targets.function_state(a, b, voter)
    return None if state == MAPPED else ('differs' if state == CONFLICT else 'unavailable')


def _scopes_state(old: FnView, new: FnView, scopes_old: list, scopes_new: list, targets: TargetMap,
                  voter: Voter | None) -> str | None:
    if len(scopes_old) != len(scopes_new):
        return 'differs'
    verdict = None
    for (begin_a, end_a, filter_a, target_a), (begin_b, end_b, filter_b, target_b) in zip(scopes_old, scopes_new,
                                                                                           strict=True):
        if (begin_a, end_a, target_a) != (begin_b, end_b, target_b):
            return 'differs'
        state = _filter_state(old, new, filter_a, filter_b, targets, voter)
        if state == 'differs':
            return 'differs'
        verdict = verdict or state
    return verdict


def eh_state(old: FnView, new: FnView, targets: TargetMap, voter: Voter | None = None, *,
             unreadable: bool = False) -> str:
    """`equal` | `differs` | `absent` | `unavailable` for the pair."""
    if unreadable:
        return 'unavailable'
    if old.eh is None and new.eh is None:
        return 'absent'
    if old.eh is None or new.eh is None:
        return 'differs'
    doc_old, doc_new = _parse(old.eh), _parse(new.eh)
    if doc_old is None or doc_new is None or doc_old.get('trunc') or doc_new.get('trunc'):
        return 'unavailable'
    for key in ('ver', 'fl', 'prolog', 'frame', 'codes', 'hlen'):
        if doc_old.get(key) != doc_new.get(key):
            return 'differs'
    pending = None
    handler_old, handler_new = doc_old.get('handler'), doc_new.get('handler')
    if (handler_old is None) != (handler_new is None):
        return 'differs'
    if handler_old is not None:
        state = targets.function_state(handler_old, handler_new, voter)
        if state == CONFLICT:
            return 'differs'
        if state != MAPPED:
            pending = 'unavailable'
    scopes_old, scopes_new = doc_old.get('scopes'), doc_new.get('scopes')
    if (scopes_old is None) != (scopes_new is None):
        return 'differs'
    if scopes_old is not None:
        state = _scopes_state(old, new, scopes_old, scopes_new, targets, voter)
        if state == 'differs':
            return 'differs'
        pending = pending or state
    return pending or 'equal'
