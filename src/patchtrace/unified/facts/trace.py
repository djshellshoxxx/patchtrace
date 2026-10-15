"""F17 trace-argument ordering (SPEC-31 05 s3, review R-29, S3). Pure.

WPP/ETW trace messages carry ids, line numbers and flags that change with unrelated edits. A `constant` delta whose
instruction loads an argument register (RCX, RDX, R8, R9, or a stack argument slot) that a call in the same block to a
tracing function then consumes is ordered last inside its verdict and the row gets the hint `trace-arg`. Ordering only:
the verdict is untouched and the row is never hidden.
"""
from __future__ import annotations

from collections.abc import Iterable

from ..contracts import Delta
from ..ir.features import F_CALL
from ..ir.operands import VK_REGISTER, VK_SCALAR
from .datamap import TargetMap
from .fnview import FnView
from .operands import DeltaInfo, call_target

TRACE_PREFIXES = ('etwwrite', 'wmitracemessage', 'tracemessage', 'tracelogging', '_tlgwrite')
ARGUMENT_REGISTERS = frozenset({'RCX', 'ECX', 'CX', 'CL', 'RDX', 'EDX', 'DX', 'DL', 'R8', 'R8D', 'R8W', 'R8B', 'R9', 'R9D',
                                'R9W', 'R9B'})
MAX_CHAIN = 4


def is_tracing(key: str | None) -> bool:
    """A tracing import by its name (the part after `!`), from the closed table of 05 s3 F17."""
    return key is not None and key.split('!', 1)[-1].lower().startswith(TRACE_PREFIXES)


def _tracing_target(view: FnView, side: str, index: int, targets: TargetMap) -> bool:
    target = call_target(view, index)
    if target is None:
        return False
    if target.kind == 'imp':
        return is_tracing(str(target.value))
    if target.kind != 'fn':
        return False
    rva = target.value
    for _ in range(MAX_CHAIN):                       # a WPP thunk resolves to the tracing import behind it
        key = targets.import_key(side, rva)
        if key is not None:
            return is_tracing(key)
        following = targets.thunk_target(side, rva)
        if following is None:
            return False
        rva = following
    return False


def _feeds_argument(view: FnView, index: int) -> bool:
    insn = view.insns[index]
    first = insn.ops[0] if insn.ops else None
    return (first is not None and first.vkind == VK_REGISTER and first.value in ARGUMENT_REGISTERS
            and len(insn.ops) > 1 and insn.ops[1].vkind == VK_SCALAR)


def feeds_tracing_call(view: FnView, side: str, index: int, targets: TargetMap) -> bool:
    """The instruction loads an argument register and a later call of its block goes to a tracing function."""
    if not _feeds_argument(view, index):
        return False
    block = view.block_of[index]
    for later in view.block_kept[block]:
        if later > index and view.insns[later].flags & F_CALL:
            return _tracing_target(view, side, later, targets)
    return False


def trace_arg_only(old: FnView, new: FnView, deltas: Iterable[tuple[Delta, DeltaInfo]], targets: TargetMap) -> bool:
    """Every semantic constant delta of the pair is a trace argument, and there is at least one."""
    constants = 0
    for delta, _info in deltas:
        if delta.cls == 'constant':
            constants += 1
            index_new = new.index_of.get(delta.newer_rva) if delta.newer_rva is not None else None
            index_old = old.index_of.get(delta.older_rva) if delta.older_rva is not None else None
            fed = (index_new is not None and feeds_tracing_call(new, 'newer', index_new, targets)) or \
                  (index_old is not None and feeds_tracing_call(old, 'older', index_old, targets))
            if not fed:
                return False
        elif delta.cls in ('callee', 'call-added', 'call-removed', 'condition', 'comparison', 'struct-offset',
                           'data-ref', 'string', 'block-added', 'block-removed'):
            return False
    return constants > 0

