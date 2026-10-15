"""Operand-delta classifier C2 with target consistency (SPEC-31 05 s2.2, review R-01 and R-14, S3). Pure.

Every operand of every ALIGNED instruction pair is compared, also when the masked bytes are equal (R-01: equal masked
bytes say nothing about where an address operand points). Address operands go through `TargetMap`: `mapped` is silent,
`unmapped` is not a delta but blocks every proof, `conflict` (the target maps elsewhere) and `string` (two defined
strings with different content) are semantic deltas. Scalar differences are `constant` (`frame` for `sub/add rsp`),
stack differences are `frame` (R-14), other memory differences `struct-offset`, register differences `register-only`;
unmatched instructions are `call-added`/`call-removed` for calls and `unknown` otherwise. Direct branches are the
CFG logic's (`layout.py`).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import NamedTuple

from ..contracts import Delta
from ..ir.features import F_CALL, F_NOP
from ..ir.ins import Insn, Op
from ..ir.operands import VK_ADDRESS, VK_MEMORY, VK_REGISTER, VK_SCALAR, VK_STACK
from .align import Alignment, family
from .datamap import CONFLICT, MAPPED, STRING, UNMAPPED, TargetMap, Voter, string_sha
from .fnview import FnView

TEXT_LIMIT = 120
NON_WRITING = frozenset({'CMP', 'TEST', 'BT', 'PUSH', 'JMP', 'CALL', 'NOP', 'LEA', 'UCOMISS', 'UCOMISD', 'COMISS',
                         'COMISD', 'CMPPS', 'CMPPD', 'PREFETCHT0', 'PREFETCHT1', 'PREFETCHT2', 'PREFETCHNTA'})
FRAME_REGISTERS = frozenset({'RSP', 'ESP'})


class CallTarget(NamedTuple):
    """Identity of a call target: ('fn', rva), ('imp', import key) or ('ind', None) for an unresolved indirect call."""
    kind: str
    value: object


@dataclass(frozen=True)
class DeltaInfo:
    """What an anchored second channel needs to know about one delta (05 s2.5 MAT-ANCHOR); parallel to `Delta`."""
    tokens: tuple[CallTarget | None, CallTarget | None] = (None, None)    # call classes: old, new target
    values: tuple[int | None, int | None] = (None, None)                    # constant / struct offset: old, new
    data: tuple[int | None, int | None] = (None, None)                      # data-ref: old, new datum
    strings: tuple[str | None, str | None] = (None, None)                   # string: old, new prefix
    shas: tuple[str | None, str | None] = (None, None)                      # string: old, new SHA-256
    effect: bool = False                                                    # block delta: holds a store or a call
    condition: bool = False                                                 # an operator change (relational/logical)


@dataclass
class Consistency:
    """Address operand pairs by state (05 s2.7); `string` counts with the conflicts, so neither can pass a proof."""
    mapped: int = 0
    unmapped: int = 0
    conflict: int = 0

    def add(self, state: str) -> None:
        if state == MAPPED:
            self.mapped += 1
        elif state == UNMAPPED:
            self.unmapped += 1
        else:
            self.conflict += 1

    def as_tuple(self) -> tuple[int, int, int]:
        return (self.mapped, self.unmapped, self.conflict)


@dataclass
class OperandResult:
    deltas: list[tuple[Delta, DeltaInfo]] = field(default_factory=list)
    cons: Consistency = field(default_factory=Consistency)


def short(text: object) -> str:
    from ...secondary.evidence_view import sanitize_text
    return sanitize_text(text, TEXT_LIMIT)


def is_frame_alloc(insn: Insn) -> bool:
    return (insn.mnem in ('SUB', 'ADD') and len(insn.ops) == 2 and insn.ops[0].vkind == VK_REGISTER
            and insn.ops[0].value in FRAME_REGISTERS and insn.ops[1].vkind == VK_SCALAR)


def is_store(insn: Insn) -> bool:
    """A write to memory: a destination operand that is memory, stack or a data address, on an instruction that writes."""
    if insn.mnem in NON_WRITING or not insn.ops:
        return False
    first = insn.ops[0]
    return first.vkind in (VK_MEMORY, VK_STACK) or (first.vkind == VK_ADDRESS and isinstance(first.value, int)
                                                    and insn.ops[0].offset is not None)


def holds_effect(view: FnView, block: int) -> bool:
    """A block that stores to memory or calls: adding or removing one is a semantic change (05 s2.5)."""
    return any(view.insns[i].flags & F_CALL or is_store(view.insns[i]) for i in view.block_kept[block])


def call_target(view: FnView, index: int) -> CallTarget | None:
    site = view.insns[index].rva
    rows = sorted(c for c in view.calls if c.site == site)
    if not rows:
        return None
    first = rows[0]
    if first.rva is not None:
        return CallTarget('fn', first.rva)
    return CallTarget('imp', first.key) if first.key is not None else CallTarget('ind', None)


def landing(view: FnView, rva: int) -> int | None:
    """The first non-NOP instruction at or after `rva` (a branch into padding lands on the next real instruction)."""
    index = view.index_of.get(rva)
    while index is not None and index < len(view.insns) and view.insns[index].flags & F_NOP:
        index += 1
    return index if index is not None and index < len(view.insns) else None


def _target_kind(view: FnView, index: int, opi: int, value: object, targets: TargetMap, side: str) -> str:
    if isinstance(value, str):
        return 'import'
    for row in view.refs.get((index, opi), ()):
        if row.target == value and row.kind in ('code', 'data'):
            return row.kind
    if isinstance(value, int) and targets.is_entry(side, value):
        return 'code'
    return 'unknown'


def address_state(old: FnView, new: FnView, i: int, j: int, opi: int, ox: Op, oy: Op, align: Alignment,
                  targets: TargetMap, voter: Voter | None) -> tuple[str, str]:
    """(state, context) of one address operand pair; context is `function`, `data` or `code`."""
    vx, vy = ox.value, oy.value
    if vx is None or vy is None:
        return UNMAPPED, 'data'
    if targets.identical:     # the same artifact on both sides: an address is the same thing wherever it points
        function = isinstance(vx, str) or (targets.is_entry('older', vx) and targets.is_entry('newer', vy))
        return (MAPPED if vx == vy else CONFLICT), 'function' if function else 'data'
    if isinstance(vx, str) or isinstance(vy, str):
        key_old = vx if isinstance(vx, str) else targets.import_key('older', vx)
        key_new = vy if isinstance(vy, str) else targets.import_key('newer', vy)
        if key_old is None or key_new is None:
            return UNMAPPED, 'function'
        return (MAPPED if key_old == key_new else CONFLICT), 'function'
    kind_old = _target_kind(old, i, opi, vx, targets, 'older')
    kind_new = _target_kind(new, j, opi, vy, targets, 'newer')
    if kind_old == kind_new == 'data':
        return targets.data_state(vx, vy, voter, (string_sha(old, i), string_sha(new, j))), 'data'
    if kind_old == kind_new == 'code':
        if targets.is_entry('older', vx) and targets.is_entry('newer', vy):
            return targets.function_state(vx, vy, voter), 'function'
        land_old, land_new = landing(old, vx), landing(new, vy)
        if land_old is not None and land_new is not None:
            mapped = align.instruction_map.get(land_old)
            if mapped is not None:
                return (MAPPED if mapped == land_new else CONFLICT), 'code'
        return UNMAPPED, 'code'
    if {kind_old, kind_new} == {'code', 'data'}:
        return CONFLICT, 'data'
    return UNMAPPED, 'data'


def _delta(cls: str, old: FnView, new: FnView, i: int | None, j: int | None, info: DeltaInfo | None = None,
           channel: str = 'C2') -> tuple[Delta, DeltaInfo]:
    return (Delta(cls=cls, channel=channel, older_rva=None if i is None else old.insns[i].rva,
                  newer_rva=None if j is None else new.insns[j].rva,
                  old=None if i is None else short(old.text(i)), new=None if j is None else short(new.text(j))),
            info or DeltaInfo())


def _compare_operands(old: FnView, new: FnView, i: int, j: int, align: Alignment, targets: TargetMap,
                      voter: Voter | None, out: OperandResult) -> None:
    x, y = old.insns[i], new.insns[j]
    if len(x.ops) != len(y.ops):
        out.deltas.append(_delta('unknown', old, new, i, j))
        return
    for opi, (ox, oy) in enumerate(zip(x.ops, y.ops, strict=True)):
        if ox.vkind != oy.vkind:
            out.deltas.append(_delta('unknown', old, new, i, j))
        elif ox.vkind == VK_ADDRESS:
            state, context = address_state(old, new, i, j, opi, ox, oy, align, targets, voter)
            out.cons.add(state)
            _address_delta(state, context, old, new, i, j, ox, oy, out)
            if ox.regs != oy.regs:
                out.deltas.append(_delta('register-only', old, new, i, j))
        elif ox.vkind == VK_SCALAR and ox.value != oy.value:
            cls = 'frame' if is_frame_alloc(x) and is_frame_alloc(y) else 'constant'
            out.deltas.append(_delta(cls, old, new, i, j, DeltaInfo(values=_ints(ox.value, oy.value))))
        elif ox.vkind in (VK_STACK, VK_MEMORY):
            if ox.value != oy.value:
                cls = 'frame' if ox.vkind == VK_STACK else 'struct-offset'
                out.deltas.append(_delta(cls, old, new, i, j, DeltaInfo(values=_ints(ox.value, oy.value))))
            if ox.regs != oy.regs:
                out.deltas.append(_delta('register-only', old, new, i, j))
        elif ox.vkind == VK_REGISTER and ox.value != oy.value:
            out.deltas.append(_delta('register-only', old, new, i, j))


def _ints(a: object, b: object) -> tuple[int | None, int | None]:
    return (a if isinstance(a, int) else None, b if isinstance(b, int) else None)


def _address_delta(state: str, context: str, old: FnView, new: FnView, i: int, j: int, ox: Op, oy: Op,
                   out: OperandResult) -> None:
    if state not in (CONFLICT, STRING):
        return
    if state == STRING:
        rows_old, rows_new = old.strings.get(old.insns[i].rva, ()), new.strings.get(new.insns[j].rva, ())
        rows = (rows_old[0] if len(rows_old) == 1 else None, rows_new[0] if len(rows_new) == 1 else None)
        out.deltas.append(_delta('string', old, new, i, j, DeltaInfo(
            strings=tuple(None if r is None else r.prefix for r in rows), shas=tuple(None if r is None else r.sha for r in rows))))
    elif context == 'function':
        out.deltas.append(_delta('callee', old, new, i, j, DeltaInfo(tokens=(_function_token(ox.value),
                                                                             _function_token(oy.value)))))
    elif context == 'code':
        out.deltas.append(_delta('cfg', old, new, i, j))
    else:
        out.deltas.append(_delta('data-ref', old, new, i, j, DeltaInfo(data=_ints(ox.value, oy.value))))


def _function_token(value: object) -> CallTarget:
    return CallTarget('imp', value) if isinstance(value, str) else CallTarget('fn', value)


def operand_deltas(old: FnView, new: FnView, align: Alignment, targets: TargetMap,
                   voter: Voter | None = None) -> OperandResult:
    """05 s2.2: every operand of every aligned pair, plus the unmatched instructions of paired blocks."""
    out = OperandResult()
    for i, j in align.pairs:
        _compare_operands(old, new, i, j, align, targets, voter, out)
    for i, j in align.replaced:
        x, y = old.insns[i], new.insns[j]
        if x.mnem != y.mnem and family(x.mnem) in ('SETcc', 'CMOVcc'):
            out.deltas.append(_delta('comparison', old, new, i, j, DeltaInfo(condition=True)))
        _compare_operands(old, new, i, j, align, targets, voter, out)
    for i in align.old_only:
        target = call_target(old, i) if old.insns[i].flags & F_CALL else None
        cls = 'call-removed' if target is not None else 'unknown'
        out.deltas.append(_delta(cls, old, new, i, None, DeltaInfo(tokens=(target, None))))
    for j in align.new_only:
        target = call_target(new, j) if new.insns[j].flags & F_CALL else None
        cls = 'call-added' if target is not None else 'unknown'
        out.deltas.append(_delta(cls, old, new, None, j, DeltaInfo(tokens=(None, target))))
    return out
