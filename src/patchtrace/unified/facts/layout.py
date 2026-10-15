"""CFG edge logic: the positional equality COS-ADDR/1 needs and the polarity-preserving block bijection COS-LAYOUT/1
needs (SPEC-31 05 s2.5, review R-04, S3). Pure.

Equal block counts, edge counts, MD indices and body multisets do NOT prove two CFGs isomorphic (a then/else swap keeps
them all), so the proofs compare the edges themselves. Blocks are paired by the alignment (unique body key first);
every edge of an old block must map, through that pairing, to an edge of the paired new block with the same polarity.
A conditional branch may be inverted only by the closed table JZ/JNZ, JB/JAE, JBE/JA, JL/JGE, JLE/JG, JS/JNS, JO/JNO,
JP/JNP with the successors swapped; a terminating unconditional JMP to the fall-through block may be added or removed.
Branch operands whose edges are verified count as `mapped` targets; anything else is a `cfg` delta (never cosmetic).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..contracts import Delta
from ..ir.features import is_conditional_branch
from .align import Alignment
from .datamap import CONFLICT, MAPPED, UNMAPPED, TargetMap, Voter
from .fnview import FnView, positional_cfg_equal
from .operands import Consistency, DeltaInfo, holds_effect, short

__all__ = ['CfgResult', 'INVERSE', 'compare_cfg', 'condition_code', 'inverted', 'positional_cfg_equal']

_CANON = {'E': 'Z', 'NE': 'NZ', 'C': 'B', 'NAE': 'B', 'NC': 'AE', 'NB': 'AE', 'NA': 'BE', 'NBE': 'A', 'NGE': 'L',
          'NL': 'GE', 'NG': 'LE', 'NLE': 'G', 'PE': 'P', 'PO': 'NP'}
_INVERSE_PAIRS = (('Z', 'NZ'), ('B', 'AE'), ('BE', 'A'), ('L', 'GE'), ('LE', 'G'), ('S', 'NS'), ('O', 'NO'), ('P', 'NP'))
INVERSE = {**dict(_INVERSE_PAIRS), **{b: a for a, b in _INVERSE_PAIRS}}


def condition_code(mnemonic: str) -> str | None:
    if not mnemonic.startswith('J') or mnemonic == 'JMP':
        return None
    code = mnemonic[1:]
    code = _CANON.get(code, code)
    return code if code in INVERSE else None


def inverted(a: str, b: str) -> bool:
    """`a` and `b` are conditional jumps with opposite conditions (the closed table)."""
    code_a, code_b = condition_code(a), condition_code(b)
    return code_a is not None and code_b is not None and INVERSE[code_a] == code_b


@dataclass
class CfgResult:
    deltas: list[tuple[Delta, DeltaInfo]] = field(default_factory=list)
    cons: Consistency = field(default_factory=Consistency)
    layout_ok: bool = True       # every block paired by key, every terminator and edge polarity-preserving


def _edge(edges, kind: str) -> int | None:
    found = [target for target, k in edges if k == kind]
    return found[0] if len(found) == 1 else None


def _block_delta(cls: str, old: FnView, new: FnView, bo: int | None, bn: int | None, i: int | None, j: int | None,
                 info: DeltaInfo | None = None) -> tuple[Delta, DeltaInfo]:
    """A delta located at a block (and its terminating branch when there is one)."""
    first_old = old.block_kept[bo][0] if bo is not None and old.block_kept[bo] and i is None else i
    first_new = new.block_kept[bn][0] if bn is not None and new.block_kept[bn] and j is None else j
    older_rva = old.blocks[bo].rva if bo is not None else (None if i is None else old.insns[i].rva)
    newer_rva = new.blocks[bn].rva if bn is not None else (None if j is None else new.insns[j].rva)
    return (Delta(cls=cls, channel='C2', older_rva=older_rva, newer_rva=newer_rva,
                  old=None if first_old is None else short(old.text(first_old)),
                  new=None if first_new is None else short(new.text(first_new))), info or DeltaInfo())


def _same_edges(edges_old, edges_new, mapping: dict[int, int]) -> tuple[bool, bool]:
    """(old edges map onto the new edges, some old successor has no paired block)."""
    unpaired = any(t not in mapping for t, _ in edges_old)
    if unpaired:
        return False, True
    return sorted((mapping[t], k) for t, k in edges_old) == sorted(edges_new), False


def _target(view: FnView, index: int) -> int | None:
    operands = view.insns[index].ops
    return operands[0].value if operands and isinstance(operands[0].value, int) else None


def _check_external(old: FnView, new: FnView, to: int, tn: int, targets: TargetMap, voter: Voter | None,
                    out: CfgResult) -> None:
    """A direct jump that leaves the function (a tail call) is a function target, not an edge."""
    state = targets.function_state(_target(old, to), _target(new, tn), voter)
    out.cons.add(state)
    if state != MAPPED:
        out.layout_ok = False
    if state == CONFLICT:
        out.deltas.append(_block_delta('callee', old, new, None, None, to, tn, DeltaInfo()))


def _fall_through_jump_ok(old: FnView, new: FnView, bo: int, bn: int, to: int | None, tn: int | None,
                          mapping: dict[int, int]) -> bool:
    """One block ends with an unconditional JMP, the other falls through into the same (mapped) block."""
    view, term = (old, to) if to is not None else (new, tn)
    if view.insns[term].mnem != 'JMP':
        return False
    edges_old, edges_new = old.blocks[bo].succ, new.blocks[bn].succ
    if len(edges_old) != 1 or len(edges_new) != 1:
        return False
    (t_old, k_old), (t_new, k_new) = edges_old[0], edges_new[0]
    kinds = {'jump', 'fall'}
    return {k_old, k_new} == kinds and k_old != k_new and mapping.get(t_old) == t_new


def _check_block(old: FnView, new: FnView, bo: int, bn: int, to: int | None, tn: int | None, mapping: dict[int, int],
                 targets: TargetMap, voter: Voter | None, out: CfgResult) -> None:
    edges_old, edges_new = old.blocks[bo].succ, new.blocks[bn].succ
    same, unpaired = _same_edges(edges_old, edges_new, mapping)
    mismatch = _block_delta('cfg', old, new, bo, bn, to, tn)
    if to is None and tn is None:
        if not same:
            out.layout_ok = False
            out.deltas.append(mismatch)
        return
    if to is None or tn is None:
        if not _fall_through_jump_ok(old, new, bo, bn, to, tn, mapping):
            out.layout_ok = False
            out.deltas.append(mismatch)
        return
    x, y = old.insns[to], new.insns[tn]
    leaves_old, leaves_new = old.block_start_ord(_target(old, to) or -1) is None, \
        new.block_start_ord(_target(new, tn) or -1) is None
    if leaves_old or leaves_new:
        if leaves_old != leaves_new:
            out.cons.add(CONFLICT)
            out.layout_ok = False
            out.deltas.append(mismatch)
        else:
            _check_external(old, new, to, tn, targets, voter, out)
        return
    if x.mnem == y.mnem:
        out.cons.add(MAPPED if same else (UNMAPPED if unpaired else CONFLICT))
        if not same:
            out.layout_ok = False
            out.deltas.append(mismatch)
        return
    cond_old, fall_old, cond_new, fall_new = (_edge(edges_old, 'cond'), _edge(edges_old, 'fall'),
                                              _edge(edges_new, 'cond'), _edge(edges_new, 'fall'))
    if is_conditional_branch(x.flow) and is_conditional_branch(y.flow):
        swapped = (inverted(x.mnem, y.mnem) and None not in (cond_old, fall_old, cond_new, fall_new)
                   and mapping.get(cond_old) == fall_new and mapping.get(fall_old) == cond_new)
        if swapped:
            out.cons.add(MAPPED)
            return
        out.layout_ok = False
        out.cons.add(UNMAPPED if unpaired else CONFLICT)
        out.deltas.append(_block_delta('condition', old, new, bo, bn, to, tn, DeltaInfo(condition=True)))
        return
    out.layout_ok = False
    out.cons.add(CONFLICT)
    out.deltas.append(mismatch)


def compare_cfg(old: FnView, new: FnView, align: Alignment, targets: TargetMap, voter: Voter | None = None) -> CfgResult:
    out = CfgResult(layout_ok=align.by_key and not align.capped)
    mapping = align.block_map
    for (bo, bn), (to, tn) in align.terminators.items():
        _check_block(old, new, bo, bn, to, tn, mapping, targets, voter, out)
    for ordinal in align.old_blocks_only:
        out.layout_ok = False
        out.deltas.append(_block_delta('block-removed', old, new, ordinal, None, None, None,
                                       DeltaInfo(effect=holds_effect(old, ordinal))))
    for ordinal in align.new_blocks_only:
        out.layout_ok = False
        out.deltas.append(_block_delta('block-added', old, new, None, ordinal, None, None,
                                       DeltaInfo(effect=holds_effect(new, ordinal))))
    return out
