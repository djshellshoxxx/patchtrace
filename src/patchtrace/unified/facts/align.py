"""Bounded instruction-stream alignment of two functions (SPEC-31 05 s2.3, S3). Pure and deterministic.

First rule of 2.3: functions with equal address-masked bytes (`h1`) and a positionally equal CFG align block k with
block k and instruction k with instruction k (`_positional_alignment`, linear, no cap needed).

Otherwise blocks first: blocks are paired by their UNIQUE body key (`bb.h1`, the block without its terminating direct branch),
then by CFG position (the entry block, then successors of paired blocks that are unique per edge kind). Inside paired
blocks the non-NOP bodies are aligned by a patience diff on strict tokens (opcode, operand classes, registers) with a
longest-common-subsequence fill on weak tokens (opcode, operand classes) between the anchors; runs that stay unmatched
between two matched neighbours are paired as SUBSTITUTIONS when both sides are the same kind of instruction, so a
changed condition code is a changed operand and not a deletion plus an insertion. Terminating direct branches are not
aligned here: the CFG edge logic (`layout.py`) owns them.

Deviation from 05 s2.3, recorded in docs/modules.md: the LCS fill is a plain dynamic programme with a cell cap
(`DP_CELL_CAP`) instead of Hirschberg's linear-space variant; a gap beyond the cap stays unmatched and the pair is
marked `align-cap` (verdict at most `review`), exactly like the whole-function cap L-27 (prefix and suffix only).
"""
from __future__ import annotations

from bisect import bisect_left
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from functools import cached_property

from ..ir.ins import Insn
from ..limits import DEFAULT_LIMITS, Budget, UnifiedLimits
from .fnview import FnView, positional_cfg_equal

DP_CELL_CAP = 1_000_000
CC_NAMES = frozenset({'O', 'NO', 'B', 'C', 'NAE', 'AE', 'NB', 'NC', 'E', 'Z', 'NE', 'NZ', 'BE', 'NA', 'A', 'NBE', 'S',
                      'NS', 'P', 'PE', 'NP', 'PO', 'L', 'NGE', 'GE', 'NL', 'LE', 'NG', 'G', 'NLE'})
EDGE_ORDER = ('cond', 'fall', 'jump', 'switch', 'call-return')


def weak_token(insn: Insn) -> tuple:
    """Opcode plus operand classes: what two instructions must share to be aligned at all."""
    return (insn.mnem, tuple(op.vkind for op in insn.ops))


def strict_token(insn: Insn) -> tuple:
    """Weak token plus the registers of every operand (immediates and displacements stay out)."""
    return (insn.mnem, tuple((op.vkind, op.regs) for op in insn.ops))


def family(mnemonic: str) -> str:
    """`Jcc`, `SETcc` and `CMOVcc` form one family each, whatever the condition code; any other mnemonic its own."""
    for prefix in ('CMOV', 'SET', 'J'):
        if mnemonic.startswith(prefix) and mnemonic[len(prefix):] in CC_NAMES:
            return prefix + 'cc'
    return mnemonic


@dataclass(frozen=True)
class Alignment:
    """`pairs`: instructions with equal weak token, `replaced`: same-family substitutions, both as (old index, new
    index) into `FnView.insns`, ascending. `old_only`/`new_only`: unmatched body instructions of PAIRED blocks (the
    instructions of unpaired blocks are in `*_blocks_only`). `terminators` maps a paired block (old, new) to its two
    terminating direct branches, either of which may be None."""
    pairs: tuple[tuple[int, int], ...]
    replaced: tuple[tuple[int, int], ...]
    old_only: tuple[int, ...]
    new_only: tuple[int, ...]
    block_pairs: tuple[tuple[int, int], ...]
    old_blocks_only: tuple[int, ...]
    new_blocks_only: tuple[int, ...]
    terminators: dict[tuple[int, int], tuple[int | None, int | None]]
    by_key: bool            # EVERY block of both sides was paired by a unique body key
    capped: bool

    @cached_property
    def block_map(self) -> dict[int, int]:
        return dict(self.block_pairs)

    @cached_property
    def instruction_map(self) -> dict[int, int]:
        return {**dict(self.pairs), **dict(self.replaced)}


# --- sequence primitives ----------------------------------------------------------------------------------------------

def _trim(a: Sequence, b: Sequence) -> tuple[int, int]:
    """Length of the common prefix and of the common suffix (never overlapping)."""
    prefix, limit = 0, min(len(a), len(b))
    while prefix < limit and a[prefix] == b[prefix]:
        prefix += 1
    suffix = 0
    while suffix < limit - prefix and a[len(a) - 1 - suffix] == b[len(b) - 1 - suffix]:
        suffix += 1
    return prefix, suffix


def patience_anchors(a: Sequence, b: Sequence) -> list[tuple[int, int]]:
    """Longest chain of items that occur exactly once on each side, increasing on both (patience sorting)."""
    def unique(items: Sequence) -> dict:
        seen: dict = {}
        dupes: set = set()
        for index, item in enumerate(items):
            if item in seen:
                dupes.add(item)
            else:
                seen[item] = index
        return {item: index for item, index in seen.items() if item not in dupes}
    pos_a, pos_b = unique(a), unique(b)
    common = sorted((pos_a[item], pos_b[item]) for item in pos_a.keys() & pos_b.keys())
    tails: list[int] = []          # smallest b-position ending a chain of each length
    ends: list[int] = []           # index into `common` of that chain end
    back = [-1] * len(common)
    for index, (_i, j) in enumerate(common):
        slot = bisect_left(tails, j)
        if slot == len(tails):
            tails.append(j)
            ends.append(index)
        else:
            tails[slot], ends[slot] = j, index
        back[index] = ends[slot - 1] if slot else -1
    chain: list[tuple[int, int]] = []
    cursor = ends[-1] if ends else -1
    while cursor >= 0:
        chain.append(common[cursor])
        cursor = back[cursor]
    chain.reverse()
    return chain


def lcs_pairs(a: Sequence, b: Sequence, cap: int = DP_CELL_CAP) -> list[tuple[int, int]] | None:
    """Longest common subsequence as index pairs (common ends are trimmed first); None when the remaining table
    would exceed `cap` cells."""
    prefix, suffix = _trim(a, b)
    out = [(i, i) for i in range(prefix)]
    mid_a, mid_b = a[prefix:len(a) - suffix], b[prefix:len(b) - suffix]
    n, m = len(mid_a), len(mid_b)
    if n * m > cap:
        return None
    rows = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        row, below = rows[i], rows[i + 1]
        for j in range(m - 1, -1, -1):
            row[j] = below[j + 1] + 1 if mid_a[i] == mid_b[j] else max(below[j], row[j + 1])
    i = j = 0
    while i < n and j < m:
        if mid_a[i] == mid_b[j]:
            out.append((prefix + i, prefix + j))
            i, j = i + 1, j + 1
        elif rows[i + 1][j] >= rows[i][j + 1]:
            i += 1
        else:
            j += 1
    out.extend((len(a) - suffix + k, len(b) - suffix + k) for k in range(suffix))
    return out


def diff_tokens(a_strict: Sequence, b_strict: Sequence, a_weak: Sequence, b_weak: Sequence,
                cap: int = DP_CELL_CAP) -> tuple[list[tuple[int, int]], bool]:
    """Matched index pairs between two token sequences and whether a gap exceeded the LCS cap."""
    prefix, suffix = _trim(a_strict, b_strict)
    pairs = [(i, i) for i in range(prefix)]
    hi_a, hi_b = len(a_strict) - suffix, len(b_strict) - suffix
    anchors = patience_anchors(a_strict[prefix:hi_a], b_strict[prefix:hi_b])
    capped = False
    cursor_a = cursor_b = prefix
    for x, y in [*((prefix + x, prefix + y) for x, y in anchors), (None, None)]:
        i, j = (hi_a, hi_b) if x is None else (x, y)
        filled = lcs_pairs(a_weak[cursor_a:i], b_weak[cursor_b:j], cap)
        if filled is None:
            capped = True
        else:
            pairs.extend((cursor_a + p, cursor_b + q) for p, q in filled)
        if x is not None:
            pairs.append((i, j))
        cursor_a, cursor_b = i + 1, j + 1
    pairs.extend((hi_a + k, hi_b + k) for k in range(suffix))
    return pairs, capped


# --- block pairing ------------------------------------------------------------------------------------------------------

def _entry_block(view: FnView) -> int:
    index = view.index_of.get(view.rva)
    return view.block_of[index] if index is not None else 0


def pair_blocks(old: FnView, new: FnView) -> tuple[dict[int, int], bool]:
    """(old ordinal -> new ordinal, every block paired by a unique body key?) per 05 s2.3."""
    keys_old, keys_new = defaultdict(list), defaultdict(list)
    for block in old.blocks:               # a block without a body (a lone jump) has the key None: also a key
        keys_old[block.h1].append(block.ord)
    for block in new.blocks:
        keys_new[block.h1].append(block.ord)
    pairs: dict[int, int] = {}
    for key in sorted(keys_old.keys() & keys_new.keys(), key=lambda k: (k is not None, k or 0)):
        if len(keys_old[key]) == 1 and len(keys_new[key]) == 1:
            pairs[keys_old[key][0]] = keys_new[key][0]
    by_key = len(pairs) == len(old.blocks) == len(new.blocks)
    taken = set(pairs.values())
    entry_old, entry_new = _entry_block(old), _entry_block(new)
    if entry_old not in pairs and entry_new not in taken:
        pairs[entry_old] = entry_new
        taken.add(entry_new)
    queue = sorted(pairs.items())
    while queue:
        block_old, block_new = queue.pop(0)
        for kind in EDGE_ORDER:
            # the successors of this kind that no other evidence paired yet; exactly one on each side is a pair
            rest_old = [t for t, k in old.blocks[block_old].succ if k == kind and t not in pairs]
            rest_new = [t for t, k in new.blocks[block_new].succ if k == kind and t not in taken]
            if len(rest_old) == len(rest_new) == 1:
                pairs[rest_old[0]] = rest_new[0]
                taken.add(rest_new[0])
                queue.append((rest_old[0], rest_new[0]))
    return pairs, by_key


# --- the alignment ------------------------------------------------------------------------------------------------------

def _align_block(old: FnView, new: FnView, block_old: int, block_new: int, cap: int):
    """(pairs, replaced, old leftovers, new leftovers, capped) of the bodies of one paired block."""
    a_idx, b_idx = old.body(block_old), new.body(block_new)
    a_strict = [strict_token(old.insns[i]) for i in a_idx]
    b_strict = [strict_token(new.insns[j]) for j in b_idx]
    if a_strict == b_strict:
        return list(zip(a_idx, b_idx, strict=True)), [], [], [], False
    a_weak = [weak_token(old.insns[i]) for i in a_idx]
    b_weak = [weak_token(new.insns[j]) for j in b_idx]
    found, capped = diff_tokens(a_strict, b_strict, a_weak, b_weak, cap)
    replaced: list[tuple[int, int]] = []
    left_a: list[int] = []
    left_b: list[int] = []
    cursor_a = cursor_b = 0
    for x, y in [*found, (len(a_idx), len(b_idx))]:
        run_a, run_b = a_idx[cursor_a:x], b_idx[cursor_b:y]
        taken = 0
        for i, j in zip(run_a, run_b, strict=False):
            if family(old.insns[i].mnem) != family(new.insns[j].mnem):
                break
            replaced.append((i, j))
            taken += 1
        left_a.extend(run_a[taken:])
        left_b.extend(run_b[taken:])
        cursor_a, cursor_b = x + 1, y + 1
    return [(a_idx[x], b_idx[y]) for x, y in found], replaced, left_a, left_b, capped


def _capped_alignment(old: FnView, new: FnView) -> Alignment:
    """Beyond L-27: only the common prefix and suffix of the whole body stream are aligned (verdict at most review)."""
    a_idx = [i for i in old.kept if old.terminator(old.block_of[i]) != i]
    b_idx = [j for j in new.kept if new.terminator(new.block_of[j]) != j]
    prefix, suffix = _trim([strict_token(old.insns[i]) for i in a_idx], [strict_token(new.insns[j]) for j in b_idx])
    pairs = [(a_idx[k], b_idx[k]) for k in range(prefix)]
    pairs += [(a_idx[len(a_idx) - suffix + k], b_idx[len(b_idx) - suffix + k]) for k in range(suffix)]
    matched_a, matched_b = {i for i, _ in pairs}, {j for _, j in pairs}
    return Alignment(tuple(sorted(pairs)), (), tuple(i for i in a_idx if i not in matched_a),
                     tuple(j for j in b_idx if j not in matched_b), (), tuple(b.ord for b in old.blocks),
                     tuple(b.ord for b in new.blocks), {}, False, True)


def _positional_alignment(old: FnView, new: FnView, budget: Budget) -> Alignment | None:
    """05 s2.3, first rule: equal address-masked bytes (`h1`) and a positionally equal CFG align block k with block k
    and instruction k with instruction k, in linear time and without any body key having to be unique (switch cases
    with equal bodies are the usual twins). The classifier still compares every operand of every pair (R-01)."""
    if old.h1 is None or old.h1 != new.h1 or not positional_cfg_equal(old, new):
        return None
    pairs: list[tuple[int, int]] = []
    terminators: dict[tuple[int, int], tuple[int | None, int | None]] = {}
    for block in range(len(old.blocks)):
        budget.tick(len(old.block_kept[block]) + len(new.block_kept[block]))
        pairs.extend(zip(old.body(block), new.body(block), strict=True))
        terminators[(block, block)] = (old.terminator(block), new.terminator(block))
    keys = [block.h1 for block in old.blocks]
    return Alignment(tuple(sorted(pairs)), (), (), (), tuple((block, block) for block in range(len(old.blocks))), (), (),
                     terminators, len(set(keys)) == len(keys), False)


def align(old: FnView, new: FnView, *, limits: UnifiedLimits = DEFAULT_LIMITS, budget: Budget | None = None,
          cell_cap: int = DP_CELL_CAP) -> Alignment:
    budget = budget or Budget()
    positional = _positional_alignment(old, new, budget)
    if positional is not None:
        return positional
    if max(len(old.kept), len(new.kept)) > limits.l27_align_instructions:
        return _capped_alignment(old, new)
    mapping, by_key = pair_blocks(old, new)
    pairs: list[tuple[int, int]] = []
    replaced: list[tuple[int, int]] = []
    old_only: list[int] = []
    new_only: list[int] = []
    capped = False
    for block_old, block_new in sorted(mapping.items()):
        budget.tick(len(old.block_kept[block_old]) + len(new.block_kept[block_new]))
        found, substituted, left_a, left_b, over = _align_block(old, new, block_old, block_new, cell_cap)
        pairs.extend(found)
        replaced.extend(substituted)
        old_only.extend(left_a)
        new_only.extend(left_b)
        capped |= over
    paired_new = set(mapping.values())
    return Alignment(
        tuple(sorted(pairs)), tuple(sorted(replaced)), tuple(sorted(old_only)), tuple(sorted(new_only)),
        tuple(sorted(mapping.items())), tuple(b.ord for b in old.blocks if b.ord not in mapping),
        tuple(b.ord for b in new.blocks if b.ord not in paired_new),
        {(bo, bn): (old.terminator(bo), new.terminator(bn)) for bo, bn in sorted(mapping.items())}, by_key, capped)
