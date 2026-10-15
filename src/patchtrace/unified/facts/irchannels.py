"""IR change channels C0-C5 of one chosen pair, with the deltas and proof inputs behind them (SPEC-31 05 s2.1-s2.3, S3).

C0/C1 compare the raw and the address-masked body keys, C2 is the aligned operand classifier with target consistency
(`operands.py`, `layout.py`), C3 the CFG filter (counts, MD indices and the block-body multiset: equality is a filter,
never a proof), C4 the callee multiset mapped through the matched rows (pure jump thunks collapse, imports compare by
key, an unmatched callee is a semantic difference), C5 the multiset of ALL non-address constants and of the defined
strings. A channel whose data is missing is `unavailable`; absence is never `equal`. No channel decides anything: the
verdict rules of `verdict.py` read this output. Pure; the readers are only read.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from ..contracts import Delta
from ..ir import schema
from ..ir.reader import IrReader
from ..limits import DEFAULT_LIMITS, Budget, UnifiedLimits
from . import severity
from .align import align
from .datamap import MAPPED, Section, TargetMap, Voter
from .eh import eh_state
from .fnview import FnView, load_view
from .layout import compare_cfg, positional_cfg_equal
from .operands import CallTarget, Consistency, DeltaInfo, operand_deltas, short
from .trace import trace_arg_only

CHANNELS_IR = ('C0', 'C1', 'C2', 'C3', 'C4', 'C5')
ROW_FLAGS = ('tiny', 'thunk', 'import', 'oversize', 'truncated', 'library', 'mask-missing', 'mask-unlocated')


@dataclass(frozen=True)
class IrSides:
    """The two ProgramIR readers of a run. `identical` = the same artifact on both sides (every address maps to itself);
    `*_sections` are the PE sections as (start rva, end rva), needed only for the DATA-MAP region shift (rule c)."""
    older: IrReader
    newer: IrReader
    older_sections: tuple[Section, ...] = ()
    newer_sections: tuple[Section, ...] = ()
    identical: bool = False


@dataclass(frozen=True)
class IrPair:
    """Everything the verdict needs from the IR for one pair (05 s2.5)."""
    states: dict[str, str]                                   # C0..C5
    deltas: tuple[tuple[Delta, DeltaInfo], ...]              # sorted by severity (05 s2.6)
    targets: tuple[int, int, int]                            # address operand pairs: mapped, unmapped, conflict
    eh: str
    positional_cfg: bool                                     # COS-ADDR/1: blocks and successors equal positionally
    layout_ok: bool                                          # COS-LAYOUT/1: polarity-preserving block bijection
    mask_unlocated: bool                                     # an unlocated address field: no COS-ADDR possible
    leftovers: tuple[tuple[CallTarget, ...], tuple[CallTarget, ...]]    # C4: callees only in the older / newer function
    limits_hit: tuple[str, ...]
    flags: tuple[str, ...]
    counts_differ: bool = False                              # block or edge counts differ (the C3 anchor of a block delta)
    trace_arg: bool = False                                  # F17: every constant delta feeds a tracing call


def _flags(table_old, table_new, fo: int, fn: int) -> tuple[str, ...]:
    out = []
    for name in ROW_FLAGS:
        bit = schema.FN_FLAGS[name]
        if (table_old.get('flags', fo) or 0) & bit or (table_new.get('flags', fn) or 0) & bit:
            out.append(name)
    both = schema.FN_FLAGS['pdata-confirmed']
    if (table_old.get('flags', fo) or 0) & both and (table_new.get('flags', fn) or 0) & both:
        out.append('pdata-confirmed')
    return tuple(sorted(out))


def _equal(a: object, b: object) -> str:
    return 'unavailable' if a is None or b is None else ('equal' if a == b else 'differs')


def _call_key(target: CallTarget) -> tuple:
    return (target.kind, target.value if isinstance(target.value, int) else -1,
            target.value if isinstance(target.value, str) else '')


def _targets_of(view: FnView) -> list[CallTarget]:
    out = []
    for call in view.calls:
        if call.rva is not None:
            out.append(CallTarget('fn', call.rva))
        elif call.key is not None:
            out.append(CallTarget('imp', call.key))
        else:
            out.append(CallTarget('ind', None))
    return sorted(out, key=_call_key)


def _same_callee(a: CallTarget, b: CallTarget, targets: TargetMap, voter: Voter | None) -> bool:
    if a.kind == 'ind' or b.kind == 'ind':
        return a.kind == b.kind
    if a.kind == b.kind == 'imp':
        return a.value == b.value
    if a.kind == b.kind == 'fn':
        return targets.function_state(a.value, b.value, voter) == MAPPED
    if a.kind == 'imp':
        return targets.import_key('newer', b.value) == a.value
    return targets.import_key('older', a.value) == b.value


def callee_leftovers(old: FnView, new: FnView, targets: TargetMap,
                     voter: Voter | None) -> tuple[list[CallTarget], list[CallTarget]]:
    """C4: the callees without a counterpart on the other side (empty on both sides = `equal`)."""
    old_targets, new_targets = _targets_of(old), _targets_of(new)
    used: set[int] = set()
    only_old = []
    for a in old_targets:
        for k, b in enumerate(new_targets):
            if k not in used and _same_callee(a, b, targets, voter):
                used.add(k)
                break
        else:
            only_old.append(a)
    return only_old, [b for k, b in enumerate(new_targets) if k not in used]


def _text_of(target: CallTarget) -> str:
    return 'indirect call' if target.kind == 'ind' else (f'0x{target.value:x}' if target.kind == 'fn' else str(target.value))


def _call_deltas(old: FnView, new: FnView, only_old: Sequence[CallTarget], only_new: Sequence[CallTarget],
                 explained: Counter) -> list[tuple[Delta, DeltaInfo]]:
    """C4 deltas for the callees the aligned C2 deltas did not already describe (replacements pair up in order)."""
    def unexplained(side: str, targets: Sequence[CallTarget]) -> list[CallTarget]:
        out = []
        for target in targets:
            if explained.get((side, target), 0) > 0:
                explained[(side, target)] -= 1
            else:
                out.append(target)
        return out
    left_old, left_new = unexplained('old', only_old), unexplained('new', only_new)
    out: list[tuple[Delta, DeltaInfo]] = []
    for before, after in zip(left_old, left_new, strict=False):
        out.append((Delta(cls='callee', channel='C4', older_rva=old.rva, newer_rva=new.rva, old=short(_text_of(before)),
                          new=short(_text_of(after))), DeltaInfo(tokens=(before, after))))
    for before in left_old[len(left_new):]:
        out.append((Delta(cls='call-removed', channel='C4', older_rva=old.rva, newer_rva=None, old=short(_text_of(before))),
                    DeltaInfo(tokens=(before, None))))
    for after in left_new[len(left_old):]:
        out.append((Delta(cls='call-added', channel='C4', older_rva=None, newer_rva=new.rva, new=short(_text_of(after))),
                    DeltaInfo(tokens=(None, after))))
    return out


def _explained_calls(deltas: Iterable[tuple[Delta, DeltaInfo]]) -> Counter:
    explained: Counter = Counter()
    for delta, info in deltas:
        if delta.cls in ('callee', 'call-added', 'call-removed'):
            before, after = info.tokens
            if before is not None:
                explained[('old', before)] += 1
            if after is not None:
                explained[('new', after)] += 1
    return explained


def _constant_residue(old: FnView, new: FnView, deltas: Iterable[tuple[Delta, DeltaInfo]]) -> list[tuple[Delta, DeltaInfo]]:
    """C5: constants and strings that exist on one side only and that no C2 delta already explains."""
    out: list[tuple[Delta, DeltaInfo]] = []
    removed = Counter(c.value for c in old.consts)
    added = Counter(c.value for c in new.consts)
    removed.subtract(added)
    surplus_old = Counter({v: n for v, n in removed.items() if n > 0})
    surplus_new = Counter({v: -n for v, n in removed.items() if n < 0})
    for delta, info in deltas:
        if delta.cls in ('constant', 'frame'):
            before, after = info.values
            if before is not None and surplus_old.get(before, 0) > 0:
                surplus_old[before] -= 1
            if after is not None and surplus_new.get(after, 0) > 0:
                surplus_new[after] -= 1
    site_old = {c.value: c.site for c in reversed(old.consts)}
    site_new = {c.value: c.site for c in reversed(new.consts)}
    values_old, values_new = sorted(surplus_old.elements()), sorted(surplus_new.elements())
    for before, after in zip(values_old, values_new, strict=False):
        out.append((Delta(cls='constant', channel='C5', older_rva=site_old[before], newer_rva=site_new[after],
                          old=f'0x{before:x}' if before >= 0 else f'-0x{-before:x}',
                          new=f'0x{after:x}' if after >= 0 else f'-0x{-after:x}'), DeltaInfo(values=(before, after))))
    for before in values_old[len(values_new):]:
        out.append((Delta(cls='constant', channel='C5', older_rva=site_old[before], newer_rva=None,
                          old=f'0x{before:x}' if before >= 0 else f'-0x{-before:x}'), DeltaInfo(values=(before, None))))
    for after in values_new[len(values_old):]:
        out.append((Delta(cls='constant', channel='C5', older_rva=None, newer_rva=site_new[after],
                          new=f'0x{after:x}' if after >= 0 else f'-0x{-after:x}'), DeltaInfo(values=(None, after))))
    out.extend(_string_residue(old, new, deltas))
    return out


def _string_residue(old: FnView, new: FnView, deltas: Iterable[tuple[Delta, DeltaInfo]]) -> list[tuple[Delta, DeltaInfo]]:
    rows_old = [row for rows in old.strings.values() for row in rows]
    rows_new = [row for rows in new.strings.values() for row in rows]
    surplus_old = Counter(r.sha for r in rows_old)
    surplus_old.subtract(Counter(r.sha for r in rows_new))
    gone = Counter({sha: n for sha, n in surplus_old.items() if n > 0})
    came = Counter({sha: -n for sha, n in surplus_old.items() if n < 0})
    for delta, info in deltas:
        if delta.cls == 'string':
            before, after = info.shas
            if before is not None and gone.get(before, 0) > 0:
                gone[before] -= 1
            if after is not None and came.get(after, 0) > 0:
                came[after] -= 1
    prefix_old = {r.sha: (r.prefix, r.site) for r in reversed(rows_old)}
    prefix_new = {r.sha: (r.prefix, r.site) for r in reversed(rows_new)}
    out = []
    list_old, list_new = sorted(gone.elements()), sorted(came.elements())
    for k in range(max(len(list_old), len(list_new))):
        before = prefix_old[list_old[k]] if k < len(list_old) else None
        after = prefix_new[list_new[k]] if k < len(list_new) else None
        out.append((Delta(cls='string', channel='C5', older_rva=None if before is None else before[1],
                          newer_rva=None if after is None else after[1],
                          old=None if before is None else short(before[0]), new=None if after is None else short(after[0])),
                    DeltaInfo(strings=(None if before is None else before[0], None if after is None else after[0]))))
    return out


def _constants_equal(old: FnView, new: FnView) -> str:
    """C5: the multiset of ALL non-address constants and of the defined strings (rarity filters are keys only)."""
    same_constants = Counter(c.value for c in old.consts) == Counter(c.value for c in new.consts)
    same_strings = (Counter(r.sha for rows in old.strings.values() for r in rows)
                    == Counter(r.sha for rows in new.strings.values() for r in rows))
    return 'equal' if same_constants and same_strings else 'differs'


def _cfg_filter(old: FnView, new: FnView, table_old, table_new, fo: int, fn: int) -> str:
    """C3: counts, MD indices and the block-body multiset (a filter, never a proof)."""
    for column in ('n_bb', 'n_edge', 'md_td', 'md_bu'):
        if table_old.get(column, fo) != table_new.get(column, fn):
            return 'differs'
    keys_old = Counter(b.h1 for b in old.blocks)
    keys_new = Counter(b.h1 for b in new.blocks)
    return 'equal' if keys_old == keys_new else 'differs'


class IrFacts:
    """Per-run state: the target map (votes over all matched pairs) and the two readers. `analyze` is O(the pair)."""

    def __init__(self, sides: IrSides, pairs: Iterable[tuple[int, int]], *, limits: UnifiedLimits = DEFAULT_LIMITS,
                 budget: Budget | None = None):
        self.sides, self.limits, self.budget = sides, limits, budget or Budget()
        self.targets = TargetMap(sides.older, sides.newer, pairs, older_sections=sides.older_sections,
                                 newer_sections=sides.newer_sections, identical=sides.identical, limits=limits,
                                 budget=self.budget)
        self.unreadable = tuple(
            any('pdata-unreadable' in warning for warning in (reader.manifest.warnings if reader.manifest else ()))
            for reader in (sides.older, sides.newer))

    def analyze(self, older_rva: int, newer_rva: int) -> IrPair | None:
        """The IR channels of the chosen pair, or None when either function is not in its IR."""
        older, newer = self.sides.older, self.sides.newer
        fo, fn = older.functions.rva_to_fid.get(older_rva), newer.functions.rva_to_fid.get(newer_rva)
        if fo is None or fn is None:
            return None
        table_old, table_new = older.functions, newer.functions
        voter = (older_rva, newer_rva)
        states = {c: 'unavailable' for c in CHANNELS_IR}
        states['C0'] = _equal(table_old.get('h0', fo), table_new.get('h0', fn))
        states['C1'] = _equal(table_old.get('h1', fo), table_new.get('h1', fn))
        flags = _flags(table_old, table_new, fo, fn)
        unlocated = bool((table_old.get('flags', fo) or 0) & schema.FN_FLAGS['mask-unlocated']
                         or (table_new.get('flags', fn) or 0) & schema.FN_FLAGS['mask-unlocated'])
        old, new = load_view(older, 'older', fo), load_view(newer, 'newer', fn)
        if old is None or new is None:
            return IrPair(states, (), (0, 0, 0), 'unavailable', False, False, unlocated, ((), ()), (), flags)
        self.budget.tick(len(old.insns) + len(new.insns))
        alignment = align(old, new, limits=self.limits, budget=self.budget)
        operands = operand_deltas(old, new, alignment, self.targets, voter)
        cfg = compare_cfg(old, new, alignment, self.targets, voter)
        cons = Consistency(*(a + b for a, b in zip(operands.cons.as_tuple(), cfg.cons.as_tuple(), strict=True)))
        deltas = [*operands.deltas, *cfg.deltas]
        only_old, only_new = callee_leftovers(old, new, self.targets, voter)
        states['C4'] = 'equal' if not only_old and not only_new else 'differs'
        deltas += _call_deltas(old, new, only_old, only_new, _explained_calls(deltas))
        residue = _constant_residue(old, new, deltas)
        deltas += residue
        states['C2'] = 'differs' if any(d.channel == 'C2' for d, _ in deltas) else 'equal'
        states['C3'] = _cfg_filter(old, new, table_old, table_new, fo, fn)
        states['C5'] = _constants_equal(old, new)
        deltas.sort(key=lambda item: severity(item[0]))
        eh = eh_state(old, new, self.targets, voter, unreadable=any(self.unreadable))
        limits_hit = ('align-cap',) if alignment.capped else ()
        counts_differ = any(table_old.get(c, fo) != table_new.get(c, fn) for c in ('n_bb', 'n_edge'))
        return IrPair(states, tuple(deltas), cons.as_tuple(), eh, positional_cfg_equal(old, new), cfg.layout_ok,
                      unlocated, (tuple(only_old), tuple(only_new)), limits_hit, flags, counts_differ,
                      trace_arg_only(old, new, deltas, self.targets))

    def function_name(self, side: str, rva: int) -> str | None:
        """The real symbol of a function (imported or user defined), never a default `FUN_` label."""
        reader = self.sides.older if side == 'older' else self.sides.newer
        fid = reader.functions.rva_to_fid.get(rva)
        if fid is None or reader.functions.get('name_src', fid) not in (schema.NAME_SRC_CODES['IMPORTED'],
                                                                         schema.NAME_SRC_CODES['USER_DEFINED']):
            return None
        return reader.functions.name[fid]
