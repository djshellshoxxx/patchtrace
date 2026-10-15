"""DATA-MAP/1 and target consistency (SPEC-31 05 s2.7, review R-01, S3). Pure, deterministic, bounded.

Equal bytes at a moved address re-target every relative operand, so no proof may trust an address operand until its
target is proven to reach the counterpart. `TargetMap` answers, for a pair of targets (t in the older image, u in the
newer one) seen by one function pair r: `mapped`, `unmapped` (no evidence either way: not a delta, but it blocks every
proof) or `conflict` (a target maps elsewhere: a semantic delta); data targets add `string` (both defined strings with
different content).

Function targets are mapped by (i) a `matched` row of tier A or M (`pairs`), (ii) two imports with the same key,
(iii) two thunks whose targets are mapped, (iv) two bodies with equal `h0` that sit at the same RVA or are the consensus
of the call operands of another matched pair. Data targets are mapped by (a) two defined strings with equal SHA-256,
unique per side, (b) the bidirectional consensus of the data operands of OTHER matched pairs with equal `h1`
(leave-one-out: a function never proves its own references), (c) a region shift: a single-use datum between neighbours
that moved by the same displacement within one section, (d) the PE header region, which does not shift. A consensus that
points elsewhere is a `conflict`: the patched function of a swapped global is a dissenter, the innocent ones keep their
mapping. Identical artifacts (X vs X) map every address to itself.
"""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import defaultdict
from collections.abc import Iterable, Sequence

from ..ir.operands import VK_ADDRESS
from ..ir.reader import IrReader
from ..limits import DEFAULT_LIMITS, Budget, UnifiedLimits
from .fnview import FnView

MAPPED, UNMAPPED, CONFLICT, STRING = 'mapped', 'unmapped', 'conflict', 'string'
KIND_THUNK = 1
MAX_THUNK_DEPTH = 4

Voter = tuple[int, int]
Section = tuple[int, int]


def data_target(insn) -> int | None:
    """The one in-image address an instruction's address operands point at, else None (none or several)."""
    found = {op.value for op in insn.ops if op.vkind == VK_ADDRESS and isinstance(op.value, int)}
    return next(iter(found)) if len(found) == 1 else None


def string_sha(view: FnView, index: int) -> str | None:
    """SHA-256 of the defined string an instruction references, when it references exactly one."""
    rows = view.strings.get(view.insns[index].rva, ())
    if len(rows) == 1 and data_target(view.insns[index]) is not None:
        return rows[0].sha
    return None


class _Votes:
    """Distinct voters per (old datum, new datum), per class ('data' or 'fn'). Per datum only `kept + 1` voters are
    remembered (L-40): enough to know whether anybody other than the function under judgment voted for it."""

    def __init__(self, cap_pairs: int, kept: int):
        self.cap_pairs, self.remembered = cap_pairs, kept + 1
        self.count: dict[tuple, int] = {}
        self.by_old: dict[str, dict[int, dict[int, int]]] = {'data': {}, 'fn': {}}
        self.by_new: dict[str, dict[int, dict[int, int]]] = {'data': {}, 'fn': {}}
        self.voters_old: dict[tuple, set[Voter]] = {}
        self.voters_new: dict[tuple, set[Voter]] = {}
        self.capped = False

    def add(self, cls: str, t: int, u: int, voter: Voter) -> None:
        key = (cls, t, u)
        if key not in self.count:
            if len(self.count) >= self.cap_pairs:
                self.capped = True
                return
            self.count[key] = 0
        self.count[key] += 1
        self.by_old[cls].setdefault(t, {})[u] = self.count[key]
        self.by_new[cls].setdefault(u, {})[t] = self.count[key]
        for table, datum in ((self.voters_old, (cls, t)), (self.voters_new, (cls, u))):
            seen = table.setdefault(datum, set())
            if len(seen) < self.remembered:
                seen.add(voter)

    @staticmethod
    def consensus(table: dict[int, int] | None) -> int | None:
        """The partner chosen by a strict majority of the voters, with at least two of them (05 s2.7 rule 3)."""
        if not table:
            return None
        total = sum(table.values())
        value, count = min(table.items(), key=lambda item: (-item[1], item[0]))
        return value if count >= 2 and count * 2 > total else None


class TargetMap:
    def __init__(self, older: IrReader, newer: IrReader, pairs: Iterable[tuple[int, int]], *,
                 older_sections: Sequence[Section] = (), newer_sections: Sequence[Section] = (),
                 identical: bool = False, limits: UnifiedLimits = DEFAULT_LIMITS, budget: Budget | None = None):
        self.older, self.newer, self.identical, self.limits = older, newer, identical, limits
        self.sections = {'older': tuple(sorted(older_sections)), 'newer': tuple(sorted(newer_sections))}
        self.pair_old: dict[int, int] = {}
        self.pair_new: dict[int, int] = {}
        for o, n in sorted(set(pairs)):
            if o not in self.pair_old and n not in self.pair_new:     # a contradictory row never maps anything
                self.pair_old[o], self.pair_new[n] = n, o
        self.limits_hit: set[str] = set()
        self._votes = _Votes(limits.l40_data_pairs, limits.l40_votes_kept)
        self._consensus_cache: dict[tuple, int | None] = {}
        self._confirmed: tuple[list[int], list[int]] | None = None
        self._strings: dict[str, dict[str, set[int]]] | None = None
        if not identical:
            self._collect_votes(budget or Budget())
        if self._votes.capped:
            self.limits_hit.add('datamap-cap')

    # --- votes -----------------------------------------------------------------------------------------------------------

    def _collect_votes(self, budget: Budget) -> None:
        """Rule 2: matched pairs with equal `h1` are aligned by their reference lists; each aligned data or call
        reference votes for the pair of its targets."""
        old_rvas, new_rvas = self.older.functions.rva_to_fid, self.newer.functions.rva_to_fid
        for o, n in sorted(self.pair_old.items()):
            budget.tick()
            fo, fn = old_rvas.get(o), new_rvas.get(n)
            if fo is None or fn is None:
                continue
            h1 = self.older.functions.get('h1', fo)
            if h1 is None or h1 != self.newer.functions.get('h1', fn):
                continue
            refs_old, refs_new = self.older.refs(fo), self.newer.refs(fn)
            if len(refs_old) != len(refs_new) or any((a.opi, a.kind) != (b.opi, b.kind)
                                                     for a, b in zip(refs_old, refs_new, strict=True)):
                continue
            seen: set[tuple[str, int, int]] = set()
            for a, b in zip(refs_old, refs_new, strict=True):
                if a.target is None or b.target is None:
                    continue
                if a.kind == 'data':
                    seen.add(('data', a.target, b.target))
                elif a.kind == 'code' and a.target in old_rvas and b.target in new_rvas and a.target not in self.pair_old:
                    seen.add(('fn', a.target, b.target))
            for cls, t, u in sorted(seen):
                self._votes.add(cls, t, u, (o, n))

    def _consensus_old(self, cls: str, t: int) -> int | None:
        key = ('o', cls, t)
        if key not in self._consensus_cache:
            self._consensus_cache[key] = _Votes.consensus(self._votes.by_old[cls].get(t))
        return self._consensus_cache[key]

    def _consensus_new(self, cls: str, u: int) -> int | None:
        key = ('n', cls, u)
        if key not in self._consensus_cache:
            self._consensus_cache[key] = _Votes.consensus(self._votes.by_new[cls].get(u))
        return self._consensus_cache[key]

    def _voted_by_others(self, voters: set[Voter] | None, voter: Voter | None) -> bool:
        return bool(voters) and bool(voters - {voter})

    # --- function targets ---------------------------------------------------------------------------------------------------

    def _function(self, side: str, rva: int) -> int | None:
        return (self.older if side == 'older' else self.newer).functions.rva_to_fid.get(rva)

    def is_entry(self, side: str, rva: int) -> bool:
        return self._function(side, rva) is not None

    def import_key(self, side: str, rva: int) -> str | None:
        fid = self._function(side, rva)
        return None if fid is None else (self.older if side == 'older' else self.newer).functions.import_key[fid]

    def thunk_target(self, side: str, rva: int) -> int | None:
        fid = self._function(side, rva)
        if fid is None:
            return None
        table = (self.older if side == 'older' else self.newer).functions
        return table.get('thunk_target', fid) if table.get('kind', fid) == KIND_THUNK else None

    def _h0(self, side: str, rva: int) -> int | None:
        fid = self._function(side, rva)
        return None if fid is None else (self.older if side == 'older' else self.newer).functions.get('h0', fid)

    def function_state(self, t: int, u: int, voter: Voter | None = None, _depth: int = 0) -> str:
        if self.identical:
            return MAPPED if t == u else CONFLICT
        if self.pair_old.get(t) == u:
            return MAPPED
        key_old, key_new = self.import_key('older', t), self.import_key('newer', u)
        if key_old is not None and key_new is not None:
            return MAPPED if key_old == key_new else CONFLICT
        # A pure jump thunk stands for its target (an import stub is itself the end of the chain).
        target_old = self.thunk_target('older', t) if key_old is None else None
        target_new = self.thunk_target('newer', u) if key_new is None else None
        if (target_old is not None or target_new is not None) and _depth < MAX_THUNK_DEPTH:
            state = self.function_state(t if target_old is None else target_old, u if target_new is None else target_new,
                                        voter, _depth + 1)
            if state != UNMAPPED:
                return state
        if t in self.pair_old or u in self.pair_new:
            return CONFLICT                                      # a matched row pairs one of them with another function
        if key_old is not None or key_new is not None:
            return UNMAPPED                                      # an import against a function: no evidence
        h0 = self._h0('older', t)
        if h0 is not None and h0 == self._h0('newer', u):
            if t == u:
                return MAPPED
            if self._consensus_old('fn', t) == u and self._consensus_new('fn', u) == t:
                return MAPPED                                    # >= 2 callers voted, so somebody besides `voter` did
        return UNMAPPED

    # --- data targets -------------------------------------------------------------------------------------------------------

    def _section(self, side: str, rva: int) -> Section | None:
        sections = self.sections[side]
        index = bisect_right([s[0] for s in sections], rva) - 1
        return sections[index] if index >= 0 and rva < sections[index][1] else None

    def _string_index(self) -> dict[str, dict[str, set[int]]]:
        """sha -> targets of the defined strings per side (built once; uniqueness is global, not per pair)."""
        if self._strings is None:
            self._strings = {'older': self._string_targets(self.older), 'newer': self._string_targets(self.newer)}
        return self._strings

    @staticmethod
    def _string_targets(reader: IrReader) -> dict[str, set[int]]:
        out: dict[str, set[int]] = defaultdict(set)
        for fid in range(reader.functions.n):
            rows = reader.strings(fid)
            if not rows:
                continue
            by_rva = {insn.rva: insn for insn in reader.instructions(fid)}
            for row in rows:
                insn = by_rva.get(row.site)
                target = data_target(insn) if insn is not None else None
                if target is not None:
                    out[row.sha].add(target)
        return out

    def _confirmed_pairs(self) -> tuple[list[int], list[int]]:
        """(old datum, new datum) pairs with a bidirectional consensus, ascending by the old datum."""
        if self._confirmed is None:
            found = sorted((t, u) for t in self._votes.by_old['data']
                           if (u := self._consensus_old('data', t)) is not None and self._consensus_new('data', u) == t)
            self._confirmed = ([t for t, _ in found], [u for _, u in found])
        return self._confirmed

    def _region_shift(self, t: int, u: int, voter: Voter | None) -> bool:
        """Rule (c): no consensus and no vote from another function, neighbours below and above (in the same section)
        moved by the same displacement and keep their order."""
        for cls_votes, datum in ((self._votes.voters_old, ('data', t)), (self._votes.voters_new, ('data', u))):
            if self._voted_by_others(cls_votes.get(datum), voter):
                return False
        section_old, section_new = self._section('older', t), self._section('newer', u)
        if section_old is None or section_new is None:
            return False
        olds, news = self._confirmed_pairs()
        index = bisect_left(olds, t)
        displacement = u - t
        neighbours = 0
        for position, side in ((index - 1, -1), (index, 1)):
            if not 0 <= position < len(olds):
                continue
            t_n, u_n = olds[position], news[position]
            if not (section_old[0] <= t_n < section_old[1]):
                continue
            if u_n - t_n != displacement or not (section_new[0] <= u_n < section_new[1]) or \
                    (side < 0 and not u_n < u) or (side > 0 and not u_n > u):
                return False
            neighbours += 1
        return neighbours > 0

    def data_token(self, side: str, rva: int) -> str | None:
        """The token of the datum pair a data address belongs to (bidirectional consensus), else None: the same text
        on both sides, so equal pseudo-code stays equal and a swapped global changes it."""
        if self.identical:
            return f'@D:{rva:x}'
        if side == 'older':
            partner = self._consensus_old('data', rva)
            return None if partner is None or self._consensus_new('data', partner) != rva else f'@D:{rva:x}.{partner:x}'
        partner = self._consensus_new('data', rva)
        return None if partner is None or self._consensus_old('data', partner) != rva else f'@D:{partner:x}.{rva:x}'

    def data_state(self, t: int, u: int, voter: Voter | None = None,
                   shas: tuple[str | None, str | None] = (None, None)) -> str:
        if self.identical:
            return MAPPED if t == u else CONFLICT
        sha_old, sha_new = shas
        if sha_old is not None and sha_new is not None:
            if sha_old != sha_new:
                return STRING
            index = self._string_index()
            if len(index['older'].get(sha_old, ())) == 1 and len(index['newer'].get(sha_new, ())) == 1:
                return MAPPED
        header = [s[0] for s in (self.sections['older'][:1] + self.sections['newer'][:1])]
        if t == u and header and t < min(header):
            return MAPPED                                        # the PE header region does not shift
        cons_old, cons_new = self._consensus_old('data', t), self._consensus_new('data', u)
        if (cons_old is not None and cons_old != u) or (cons_new is not None and cons_new != t):
            return CONFLICT
        if cons_old == u and cons_new == t:
            return MAPPED                                        # >= 2 voters, so somebody besides `voter` voted
        if cons_old is None and cons_new is None and self._region_shift(t, u, voter):
            return MAPPED
        return UNMAPPED
