"""DATA-MAP/1 and target consistency (SPEC-31 05 s2.7, review R-01, S3, amendment A-30). Pure, deterministic, bounded.

Equal bytes at a moved address re-target every relative operand, so no proof may trust an address operand until its
target is proven to reach the counterpart. `TargetMap` answers, for a pair of targets (t in the older image, u in the
newer one) seen by one function pair r: `mapped`, `unmapped` (no evidence either way: not a delta, but it blocks every
proof) or `conflict` (a target maps elsewhere: a semantic delta); data targets add `string` (both defined strings with
different content).

Function targets are mapped by (i) a `matched` row of tier A or M (`pairs`), (ii) two imports with the same key,
(iii) two thunks whose targets are mapped, (iv) two bodies with equal `h0` that sit at the same RVA or are the consensus
of the call operands of other matched pairs. Data targets are mapped by (a) two defined strings with equal SHA-256,
unique per side, (b) the bidirectional consensus of the data operands of OTHER matched pairs with equal `h1`, (c) a
region shift: a single-use datum between neighbours that moved by the same displacement within one section, (d) the PE
header region, which does not shift. A consensus that points elsewhere is a `conflict`: the patched function of a
swapped global is a dissenter, the innocent ones keep their mapping. Identical artifacts (X vs X) map every address to
itself.

Consensus (A-30, p15). The raw consensus of a datum is the partner voted by a strict majority of its voters, with at
least two voters (none when the datum is incomplete, L-40). The consensus additionally needs no blocking competing claim:
consensus(t) = u is blocked by a claim (t', u), t' != t, with >= 2 voters whose t' has no raw consensus other than u, or
whose t' is incomplete; symmetrically for consensus(u) = t with claims (t, u'). Leave-one-out (rule 4(b)): row r is
judged by a strict majority of the OTHER voters, with at least one of them, and no blocking competing claim (judged on
the full tables): r's own vote never tips the majority and a function never proves its own references, while two
functions that agree and face no competing claim do map. In that count an explained dissent is ignored: a vote for
(t, u') with u' != u when u' has a full-table consensus other than t (symmetrically (t', u)), so a lone dissenter
whose other datum has its own consensus never ties two innocent referrers; a dissent whose other datum has no
consensus still counts (p15: two retargets against one genuine referrer stay a tie). `data_token`, the confirmed neighbours of the region shift and
the `conflict` test use the full-table consensus (they judge no row's own evidence).

What is still decided by majority: a lone dissenting vote (one function reading another datum) never blocks, so the
typical patched function stays a `conflict` beside the innocent `mapped` referrers. That is sound enough because the
dissenter itself is never mapped (it is the `conflict`) and the innocent mapping rests on at least two other agreeing
functions with no unexplained competing claim; what votes cannot tell apart ("several functions retargeted to a global
others still reference" against "that global moved and the others were retargeted") now abstains. Known cost: two
functions retargeted together to a brand-new global make every referrer of the old datum `unmapped` (`review`, never a
wrong `cosmetic`).

Orientation (A-30, p11): every rule is symmetric under swapping the images and mirroring the pairs, except which vote
pairs a capped table (`datamap-cap`) keeps; the data of a dropped pair are incomplete and abstain either way.
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
    remembered (L-40): enough to know whether anybody other than the function under judgment voted for it. Beyond
    `cap_pairs` distinct pairs a new pair is dropped and both of its data are `incomplete`: a majority over the votes
    that were kept could contradict the full one, so an incomplete datum has no consensus and no region shift."""

    def __init__(self, cap_pairs: int, kept: int):
        self.cap_pairs, self.remembered = cap_pairs, kept + 1
        self.count: dict[tuple, int] = {}
        self.by_old: dict[str, dict[int, dict[int, int]]] = {'data': {}, 'fn': {}}
        self.by_new: dict[str, dict[int, dict[int, int]]] = {'data': {}, 'fn': {}}
        self.voters_old: dict[tuple, set[Voter]] = {}
        self.voters_new: dict[tuple, set[Voter]] = {}
        self.incomplete_old: dict[str, set[int]] = {'data': set(), 'fn': set()}
        self.incomplete_new: dict[str, set[int]] = {'data': set(), 'fn': set()}
        self.of: dict[Voter, set[tuple]] = {}             # the kept votes of each voter, for leave-one-out (O(votes))
        self.capped = False

    def add(self, cls: str, t: int, u: int, voter: Voter) -> None:
        key = (cls, t, u)
        if key not in self.count:
            if len(self.count) >= self.cap_pairs:
                self.capped = True
                self.incomplete_old[cls].add(t)
                self.incomplete_new[cls].add(u)
                return
            self.count[key] = 0
        self.count[key] += 1
        self.of.setdefault(voter, set()).add(key)
        self.by_old[cls].setdefault(t, {})[u] = self.count[key]
        self.by_new[cls].setdefault(u, {})[t] = self.count[key]
        for table, datum in ((self.voters_old, (cls, t)), (self.voters_new, (cls, u))):
            seen = table.setdefault(datum, set())
            if len(seen) < self.remembered:
                seen.add(voter)

    @staticmethod
    def majority(table: dict[int, int] | None, floor: int = 2) -> int | None:
        """The partner chosen by a strict majority of the voters, with at least `floor` of them: two for the raw
        consensus of 05 s2.7 rule 3, one among the other voters for leave-one-out (rule 4(b))."""
        if not table:
            return None
        total = sum(table.values())
        value, count = min(table.items(), key=lambda item: (-item[1], item[0]))
        return value if count >= floor and count * 2 > total else None


class TargetMap:
    def __init__(self, older: IrReader, newer: IrReader, pairs: Iterable[tuple[int, int]], *,
                 older_sections: Sequence[Section] = (), newer_sections: Sequence[Section] = (),
                 identical: bool = False, limits: UnifiedLimits = DEFAULT_LIMITS, budget: Budget | None = None):
        self.older, self.newer, self.identical, self.limits = older, newer, identical, limits
        self.budget = budget or Budget()
        self.sections = {'older': tuple(sorted(older_sections)), 'newer': tuple(sorted(newer_sections))}
        self.pair_old: dict[int, int] = {}
        self.pair_new: dict[int, int] = {}
        for o, n in sorted(set(pairs)):
            if o not in self.pair_old and n not in self.pair_new:     # a contradictory row never maps anything
                self.pair_old[o], self.pair_new[n] = n, o
        self.limits_hit: set[str] = set()
        self._votes = _Votes(limits.l40_data_pairs, limits.l40_votes_kept)
        self._consensus_cache: dict[tuple, int | None] = {}
        self._loo_cache: dict[tuple, bool] = {}
        self._confirmed: tuple[list[tuple[int, int]], list[int], list[tuple[int, int]], list[int]] | None = None
        self._strings: dict[str, dict[str, set[int]]] | None = None
        if not identical:
            self._collect_votes(self.budget)
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
                elif a.kind == 'code' and a.target in old_rvas and b.target in new_rvas and \
                        a.target not in self.pair_old and b.target not in self.pair_new:
                    seen.add(('fn', a.target, b.target))         # rule 2: neither target is in a pair (A-30, p11)
            for cls, t, u in sorted(seen):
                self._votes.add(cls, t, u, (o, n))

    # --- consensus (rule 3, A-30) --------------------------------------------------------------------------------------------
    # `side` is 'o' (an older datum and its newer partners) or 'n' (the converse); `drop` is the set of votes of the row
    # under judgment (leave-one-out), empty for the full tables.

    def _drop(self, voter: Voter | None) -> frozenset | set:
        return self._votes.of.get(voter, frozenset()) if voter is not None else frozenset()

    def _incomplete(self, side: str, cls: str, x: int) -> bool:
        return x in (self._votes.incomplete_old if side == 'o' else self._votes.incomplete_new)[cls]

    def _partners(self, side: str, cls: str, x: int, drop) -> dict[int, int]:
        """Voters per partner of x, without the votes in `drop`: O(partners of x)."""
        table = (self._votes.by_old if side == 'o' else self._votes.by_new)[cls].get(x) or {}
        if not drop or not table:
            return table
        out: dict[int, int] = {}
        for y, count in table.items():
            count -= ((cls, x, y) if side == 'o' else (cls, y, x)) in drop
            if count > 0:
                out[y] = count
        return out

    def _raw(self, side: str, cls: str, x: int, drop=frozenset(), floor: int = 2) -> int | None:
        """The raw consensus: a strict majority of >= `floor` voters (without `drop`), none for an incomplete datum."""
        return None if self._incomplete(side, cls, x) else _Votes.majority(self._partners(side, cls, x, drop), floor)

    def _blocked(self, side: str, cls: str, x: int, y: int) -> bool:
        """Rule 3 on the full tables: y (the partner of x) is incomplete (the claims of its dropped pairs are unknown), or
        a competing claim (x', y), x' != x, blocks: x' is incomplete, or has >= 2 voters for y and no raw consensus of
        its own other than y. A single dissenting vote never blocks."""
        other = 'n' if side == 'o' else 'o'
        if self._incomplete(other, cls, y):
            return True
        return any(x2 != x and (self._incomplete(side, cls, x2) or
                                (count >= 2 and self._raw(side, cls, x2) in (None, y)))
                   for x2, count in sorted(self._partners(other, cls, y, frozenset()).items()))

    def _consensus(self, side: str, cls: str, x: int) -> int | None:
        """The rule-3 consensus of x on the full tables: its raw consensus y unless a competing claim blocks it."""
        key = (side, cls, x)
        if key not in self._consensus_cache:
            y = self._raw(side, cls, x)
            self._consensus_cache[key] = None if y is None or self._blocked(side, cls, x, y) else y
        return self._consensus_cache[key]

    def _others_agree(self, side: str, cls: str, x: int, y: int, voter: Voter) -> bool:
        """Rule 4(b) for one direction: y is the strict majority of the voters of x other than `voter`, with at least
        one of them, after ignoring an explained dissent (a vote for y' != y whose y' has a full-table consensus other
        than x), and no competing claim blocks y on the full tables."""
        key = (side, cls, x, y, voter)
        if key not in self._loo_cache:
            other = 'n' if side == 'o' else 'o'
            agree = False
            if not self._incomplete(side, cls, x):
                table = {partner: count for partner, count in self._partners(side, cls, x, self._drop(voter)).items()
                         if partner == y or self._consensus(other, cls, partner) in (None, x)}
                agree = _Votes.majority(table, 1) == y and not self._blocked(side, cls, x, y)
            self._loo_cache[key] = agree
        return self._loo_cache[key]

    def _bidirectional(self, cls: str, t: int, u: int, voter: Voter | None = None) -> bool:
        """consensus(t) = u and consensus(u) = t: on the full tables without `voter`, else over the other voters (rule
        4(b), A-30)."""
        if voter is None:
            return self._consensus('o', cls, t) == u and self._consensus('n', cls, u) == t
        return self._others_agree('o', cls, t, u, voter) and self._others_agree('n', cls, u, t, voter)

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

    def function_state(self, t: int | None, u: int | None, voter: Voter | None = None, _depth: int = 0) -> str:
        if t is None or u is None:
            return UNMAPPED                                      # an unresolved target is no evidence either way
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
            if self._bidirectional('fn', t, u, voter):
                return MAPPED                                    # the callers other than `voter` agree
        return UNMAPPED

    # --- data targets -------------------------------------------------------------------------------------------------------

    def _section(self, side: str, rva: int) -> Section | None:
        sections = self.sections[side]
        index = bisect_right([s[0] for s in sections], rva) - 1
        return sections[index] if index >= 0 and rva < sections[index][1] else None

    def _string_index(self) -> dict[str, dict[str, set[int]]]:
        """sha -> targets of the defined strings per side (built once; uniqueness is global, not per pair)."""
        if self._strings is None:
            self._strings = {'older': self._string_targets(self.older, self.budget),
                             'newer': self._string_targets(self.newer, self.budget)}
        return self._strings

    @staticmethod
    def _string_targets(reader: IrReader, budget: Budget) -> dict[str, set[int]]:
        """O(image): it decodes every function that references a string, so it ticks the run's budget."""
        out: dict[str, set[int]] = defaultdict(set)
        for fid in range(reader.functions.n):
            budget.tick()
            rows = reader.strings(fid)
            if not rows:
                continue
            instructions = reader.instructions(fid)
            budget.tick(len(instructions))
            by_rva = {insn.rva: insn for insn in instructions}
            for row in rows:
                insn = by_rva.get(row.site)
                target = data_target(insn) if insn is not None else None
                if target is not None:
                    out[row.sha].add(target)
        return out

    def _confirmed_pairs(self) -> tuple[list[tuple[int, int]], list[int], list[tuple[int, int]], list[int]]:
        """(old datum, new datum) pairs with a bidirectional consensus (full tables), ascending by the old datum and by
        the new one, with their keys for bisection."""
        if self._confirmed is None:
            found = sorted((t, u) for t in self._votes.by_old['data']
                           if (u := self._consensus('o', 'data', t)) is not None and self._consensus('n', 'data', u) == t)
            by_new = sorted(found, key=lambda pair: (pair[1], pair[0]))
            self._confirmed = (found, [t for t, _ in found], by_new, [u for _, u in by_new])
        return self._confirmed

    def _region_shift(self, t: int, u: int, voter: Voter | None) -> bool:
        """Rule (c): no consensus and no vote from another function; the nearest confirmed pairs below and above t (in
        older order, within t's section) and below and above u (in newer order, within u's section) all sit in both
        sections and moved by the same displacement u - t (which keeps their order); at least one exists. Symmetric
        under swapping the images (A-30, p11)."""
        if t in self._votes.incomplete_old['data'] or u in self._votes.incomplete_new['data']:
            return False                                         # dropped votes: "nobody else voted" is unknown
        for cls_votes, datum in ((self._votes.voters_old, ('data', t)), (self._votes.voters_new, ('data', u))):
            if self._voted_by_others(cls_votes.get(datum), voter):
                return False
        section_old, section_new = self._section('older', t), self._section('newer', u)
        if section_old is None or section_new is None:
            return False
        by_old, olds, by_new, news = self._confirmed_pairs()
        neighbours: set[tuple[int, int]] = set()
        for ordered, keys, at, index, section in ((by_old, olds, t, 0, section_old), (by_new, news, u, 1, section_new)):
            position = bisect_left(keys, at)
            for candidate in (position - 1, position):
                if 0 <= candidate < len(ordered) and section[0] <= ordered[candidate][index] < section[1]:
                    neighbours.add(ordered[candidate])
        return bool(neighbours) and all(
            section_old[0] <= t_n < section_old[1] and section_new[0] <= u_n < section_new[1] and u_n - t_n == u - t
            for t_n, u_n in neighbours)

    def data_token(self, side: str, rva: int) -> str | None:
        """The token of the datum pair a data address belongs to (bidirectional consensus), else None: the same text
        on both sides, so equal pseudo-code stays equal and a swapped global changes it."""
        if self.identical:
            return f'@D:{rva:x}'
        if side == 'older':
            partner = self._consensus('o', 'data', rva)
            return None if partner is None or self._consensus('n', 'data', partner) != rva else f'@D:{rva:x}.{partner:x}'
        partner = self._consensus('n', 'data', rva)
        return None if partner is None or self._consensus('o', 'data', partner) != rva else f'@D:{partner:x}.{rva:x}'

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
        cons_old, cons_new = self._consensus('o', 'data', t), self._consensus('n', 'data', u)
        if (cons_old is not None and cons_old != u) or (cons_new is not None and cons_new != t):
            return CONFLICT                                      # r is a dissenter of the full-table consensus
        if self._bidirectional('data', t, u, voter):
            return MAPPED                                        # the other functions agree, nothing competes
        if cons_old is None and cons_new is None and self._region_shift(t, u, voter):
            return MAPPED
        return UNMAPPED
