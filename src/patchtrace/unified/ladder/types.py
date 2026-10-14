"""In-memory result types of the L1 ladder (02-data-model s4: frozen dataclasses, never persisted).

`CorrPair` carries the per-pair provenance of 04 s3: the pass that accepted it, its tier, the round, the
drill-down chain, the propagation anchors and the implied-match votes. `Correspondence.atoms()` turns pairs into
the persisted `Atom` evidence of sources `pt-ladder` / `pt-bytes` (05 s1.1: F-PT-BYTES is its own source).
"""
from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

from ..contracts import Atom

TIER_RANK = {'M': 5, 'A': 4, 'B': 3, 'C': 2, 'W': 1}
SOURCE_LADDER = 'pt-ladder'
SOURCE_BYTES = 'pt-bytes'
FAMILY_BYTES = 'F-PT-BYTES'
GROUP_KINDS = ('duplicate', 'icf', 'inlined-into', 'outlined-from')
LEFTOVER_REASONS = ('no-unique-evidence', 'tiny', 'oversize', 'thunk-unresolved', 'unfinished')


def weaker(a: str, b: str) -> str:
    """The lower of two tiers (a drill-down pair never gets a stronger tier than any key of its chain)."""
    return a if TIER_RANK[a] <= TIER_RANK[b] else b


@dataclass(frozen=True, slots=True)
class CorrPair:
    """One 1:1 pair. `chain` = drill-down parents or agreeing neighbour keys; `anchors` = the accepted pairs whose
    neighbour sets produced it (propagated pairs only); `votes` = distinct anchors that voted (implied matches)."""
    older_fid: int
    newer_fid: int
    pass_id: str
    step: str
    tier: str
    family: str
    cls: str
    round: int
    votes: int = 0
    chain: tuple[str, ...] = ()
    anchors: tuple[tuple[int, int], ...] = ()
    hints: tuple[str, ...] = ()
    seq: int = field(default=0, compare=False)


@dataclass(frozen=True, slots=True)
class CorrGroup:
    """N:M, N:1 or containment relation that the ladder refuses to cross-multiply (04 s7). For `inlined-into` and
    `outlined-from` only the contained side is exclusive to the group; the container may also be in a pair."""
    kind: str
    older_fids: tuple[int, ...]
    newer_fids: tuple[int, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class Leftover:
    fid: int
    reason: str
    hints: tuple[str, ...] = ()


@dataclass(frozen=True)
class Correspondence:
    """The ladder's result. Pairs are sorted by (older_fid, newer_fid); every function of each side is in exactly
    one of: a pair, a group (contained side for inline hints), the leftover list."""
    pairs: tuple[CorrPair, ...]
    groups: tuple[CorrGroup, ...]
    older_only: tuple[Leftover, ...]
    newer_only: tuple[Leftover, ...]
    status: Literal['complete', 'partial']
    stop_reason: str | None
    passes_completed: tuple[str, ...]
    limits_hit: tuple[tuple[str, int], ...]
    stats: tuple[tuple[str, int], ...]
    older_rva: Sequence[int]
    newer_rva: Sequence[int]
    older_hubs: tuple[int, ...] = ()
    newer_hubs: tuple[int, ...] = ()

    def pair_rvas(self) -> tuple[tuple[int, int], ...]:
        return tuple((self.older_rva[p.older_fid], self.newer_rva[p.newer_fid]) for p in self.pairs)

    def group_rvas(self, group: CorrGroup) -> tuple[tuple[int, ...], tuple[int, ...]]:
        """(older rvas, newer rvas) of a group, ascending: what fusion needs (it never sees fids)."""
        return (tuple(sorted(self.older_rva[f] for f in group.older_fids)),
                tuple(sorted(self.newer_rva[f] for f in group.newer_fids)))

    def leftover_rvas(self, side: Literal['older', 'newer']) -> tuple[tuple[int, str], ...]:
        """(rva, reason) of the one-sided functions, ascending by rva."""
        items, rva = (self.older_only, self.older_rva) if side == 'older' else (self.newer_only, self.newer_rva)
        return tuple(sorted((rva[i.fid], i.reason) for i in items))

    def stat(self, name: str) -> int:
        return dict(self.stats).get(name, 0)

    def atoms(self, *, include_anchors: bool = False) -> tuple[Atom, ...]:
        """Atoms of sources `pt-ladder` and `pt-bytes`, one per pair, sorted by (older rva, newer rva). Tier-M anchors
        are inputs that already exist as manual atoms, so they are skipped unless `include_anchors`."""
        out = []
        for pair in self.pairs:
            if pair.pass_id == 'P00' and not include_anchors:
                continue
            native = [('round', str(pair.round))]
            if pair.chain:
                native.append(('chain', '>'.join(pair.chain)[:120]))
            if pair.anchors:
                a, b = pair.anchors[0]
                native.append(('anchor', f'{self.older_rva[a]:#x}>{self.newer_rva[b]:#x}'))
            if pair.votes:
                native.append(('votes', str(pair.votes)))
            out.append(Atom(
                source=SOURCE_BYTES if pair.family == FAMILY_BYTES else SOURCE_LADDER, step=pair.step,
                tier=pair.tier, cardinality='1:1', cls=pair.cls,
                older_rva=self.older_rva[pair.older_fid], newer_rva=self.newer_rva[pair.newer_fid],
                native=tuple(native), ref=f'r{pair.round}'))
        out.sort(key=lambda a: (a.older_rva, a.newer_rva, a.source, a.step))
        return tuple(out)

    def digest(self) -> str:
        """SHA-256 over a canonical text encoding of everything but `seq`: equal digests == equal results
        (G-U4 style determinism checks across processes and hash seeds)."""
        lines = [f'status={self.status}/{self.stop_reason}', 'passes=' + ','.join(self.passes_completed)]
        for p in self.pairs:
            anchors = ';'.join(f'{a}-{b}' for a, b in p.anchors)
            lines.append(f'P|{p.older_fid}|{p.newer_fid}|{p.pass_id}|{p.step}|{p.tier}|{p.family}|{p.cls}|{p.round}|'
                         f'{p.votes}|{">".join(p.chain)}|{anchors}|{",".join(p.hints)}')
        for g in self.groups:
            lines.append(f'G|{g.kind}|{",".join(map(str, g.older_fids))}|{",".join(map(str, g.newer_fids))}|{g.reason}')
        for side, items in (('O', self.older_only), ('N', self.newer_only)):
            for item in items:
                lines.append(f'L|{side}|{item.fid}|{item.reason}|{",".join(item.hints)}')
        lines.append('H|' + ','.join(map(str, self.older_hubs)) + '|' + ','.join(map(str, self.newer_hubs)))
        lines.append('X|' + ';'.join(f'{k}={v}' for k, v in self.limits_hit))
        return hashlib.sha256('\n'.join(lines).encode('utf-8')).hexdigest()
