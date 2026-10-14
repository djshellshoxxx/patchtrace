"""Lineage groups by union-find (spec §4.2) and deterministic role assignment (spec §4.4).

Edges: same file name, same source project, same PDB name, or relocation-masked body-hash overlap
>= threshold. If everything collapses into one component the overlap threshold is raised (15 -> 30 -> 50 %)
and recorded; a component is never split to improve balance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .common import canonical_json

THRESHOLDS = (0.15, 0.30, 0.50)
ROLE_CUTS = ((0.60, 'dev'), (0.85, 'locked-test'), (1.01, 'shift-test'))


@dataclass(frozen=True)
class BinaryInfo:
    id: str
    file_name: str
    project: str | None = None
    pdb_name: str | None = None
    body_hashes: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class LineageResult:
    lineages: dict[str, tuple[str, ...]]  # lineage id -> sorted member ids
    threshold: float
    edges: tuple[tuple[str, str, str], ...]
    evidence_sha256: str


class UnionFind:
    def __init__(self, items: Iterable[str]):
        self.parent = {i: i for i in items}

    def find(self, item: str) -> str:
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != root:
            self.parent[item], item = root, self.parent[item]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            lo, hi = sorted((ra, rb))  # deterministic: smaller id is the root
            self.parent[hi] = lo


def overlap(a: frozenset[str], b: frozenset[str]) -> float:
    return len(a & b) / min(len(a), len(b)) if a and b else 0.0


def _edges(binaries: Sequence[BinaryInfo], threshold: float) -> list[tuple[str, str, str]]:
    out = []
    items = sorted(binaries, key=lambda b: b.id)
    for i, a in enumerate(items):
        for b in items[i + 1:]:
            if a.file_name.lower() == b.file_name.lower():
                out.append((a.id, b.id, 'file-name'))
            elif a.project and a.project == b.project:
                out.append((a.id, b.id, 'project'))
            elif a.pdb_name and a.pdb_name.lower() == (b.pdb_name or '').lower():
                out.append((a.id, b.id, 'pdb-name'))
            elif overlap(a.body_hashes, b.body_hashes) >= threshold:
                out.append((a.id, b.id, f'body-overlap>={threshold:.2f}'))
    return out


def cluster(binaries: Sequence[BinaryInfo], thresholds: Sequence[float] = THRESHOLDS) -> LineageResult:
    if len({b.id for b in binaries}) != len(binaries):
        raise ValueError('duplicate binary id')
    for threshold in thresholds:
        edges = _edges(binaries, threshold)
        uf = UnionFind(b.id for b in binaries)
        for a, b, _ in edges:
            uf.union(a, b)
        comps: dict[str, list[str]] = {}
        for b in sorted(binaries, key=lambda b: b.id):
            comps.setdefault(uf.find(b.id), []).append(b.id)
        if len(comps) > 1 or len(binaries) <= 1 or threshold == thresholds[-1]:
            break
    lineages = {}
    for members in comps.values():
        lid = 'L-' + hashlib.sha256('|'.join(members).encode()).hexdigest()[:12]
        lineages[lid] = tuple(members)
    evidence = hashlib.sha256(canonical_json({'threshold': threshold, 'edges': [list(e) for e in edges]})).hexdigest()
    return LineageResult(dict(sorted(lineages.items())), threshold, tuple(edges), evidence)


def role_u(lineage_id: str, salt: str) -> float:
    return int(hashlib.sha256(f'{lineage_id}|{salt}'.encode()).hexdigest()[:8], 16) / 2**32


def assign_roles(lineage_ids: Iterable[str], salt: str, shift_test: Iterable[str] = ()) -> dict[str, str]:
    """u < .60 dev, < .85 locked-test, else shift-test; pre-declared shift-test lineages override."""
    forced = set(shift_test)
    out = {}
    for lid in sorted(set(lineage_ids)):
        u = role_u(lid, salt)
        out[lid] = 'shift-test' if lid in forced else next(role for cut, role in ROLE_CUTS if u < cut)
    return out


@dataclass(frozen=True)
class CandidateIdentity:
    """A labelled candidate with its lineage and function-identity keys (e.g. 'body:<relocation-masked
    sha256>' for each endpoint, or 'src:<name|file|line>' from debug info)."""
    id: str
    lineage: str
    identities: tuple[str, ...]


@dataclass(frozen=True)
class IdentityGrouping:
    group_of: dict[str, str]           # candidate id -> CV group id
    hub_identities: frozenset[str]     # identities shared by too many lineages: not unioned, see `seen_body`
    seen_body: frozenset[str]          # candidates carrying a hub identity -> report as 'seen-body' stratum
    merged_lineages: int               # lineages that were merged with another through a shared identity
    largest_share: float               # largest group's share of candidates


def identity_groups(cands: Sequence[CandidateIdentity], *, hub_max_lineages: int | None = None) -> IdentityGrouping:
    """CV groups = connected components over lineages AND shared function identities (spec §4.5 amended).

    An identity present in more than `hub_max_lineages` lineages (shared CRT/static code) is NOT used as a
    union edge (that would collapse everything); its candidates are returned in `seen_body` instead."""
    lineages_of: dict[str, set[str]] = {}
    for c in cands:
        for ident in c.identities:
            lineages_of.setdefault(ident, set()).add(c.lineage)
    hubs = frozenset(i for i, ls in lineages_of.items() if hub_max_lineages is not None and len(ls) > hub_max_lineages)
    uf = UnionFind(['L:' + c.lineage for c in cands] + ['I:' + i for i in lineages_of])
    for c in sorted(cands, key=lambda c: c.id):
        for ident in c.identities:
            if ident not in hubs:
                uf.union('L:' + c.lineage, 'I:' + ident)
    members: dict[str, set[str]] = {}
    for c in cands:
        members.setdefault(uf.find('L:' + c.lineage), set()).add(c.lineage)
    names = {root: 'G-' + hashlib.sha256('|'.join(sorted(ls)).encode()).hexdigest()[:12]
             for root, ls in members.items()}
    group_of = {c.id: names[uf.find('L:' + c.lineage)] for c in cands}
    sizes: dict[str, int] = {}
    for g in group_of.values():
        sizes[g] = sizes.get(g, 0) + 1
    return IdentityGrouping(group_of, hubs, frozenset(c.id for c in cands if set(c.identities) & hubs),
                            sum(len(ls) for ls in members.values() if len(ls) > 1),
                            max(sizes.values()) / len(cands) if cands else 0.0)


def shared_identities(train: Sequence[CandidateIdentity], test: Sequence[CandidateIdentity]) -> set[str]:
    """Leakage audit: function identities present on both sides of a split."""
    return {i for c in train for i in c.identities} & {i for c in test for i in c.identities}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Cluster binaries into lineages (JSON in, JSON out).')
    parser.add_argument('binaries', type=Path, help='JSON list of {id,file_name,project,pdb_name,body_hashes}')
    args = parser.parse_args(argv)
    from .common import strict_json
    items = [BinaryInfo(d['id'], d['file_name'], d.get('project'), d.get('pdb_name'),
                        frozenset(d.get('body_hashes', ()))) for d in strict_json(args.binaries.read_bytes())]
    res = cluster(items)
    json.dump({'threshold': res.threshold, 'evidence_sha256': res.evidence_sha256,
               'lineages': {k: list(v) for k, v in res.lineages.items()}}, sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
