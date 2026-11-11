"""Corpus-level vendoring scan (PREREG 2.4; LBL-remaining 4.3).

Input: per-lineage sets of relocation-masked function body hashes (`masked_sha256` of tier_r/bodyhash.py).
Output: merge-lineage PROPOSALS where lineages share enough masked bodies (cross-project vendoring such as zstd,
zlib, Mbed TLS bundles). It never splits a lineage. A body present in more than `hub_max_lineages` lineages is a
hub (shared CRT/static code): it is not a merge edge and is listed separately, matching `lineage.identity_groups`.
`hub_max_lineages` and `threshold` are required: there is no code default (PREREG Q3).
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .common import strict_json
from .lineage import UnionFind, overlap


@dataclass(frozen=True)
class MergeProposal:
    lineages: tuple[str, ...]                    # sorted, at least two
    shared_bodies: int                           # distinct non-hub bodies present in more than one member
    pairs: tuple[tuple[str, str, float], ...]    # (a, b, overlap) for each pair at or above the threshold


@dataclass(frozen=True)
class ScanResult:
    proposals: tuple[MergeProposal, ...]
    hub_bodies: tuple[str, ...]


def scan(bodies: Mapping[str, Iterable[str]], *, threshold: float, hub_max_lineages: int) -> ScanResult:
    sets = {lid: frozenset(h) for lid, h in bodies.items()}
    holders: dict[str, set[str]] = defaultdict(set)
    for lid, hashes in sets.items():
        for h in hashes:
            holders[h].add(lid)
    hubs = frozenset(h for h, ls in holders.items() if len(ls) > hub_max_lineages)
    kept = {lid: hashes - hubs for lid, hashes in sets.items()}
    ids = sorted(kept)
    uf = UnionFind(ids)
    pair_hits: list[tuple[str, str, float]] = []
    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            ov = overlap(kept[a], kept[b])
            if ov >= threshold and kept[a] & kept[b]:
                uf.union(a, b)
                pair_hits.append((a, b, round(ov, 6)))
    comps: dict[str, list[str]] = defaultdict(list)
    for lid in ids:
        comps[uf.find(lid)].append(lid)
    proposals = []
    for members in comps.values():
        if len(members) < 2:
            continue
        inside = set(members)
        shared = sum(1 for h, ls in holders.items() if h not in hubs and len(ls & inside) > 1)
        pairs = tuple(p for p in pair_hits if p[0] in inside)
        proposals.append(MergeProposal(tuple(members), shared, pairs))
    return ScanResult(tuple(sorted(proposals, key=lambda p: p.lineages)), tuple(sorted(hubs)))


def load_bodies(data: object) -> dict[str, list[str]]:
    """Accepts {lineage: [hash, ...]} or a list of {lineage, masked_sha256} records."""
    out: dict[str, list[str]] = defaultdict(list)
    if isinstance(data, dict):
        for lid, hashes in data.items():
            out[str(lid)].extend(hashes)
    elif isinstance(data, list):
        for rec in data:
            out[str(rec['lineage'])].append(rec['masked_sha256'])
    else:
        raise ValueError('expected an object or a list of records')
    return dict(out)


def to_json(result: ScanResult) -> dict:
    return {'proposals': [{'lineages': list(p.lineages), 'shared_bodies': p.shared_bodies,
                           'pairs': [list(x) for x in p.pairs]} for p in result.proposals],
            'hub_bodies': list(result.hub_bodies), 'action': 'merge-only'}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Propose lineage merges from shared masked function bodies.')
    parser.add_argument('bodies', type=Path)
    parser.add_argument('--threshold', type=float, required=True, help='pairwise masked-body overlap, e.g. 0.15')
    parser.add_argument('--hub-max-lineages', type=int, required=True)
    args = parser.parse_args(argv)
    result = scan(load_bodies(strict_json(args.bodies.read_bytes())), threshold=args.threshold,
                  hub_max_lineages=args.hub_max_lineages)
    json.dump(to_json(result), sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
