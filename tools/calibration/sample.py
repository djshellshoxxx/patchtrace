"""Stratified natural sampling with recorded inclusion probabilities (spec §5.3).

Strata per pair: Ghidriff match type x ratio decile x size tercile. The sample list is generated before
labelling and its SHA-256 committed, so labelling cannot influence what gets sampled.
"""
from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

from .common import canonical_json, det_uniform


@dataclass(frozen=True)
class Candidate:
    pair: str
    match_id: str
    match_type: str
    ratio: float | None
    size: int | None


def _terciles(sizes: Sequence[int]) -> tuple[int, int]:
    s = sorted(sizes)
    return (s[len(s) // 3], s[(2 * len(s)) // 3]) if s else (0, 0)


def stratum_of(c: Candidate, cuts: tuple[int, int]) -> str:
    decile = 'na' if c.ratio is None else str(min(int(c.ratio * 10), 9))
    tercile = 'na' if c.size is None else ('s' if c.size < cuts[0] else 'm' if c.size < cuts[1] else 'l')
    return f'{c.match_type}|r{decile}|{tercile}'


def sample(candidates: Sequence[Candidate], *, budget_per_pair: int, seed, full_enumeration: int = 200,
           stage: str = 'S1') -> list[dict]:
    by_pair: dict[str, list[Candidate]] = {}
    for c in sorted(candidates, key=lambda c: (c.pair, c.match_id)):
        by_pair.setdefault(c.pair, []).append(c)
    out = []
    for pair, items in sorted(by_pair.items()):
        if len({c.match_id for c in items}) != len(items):
            raise ValueError(f'duplicate candidate in pair {pair}')
        if len(items) <= max(full_enumeration, budget_per_pair):
            out += [{'pair': pair, 'match_id': c.match_id, 'stratum': 'all', 'stage': stage, 'p_incl': 1.0}
                    for c in items]
            continue
        cuts = _terciles([c.size for c in items if c.size is not None])
        strata: dict[str, list[Candidate]] = {}
        for c in items:
            strata.setdefault(stratum_of(c, cuts), []).append(c)
        for key, members in sorted(strata.items()):
            k = min(len(members), max(1, round(budget_per_pair * len(members) / len(items))))
            chosen = sorted(members, key=lambda c: (det_uniform(seed, 'sample', pair, c.match_id), c.match_id))[:k]
            out += [{'pair': pair, 'match_id': c.match_id, 'stratum': key, 'stage': stage,
                     'p_incl': k / len(members)} for c in sorted(chosen, key=lambda c: c.match_id)]
    return out


def sample_digest(items: Sequence[dict]) -> str:
    return hashlib.sha256(canonical_json(list(items))).hexdigest()
