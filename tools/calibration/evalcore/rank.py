"""Rank metrics for "which changed function is the fix" (LBL-10; plan s5, s7.1).

Conventions (all pinned by tests):
* A flagged list is ordered by an ascending sort key (smaller = more suspicious); equal keys are TIES.
* Ties get the MIDRANK: a block occupying positions lo..hi has rank (lo + hi) / 2. Midranks depend only on
  the multiset of keys, so permuting tied entries cannot change any metric.
* A target absent from the flagged list ("not found in pool") has rank None: hit 0, RR 0, nDCG 0.
* hit@k = 1 when midrank <= k.  RR = 1 / midrank.
* nDCG@k: gain 2**rel - 1, discount 1 / log2(rank + 1) evaluated at the (possibly fractional) midrank;
  only items with midrank <= k contribute; the ideal ranking places ALL relevant items (found or not)
  at positions 1, 2, ... by descending relevance, truncated at k.
"""
from __future__ import annotations

import math
import statistics
from collections.abc import Hashable, Mapping, Sequence

HIT_KS = (1, 3, 5, 10, 20)
TIE_RULE = 'midrank'


def midranks(keys: Sequence) -> list[float]:
    """Midrank of each key (1-based; ascending keys rank first), in input order."""
    order = sorted(range(len(keys)), key=lambda i: keys[i])
    out = [0.0] * len(keys)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and keys[order[j + 1]] == keys[order[i]]:
            j += 1
        mid = (i + j + 2) / 2  # positions i+1 .. j+1
        for t in range(i, j + 1):
            out[order[t]] = mid
        i = j + 1
    return out


def rank_map(flagged: Mapping[Hashable, object]) -> dict[Hashable, float]:
    """item -> midrank, for {item: sort_key}."""
    items = list(flagged)
    return dict(zip(items, midranks([flagged[i] for i in items]), strict=True))


def hit_at_k(rank: float | None, k: int) -> int:
    return int(rank is not None and rank <= k)


def reciprocal_rank(rank: float | None) -> float:
    return 0.0 if rank is None else 1.0 / rank


def _dcg(items: Sequence[tuple[float, int]], k: int) -> float:
    return math.fsum((2 ** rel - 1) / math.log2(rank + 1) for rank, rel in items if rank <= k)


def ndcg_at_k(ranked: Sequence[tuple[float | None, int]], k: int = 10) -> float | None:
    """`ranked` = (midrank or None if not flagged, relevance) for EVERY relevant item. None if no gain."""
    ideal = [(float(p + 1), rel) for p, rel in enumerate(sorted((r for _, r in ranked), reverse=True))]
    denom = _dcg(ideal, k)
    if denom <= 0:
        return None
    return _dcg([(rk, rel) for rk, rel in ranked if rk is not None], k) / denom


def pair_metrics(rank: float | None, relevant: Sequence[tuple[float | None, int]] | None = None,
                 ks: Sequence[int] = HIT_KS, ndcg_k: int = 10) -> dict:
    """Per-pair observation for the fix item. `relevant` defaults to just the fix with relevance 2."""
    rel = [(rank, 2)] if relevant is None else list(relevant)
    out: dict = {f'hit@{k}': float(hit_at_k(rank, k)) for k in ks}
    out['rr'] = reciprocal_rank(rank)
    out['ndcg'] = ndcg_at_k(rel, ndcg_k)
    out['rank'] = rank
    return out


def summarise(ranks: Sequence[float | None], pool_sizes: Sequence[int] | None = None,
              ks: Sequence[int] = HIT_KS) -> dict:
    """Point summary over pairs (per source and population; never pool populations)."""
    n = len(ranks)
    found = [r for r in ranks if r is not None]
    return {
        'pairs': n,
        'found_in_pool': len(found),
        'pool_median': None if not pool_sizes else statistics.median(pool_sizes),
        'hit_at': {k: (math.fsum(hit_at_k(r, k) for r in ranks) / n if n else None) for k in ks},
        'mrr': math.fsum(reciprocal_rank(r) for r in ranks) / n if n else None,
        'mean_rank': math.fsum(found) / len(found) if found else None,
        'tie_rule': TIE_RULE,
    }
