"""AV-4: rank scoring of an engine's changed-function candidates against a frozen case manifest.

Per case: is the expected function in the top k candidates, and at what rank? A `no_change` case is correct only
when the engine reports no candidates (anything listed is a false positive). Cases the engine did not run are
BLOCKED and excluded from the accuracy count but reported; they are never counted as hits. Aggregates use the
exact lower bound over distinct projects' cases as supplied (the caller decides independence; see cases.summary).
"""
from __future__ import annotations

from typing import Any

from .sample_size import lower_bound


def score_case(case: dict[str, Any], candidates: list[str] | None, k: int = 5) -> dict[str, Any]:
    if k < 1:
        raise ValueError('k must be >= 1')
    exp = case['expected']
    if candidates is None:
        return {'id': case['id'], 'outcome': 'BLOCKED', 'rank': None}
    if not isinstance(candidates, list) or not all(isinstance(c, str) for c in candidates):
        raise ValueError(f'candidates for {case["id"]} must be a list of function names or null')
    if exp.get('no_change') is True:
        return {'id': case['id'], 'outcome': 'HIT' if not candidates else 'FALSE_POSITIVE', 'rank': None,
                'reported': len(candidates)}
    rank = candidates.index(exp['function']) + 1 if exp['function'] in candidates else None
    return {'id': case['id'], 'outcome': 'HIT' if rank is not None and rank <= k else 'MISS', 'rank': rank}


def score_run(manifest: dict[str, Any], results: dict[str, list[str] | None], k: int = 5, alpha: float = 0.05
              ) -> dict[str, Any]:
    ids = {c['id'] for c in manifest['cases']}
    unknown = sorted(set(results) - ids)
    if unknown:
        raise ValueError(f'results name cases not in the manifest: {unknown}')
    rows = [score_case(c, results.get(c['id']), k) for c in manifest['cases']]
    scored = [r for r in rows if r['outcome'] != 'BLOCKED']
    hits = sum(r['outcome'] == 'HIT' for r in scored)
    ranks = sorted(r['rank'] for r in scored if r['rank'])
    return {
        'k': k, 'cases': len(rows), 'scored': len(scored), 'blocked': len(rows) - len(scored), 'hits': hits,
        'misses': sum(r['outcome'] == 'MISS' for r in scored),
        'false_positives': sum(r['outcome'] == 'FALSE_POSITIVE' for r in scored),
        'top1': sum(1 for r in ranks if r == 1),
        'lower_bound': round(lower_bound(hits, len(scored), alpha), 3) if scored else None,
        'rows': rows,
        'caveat': 'bound assumes the scored cases are independent; blocked cases are not counted as hits',
    }
