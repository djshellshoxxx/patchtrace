"""AV-4: rank scoring of an engine's changed-function candidates against a frozen case manifest.

Per case: is the expected function in the top k candidates, and at what rank? A `no_change` case is correct only
when the engine reports no candidates (anything listed is a false positive). Cases without verified facts or
an engine result are BLOCKED and excluded from the accuracy count but reported; they are never counted as hits.
Generic aggregates contain one explicit layer/stratum/holdout cohort. Confidence bounds are withheld for
repeated or missing scored project identities; distinct labels still require justified independence.
"""
from __future__ import annotations

from typing import Any

from .cases import LAYERS
from .sample_size import lower_bound


def require_cohort(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Refuse a pooled claim across incompatible experimental cohorts."""
    if not cases:
        return {'layer': None, 'stratum': None, 'holdout': None}
    cohorts = set()
    for case in cases:
        layer, stratum, holdout = (case.get(key) for key in ('layer', 'stratum', 'holdout'))
        if (not isinstance(layer, str) or layer not in LAYERS
                or not isinstance(stratum, str) or not stratum.strip()
                or not isinstance(holdout, bool)):
            raise ValueError('a scoring cohort needs an explicit layer, stratum and boolean holdout')
        cohorts.add((layer, stratum, holdout))
    if len(cohorts) != 1:
        raise ValueError('mixed layer, stratum or holdout cohorts cannot be aggregated; use separate frozen cohorts')
    layer, stratum, holdout = next(iter(cohorts))
    return {'layer': layer, 'stratum': stratum, 'holdout': holdout}


def conditional_bound(scored: list[dict[str, Any]], hits: int, alpha: float = 0.05) -> dict[str, Any]:
    """Do not treat repeated cases as independent project trials or invent a project-success rule."""
    projects = [case.get('project') for case in scored]
    known = {p for p in projects if isinstance(p, str) and p.strip()}
    if not scored:
        reason = 'no_scored_cases'
    elif any(not isinstance(p, str) or not p.strip() for p in projects):
        reason = 'missing_project'
    elif len(known) != len(scored):
        reason = 'repeated_projects'
    elif len({case.get('stratum') for case in scored}) != 1:
        reason = 'mixed_strata'
    else:
        reason = 'conditional_on_independence'
    bound = round(lower_bound(hits, len(scored), alpha), 3) if reason == 'conditional_on_independence' else None
    return {'lower_bound': bound, 'bound_reason': reason, 'scored_projects': len(known)}


def score_case(case: dict[str, Any], candidates: list[str] | None, k: int = 5) -> dict[str, Any]:
    if k < 1:
        raise ValueError('k must be >= 1')
    if candidates is not None and (not isinstance(candidates, list)
                                   or not all(isinstance(c, str) for c in candidates)):
        raise ValueError(f'candidates for {case["id"]} must be a list of function names or null')
    if case.get('facts') != 'verified':
        return {'id': case['id'], 'outcome': 'BLOCKED', 'rank': None, 'reason': 'facts_not_verified'}
    if candidates is None:
        return {'id': case['id'], 'outcome': 'BLOCKED', 'rank': None}
    exp = case['expected']
    if exp.get('no_change') is True:
        return {'id': case['id'], 'outcome': 'HIT' if not candidates else 'FALSE_POSITIVE', 'rank': None,
                'reported': len(candidates)}
    # `accept` lists other functions the same fix changed (or a post-patch rename); the best-ranked listed name counts.
    names = [exp['function'], *exp.get('accept', [])]
    ranks = [candidates.index(n) + 1 for n in names if n in candidates]
    rank = min(ranks) if ranks else None
    return {'id': case['id'], 'outcome': 'HIT' if rank is not None and rank <= k else 'MISS', 'rank': rank}


def score_run(manifest: dict[str, Any], results: dict[str, list[str] | None], k: int = 5, alpha: float = 0.05
              ) -> dict[str, Any]:
    cohort = require_cohort(manifest['cases'])
    ids = {c['id'] for c in manifest['cases']}
    unknown = sorted(set(results) - ids)
    if unknown:
        raise ValueError(f'results name cases not in the manifest: {unknown}')
    rows = [score_case(c, results.get(c['id']), k) for c in manifest['cases']]
    scored = [r for r in rows if r['outcome'] != 'BLOCKED']
    hits = sum(r['outcome'] == 'HIT' for r in scored)
    ranks = sorted(r['rank'] for r in scored if r['rank'])
    scored_cases = [c for c, r in zip(manifest['cases'], rows, strict=True) if r['outcome'] != 'BLOCKED']
    return {
        **cohort,
        'k': k, 'cases': len(rows), 'scored': len(scored), 'blocked': len(rows) - len(scored), 'hits': hits,
        'misses': sum(r['outcome'] == 'MISS' for r in scored),
        'false_positives': sum(r['outcome'] == 'FALSE_POSITIVE' for r in scored),
        'top1': sum(1 for r in ranks if r == 1),
        **conditional_bound(scored_cases, hits, alpha),
        'rows': rows,
        'caveat': 'a bound is conditional on justified independent projects under the frozen protocol; '
                  'distinct project labels alone do not prove independence. Blocked cases are excluded.',
    }
