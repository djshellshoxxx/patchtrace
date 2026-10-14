"""Inter-annotator agreement on A (spec §5.6): raw agreement, Cohen's kappa, lineage-bootstrap CI.

The same functions serve test-retest (one annotator, two passes >= 14 days apart) when only one annotator
exists (decision O2); in that case claims are capped at L1 bands by the gate evaluator.
"""
from __future__ import annotations

import math
from collections.abc import Sequence

from .common import det_uniform

KAPPA_MIN, KAPPA_LO_MIN, RAW_MIN = 0.80, 0.70, 0.95
# Spec §5.6 minimums (300 items overall, 60 per reported subtype) plus the lineage-bootstrap floor: a kappa from
# fewer items or fewer than 30 lineages is reported but can never pass (the interval is anti-conservative).
MIN_ITEMS, MIN_SUBTYPE_ITEMS, MIN_GROUPS = 300, 60, 30


def raw_agreement(a: Sequence[str], b: Sequence[str]) -> float:
    if len(a) != len(b) or not a:
        raise ValueError('paired, non-empty label lists required')
    return sum(x == y for x, y in zip(a, b, strict=True)) / len(a)


def cohen_kappa(a: Sequence[str], b: Sequence[str]) -> float | None:
    """None when chance agreement is 1 (a single category used by both): kappa is undefined."""
    po = raw_agreement(a, b)
    n = len(a)
    cats = sorted(set(a) | set(b))
    pe = math.fsum((a.count(c) / n) * (b.count(c) / n) for c in cats)
    return None if pe >= 1 else (po - pe) / (1 - pe)


def kappa_ci(a: Sequence[str], b: Sequence[str], groups: Sequence[str] | None = None, *, b_count: int = 2000,
             seed=11, alpha: float = 0.05) -> dict:
    """Percentile bootstrap over groups (lineages) when given, else over items."""
    groups = list(groups) if groups is not None else [str(i) for i in range(len(a))]
    by_g: dict[str, list[int]] = {}
    for i, g in enumerate(groups):
        by_g.setdefault(g, []).append(i)
    gs = sorted(by_g)
    vals = []
    for rep in range(b_count):
        idx = [i for j in range(len(gs)) for i in by_g[gs[int(det_uniform(seed, 'kappa', rep, j) * len(gs))]]]
        k = cohen_kappa([a[i] for i in idx], [b[i] for i in idx])
        if k is not None:
            vals.append(k)
    vals.sort()
    point = cohen_kappa(a, b)
    if not vals:
        return {'kappa': point, 'lo': None, 'hi': None, 'raw': raw_agreement(a, b)}
    return {'kappa': point, 'lo': vals[int(alpha / 2 * len(vals))],
            'hi': vals[min(len(vals) - 1, int((1 - alpha / 2) * len(vals)))], 'raw': raw_agreement(a, b)}


def agreement_report(pairs: Sequence[tuple[str, str, str, str | None]], *, b_count: int = 2000, seed=11) -> dict:
    """pairs: (label_a, label_b, group, subtype). Overall and per-subtype statistics plus the pass rule."""
    def block(items):
        a, b, g = [p[0] for p in items], [p[1] for p in items], [p[2] for p in items]
        out = kappa_ci(a, b, g, b_count=b_count, seed=seed)
        out['n'] = len(items)
        out['n_groups'] = len(set(g))
        return out
    overall = block(pairs)
    subtypes = {}
    for st in sorted({p[3] for p in pairs if p[3]}):
        items = [p for p in pairs if p[3] == st]
        subtypes[st] = block(items)
        subtypes[st]['insufficient'] = len(items) < MIN_SUBTYPE_ITEMS
    reasons = []
    if overall['n'] < MIN_ITEMS:
        reasons.append(f'only {overall["n"]} double-labelled items (< {MIN_ITEMS})')
    if overall['n_groups'] < MIN_GROUPS:
        reasons.append(f'only {overall["n_groups"]} lineages (< {MIN_GROUPS}): interval is anti-conservative')
    if overall['kappa'] is None:
        reasons.append('kappa undefined (a single category)')
    ok = (not reasons and overall['kappa'] >= KAPPA_MIN and overall['raw'] >= RAW_MIN
          and overall['lo'] is not None and overall['lo'] >= KAPPA_LO_MIN)
    return {'overall': overall, 'subtypes': subtypes, 'meets_threshold': ok, 'insufficient_reasons': reasons}
