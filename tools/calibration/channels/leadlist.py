"""Lead-list pack: does one detector earn a place in the default profile (LBL s7.6 flow, conditions i-iii)?

Hit@k is reported with and without the detector, separately; the gate reads the paired delta, never a pooled number.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from ..evalcore import boot, rank
from .common import EMPTY, PackReport, interval, lineage_count, observations, ratio

NON_INFERIORITY_MARGIN = -0.02
AA_FALSE_LEAD_MAX = 0.001
HIT_K = 10
Key = int | float | str


@dataclass(frozen=True)
class LeadPair:
    pair_id: str
    lineage: str
    stratum: str
    fix: str  # the changed function that is the fix
    truth: frozenset[str]  # every truth-changed function in the pool
    with_keys: Mapping[str, Key]  # lead-list sort keys with the detector (smaller = more suspicious)
    without_keys: Mapping[str, Key]
    flagged: frozenset[str]  # functions the detector flagged


@dataclass(frozen=True)
class LeadAA:
    pair_id: str
    lineage: str
    flagged: int  # false leads the detector raised on an A/A pair
    pool: int


def _hit(keys: Mapping[str, Key], fix: str, k: int) -> float:
    return float(rank.hit_at_k(rank.rank_map(keys).get(fix), k))


def _hits(pairs: Sequence[LeadPair], with_detector: bool, k: int) -> boot.Obs:
    return observations(pairs, lambda p: _hit(p.with_keys if with_detector else p.without_keys, p.fix, k))


def _precision(p: LeadPair) -> float | None:
    return ratio(len(p.flagged & p.truth), len(p.flagged))


def _base_rate(p: LeadPair) -> float | None:
    return ratio(len(p.truth), len(p.without_keys))


def _delta(a: boot.Obs, b: boot.Obs, name: str, b_count: int) -> tuple[dict, boot.Interval | None]:
    if not a or set(a) != set(b):
        return dict(EMPTY), None
    d = boot.paired_delta_bootstrap(a, b, b_count, seed=f'channels:leadlist:{name}')
    return {'point': d.point, 'lo': d.lo, 'hi': d.hi, 'n': len(a), 'anti_conservative': d.anti_conservative,
            'undefined': d.undefined}, d


def _hit_total(pairs: Sequence[LeadPair], with_detector: bool) -> float:
    return sum(v for _, v in _hits(pairs, with_detector, HIT_K).values())


def _slice_improves(pairs: Sequence[LeadPair]) -> bool | None:
    if not pairs:
        return None
    for s in sorted({p.stratum for p in pairs}):
        sub = [p for p in pairs if p.stratum == s]
        if _hit_total(sub, True) > _hit_total(sub, False):
            return True
    return False


def score(pairs: Sequence[LeadPair], aa: Sequence[LeadAA], b_count: int = boot.B_COUNT) -> PackReport:
    metrics = {}
    for k in rank.HIT_KS:
        metrics[f'hit@{k}:with'] = interval(_hits(pairs, True, k), 'leadlist', f'with{k}', b_count)
        metrics[f'hit@{k}:without'] = interval(_hits(pairs, False, k), 'leadlist', f'without{k}', b_count)
    flagged = [p for p in pairs if p.flagged]
    metrics['precision_minus_base'], d_prec = _delta(
        observations(flagged, _precision), observations(flagged, _base_rate), 'precision', b_count)
    metrics['hit@10_delta'], d_hit = _delta(_hits(pairs, True, HIT_K), _hits(pairs, False, HIT_K), 'hit10', b_count)
    aa_rate = ratio(sum(a.flagged for a in aa), sum(a.pool for a in aa))
    conditions = {
        'precision_above_base': None if d_prec is None or d_prec.lo is None or d_prec.anti_conservative
        else d_prec.lo > 0,
        'aa_false_lead_rate': None if aa_rate is None else aa_rate <= AA_FALSE_LEAD_MAX,
        'hit10_non_inferior': None if d_hit is None else boot.non_inferior(d_hit, NON_INFERIORITY_MARGIN),
        'improves_a_slice': _slice_improves(pairs),
    }
    if any(c is False for c in conditions.values()):
        verdict = 'fail'
    else:
        verdict = 'pass' if all(c is True for c in conditions.values()) else 'inconclusive'
    return PackReport('leadlist', 'ok', pairs=len(pairs), lineages=lineage_count(pairs), metrics=metrics,
                      counts={'aa_flagged': sum(a.flagged for a in aa), 'aa_pool': sum(a.pool for a in aa)},
                      gate={**conditions, 'verdict': verdict})
