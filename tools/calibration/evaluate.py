"""Per-profile evaluation with lineage-cluster CIs (spec §9.1-9.2, §12 inputs for the gate evaluator)."""
from __future__ import annotations

import math
from collections.abc import Mapping, Sequence

from . import metrics as M
from .bootstrap import (
    MAX_UNDEFINED_SHARE,
    cluster_bootstrap,
    cluster_bootstrap_many,
    coverage_stat,
    fdr_at_coverage,
    fdr_reduction_stat,
    group_rows,
    jackknife,
    paired_delta,
    precision_stat,
)
from .common import Row
from .ece_null import NULL_SIMS, debiased_l2, ece_null, ece_null_summary, residual_rho
from .guards import RowError, validate_preds
from .ood_fit import risk_ratio
from .threshold import evaluate_frozen_tau

STRATUM_MIN_N = 200


def _arrays(rows, preds):
    return [preds[r.id] for r in rows], [r.y for r in rows], [r.w for r in rows]


def _metric(fn):
    def stat(rows, preds):
        if not rows:
            return None
        p, y, w = _arrays(rows, preds)
        return fn(p, y, w)
    return stat


def evaluate_profile(rows: Sequence[Row], preds: Mapping[str, float], *, tau: float | None,
                     tau_low: float | None = None, baselines: Mapping[str, Mapping[str, float]] | None = None,
                     ood_hard: Mapping[str, bool] | None = None, b_count: int = 2000, seed=21,
                     with_slope_ci: bool = True, null_sims: int = NULL_SIMS) -> dict:
    nat = sorted((r for r in rows if r.stratum == 'natural'), key=lambda r: r.id)
    if not nat:
        raise RowError('no natural-stratum rows to evaluate')
    validate_preds(nat, preds)
    p, y, w = _arrays(nat, preds)
    out: dict = {'n_natural': len(nat), 'n_groups': len(group_rows(nat)),
                 'prevalence': M.prevalence(y, w), 'tau': tau, 'tau_low': tau_low}
    stats = {'brier': _metric(M.brier), 'brier_skill': _metric(M.brier_skill), 'ece': _metric(M.ece),
             'ece_eqmass10': _metric(M.ece_equal_mass), 'auc': _metric(M.auc), 'logloss': _metric(M.logloss)}
    for name, fn in stats.items():
        out[name] = cluster_bootstrap(nat, preds, fn, b_count, (seed, name), max_undefined=MAX_UNDEFINED_SHARE)
    null = ece_null(p, w, [r.group for r in nat], rho=residual_rho(p, y, [r.group for r in nat]),
                    sims=null_sims, seed=(seed, 'ece-null'))
    out['ece_null'] = ece_null_summary(out['ece']['point'], out['ece']['hi'], null)
    out['ece_l2_debiased'] = debiased_l2(p, y, w)
    if with_slope_ci:
        both = cluster_bootstrap_many(nat, preds, _metric(M.calib_slope_intercept), ('slope', 'intercept'),
                                      b_count, (seed, 'slope-intercept'), max_undefined=MAX_UNDEFINED_SHARE)
        out['slope'], out['intercept'] = both['slope'], both['intercept']
    else:
        slope, intercept = M.calib_slope_intercept(p, y, w)
        out['slope'], out['intercept'] = {'point': slope}, {'point': intercept}
    out['reliability_curve'] = M.reliability(p, y, w)
    out['coverage_precision_curve'] = M.downsample_curve(M.coverage_precision_curve(p, y, w, [r.abstain for r in nat]))
    if tau is not None:
        out['precision'] = cluster_bootstrap(nat, preds, precision_stat(tau), b_count, (seed, 'prec'),
                                           max_undefined=MAX_UNDEFINED_SHARE)
        out['coverage'] = cluster_bootstrap(nat, preds, coverage_stat(tau), b_count, (seed, 'cov'),
                                          max_undefined=MAX_UNDEFINED_SHARE)
        out['jackknife_precision'] = jackknife(nat, preds, precision_stat(tau))
        out['ltt'] = evaluate_frozen_tau(rows, preds, tau)
        if baselines:
            cov = out['coverage']['point']
            fdrs = {k: fdr_at_coverage(nat, b, cov) for k, b in sorted(baselines.items())}
            best = min((k for k in fdrs if fdrs[k] is not None), key=lambda k: (fdrs[k], k), default=None)
            if best is not None:
                delta = paired_delta(nat, preds, baselines[best], fdr_reduction_stat(tau), b_count, (seed, 'h4'))
                rel = None if not fdrs[best] or delta['point'] is None else delta['point'] / fdrs[best]
                out['fdr_reduction'] = dict(delta, baseline=best, baseline_fdr=fdrs[best], relative=rel)
        strata = {}
        for key in sorted({r.subtype or r.stratum for r in rows}):
            members = [r for r in rows if (r.subtype or r.stratum) == key]
            ci = cluster_bootstrap(members, preds, precision_stat(tau), b_count, (seed, 'stratum', key))
            n_w = math.fsum(r.w for r in members)
            strata[key] = {'n': len(members), 'n_weighted': n_w, 'precision': ci,
                           'insufficient': n_w < STRATUM_MIN_N}
        out['strata'] = strata
        los = [s['precision']['lo'] for s in strata.values() if not s['insufficient']]
        out['strata_min_lo'] = None if any(v is None for v in los) or not los else min(los)
    if ood_hard is not None:
        # error = misclassification at p = 0.5; flagged rows must err more often than unflagged ones
        def rr(rs, pr):
            return risk_ratio([bool(ood_hard.get(r.id)) for r in rs], [int((pr[r.id] >= 0.5) != bool(r.y)) for r in rs],
                              [r.w for r in rs])
        flagged = [bool(ood_hard.get(r.id)) for r in nat]
        out['ood_flag_rate'] = sum(flagged) / len(flagged) if flagged else None
        out['ood_risk_ratio'] = cluster_bootstrap(nat, preds, rr, b_count, (seed, 'ood'))
        out['ood_risk_ratio_lo'] = out['ood_risk_ratio']['lo']
    return out
