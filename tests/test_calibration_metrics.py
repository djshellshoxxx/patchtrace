"""Metrics, exact statistics, Learn-then-Test thresholds, the ECE null simulation and the lineage bootstrap
(calibration-corpus-and-model.md §9, amended). Synthetic data only."""
from __future__ import annotations

import math
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.calibration import metrics as M  # noqa: E402
from tools.calibration.bootstrap import (  # noqa: E402
    cluster_bootstrap,
    cluster_bootstrap_many,
    fdr_at_coverage,
    fdr_reduction_stat,
    jackknife,
    paired_delta,
    precision_stat,
)
from tools.calibration.common import Row, det_uniform  # noqa: E402
from tools.calibration.ece_null import debiased_l2, ece_null, ece_null_summary, residual_rho  # noqa: E402
from tools.calibration.stats import (  # noqa: E402
    binom_cdf,
    binom_draw,
    design_effect,
    effective_n,
    icc_anova,
    kish_n,
    ltt_start_n,
    zero_error_min_n,
)
from tools.calibration.threshold import (  # noqa: E402
    choose_tau,
    choose_tau_low,
    evaluate_frozen_tau,
    ltt_pvalue,
)


def test_brier_reliability_ece_hand_computed():
    assert M.brier([0.9, 0.2], [1, 0], [1, 1]) == pytest.approx(0.025)
    p, y, w = [0.9, 0.9, 0.1, 0.1], [1, 0, 0, 0], [1, 1, 1, 1]
    assert M.ece(p, y, w) == pytest.approx(0.25)
    rel = M.reliability(p, y, w)
    assert len(rel) == 15 and rel[13]['n'] == 2 and rel[13]['acc'] == 0.5 and rel[0]['conf'] is None
    assert M.bin_index(1.0) == 14 and M.bin_index(0.0) == 0 and M.bin_index(0.999999) == 14
    assert M.ece([0.5], [1], [1]) == pytest.approx(0.5)
    assert M.brier_skill([0.5, 0.5], [1, 0], [1, 1]) == pytest.approx(0.0)
    assert M.brier_skill([0.5], [1], [1]) is None
    assert M.ece_equal_mass(p, y, w, bins=2) == pytest.approx(0.25)
    assert M.logloss([0.5, 0.5], [1, 0], [1, 1]) == pytest.approx(math.log(2))


def test_weights_act_like_replication_in_metrics():
    p, y = [0.8, 0.3, 0.6], [1, 0, 0]
    rep_p, rep_y = [0.8, 0.8, 0.3, 0.6], [1, 1, 0, 0]
    for fn in (M.brier, M.ece, M.logloss, M.auc):
        assert fn(p, y, [2, 1, 1]) == pytest.approx(fn(rep_p, rep_y, [1, 1, 1, 1]))


def test_auc_and_ties():
    assert M.auc([0.1, 0.4, 0.35, 0.8], [0, 0, 1, 1], [1, 1, 1, 1]) == pytest.approx(0.75)
    assert M.auc([0.5, 0.5], [0, 1], [1, 1]) == pytest.approx(0.5)
    assert M.auc([0.5], [1], [1]) is None


def test_coverage_precision_curve_ties_and_monotone():
    pts = M.coverage_precision_curve([0.9, 0.9, 0.5, 0.2], [1, 0, 1, 1], [1, 1, 1, 1], [False, False, False, True])
    assert [(pt['tau'], pt['coverage'], pt['precision']) for pt in pts] == [(0.9, 0.5, 0.5),
                                                                           (0.5, 0.75, pytest.approx(2 / 3))]
    covs = [pt['coverage'] for pt in pts]
    assert covs == sorted(covs)  # abstained row counts against coverage, never reaches 1
    assert M.precision_at([0.9, 0.5], [1, 0], [1, 1], 0.6) == 1.0 and M.precision_at([0.1], [1], [1], 0.6) is None
    assert M.npv_at([0.9, 0.1], [1, 0], [1, 1], 0.2) == 1.0
    assert M.downsample_curve(list(range(1000)), 200)[-1] == 999


def test_calibration_slope_intercept_identity_for_calibrated_predictions():
    p = [det_uniform('cs', i) * 0.9 + 0.05 for i in range(6000)]
    y = [int(det_uniform('cs-y', i) < pi) for i, pi in enumerate(p)]
    slope, intercept = M.calib_slope_intercept(p, y, [1.0] * len(p))
    assert slope == pytest.approx(1.0, abs=0.12) and intercept == pytest.approx(0.0, abs=0.12)


# ---- exact statistics ------------------------------------------------------------------------------------

def test_binomial_cdf_exact_small_cases():
    assert binom_cdf(0, 59, 0.05) == pytest.approx(0.95 ** 59)
    exact = sum(math.comb(20, i) * 0.3 ** i * 0.7 ** (20 - i) for i in range(6))
    assert binom_cdf(5, 20, 0.3) == pytest.approx(exact, rel=1e-12)
    assert binom_cdf(-1, 5, 0.5) == 0.0 and binom_cdf(5, 5, 0.5) == 1.0
    assert zero_error_min_n(0.05, 0.05) == 59


@pytest.mark.parametrize('n, p', [(30, 0.1), (400, 0.97), (5000, 0.5), (12, 0.0), (12, 1.0)])
def test_binomial_draw_mean(n, p):
    draws = [binom_draw(n, p, 'bd', n, i) for i in range(600)]
    assert all(0 <= d <= n for d in draws)
    assert sum(draws) / len(draws) == pytest.approx(n * p, abs=max(0.5, 0.05 * math.sqrt(n * p * (1 - p)) * 4))


def test_icc_design_effect_effective_n():
    groups = ['a'] * 5 + ['b'] * 5 + ['c'] * 5
    assert icc_anova(groups, [1.0] * 5 + [0.0] * 5 + [1.0] * 5, undefined=-1) == 1.0
    assert icc_anova(groups, [1.0] * 15, undefined=-1) == -1  # no variance: undefined
    mixed = [float(det_uniform('icc', i) < 0.5) for i in range(300)]
    assert icc_anova([str(i % 30) for i in range(300)], mixed, undefined=-1) < 0.1
    assert design_effect(['a', 'a', 'b', 'b'], 1.0) == 2.0 and design_effect(['a', 'b'], 1.0) == 1.0
    assert kish_n([1.0, 1.0, 2.0]) == pytest.approx(16 / 6)
    assert effective_n(['a', 'a', 'b', 'b'], [1.0] * 4, 1.0) == pytest.approx(2.0)


# ---- Learn-then-Test thresholds ---------------------------------------------------------------------------

def rows_from(p, y, groups=None, w=None, stratum='natural'):
    groups = groups or [f'L{i % 40:02d}' for i in range(len(p))]
    w = w or [1.0] * len(p)
    rows = [Row(f'r{i:05d}', groups[i], (p[i],), y[i], w[i], stratum) for i in range(len(p))]
    return rows, {r.id: p[i] for i, r in enumerate(rows)}


def calibrated(n=4000, seed='ltt', lo=0.3):
    p = [round(lo + (1 - lo) * det_uniform(seed, i), 6) for i in range(n)]
    y = [int(det_uniform(seed, 'y', i) < pi) for i, pi in enumerate(p)]
    return p, y


def test_choose_tau_certifies_on_calibrated_scores_and_truth_meets_target():
    p, y = calibrated(lo=0.85)
    rows, preds = rows_from(p, y)
    res = choose_tau(rows, preds)
    assert res is not None and res['p_value'] <= 0.05
    accepted = [pi for pi in p if pi >= res['tau']]
    assert sum(accepted) / len(accepted) >= 0.95  # TRUE precision of the certified set (scores are calibrated)
    assert res['tau'] >= 0.9


def test_choose_tau_none_for_uninformative_scores():
    p = [round(det_uniform('u', i), 6) for i in range(2000)]
    y = [int(det_uniform('u-y', i) < 0.7) for i in range(2000)]
    rows, preds = rows_from(p, y)
    assert choose_tau(rows, preds) is None


def test_fixed_sequence_stops_at_first_failure():
    # Strict region has 20 % errors; a looser threshold would look fine cumulatively. A scan would pick it,
    # fixed-sequence LTT must stop at the first non-rejection and certify nothing.
    p = [0.995] * 600 + [0.8] * 5000
    y = [0] * 120 + [1] * 480 + [1] * 5000
    rows, preds = rows_from(p, y)
    assert choose_tau(rows, preds, rho=0.0) is None
    cumulative = (480 + 5000) / 5600
    assert cumulative > 0.95


def test_ltt_start_size_and_label_free_sequence_rules():
    assert ltt_start_n(0.05, 0.05) > zero_error_min_n(0.05, 0.05)
    # 10 strict items with an error are below the start size: skipped (not a stop) using scores only.
    p = [0.999] * 10 + [0.97] * 1000
    y = [0] + [1] * 9 + [1] * 990 + [0] * 10
    rows, preds = rows_from(p, y)
    res = choose_tau(rows, preds, rho=0.0)
    # Looser grid points select the same 1010 rows: no extrapolation below the lowest observed score.
    assert res is not None and res['tau'] == 0.97


def test_clustered_errors_reduce_effective_n():
    p = [0.97] * 400
    y = [0 if i < 12 else 1 for i in range(400)]
    spread = [f'L{i % 40}' for i in range(400)]
    clustered = ['L0' if i < 12 else f'L{1 + i % 39}' for i in range(400)]
    rows_s, preds = rows_from(p, y, spread)
    rows_c, _ = rows_from(p, y, clustered)
    test_s = ltt_pvalue(rows_s, lambda r: 1 - r.y, 0.05, rho=0.0)
    from tools.calibration.threshold import lineage_rho
    rho_c = lineage_rho(rows_c)
    test_c = ltt_pvalue(rows_c, lambda r: 1 - r.y, 0.05, rho=rho_c)
    assert rho_c > 0.1 and test_c['n_eff'] < test_s['n_eff'] and test_c['p_value'] > test_s['p_value']


def test_tau_low_and_frozen_evaluation():
    p = [0.02] * 600 + [0.5] * 300 + [0.99] * 600
    y = [0] * 595 + [1] * 5 + [1, 0] * 150 + [1] * 600
    rows, preds = rows_from(p, y)
    tau = choose_tau(rows, preds)
    low = choose_tau_low(rows, preds, tau['tau'] if tau else None)
    assert low is not None and low['tau_low'] < 0.5 and low['npv'] >= 0.9
    frozen = evaluate_frozen_tau(rows, preds, 0.99)
    assert frozen['certified'] and frozen['k'] == 0 and frozen['n'] <= 600  # design effect may shrink n


# ---- ECE null simulation ----------------------------------------------------------------------------------

def test_ece_null_explains_plugin_bias_for_calibrated_model_and_flags_miscalibration():
    p, y = calibrated(3000, 'ece')
    groups = [f'L{i % 50}' for i in range(3000)]
    w = [1.0] * 3000
    obs = M.ece(p, y, w)
    null = ece_null(p, w, groups, rho=residual_rho(p, y, groups), sims=400, seed='t')
    good = ece_null_summary(obs, obs + 0.01, null)
    assert null['null_mean'] > 0.005            # plug-in ECE of a perfect model is not zero
    assert abs(good['excess']) < 0.01 and good['p_value'] > 0.05
    shifted = [min(1.0, pi + 0.12) for pi in p]  # overconfident by 12 points
    bad = ece_null_summary(M.ece(shifted, y, w), None, ece_null(shifted, w, groups, rho=0.0, sims=400, seed='t'))
    assert bad['excess'] > 0.03 and bad['p_value'] < 0.01
    assert debiased_l2(p, y, w) < 0.02 < debiased_l2(shifted, y, w)


def test_ece_null_uses_clustered_effective_n():
    p, y = calibrated(2000, 'ece2')
    w = [1.0] * 2000
    groups = [f'L{i % 20}' for i in range(2000)]
    iid = ece_null(p, w, groups, rho=0.0, sims=300, seed='c')
    clustered = ece_null(p, w, groups, rho=0.5, sims=300, seed='c')
    assert clustered['null_mean'] > iid['null_mean']
    assert sum(b['n_eff'] for b in clustered['bins']) < sum(b['n_eff'] for b in iid['bins'])
    assert ece_null(p, w, groups, rho=0.0, sims=300, seed='c')['values'] == iid['values']  # deterministic


# ---- lineage bootstrap ------------------------------------------------------------------------------------

def test_cluster_bootstrap_deterministic_keeps_groups_whole_and_counts_undefined():
    rows = [Row(f'{g}-{i}', g, (0.0,), i % 2, 1.0) for g in ('a', 'b', 'c') for i in range(3)]
    preds = {r.id: 0.5 for r in rows}
    seen = []

    def stat(rs, _):
        counts = {}
        for r in rs:
            counts[r.group] = counts.get(r.group, 0) + 1
        seen.append(counts)
        return None if counts.get('a', 0) == 0 else float(len(rs))
    out = cluster_bootstrap(rows, preds, stat, 200, 's')
    assert all(c % 3 == 0 for counts in seen for c in counts.values())  # whole lineages only
    assert out['undefined'] > 0 and out['anti_conservative'] is True
    again = cluster_bootstrap(rows, preds, stat, 200, 's')
    assert {k: again[k] for k in ('lo', 'hi', 'undefined')} == {k: out[k] for k in ('lo', 'hi', 'undefined')}


def test_bootstrap_helpers():
    p, y = calibrated(1200, 'bs')
    rows, preds = rows_from(p, y)
    ci = cluster_bootstrap(rows, preds, precision_stat(0.9), 300, 'b')
    assert ci['lo'] <= ci['point'] <= ci['hi'] and ci['anti_conservative'] is False
    many = cluster_bootstrap_many(rows, preds, lambda rs, pr: M.calib_slope_intercept(
        [pr[r.id] for r in rs], [r.y for r in rs], [r.w for r in rs]), ('slope', 'intercept'), 100, 'm')
    assert many['slope']['lo'] <= 1.0 <= many['slope']['hi']
    same = paired_delta(rows, preds, preds, fdr_reduction_stat(0.9), 100, 'pd')
    assert same['point'] == pytest.approx(0.0) and same['lo'] == pytest.approx(0.0, abs=1e-12)
    jk = jackknife(rows, preds, precision_stat(0.9))
    assert jk['worst'] <= ci['point'] and jk['max_influence'] >= 0
    assert fdr_at_coverage(rows, preds, 1.0) == pytest.approx(1 - sum(y) / len(y))
