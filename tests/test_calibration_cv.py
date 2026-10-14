"""Grouped CV, leakage, simulations (a)-(e), gates and end-to-end determinism (calibration-corpus-and-model.md
§4, §8, §12, §13). Everything runs on generated worlds with known ground truth; no real-data claim."""
from __future__ import annotations

import datetime as dt
import math
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchtrace.calibration.artifact import canonical_json, parse_artifact  # noqa: E402
from patchtrace.calibration.policy import artifact_display_level  # noqa: E402
from tools.calibration import metrics as M  # noqa: E402
from tools.calibration.baselines import all_baselines, m0b  # noqa: E402
from tools.calibration.common import Row, det_uniform  # noqa: E402
from tools.calibration.cv import (  # noqa: E402
    CVConfig,
    CVError,
    _check_disjoint,
    group_folds_as_ids,
    grouped_kfold,
    nested_cv,
    random_kfold_ids,
    simple_cv,
    training_weights,
)
from tools.calibration.evaluate import evaluate_profile  # noqa: E402
from tools.calibration.fit import PromotionError, promote, run_pipeline, validated_ood  # noqa: E402
from tools.calibration.gates import evaluate_gates  # noqa: E402
from tools.calibration.lineage import CandidateIdentity, identity_groups, shared_identities  # noqa: E402
from tools.calibration.mathcore import logit, sigmoid  # noqa: E402
from tools.calibration.synth import make_world, subsample_by_class  # noqa: E402

FAST = CVConfig(k_outer=3, k_inner=3, c_grid=(1.0,))
CREATED = dt.date(2026, 10, 14)


def auc_of(rows, preds):
    return M.auc([preds[r.id] for r in rows], [r.y for r in rows], [1.0] * len(rows))


# ---- grouped folds -----------------------------------------------------------------------------------

def test_grouped_kfold_never_splits_a_group_is_deterministic_and_balanced():
    world = make_world(n_groups=23, per_group=7, beta=(0.0, 1.0), seed='folds')
    folds = grouped_kfold(world.rows, 5, 9)
    groups = {r.group for r in world.rows}
    assert set().union(*folds) == groups and sum(len(f) for f in folds) == len(groups)  # disjoint cover
    assert folds == grouped_kfold(list(reversed(world.rows)), 5, 9)
    sizes = [sum(1 for r in world.rows if r.group in f) for f in folds]
    assert max(sizes) - min(sizes) <= 14
    with pytest.raises(CVError):
        grouped_kfold(world.rows[:14], 5, 9)  # only 2 groups


def test_check_disjoint_refuses_shared_groups():
    a, b = Row('1', 'g', (0.0,), 1), Row('2', 'g', (0.0,), 0)
    with pytest.raises(CVError):
        _check_disjoint([a], [b])


def test_lineage_roles_and_folds_never_share_groups_in_nested_cv(monkeypatch):
    world = make_world(n_groups=12, per_group=10, beta=(0.3, 1.0), seed='nested')
    import tools.calibration.cv as cv
    seen = []
    original = cv.fit_base

    def spy(rows, c, scale):
        seen.append(frozenset(r.group for r in rows))
        return original(rows, c, scale)
    monkeypatch.setattr(cv, 'fit_base', spy)
    result = nested_cv(world.rows, FAST)
    # every base fit made while producing OOF predictions for an outer fold excludes that fold's lineages
    per_outer = len(seen) // len(result.folds)
    for i, test_groups in enumerate(result.folds):
        for train_groups in seen[i * per_outer:(i + 1) * per_outer]:
            assert not train_groups & test_groups


def test_planted_group_leakage_random_cv_is_optimistic_grouped_is_not():
    """Simulation (b): a lineage-level effect only memorisable through a per-lineage fingerprint."""
    world = make_world(n_groups=12, per_group=40, beta=(0.5, 0.8), seed='leak', group_sd=2.0, fingerprint_dim=12)
    rows = world.rows
    random_cv = simple_cv(rows, random_kfold_ids(rows, 4, 's'), 10.0)
    grouped_cv = simple_cv(rows, group_folds_as_ids(rows, grouped_kfold(rows, 4, 's')), 10.0)
    gap = auc_of(rows, random_cv) - auc_of(rows, grouped_cv)
    assert gap > 0.15  # preset: random-split CV materially more optimistic


def test_pure_group_world_nested_cv_shows_no_leak():
    world = make_world(n_groups=12, per_group=30, beta=(0.0, 0.0), seed='pure', group_sd=3.0, fingerprint_dim=12)
    nested = nested_cv(world.rows, CVConfig(k_outer=4, k_inner=3, c_grid=(10.0,)))
    leaky = simple_cv(world.rows, random_kfold_ids(world.rows, 4, 's'), 10.0)
    assert auc_of(world.rows, nested.oof) < 0.6 < 0.8 < auc_of(world.rows, leaky)


def test_function_identity_grouping_closes_cross_lineage_body_leak():
    cands = []
    for lin in range(8):
        for k in range(5):
            shared = f'body:shared{lin // 2}' if k == 0 else f'body:own{lin}-{k}'  # lineage pairs share a body
            cands.append(CandidateIdentity(f'c{lin}-{k}', f'L{lin}', (shared, f'body:new{lin}-{k}')))
    by_lineage = {c.id: c.lineage for c in cands}
    grouping = identity_groups(cands)
    assert len(set(grouping.group_of.values())) == 4 and grouping.merged_lineages == 8
    for group_of in (by_lineage, grouping.group_of):
        rows = [Row(c.id, group_of[c.id], (0.0,), i % 2) for i, c in enumerate(cands)]
        folds = grouped_kfold(rows, 2, 3)
        train = [c for c in cands if group_of[c.id] not in folds[0]]
        test = [c for c in cands if group_of[c.id] in folds[0]]
        leaked = shared_identities(train, test)
        if group_of is by_lineage:
            assert leaked  # lineage-only grouping lets one identical body sit on both sides
        else:
            assert not leaked
    hubs = identity_groups(cands + [CandidateIdentity(f'crt{lin}', f'L{lin}', ('body:crt',)) for lin in range(8)],
                           hub_max_lineages=3)
    assert hubs.hub_identities == frozenset({'body:crt'}) and len(hubs.seen_body) == 8
    assert len(set(hubs.group_of.values())) == 4  # the CRT hub did not collapse everything


def test_choose_calibrator_isotonic_only_with_enough_data_and_one_se_gain():
    from tools.calibration.cv import choose_calibrator, fit_calibrator
    from tools.calibration.mathcore import apply_isotonic

    def world(n):
        rows, scores, fold_of = [], {}, {}
        for i in range(n):
            s = 4 * det_uniform('iso-s', i) - 2
            p = 0.1 if s < 0 else 0.9  # plateaus: no sigmoid reproduces them
            rid = f'r{i:05d}'
            rows.append(Row(rid, f'L{i % 50}', (s,), int(det_uniform('iso-y', i) < p)))
            scores[rid], fold_of[rid] = s, (i % 50) % 5
        return rows, scores, fold_of
    rows, scores, fold_of = world(6000)
    assert choose_calibrator(rows, scores, fold_of, FAST) == 'isotonic'
    cal = fit_calibrator('isotonic', rows, scores)
    assert apply_isotonic(cal[1], -1.0) == pytest.approx(0.1, abs=0.03)
    assert apply_isotonic(cal[1], 1.0) == pytest.approx(0.9, abs=0.03)
    small_rows, small_scores, small_fold = world(800)  # < 1000 effective per class: project heuristic -> Platt
    assert choose_calibrator(small_rows, small_scores, small_fold, FAST) == 'platt'


def test_training_weights_clip_natural_and_unit_adversarial():
    rows = [Row(str(i), 'g', (0.0,), 1, w, 'natural') for i, w in enumerate([1.0, 1.0, 1.0, 100.0])]
    rows.append(Row('adv', 'g', (0.0,), 0, 50.0, 'adversarial'))
    assert training_weights(rows) == [1.0, 1.0, 1.0, 20.0, 1.0]


# ---- simulations -----------------------------------------------------------------------------------------

@pytest.fixture(scope='module')
def well_specified():
    world = make_world(n_groups=30, per_group=40, beta=(2.0, 1.5, -1.0), seed='ws')
    return world, run_pipeline(world.rows, names=['G.ratio', 'R.similarity'], kinds=['num', 'num'], profile='G+R',
                               cfg=FAST, b_count=150, created=CREATED, model_id='sim-ws', null_sims=200)


def test_simulation_a_calibration_recovery(well_specified):
    world, res = well_specified
    rows = world.rows
    p = [res.oof[r.id] for r in rows]
    oracle = [world.true_p[r.id] for r in rows]
    y, w = [r.y for r in rows], [1.0] * len(rows)
    ev = res.evaluation
    assert abs(ev['ece_null']['excess']) < 0.02            # OOF ECE explained by sampling noise
    assert ev['slope']['lo'] <= 1.0 <= ev['slope']['hi']
    assert ev['intercept']['lo'] <= 0.0 <= ev['intercept']['hi']
    assert abs(M.brier(p, y, w) - M.brier(oracle, y, w)) < 0.01  # close to the oracle
    assert res.model.beta == pytest.approx((2.0, 1.5, -1.0), abs=0.25)  # x ~ N(0,1): standardisation ~ identity
    assert res.tau is not None and res.tau['p_value'] <= 0.05
    acc = [world.true_p[r.id] for r in rows if res.oof[r.id] >= res.tau['tau']]
    assert sum(acc) / len(acc) >= 0.95  # the LTT-certified set really has >= 95 % precision in the known world


def test_simulation_c_lineage_shift_is_caught_by_shift_criterion(well_specified):
    world, res = well_specified
    shifted = make_world(n_groups=10, per_group=60, beta=(-0.5, 1.5, -1.0), seed='shift', group_prefix='S',
                         shift=0.5)
    preds = {r.id: res.model.predict(r.x) for r in shifted.rows}
    tau = res.tau['tau'] if res.tau else 0.9
    shift_precision = M.precision_at([preds[r.id] for r in shifted.rows], [r.y for r in shifted.rows],
                                     [1.0] * len(shifted.rows), tau)
    assert shift_precision is not None and shift_precision < 0.9
    profile = dict(res.evaluation, shift_precision=shift_precision)
    g3 = evaluate_gates({}, profile)['G3']
    assert g3['status'] == 'fail' and any('shift-test precision' in r for r in g3['reasons'])


def test_simulation_d_miscalibrated_model_fails_h1(well_specified):
    world, res = well_specified
    overconfident = {k: round(sigmoid(2.5 * logit(v, 1e-6)), 6) for k, v in res.oof.items()}
    ev = evaluate_profile(world.rows, overconfident, tau=0.95, b_count=100, null_sims=200, with_slope_ci=True)
    assert ev['ece_null']['excess'] > 0.03 and ev['slope']['hi'] < 1.0
    reasons = evaluate_gates({}, ev)['G3']['reasons']
    assert any('H1 ECE15 excess over null' in r for r in reasons)
    assert any('slope CI contains 1' in r for r in reasons)


def test_simulation_e_inverse_probability_weights_recover_population_precision():
    world = make_world(n_groups=40, per_group=60, beta=(1.5, 1.2), seed='weights')
    sample = subsample_by_class(world, keep_pos=0.2, keep_neg=1.0, seed='incl')
    truth = M.precision_at([world.true_p[r.id] for r in world.rows], [r.y for r in world.rows],
                           [1.0] * len(world.rows), 0.7)
    sp = [sample.true_p[r.id] for r in sample.rows]
    sy = [r.y for r in sample.rows]
    weighted = M.precision_at(sp, sy, [r.w for r in sample.rows], 0.7)
    unweighted = M.precision_at(sp, sy, [1.0] * len(sp), 0.7)
    assert abs(weighted - truth) < 0.02 < abs(unweighted - truth)


# ---- OOD validation and ablations ---------------------------------------------------------------------------

def test_ood_flags_not_predictive_of_errors_reduce_to_range_checks(well_specified):
    _, res = well_specified
    ev = res.evaluation
    assert 'ood_risk_ratio' in ev and ev['ood_reduced'] is True  # in-domain extremes are confidently right
    art = parse_artifact(canonical_json(res.artifact), today=CREATED)
    assert art.ood.names == () and art.ood.ranges  # Mahalanobis dropped, range/unseen-level kept


def test_nested_cv_flags_a_held_out_far_lineage_with_train_only_ood_statistics():
    base = make_world(n_groups=29, per_group=40, beta=(2.0, 1.5, -1.0), seed='ood')
    far = [Row(f'Z-{i:03d}', 'Z', (5.0 + 0.1 * (i % 5), 5.0 - 0.1 * (i % 3)), i % 2) for i in range(40)]
    nested = nested_cv(list(base.rows) + far, FAST, ood_columns=[0, 1])
    assert all(nested.ood_hard[r.id] for r in far)
    normal_rate = sum(nested.ood_hard[r.id] for r in base.rows) / len(base.rows)
    assert normal_rate < 0.03


def test_ood_validation_decision_uses_lineage_risk_ratio_ci():
    rows, preds, flags = [], {}, {}
    for g in range(40):
        for i in range(30):
            rid = f'L{g:02d}-{i:02d}'
            flagged = g % 4 == 0 and i < 6
            wrong = det_uniform('oodv', rid) < (0.5 if flagged else 0.08)
            rows.append(Row(rid, f'L{g:02d}', (0.0,), 0 if wrong else 1))
            preds[rid], flags[rid] = 0.9, flagged
    ev = evaluate_profile(rows, preds, tau=None, ood_hard=flags, b_count=200, null_sims=20, with_slope_ci=False)
    assert ev['ood_risk_ratio_lo'] > 1
    spec = {'names': ['a'], 'mu': [0.0], 'chol': [[1.0]], 'd2_soft': 1.0, 'd2_cut': 2.0, 'ranges': {},
            'cat_levels': {}, 'engine_versions': []}
    kept, reduced = validated_ood(spec, ev['ood_risk_ratio_lo'])
    assert reduced is False and kept['names'] == ['a']
    dropped, reduced = validated_ood(spec, 0.8)
    assert reduced is True and dropped['names'] == [] and dropped['chol'] == []
    assert validated_ood(spec, None)[1] is True


def test_ablations_identify_useful_and_useless_families():
    world = make_world(n_groups=30, per_group=40, beta=(1.5, 1.2, 1.2, 0.0), seed='abl')
    res = run_pipeline(world.rows, names=['G.ratio', 'R.similarity', 'S.size_ratio'], kinds=['num'] * 3,
                       profile='G+R', cfg=FAST, b_count=150, created=CREATED, model_id='abl', null_sims=50,
                       ablate=True)
    abl = res.evaluation['ablations']
    assert set(abl) == {'drop-R', 'drop-S', 'drop-D_ghidra', 'drop-D_symbols'}
    assert abl['drop-R']['improves_h4'] is True       # the raw-bytes family carries signal here
    assert abl['drop-S']['improves_h4'] is False      # pure noise family: removed from the profile
    assert abl['drop-D_ghidra']['kept'] == 1          # only R (D_bytes) survives
    assert res.evaluation['ablation_reported'] is True


# ---- baselines, gates, determinism, promotion ------------------------------------------------------------

def test_baselines_include_raw_bytes_m0b_and_h4_uses_best(well_specified):
    world, res = well_specified
    names = ['G.ratio', 'R.similarity']
    base = all_baselines(world.rows, names)
    assert set(base) == {'M0', 'M0b', 'M2'}
    assert m0b(world.rows, ['G.ratio']) is None  # no R family -> no raw-bytes baseline for profile G
    fdr = res.evaluation['fdr_reduction']
    assert fdr['baseline'] in base and fdr['lo'] > 0  # truth uses both features: beats the best baseline


def _passing_profile():
    ci = {'point': 0.97, 'lo': 0.95, 'hi': 0.99}
    return {'n_dev_natural': 5000, 'dev_neg': 400, 'dev_lineages': 30, 'n_groups': 40, 'precision': ci,
            'coverage': {'point': 0.6, 'lo': 0.5}, 'brier_skill': {'lo': 0.2}, 'ltt': {'certified': True},
            'fdr_reduction': {'lo': 0.01, 'relative': 0.4}, 'strata_min_lo': 0.9, 'ood_risk_ratio_lo': 1.5,
            'ablation_reported': True, 'ece_null': {'excess': 0.005, 'excess_hi': 0.02},
            'slope': {'lo': 0.9, 'hi': 1.1}, 'intercept': {'lo': -0.1, 'hi': 0.1}, 'shift_precision': 0.93}


def _passing_dataset(second_annotator=True):
    return {'n_natural': 13000, 'n_locked_natural': 3100, 'locked_eff_neg': 200, 'n_lineages': 45, 'n_families': 11,
            'locked_lineages': 13, 'locked_families': 6, 'tier_w_families': 7, 'toolchain_profiles': 2,
            'shift_lineages': 2, 'tier_w_kinds': ['kernel', 'usermode-dll', 'driver'], 'second_annotator':
            second_annotator, 'kappa': 0.85, 'kappa_lo': 0.75, 'test_retest_kappa': 0.9, 'indeterminate_rate': 0.02,
            'symbol_audit_error': 0.01, 'adversarial_subtype_counts': {f'N{i}': 40 for i in range(1, 12)}}


def test_gates_all_pass_and_o2_caps_numeric_claims():
    cond = {'reproducibility_check': True, 'owner_signoff': True, 'frozen_exe_smoke': True,
            'independence_caveat_shown': True}
    gates = evaluate_gates(_passing_dataset(), _passing_profile(), pipeline=_passing_profile(), conditions=cond)
    assert {k: v['status'] for k, v in gates.items()} == {'G0': 'pass', 'G1': 'pass', 'G2': 'pass', 'G3': 'pass'}
    single = evaluate_gates(_passing_dataset(False), _passing_profile(), conditions=cond)
    assert single['G2']['status'] == 'pass' and single['G3']['status'] == 'fail'  # decision O2: bands at most
    missing = _passing_profile()
    del missing['ece_null']
    gaps = evaluate_gates(_passing_dataset(), missing, conditions=cond)
    assert gaps['G3']['status'] == 'insufficient-data' and gaps['G2']['status'] == 'pass'
    no_ltt = dict(_passing_profile(), ltt={'certified': False})
    assert evaluate_gates(_passing_dataset(), no_ltt, conditions=cond)['G2']['status'] == 'fail'
    assert evaluate_gates({}, {})['G2']['status'] in ('insufficient-data', 'fail')
    assert all(g['status'] != 'pass' for g in evaluate_gates({}, {}).values())


def test_pipeline_is_deterministic_and_order_free():
    world = make_world(n_groups=12, per_group=30, beta=(1.0, 1.0), seed='det')
    kwargs = dict(names=['G.ratio'], kinds=['num'], profile='G', cfg=FAST, b_count=60, created=CREATED,
                  model_id='det', null_sims=60)
    first = run_pipeline(world.rows, **kwargs)
    again = run_pipeline(world.rows, **kwargs)
    shuffled = run_pipeline(sorted(world.rows, key=lambda r: r.id[::-1]), **kwargs)
    assert canonical_json(first.artifact) == canonical_json(again.artifact) == canonical_json(shuffled.artifact)
    assert canonical_json(first.report) == canonical_json(again.report)
    assert first.report['report_sha256'] == shuffled.report['report_sha256']
    assert 'SYNTHETIC' in first.report['claim']


def test_built_artifact_loads_in_shipped_runtime_and_only_promotes_on_passing_gates(well_specified):
    _, res = well_specified
    art = parse_artifact(canonical_json(res.artifact), today=CREATED)
    assert art.status == 'experimental' and artifact_display_level(art) == 'ordinal'
    with pytest.raises(PromotionError):
        promote(res.artifact, res.report)  # synthetic report gates are not passing
    tampered = dict(res.report, tool_git='edited')
    with pytest.raises(PromotionError):
        promote(res.artifact, tampered)
    gates = {'G0': {'status': 'pass'}, 'G1': {'status': 'pass'}, 'G2': {'status': 'pass'},
             'G3': {'status': 'fail'}}
    bands = promote(res.artifact, res.report, profile_gates=gates)
    loaded = parse_artifact(canonical_json(bands), today=CREATED)
    assert loaded.status == 'bands-ok' and artifact_display_level(loaded) == 'bands'
    assert math.isfinite(loaded.intercept)
