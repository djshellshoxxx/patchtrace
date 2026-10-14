"""Pure-Python fitters (calibration-corpus-and-model.md §7-8): determinism helpers, Cholesky/IRLS, Platt, PAV.
scikit-learn cross-checks run only when the optional `calibration-dev` extra is installed."""
from __future__ import annotations

import math
import sys
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.calibration.common import det_normal, det_uniform, weighted_quantile  # noqa: E402
from tools.calibration.mathcore import (  # noqa: E402
    NumericalError,
    apply_isotonic,
    cholesky,
    cholesky_solve,
    fit_isotonic,
    fit_logistic_l2,
    fit_platt,
    sigmoid,
    standardise_apply,
    standardise_fit,
)
from tools.calibration.synth import make_world  # noqa: E402


def test_det_uniform_fixed_vectors_and_strictly_below_one():
    assert det_uniform(1, 'a') == det_uniform('1', 'a')  # keys are joined as strings
    assert det_uniform('seed', 'k', 3) == det_uniform('seed', 'k', '3')
    vals = [det_uniform('v', i) for i in range(5000)]
    assert all(0.0 <= v < 1.0 for v in vals)
    assert 0.47 < sum(vals) / len(vals) < 0.53
    # The 52-bit construction cannot reach 1.0 even for an all-ones hash prefix (the 64-bit draft could).
    assert (2**52 - 1) / 2**52 < 1.0
    assert (2**64 - 1) / 2**64 == 1.0


def test_det_uniform_vector_is_pinned():
    import hashlib
    h = hashlib.sha256(b'7|x|1').hexdigest()
    assert det_uniform(7, 'x', 1) == int(h[:13], 16) / 2**52
    # Literal pins: identical on every platform (exact 52-bit fractions; Box-Muller within 1e-12).
    assert det_uniform(7, 'x', 1) == 0.14959852675725505
    assert det_uniform('c9-v1', 'g', 'L-0001') == 0.17195199428251318
    assert det_normal('n', 0) == pytest.approx(1.043159464092172, abs=1e-12)


def test_det_normal_moments():
    xs = [det_normal('n', i) for i in range(4000)]
    mean = math.fsum(xs) / len(xs)
    var = math.fsum((x - mean) ** 2 for x in xs) / len(xs)
    assert abs(mean) < 0.06 and abs(var - 1) < 0.08


def test_weighted_quantile():
    assert weighted_quantile([3, 1, 2], [1, 1, 1], 0.5) == 2
    assert weighted_quantile([1, 2], [1, 3], 0.5) == 2


def test_cholesky_and_solve_known_system():
    a = [[4.0, 2.0], [2.0, 3.0]]
    low = cholesky(a)
    assert low == [[2.0, 0.0], [1.0, pytest.approx(math.sqrt(2.0))]]
    x = cholesky_solve(a, [2.0, 1.0])
    assert x == [pytest.approx(0.5), pytest.approx(0.0)]
    with pytest.raises(NumericalError):
        cholesky([[1.0, 2.0], [2.0, 1.0]])
    # semidefinite: ridge escalation solves; indefinite beyond the ridge cap raises
    assert len(cholesky_solve([[1.0, 1.0], [1.0, 1.0]], [1.0, 1.0])) == 2
    with pytest.raises(NumericalError):
        cholesky_solve([[-1e3, 0.0], [0.0, 1.0]], [1.0, 1.0])


def test_logistic_closed_form_saturated_model():
    # One binary covariate, essentially unpenalised: MLE = group log-odds.
    x = [[0.0]] * 40 + [[1.0]] * 60
    y = [1] * 10 + [0] * 30 + [1] * 45 + [0] * 15
    beta = fit_logistic_l2(x, y, [1.0] * 100, c=1e12)
    assert beta[0] == pytest.approx(math.log(10 / 30), abs=1e-7)
    assert beta[1] == pytest.approx(math.log(45 / 15) - math.log(10 / 30), abs=1e-7)


def test_logistic_recovers_true_coefficients():
    world = make_world(n_groups=60, per_group=50, beta=(0.5, 1.2, -0.8), seed='recover')
    beta = fit_logistic_l2([list(r.x) for r in world.rows], [r.y for r in world.rows], [1.0] * 3000, c=1e6)
    assert beta[0] == pytest.approx(0.5, abs=0.15)
    assert beta[1] == pytest.approx(1.2, abs=0.15)
    assert beta[2] == pytest.approx(-0.8, abs=0.15)


def test_logistic_separable_data_stays_finite_with_penalty():
    x = [[-2.0], [-1.0], [1.0], [2.0]]
    beta = fit_logistic_l2(x, [0, 0, 1, 1], [1.0] * 4, c=1.0)
    assert all(math.isfinite(b) for b in beta) and beta[1] > 0


def test_logistic_weight_scaling_and_permutation_invariance():
    world = make_world(n_groups=20, per_group=20, beta=(0.2, 1.0, 0.5), seed='inv')
    x = [list(r.x) for r in world.rows]
    y = [r.y for r in world.rows]
    w = [1.0 + (i % 3) for i in range(len(x))]
    base = fit_logistic_l2(x, y, w, c=0.5)
    scaled = fit_logistic_l2(x, y, [7.0 * v for v in w], c=0.5)
    order = sorted(range(len(x)), key=lambda i: det_uniform('perm', i))
    perm = fit_logistic_l2([x[i] for i in order], [y[i] for i in order], [w[i] for i in order], c=0.5)
    for a, b, c in zip(base, scaled, perm, strict=True):
        assert a == pytest.approx(b, rel=1e-9, abs=1e-12) and a == pytest.approx(c, rel=1e-9, abs=1e-12)


def test_integer_weights_equal_replication():
    x = [[0.1], [0.5], [0.9], [0.3]]
    y = [1, 0, 1, 0]  # not separable, so the (negligible) penalty does not dominate
    weighted = fit_logistic_l2(x, y, [1.0, 2.0, 1.0, 3.0], c=1e6)
    replicated = fit_logistic_l2([x[0], x[1], x[1], x[2], x[3], x[3], x[3]], [1, 0, 0, 1, 0, 0, 0], [1.0] * 7, c=1e6)
    # weights are normalised to mean 1, so the penalty scale differs slightly; with C=1e6 it is negligible
    assert weighted == pytest.approx(replicated, rel=1e-5)


def test_standardise_flags_untouched_and_constant_column_safe():
    mu, sd = standardise_fit([[1.0, 0.0, 5.0], [3.0, 1.0, 5.0]], [1.0, 1.0], scale=[True, False, True])
    assert mu == [2.0, 0.0, 5.0] and sd == [1.0, 1.0, 1.0]
    assert standardise_apply([3.0, 1.0, 5.0], mu, sd) == [1.0, 1.0, 0.0]


def test_platt_recovers_parameters_and_stays_finite_on_separable_data():
    s = [det_normal('platt', i) * 2 for i in range(4000)]
    y = [int(det_uniform('platt-y', i) < sigmoid(1.7 * v - 0.6)) for i, v in enumerate(s)]
    a, b = fit_platt(s, y)
    assert a == pytest.approx(1.7, abs=0.15) and b == pytest.approx(-0.6, abs=0.12)
    a2, b2 = fit_platt([-3.0, -2.0, 2.0, 3.0], [0, 0, 1, 1])
    assert math.isfinite(a2) and math.isfinite(b2) and a2 > 0
    # target smoothing: separable data never yields p of exactly 0 or 1
    assert 0.0 < sigmoid(a2 * 3.0 + b2) < 1.0


def test_pav_known_example_ties_and_weights():
    knots = fit_isotonic([1, 2, 3, 4], [1, 0, 1, 1], clip=False)
    assert knots == [(1, 0.5), (2, 0.5), (3, 1.0), (4, 1.0)]
    tied = fit_isotonic([1, 1, 2], [1, 0, 1], clip=False)
    assert tied == [(1, 0.5), (2, 1.0)]
    weighted = fit_isotonic([1, 2], [1, 0], [3.0, 1.0], clip=False)
    assert weighted == [(1, 0.75), (2, 0.75)]
    clipped = fit_isotonic([1, 2], [0, 1])
    eps = 1 / 4
    assert clipped == [(1, eps), (2, 1 - eps)]


@settings(max_examples=60, deadline=None)
@given(st.lists(st.tuples(st.floats(-5, 5, allow_nan=False), st.integers(0, 1), st.floats(0.1, 5)),
                min_size=2, max_size=60))
def test_isotonic_property_monotone_bounded_order_free(data):
    s, y, w = zip(*data, strict=True)
    knots = fit_isotonic(s, y, w)
    assert all(0 < p < 1 for _, p in knots)
    assert all(k1[0] < k2[0] and k1[1] <= k2[1] for k1, k2 in zip(knots, knots[1:], strict=False))
    grid = [min(s) - 1 + i * (max(s) - min(s) + 2) / 50 for i in range(51)]
    out = [apply_isotonic(knots, g) for g in grid]
    assert all(a <= b + 1e-15 for a, b in zip(out, out[1:], strict=False))
    rev = fit_isotonic(s[::-1], y[::-1], w[::-1])
    assert [k[0] for k in rev] == [k[0] for k in knots]
    assert [k[1] for k in rev] == pytest.approx([k[1] for k in knots], rel=1e-12)


@settings(max_examples=30, deadline=None)
@given(st.lists(st.tuples(st.floats(-4, 4, allow_nan=False), st.integers(0, 1)), min_size=3, max_size=40))
def test_platt_property_monotone_in_score(data):
    s, y = zip(*data, strict=True)
    a, b = fit_platt(s, y)
    assert math.isfinite(a) and math.isfinite(b)
    probs = [sigmoid(a * v + b) for v in sorted(s)]
    assert all(0 <= p <= 1 for p in probs)
    if a >= 0:
        assert all(p1 <= p2 for p1, p2 in zip(probs, probs[1:], strict=False))


# ---- optional scikit-learn cross-checks (calibration-dev extra) -------------------------------------------

def _xyw():
    world = make_world(n_groups=30, per_group=30, beta=(0.3, 1.0, -0.7, 0.4), seed='skl')
    return [list(r.x) for r in world.rows], [r.y for r in world.rows], [1.0 + (i % 4) * 0.5 for i in range(900)]


def test_logistic_matches_sklearn():
    sk = pytest.importorskip('sklearn.linear_model')
    x, y, w = _xyw()
    mean_w = sum(w) / len(w)
    for c in (0.05, 1.0, 100.0):
        mine = fit_logistic_l2(x, y, w, c=c)
        ref = sk.LogisticRegression(C=c, solver='lbfgs', tol=1e-12, max_iter=100000)
        ref.fit(x, y, sample_weight=[v / mean_w for v in w])
        theirs = [float(ref.intercept_[0])] + [float(v) for v in ref.coef_[0]]
        for a, b in zip(mine, theirs, strict=True):
            assert a == pytest.approx(b, rel=1e-4, abs=1e-6)


def test_isotonic_matches_sklearn():
    iso = pytest.importorskip('sklearn.isotonic')
    s = [round(det_normal('iso', i), 1) for i in range(400)]  # tie-heavy
    y = [int(det_uniform('iso-y', i) < sigmoid(v)) for i, v in enumerate(s)]
    w = [1.0 + (i % 3) for i in range(400)]
    mine = fit_isotonic(s, y, w, clip=False)
    ref = iso.IsotonicRegression(out_of_bounds='clip').fit(s, y, sample_weight=w)
    assert [k[0] for k in mine] == pytest.approx(list(ref.X_thresholds_))
    assert [k[1] for k in mine] == pytest.approx(list(ref.y_thresholds_), abs=1e-12)


def test_platt_matches_sklearn():
    cal = pytest.importorskip('sklearn.calibration')
    s = [det_normal('pl', i) * 1.5 for i in range(600)]
    y = [int(det_uniform('pl-y', i) < sigmoid(1.3 * v + 0.4)) for i, v in enumerate(s)]
    import numpy as np
    big_a, big_b = cal._sigmoid_calibration(np.array(s), np.array(y))
    a, b = fit_platt(s, y)
    assert a == pytest.approx(-float(big_a), abs=1e-3) and b == pytest.approx(-float(big_b), abs=1e-3)
