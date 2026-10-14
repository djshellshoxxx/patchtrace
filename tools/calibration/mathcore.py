"""Pure-Python, stdlib-only fitters (spec §7.1, §8): L2 logistic (Newton/IRLS), Platt sigmoid, weighted PAV.

Deterministic: fixed iteration caps, `math.fsum` for objective sums, no randomness, no threading.
scikit-learn is only an optional cross-check (`calibration-dev` extra), never imported here.
"""
from __future__ import annotations

import math
from collections.abc import Sequence

from patchtrace.calibration.predict import apply_isotonic, sigmoid

__all__ = ['NumericalError', 'apply_isotonic', 'cholesky', 'cholesky_solve', 'fit_isotonic', 'fit_logistic_l2',
           'fit_platt', 'logit', 'logit_score', 'sigmoid', 'standardise_apply', 'standardise_fit']

SD_FLOOR = 1e-9
MAX_RIDGE_ATTEMPTS = 12


class NumericalError(ArithmeticError):
    """Raised instead of silently continuing when a system is not SPD even after ridge escalation."""


def softplus(z: float) -> float:
    return z + math.log1p(math.exp(-z)) if z > 0 else math.log1p(math.exp(z))


def logit(p: float, eps: float = 1e-12) -> float:
    p = min(1 - eps, max(eps, p))
    return math.log(p / (1 - p))


def cholesky(a: Sequence[Sequence[float]]) -> list[list[float]]:
    n = len(a)
    low = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1):
            s = a[i][j] - math.fsum(low[i][k] * low[j][k] for k in range(j))
            if i == j:
                if not s > 0 or not math.isfinite(s):
                    raise NumericalError('matrix is not symmetric positive definite')
                low[i][i] = math.sqrt(s)
            else:
                low[i][j] = s / low[j][j]
    return low


def _solve_lower(low, b):
    z = []
    for i, row in enumerate(low):
        z.append((b[i] - math.fsum(row[j] * z[j] for j in range(i))) / row[i])
    return z


def cholesky_solve(a: Sequence[Sequence[float]], b: Sequence[float]) -> list[float]:
    """Solve A x = b for SPD A; escalates a diagonal ridge (1e-10 .. 1e1) and raises if still not SPD."""
    n = len(a)
    ridge = 0.0
    for attempt in range(MAX_RIDGE_ATTEMPTS + 1):
        m = [[a[i][j] + (ridge if i == j else 0.0) for j in range(n)] for i in range(n)]
        try:
            low = cholesky(m)
            break
        except NumericalError:
            ridge = 1e-10 * 10 ** attempt
    else:
        raise NumericalError('Cholesky failed after ridge escalation')
    z = _solve_lower(low, b)
    x = [0.0] * n
    for i in range(n - 1, -1, -1):
        x[i] = (z[i] - math.fsum(low[k][i] * x[k] for k in range(i + 1, n))) / low[i][i]
    return x


def standardise_fit(x: Sequence[Sequence[float]], w: Sequence[float], scale: Sequence[bool] | None = None):
    """Weighted per-column mean/sd. Columns with scale=False (flags/one-hots) keep mean 0, sd 1."""
    d = len(x[0])
    total = math.fsum(w)
    mu, sd = [], []
    for j in range(d):
        if scale is not None and not scale[j]:
            mu.append(0.0)
            sd.append(1.0)
            continue
        m = math.fsum(wi * xi[j] for xi, wi in zip(x, w, strict=True)) / total
        v = math.fsum(wi * (xi[j] - m) ** 2 for xi, wi in zip(x, w, strict=True)) / total
        s = math.sqrt(v)
        mu.append(m)
        sd.append(s if s > SD_FLOOR else 1.0)  # constant column: centred to exactly 0, unit scale
    return mu, sd


def standardise_apply(xi: Sequence[float], mu: Sequence[float], sd: Sequence[float]) -> list[float]:
    return [(v - m) / s for v, m, s in zip(xi, mu, sd, strict=True)]


def logit_score(beta: Sequence[float], xi: Sequence[float]) -> float:
    return beta[0] + math.fsum(b * v for b, v in zip(beta[1:], xi, strict=True))


def _objective(beta, x, y, w, lam):
    terms = []
    for xi, yi, wi in zip(x, y, w, strict=True):
        z = logit_score(beta, xi)
        terms.append(wi * (softplus(z) - yi * z))
    return math.fsum(terms) + 0.5 * lam * math.fsum(b * b for b in beta[1:])


def fit_logistic_l2(x: Sequence[Sequence[float]], y: Sequence[int], w: Sequence[float], c: float,
                    iters: int = 50, tol: float = 1e-10) -> list[float]:
    """Minimise sum(w' * logloss) + (1/(2C))*|beta[1:]|^2 with weights normalised to mean 1 (so a uniform
    rescaling of weights leaves coefficients unchanged). Intercept beta[0] is unpenalised. Newton with
    Armijo backtracking, so the objective never increases."""
    n, d = len(x), len(x[0])
    mean_w = math.fsum(w) / n
    w = [wi / mean_w for wi in w]
    lam = 1.0 / c
    beta = [0.0] * (d + 1)
    current = _objective(beta, x, y, w, lam)
    for _ in range(iters):
        g = [0.0] * (d + 1)
        h = [[0.0] * (d + 1) for _ in range(d + 1)]
        for xi, yi, wi in zip(x, y, w, strict=True):
            p = sigmoid(logit_score(beta, xi))
            s, r = wi * p * (1 - p), wi * (p - yi)
            u = (1.0,) + tuple(xi)
            for a in range(d + 1):
                g[a] += r * u[a]
                ha, sa = h[a], s * u[a]
                for b in range(a, d + 1):
                    ha[b] += sa * u[b]
        for a in range(1, d + 1):
            g[a] += lam * beta[a]
            h[a][a] += lam
        for a in range(d + 1):
            for b in range(a):
                h[a][b] = h[b][a]
        h[0][0] += 1e-9
        step = cholesky_solve(h, g)
        decrease = math.fsum(gi * si for gi, si in zip(g, step, strict=True))
        t = 1.0
        while True:
            trial = [b - t * s for b, s in zip(beta, step, strict=True)]
            value = _objective(trial, x, y, w, lam)
            if value <= current - 1e-4 * t * decrease or t < 1e-10:
                break
            t *= 0.5
        moved = max(abs(t * s) for s in step)
        if value > current:  # no descent possible at machine precision: converged
            break
        beta, current = trial, value
        if moved < tol:
            break
    return beta


def fit_platt(s: Sequence[float], y: Sequence[int], w: Sequence[float] | None = None,
              iters: int = 100, smooth: bool = True) -> tuple[float, float]:
    """Platt (1999) with smoothed targets; p = sigmoid(a*s + b). Smoothing keeps separable data finite.
    With smooth=False this is the plain 2-parameter logistic MLE (used for calibration slope/intercept)."""
    w = [1.0] * len(s) if w is None else list(w)
    n_pos = math.fsum(wi for wi, yi in zip(w, y, strict=True) if yi)
    n_neg = math.fsum(w) - n_pos
    tp, tn = ((n_pos + 1) / (n_pos + 2), 1 / (n_neg + 2)) if smooth else (1.0, 0.0)
    t = [tp if yi else tn for yi in y]

    def f(a, b):
        return math.fsum(wi * (softplus(a * si + b) - ti * (a * si + b)) for si, ti, wi in zip(s, t, w, strict=True))
    a, b = 0.0, math.log((n_pos + 1) / (n_neg + 1))
    current = f(a, b)
    for _ in range(iters):
        ga = gb = haa = hab = hbb = 0.0
        for si, ti, wi in zip(s, t, w, strict=True):
            p = sigmoid(a * si + b)
            r, q = wi * (p - ti), wi * p * (1 - p)
            ga += r * si
            gb += r
            haa += q * si * si
            hab += q * si
            hbb += q
        da, db = cholesky_solve([[haa + 1e-12, hab], [hab, hbb + 1e-12]], [ga, gb])
        step = 1.0
        while True:
            na, nb = a - step * da, b - step * db
            value = f(na, nb)
            if value <= current - 1e-4 * step * (ga * da + gb * db) or step < 1e-10:
                break
            step *= 0.5
        if value > current:
            break
        moved = max(abs(step * da), abs(step * db))
        a, b, current = na, nb, value
        if moved < 1e-12:
            break
    return a, b


def fit_isotonic(s: Sequence[float], y: Sequence[float], w: Sequence[float] | None = None,
                 clip: bool = True) -> list[tuple[float, float]]:
    """Weighted pool-adjacent-violators. Equal scores are merged first (weighted mean). Each block keeps its
    min and max score as knots so interpolation is flat inside a block; values clipped to [eps, 1-eps]
    with eps = 1/(sum_w + 2) when `clip`."""
    w = [1.0] * len(s) if w is None else list(w)
    pts = sorted(zip(s, y, w, strict=True), key=lambda t: t[0])
    merged: list[list[float]] = []  # [s_min, s_max, sum_wy, sum_w]
    for sv, yv, wv in pts:
        if merged and merged[-1][1] == sv:
            merged[-1][2] += wv * yv
            merged[-1][3] += wv
        else:
            merged.append([sv, sv, wv * yv, wv])
    stack: list[list[float]] = []
    for block in merged:
        stack.append(block)
        while len(stack) > 1 and stack[-2][2] * stack[-1][3] >= stack[-1][2] * stack[-2][3]:
            top = stack.pop()
            stack[-1][1] = top[1]
            stack[-1][2] += top[2]
            stack[-1][3] += top[3]
    eps = 1.0 / (math.fsum(w) + 2) if clip else 0.0
    knots: list[tuple[float, float]] = []
    for lo, hi, swy, sw in stack:
        value = min(1 - eps, max(eps, swy / sw))
        knots.append((lo, value))
        if hi > lo:
            knots.append((hi, value))
    return knots
