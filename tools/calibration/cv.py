"""Grouped (lineage) K-fold and nested CV with an out-of-fold calibrator (spec §4.3, §8).

No fold, inner fold, standardisation, C choice or calibrator ever sees rows of a test lineage.
"""
from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field

from .common import Row, det_uniform
from .mathcore import (
    apply_isotonic,
    fit_isotonic,
    fit_logistic_l2,
    fit_platt,
    logit_score,
    sigmoid,
    standardise_apply,
    standardise_fit,
)
from .metrics import logloss
from .ood_fit import apply_spec, ood_fit

K_NEG = 1.0
WEIGHT_CLIP = 20.0
# PROJECT HEURISTIC, not from any source: isotonic is only considered with >= 1000 effective positives AND
# negatives. Niculescu-Mizil & Caruana (ICML 2005) only report that isotonic needs more data than Platt;
# they give no 1000-sample cutoff.
ISOTONIC_MIN_EFFECTIVE = 1000


class CVError(ValueError):
    pass


@dataclass(frozen=True)
class CVConfig:
    k_outer: int = 5
    k_inner: int = 5
    c_grid: tuple[float, ...] = (0.01, 0.1, 1.0, 10.0)
    seed: int = 1
    scale: tuple[bool, ...] | None = None  # False for flag/one-hot columns
    isotonic_min_effective: int = ISOTONIC_MIN_EFFECTIVE


@dataclass(frozen=True)
class FittedModel:
    c: float
    mu: tuple[float, ...]
    sd: tuple[float, ...]
    beta: tuple[float, ...]
    calibrator: tuple  # ('platt', a, b) | ('isotonic', knots)

    def score(self, x: Sequence[float]) -> float:
        return logit_score(self.beta, standardise_apply(x, self.mu, self.sd))

    def predict(self, x: Sequence[float]) -> float:
        return round(calibrate(self.calibrator, self.score(x)), 6)


def calibrate(calibrator: tuple, score: float) -> float:
    if calibrator[0] == 'platt':
        return sigmoid(calibrator[1] * score + calibrator[2])
    return apply_isotonic(calibrator[1], score)


def grouped_kfold(rows: Sequence[Row], k: int, seed) -> list[frozenset[str]]:
    """Deterministic balanced greedy (LPT) assignment of whole groups to k folds."""
    groups: dict[str, list[float]] = {}
    for r in rows:
        g = groups.setdefault(r.group, [0.0, 0.0])
        g[0] += r.w
        g[1] += r.w * (1 - r.y)
    if len(groups) < k:
        raise CVError(f'{len(groups)} groups cannot fill {k} folds')
    order = sorted(groups, key=lambda g: (-groups[g][0], det_uniform(seed, 'g', g), g))
    folds: list[list[str]] = [[] for _ in range(k)]
    load, neg = [0.0] * k, [0.0] * k
    for g in order:
        f = min(range(k), key=lambda i: (load[i] + 0.5 * neg[i] * K_NEG, i))
        folds[f].append(g)
        load[f] += groups[g][0]
        neg[f] += groups[g][1]
    return [frozenset(f) for f in folds]


def random_kfold_ids(rows: Sequence[Row], k: int, seed) -> list[frozenset[str]]:
    """Row-level random folds, for the leakage demonstration ONLY (never for reported numbers)."""
    order = sorted(rows, key=lambda r: (det_uniform(seed, 'r', r.id), r.id))
    return [frozenset(r.id for r in order[i::k]) for i in range(k)]


def training_weights(rows: Sequence[Row]) -> list[float]:
    natural = sorted(r.w for r in rows if r.stratum == 'natural')
    cap = WEIGHT_CLIP * natural[len(natural) // 2] if natural else math.inf
    return [min(r.w, cap) if r.stratum == 'natural' else 1.0 for r in rows]


def fit_base(rows: Sequence[Row], c: float, scale) -> tuple[list[float], list[float], list[float]]:
    rows = sorted(rows, key=lambda r: r.id)
    w = training_weights(rows)
    mu, sd = standardise_fit([r.x for r in rows], w, scale)
    beta = fit_logistic_l2([standardise_apply(r.x, mu, sd) for r in rows], [r.y for r in rows], w, c)
    return mu, sd, beta


def _check_disjoint(train: Sequence[Row], test: Sequence[Row]) -> None:
    if {r.group for r in train} & {r.group for r in test}:
        raise CVError('leakage: a group appears in both training and test rows')


def oof_scores(rows: Sequence[Row], c: float, k: int, seed, scale) -> tuple[dict[str, float], dict[str, int]]:
    """Inner grouped OOF logits and the fold index of every row."""
    scores, fold_of = {}, {}
    for j, held in enumerate(grouped_kfold(rows, k, seed)):
        train = [r for r in rows if r.group not in held]
        test = [r for r in rows if r.group in held]
        _check_disjoint(train, test)
        mu, sd, beta = fit_base(train, c, scale)
        for r in test:
            scores[r.id] = logit_score(beta, standardise_apply(r.x, mu, sd))
            fold_of[r.id] = j
    return scores, fold_of


def fit_calibrator(kind: str, rows: Sequence[Row], scores: dict[str, float]) -> tuple:
    rows = sorted((r for r in rows if r.stratum == 'natural'), key=lambda r: r.id)
    s, y, w = [scores[r.id] for r in rows], [r.y for r in rows], [r.w for r in rows]
    if kind == 'platt':
        return ('platt',) + fit_platt(s, y, w)
    return ('isotonic', tuple(fit_isotonic(s, y, w)))


def _effective(w: Sequence[float]) -> float:
    sq = math.fsum(v * v for v in w)
    return math.fsum(w) ** 2 / sq if sq else 0.0


def choose_calibrator(rows: Sequence[Row], scores: dict[str, float], fold_of: dict[str, int],
                      cfg: CVConfig) -> str:
    """Platt unless both classes have >= isotonic_min_effective effective natural weight AND cross-fitted
    isotonic beats Platt on Brier by more than one (lineage-clustered) standard error."""
    nat = sorted((r for r in rows if r.stratum == 'natural'), key=lambda r: r.id)
    if min(_effective([r.w for r in nat if r.y]), _effective([r.w for r in nat if not r.y])) \
            < cfg.isotonic_min_effective:
        return 'platt'
    diffs: dict[str, list[float]] = {}
    for fold in sorted(set(fold_of[r.id] for r in nat)):
        train = [r for r in nat if fold_of[r.id] != fold]
        test = [r for r in nat if fold_of[r.id] == fold]
        cal_p, cal_i = fit_calibrator('platt', train, scores), fit_calibrator('isotonic', train, scores)
        for r in test:
            d = r.w * ((calibrate(cal_p, scores[r.id]) - r.y) ** 2 - (calibrate(cal_i, scores[r.id]) - r.y) ** 2)
            diffs.setdefault(r.group, []).append(d)
    total_w = math.fsum(r.w for r in nat)
    per_group = [math.fsum(v) / total_w for v in diffs.values()]
    mean = math.fsum(per_group)
    g = len(per_group)
    se = math.sqrt(g / (g - 1) * math.fsum((v - mean / g) ** 2 for v in per_group)) if g > 1 else math.inf
    return 'isotonic' if mean > se else 'platt'


def select_c(rows: Sequence[Row], cfg: CVConfig, seed) -> tuple[float, dict[str, float], dict[str, int]]:
    """C minimising Platt-on-OOF natural log-loss; ties -> smaller C (more regularised)."""
    best = None
    for c in sorted(cfg.c_grid):
        scores, fold_of = oof_scores(rows, c, cfg.k_inner, seed, cfg.scale)
        cal = fit_calibrator('platt', rows, scores)
        nat = sorted((r for r in rows if r.stratum == 'natural'), key=lambda r: r.id)
        ll = logloss([calibrate(cal, scores[r.id]) for r in nat], [r.y for r in nat], [r.w for r in nat])
        if best is None or ll < best[0] - 1e-12:
            best = (ll, c, scores, fold_of)
    return best[1], best[2], best[3]


def final_model(rows: Sequence[Row], cfg: CVConfig, seed=None) -> FittedModel:
    """Inner procedure on all given rows: choose C, choose + fit calibrator on OOF logits, refit base."""
    seed = cfg.seed + 1 if seed is None else seed
    c, scores, fold_of = select_c(rows, cfg, seed)
    kind = choose_calibrator(rows, scores, fold_of, cfg)
    cal = fit_calibrator(kind, rows, scores)
    mu, sd, beta = fit_base(rows, c, cfg.scale)
    return FittedModel(c, tuple(mu), tuple(sd), tuple(beta), cal)


@dataclass
class NestedResult:
    oof: dict[str, float]
    folds: list[frozenset[str]]
    models: list[FittedModel] = field(default_factory=list)
    ood_hard: dict[str, bool] = field(default_factory=dict)  # lineage-held-out hard OOD flags (validation)


def nested_cv(rows: Sequence[Row], cfg: CVConfig, *, ood_columns: Sequence[int] = ()) -> NestedResult:
    """Outer grouped folds give honest OOF predictions. With `ood_columns`, the OOD spec is also fitted on
    each outer-train part only and applied to the held-out lineages, to validate the flags (spec §9.6)."""
    rows = sorted(rows, key=lambda r: r.id)
    outer = grouped_kfold(rows, cfg.k_outer, cfg.seed)
    result = NestedResult({}, outer)
    names = [f'c{j}' for j in ood_columns]
    for test_groups in outer:
        train = [r for r in rows if r.group not in test_groups]
        test = [r for r in rows if r.group in test_groups]
        _check_disjoint(train, test)
        model = final_model(train, cfg)
        result.models.append(model)
        spec = ood_fit([{n: r.x[j] for n, j in zip(names, ood_columns, strict=True)} for r in train],
                       [1.0] * len(train), names, [], []) if names else None
        for r in test:
            result.oof[r.id] = model.predict(r.x)
            if spec is not None:
                flags = apply_spec(spec, {n: r.x[j] for n, j in zip(names, ood_columns, strict=True)})
                result.ood_hard[r.id] = any(f.startswith('hard:') for f in flags)
    return result


def simple_cv(rows: Sequence[Row], folds_of_ids: list[frozenset[str]], c: float, scale=None) -> dict[str, float]:
    """Plain K-fold (no inner loop, uncalibrated sigmoid) for a given row-id partition; leakage demo helper."""
    out = {}
    for held in folds_of_ids:
        train = [r for r in rows if r.id not in held]
        mu, sd, beta = fit_base(train, c, scale)
        for r in rows:
            if r.id in held:
                out[r.id] = sigmoid(logit_score(beta, standardise_apply(r.x, mu, sd)))
    return out


def group_folds_as_ids(rows: Sequence[Row], folds: list[frozenset[str]]) -> list[frozenset[str]]:
    return [frozenset(r.id for r in rows if r.group in f) for f in folds]
