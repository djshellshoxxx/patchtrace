"""Synthetic worlds with KNOWN ground truth for validating the pipeline (spec §13 simulations).

These are not binaries and say nothing about real Ghidriff/BinDiff/rz-diff behaviour.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .common import Row, det_normal, det_uniform
from .mathcore import sigmoid


@dataclass(frozen=True)
class World:
    rows: tuple[Row, ...]
    true_p: dict[str, float]


def make_world(*, n_groups: int, per_group: int, beta: Sequence[float], seed, group_sd: float = 0.0,
               fingerprint_dim: int = 0, shift: float = 0.0, group_prefix: str = 'L',
               stratum: str = 'natural') -> World:
    """beta = (intercept, b1..bd). y ~ Bernoulli(sigmoid(beta.x + u_g)); u_g ~ N(0, group_sd) is a per-lineage
    effect. With fingerprint_dim > 0 every row of a lineage carries the same random fingerprint vector, a
    planted dependency a model can memorise only for lineages it has seen. `shift` moves feature means."""
    d = len(beta) - 1
    rows, truth = [], {}
    for g in range(n_groups):
        gid = f'{group_prefix}{g:04d}'
        u = group_sd * det_normal(seed, 'u', gid)
        fp = tuple(det_normal(seed, 'fp', gid, k) for k in range(fingerprint_dim))
        for i in range(per_group):
            rid = f'{gid}-{i:04d}'
            x = tuple(det_normal(seed, 'x', rid, j) + shift for j in range(d))
            z = beta[0] + sum(b * v for b, v in zip(beta[1:], x, strict=True)) + u
            p = sigmoid(z)
            y = int(det_uniform(seed, 'y', rid) < p)
            rows.append(Row(rid, gid, x + fp, y, 1.0, stratum))
            truth[rid] = p
    return World(tuple(rows), truth)


def subsample_by_class(world: World, keep_pos: float, keep_neg: float, seed) -> World:
    """Probability sample with known inclusion probabilities; weights = 1/p_incl (spec §5.3)."""
    rows = []
    for r in world.rows:
        p_incl = keep_pos if r.y else keep_neg
        if det_uniform(seed, 'incl', r.id) < p_incl:
            rows.append(Row(r.id, r.group, r.x, r.y, 1.0 / p_incl, r.stratum, r.profile))
    return World(tuple(rows), {r.id: world.true_p[r.id] for r in rows})
