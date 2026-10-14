"""Baseline scorers for H4 (spec §2.3 as amended): the model must beat the BEST of these at equal coverage.

- M0  Ghidriff-only rule: score = G.ratio.
- M0b raw-bytes baseline: score = R.similarity (rz-diff raw-byte Levenshtein ratio, dependency D_bytes);
      only defined for profiles containing R. (REFuSe-Bench reports raw-bytes baselines are strong; verify
      before ratification.) A PatchTrace-computed body-bytes similarity for every profile is a later slice.
- M1  Ghidriff-only L2 logistic (grouped nested CV OOF on the G-family columns).
- M2  SPEC-27 placeholder index (55 / +20 BinDiff / +8 rz-diff) used as a scorer.
Ranking scorers (M0, M0b, M2) need no calibration: H4 compares FDR at equal coverage, which uses order only.
"""
from __future__ import annotations

from collections.abc import Sequence

from .common import Row
from .cv import CVConfig, nested_cv


def column_scores(rows: Sequence[Row], names: Sequence[str], column: str) -> dict[str, float] | None:
    if column not in names:
        return None
    j = list(names).index(column)
    return {r.id: r.x[j] for r in rows}


def m0(rows, names):
    return column_scores(rows, names, 'G.ratio')


def m0b(rows, names):
    return column_scores(rows, names, 'R.similarity')


def m2(rows, names):
    idx = {n: j for j, n in enumerate(names)}

    def get(r, n):
        return r.x[idx[n]] if n in idx else 0.0
    return {r.id: min(83.0, 55.0 + 20.0 * get(r, 'X.agree_B') + 8.0 * get(r, 'X.agree_R')) for r in rows}


def restrict(rows: Sequence[Row], names: Sequence[str], keep: Sequence[str]) -> list[Row]:
    cols = [list(names).index(n) for n in keep]
    return [Row(r.id, r.group, tuple(r.x[j] for j in cols), r.y, r.w, r.stratum, r.profile, r.subtype, r.abstain)
            for r in rows]


def m1(rows: Sequence[Row], names: Sequence[str], cfg: CVConfig) -> dict[str, float] | None:
    keep = [n for n in names if n.startswith('G.')]
    if not keep:
        return None
    return nested_cv(restrict(rows, names, keep), cfg).oof


def all_baselines(rows: Sequence[Row], names: Sequence[str], cfg: CVConfig | None = None) -> dict[str, dict]:
    out = {'M0': m0(rows, names), 'M0b': m0b(rows, names), 'M2': m2(rows, names)}
    if cfg is not None:
        out['M1'] = m1(rows, names, cfg)
    return {k: v for k, v in out.items() if v is not None}
