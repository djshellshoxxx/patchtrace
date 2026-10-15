"""Shift ladder for the Tier R training run (LBL integration plan 7.3; dev-only, never ships).

Four rungs, each reporting precision at the FROZEN tau of the headline run, coverage, ECE excess over the null, the OOD
flag rate, degradation against the headline and lineage-bootstrap intervals, plus "forced" accuracy (OOD abstention off)
next to the accuracy of the rows the OOD test lets through:

1. `grouped-cv-within-toolchain`: nested grouped CV restricted to the rows of one toolchain profile;
2. `leave-one-toolchain-out`: fit on every other toolchain, score the held-out one (a gcc/clang to msvc style shift);
3. `leave-one-family-out`: fit on every other code family, score the held-out one;
4. `tier-w`: `not-run` in the cloud (owner machine only, SPEC-33).

A held-out unit never shares a CV group (lineage or function-identity component) with the training rows: groups that
contain both are removed from the training side and counted (`excluded_shared_groups`). A rung that cannot be scored
reports `insufficient-data` with the reason; it is never silently dropped and never filled with a number.
Everything here is computed on a synthetic Tier R corpus: it measures how the pipeline degrades on test builds and
says nothing about Windows system files.
"""
from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict

from .bootstrap import cluster_bootstrap, coverage_stat, group_rows, precision_stat
from .common import Row
from .cv import CVConfig, CVError, final_model, nested_cv
from .ece_null import ece_null, ece_null_summary, residual_rho
from .guards import RowError
from .metrics import ece as ece_metric
from .ood_fit import apply_spec, ood_fit

CONTRACT = 'calibration-shift/1'
RUNG_CV, RUNG_TOOLCHAIN, RUNG_FAMILY, RUNG_TIER_W = ('grouped-cv-within-toolchain', 'leave-one-toolchain-out',
                                                     'leave-one-family-out', 'tier-w')
TIER_W_REASON = 'Tier W needs the owner machine (SPEC-33); never run in the cloud'
# A rung is scored only above these floors (below them an interval would be noise, so the rung says so).
HELD_MIN = {'rows': 50, 'positives': 10, 'negatives': 10, 'groups': 3}
TRAIN_MIN = {'rows': 100, 'positives': 20, 'negatives': 20}
MAX_UNITS = 12                      # held-out units per rung kind (toolchains, families): bounded cost
FIRST_LOOK_NOTE = 'descriptive: a shift failure is a documented blind spot, never a reason to re-tune'


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class IntervalDoc(_Strict):
    point: float | None
    lo: float | None = None
    hi: float | None = None
    undefined: int = 0
    anti_conservative: bool = False


class ShiftRung(_Strict):
    rung: Literal['grouped-cv-within-toolchain', 'leave-one-toolchain-out', 'leave-one-family-out', 'tier-w']
    held_out: str | None
    status: Literal['ok', 'insufficient-data', 'not-run']
    reason: str | None = None
    n_rows: int = 0
    n_positive: int = 0
    n_negative: int = 0
    n_groups: int = 0
    n_lineages: int = 0
    excluded_shared_groups: int = 0
    precision: IntervalDoc | None = None
    coverage: IntervalDoc | None = None
    ece_excess: float | None = None
    ood_flag_rate: float | None = None
    forced_accuracy: float | None = None
    ood_abstain_accuracy: float | None = None
    delta_precision: float | None = None
    delta_precision_lo: float | None = None
    delta_precision_hi: float | None = None
    delta_coverage: float | None = None


class ShiftLadder(_Strict):
    contract: Literal['calibration-shift/1']
    tau: float | None
    baseline: dict[str, float | None]
    note: str
    rungs: tuple[ShiftRung, ...]


@dataclass(frozen=True)
class RowInfo:
    toolchain: str          # build profile of the pair (mingw-gcc, msvc-free, ...)
    family: str             # code family of the lineage
    lineage: str


@dataclass(frozen=True)
class LadderConfig:
    b_count: int = 500
    null_sims: int = 200
    seed: int = 51


def _interval(ci: Mapping | None) -> IntervalDoc | None:
    if ci is None:
        return None
    return IntervalDoc(point=ci.get('point'), lo=ci.get('lo'), hi=ci.get('hi'), undefined=int(ci.get('undefined') or 0),
                       anti_conservative=bool(ci.get('anti_conservative')))


def _counts(rows: Sequence[Row]) -> tuple[int, int]:
    pos = sum(1 for r in rows if r.y)
    return pos, len(rows) - pos


def _insufficient(rung: str, held: str | None, reason: str, rows: Sequence[Row], info: Mapping[str, RowInfo],
                  excluded: int = 0) -> ShiftRung:
    pos, neg = _counts(rows)
    return ShiftRung(rung=rung, held_out=held, status='insufficient-data', reason=reason, n_rows=len(rows),
                     n_positive=pos, n_negative=neg, n_groups=len({r.group for r in rows}),
                     n_lineages=len({info[r.id].lineage for r in rows}), excluded_shared_groups=excluded)


def _floors(rows: Sequence[Row], floor: Mapping[str, int], label: str) -> list[str]:
    pos, neg = _counts(rows)
    out = []
    if len(rows) < floor['rows']:
        out.append(f'{label} rows {len(rows)} < {floor["rows"]}')
    if pos < floor['positives']:
        out.append(f'{label} positives {pos} < {floor["positives"]}')
    if neg < floor['negatives']:
        out.append(f'{label} negatives {neg} < {floor["negatives"]}')
    groups = len({r.group for r in rows})
    if 'groups' in floor and groups < floor['groups']:
        out.append(f'{label} groups {groups} < {floor["groups"]}')
    return out


def _score(rung: str, held: str | None, rows: Sequence[Row], preds: Mapping[str, float],
           ood_hard: Mapping[str, bool], info: Mapping[str, RowInfo], tau: float | None,
           baseline: Mapping[str, float | None], excluded: int, cfg: LadderConfig) -> ShiftRung:
    """Metrics of one held-out row set (natural rows, fixed predictions, lineage resampling)."""
    rows = sorted(rows, key=lambda r: r.id)
    pos, neg = _counts(rows)
    p = [preds[r.id] for r in rows]
    y = [r.y for r in rows]
    w = [r.w for r in rows]
    groups = [r.group for r in rows]
    seed = (cfg.seed, rung, held or '-')
    prec = cov = None
    if tau is not None:
        prec = cluster_bootstrap(rows, preds, precision_stat(tau), cfg.b_count, (*seed, 'prec'))
        cov = cluster_bootstrap(rows, preds, coverage_stat(tau), cfg.b_count, (*seed, 'cov'))
    plug_in = ece_metric(p, y, w)
    null = ece_null(p, w, groups, rho=residual_rho(p, y, groups), sims=cfg.null_sims, seed=(*seed, 'ece-null'))
    excess = ece_null_summary(plug_in, None, null)['excess']
    flagged = [bool(ood_hard.get(r.id)) for r in rows]
    total_w = math.fsum(w)
    hit = [int((pi >= 0.5) == bool(yi)) for pi, yi in zip(p, y, strict=True)]
    forced = math.fsum(wi * h for wi, h in zip(w, hit, strict=True)) / total_w
    kept_w = math.fsum(wi for wi, f in zip(w, flagged, strict=True) if not f)
    kept_acc = (math.fsum(wi * h for wi, h, f in zip(w, hit, flagged, strict=True) if not f) / kept_w
                if kept_w else None)
    d_prec = d_lo = d_hi = d_cov = None
    base_p, base_lo, base_hi = baseline.get('precision'), baseline.get('precision_lo'), baseline.get('precision_hi')
    if prec and prec['point'] is not None and base_p is not None:
        d_prec = base_p - prec['point']                                   # positive = the rung is worse
        if prec['lo'] is not None and prec['hi'] is not None and base_lo is not None and base_hi is not None:
            # interval arithmetic on two independent intervals: conservative, not a paired bootstrap
            d_lo, d_hi = base_lo - prec['hi'], base_hi - prec['lo']
    if cov and cov['point'] is not None and baseline.get('coverage') is not None:
        d_cov = baseline['coverage'] - cov['point']
    return ShiftRung(rung=rung, held_out=held, status='ok',
                     reason=None if tau is not None else 'no certified tau: precision and coverage undefined',
                     n_rows=len(rows), n_positive=pos, n_negative=neg, n_groups=len(group_rows(rows)),
                     n_lineages=len({info[r.id].lineage for r in rows}), excluded_shared_groups=excluded,
                     precision=_interval(prec), coverage=_interval(cov), ece_excess=excess,
                     ood_flag_rate=sum(flagged) / len(flagged), forced_accuracy=forced, ood_abstain_accuracy=kept_acc,
                     delta_precision=d_prec, delta_precision_lo=d_lo, delta_precision_hi=d_hi, delta_coverage=d_cov)


def _ood_hard(train: Sequence[Row], test: Sequence[Row], continuous: Sequence[int]) -> dict[str, bool]:
    if not continuous:
        return {}
    names = [f'c{j}' for j in continuous]
    spec = ood_fit([{n: r.x[j] for n, j in zip(names, continuous, strict=True)} for r in train], [1.0] * len(train),
                   names, [], [])
    return {r.id: any(f.startswith('hard:') for f in apply_spec(
        spec, {n: r.x[j] for n, j in zip(names, continuous, strict=True)})) for r in test}


def _holdout_rung(rung: str, held: str, held_rows: Sequence[Row], rest: Sequence[Row], info: Mapping[str, RowInfo],
                  cv: CVConfig, continuous: Sequence[int], tau: float | None, baseline: Mapping,
                  cfg: LadderConfig) -> ShiftRung:
    held_groups = {r.group for r in held_rows}
    train = [r for r in rest if r.group not in held_groups]
    excluded = len({r.group for r in rest} & held_groups)
    why = _floors(held_rows, HELD_MIN, 'held-out') + _floors(train, TRAIN_MIN, 'training')
    if len({r.group for r in train}) < max(cv.k_inner, 2):
        why.append(f'training groups {len({r.group for r in train})} < {max(cv.k_inner, 2)}')
    if why:
        return _insufficient(rung, held, '; '.join(why), held_rows, info, excluded)
    try:
        model = final_model(train, cv)
    except (CVError, RowError, ValueError) as exc:
        return _insufficient(rung, held, f'fit failed: {str(exc)[:200]}', held_rows, info, excluded)
    preds = {r.id: model.predict(r.x) for r in held_rows}
    return _score(rung, held, held_rows, preds, _ood_hard(train, held_rows, continuous), info, tau, baseline,
                  excluded, cfg)


def _within_toolchain(toolchain: str, rows: Sequence[Row], info: Mapping[str, RowInfo], cv: CVConfig,
                      continuous: Sequence[int], tau: float | None, baseline: Mapping, cfg: LadderConfig) -> ShiftRung:
    why = _floors(rows, HELD_MIN | {'rows': max(HELD_MIN['rows'], TRAIN_MIN['rows'])}, 'toolchain')
    groups = len({r.group for r in rows})
    if groups < cv.k_outer + cv.k_inner:
        why.append(f'toolchain groups {groups} < {cv.k_outer + cv.k_inner}')
    if why:
        return _insufficient(RUNG_CV, toolchain, '; '.join(why), rows, info)
    try:
        nested = nested_cv(rows, cv, ood_columns=continuous)
    except (CVError, RowError, ValueError) as exc:
        return _insufficient(RUNG_CV, toolchain, f'fit failed: {str(exc)[:200]}', rows, info)
    return _score(RUNG_CV, toolchain, rows, nested.oof, nested.ood_hard, info, tau, baseline, 0, cfg)


def run_ladder(rows: Sequence[Row], info: Mapping[str, RowInfo], *, kinds: Sequence[str], cv: CVConfig,
               tau: float | None, baseline: Mapping[str, float | None], cfg: LadderConfig | None = None) -> dict:
    """`rows` are the natural development rows of the headline run (already imputed); `info` maps row id to its
    toolchain, family and lineage; `baseline` carries the headline precision (point, lo, hi) and coverage."""
    cfg = cfg or LadderConfig()
    nat = sorted((r for r in rows if r.stratum == 'natural'), key=lambda r: r.id)
    continuous = [j for j, k in enumerate(kinds) if k == 'num']
    rungs: list[ShiftRung] = []
    toolchains = sorted({info[r.id].toolchain for r in nat})
    families = sorted({info[r.id].family for r in nat})
    for tc in toolchains[:MAX_UNITS]:
        rungs.append(_within_toolchain(tc, [r for r in nat if info[r.id].toolchain == tc], info, cv, continuous, tau,
                                       baseline, cfg))
    for tc in toolchains[:MAX_UNITS]:
        held = [r for r in nat if info[r.id].toolchain == tc]
        rest = [r for r in nat if info[r.id].toolchain != tc]
        if not rest:
            rungs.append(_insufficient(RUNG_TOOLCHAIN, tc, 'no other toolchain to train on', held, info))
            continue
        rungs.append(_holdout_rung(RUNG_TOOLCHAIN, tc, held, rest, info, cv, continuous, tau, baseline, cfg))
    for fam in families[:MAX_UNITS]:
        held = [r for r in nat if info[r.id].family == fam]
        rest = [r for r in nat if info[r.id].family != fam]
        if not rest:
            rungs.append(_insufficient(RUNG_FAMILY, fam, 'no other family to train on', held, info))
            continue
        rungs.append(_holdout_rung(RUNG_FAMILY, fam, held, rest, info, cv, continuous, tau, baseline, cfg))
    for kind, units in ((RUNG_CV, toolchains), (RUNG_TOOLCHAIN, toolchains), (RUNG_FAMILY, families)):
        if len(units) > MAX_UNITS:
            rungs.append(ShiftRung(rung=kind, held_out=None, status='insufficient-data',
                                   reason=f'{len(units) - MAX_UNITS} further unit(s) beyond the first {MAX_UNITS} were not run'))
    rungs.append(tier_w_rung())
    doc = ShiftLadder(contract=CONTRACT, tau=tau, baseline={k: v for k, v in sorted(baseline.items())},
                      note=FIRST_LOOK_NOTE, rungs=tuple(rungs))
    return doc.model_dump(mode='json')


def tier_w_rung() -> ShiftRung:
    return ShiftRung(rung=RUNG_TIER_W, held_out=None, status='not-run', reason=TIER_W_REASON)


def ladder_not_run(reason: str, tau: float | None = None) -> dict:
    """The ladder of a run that never reached a fit: every measurable rung is absent, the reason is recorded."""
    rungs = tuple(ShiftRung(rung=r, held_out=None, status='insufficient-data', reason=reason)
                  for r in (RUNG_CV, RUNG_TOOLCHAIN, RUNG_FAMILY)) + (tier_w_rung(),)
    return ShiftLadder(contract=CONTRACT, tau=tau, baseline={}, note=FIRST_LOOK_NOTE,
                       rungs=rungs).model_dump(mode='json')
