"""`tier-r-report/1` blocks from engine runs: per-label cells, rank blocks, coverage, paired deltas (LBL-11; plan s7.1).

Everything is per engine; nothing is ever pooled across engines or across the `real-fix` and `planted` populations. The
resampling unit is the lineage (`boot`, B = `boot.B_COUNT`, 500 in smoke), so an interval from fewer than 30 lineages
carries `anti_conservative` and a delta is never called non-inferior on it. Metrics are over completed runs only; blocked
and failed runs appear in `coverage`.

Fix set: a CVE/release card names its changed functions in `case.declared_changed` (population `real-fix`); a semantic
mutant names its target in `case.mutation_case.target_function` (population `planted`). A pair without a fix function
(controls, A/A, noise, cosmetic mutants) has no rank observation. The pair's rank is the best midrank among its fix
functions in the engine's flagged list; nDCG gives the fix gain 2^2 - 1 and every other truth-changed function gain 2^1 - 1.
"""
from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import NamedTuple

from .. import bootstrap
from ..common import r12
from ..tier_r import contracts as C
from . import boot, change, curves, descriptors, identity, power, rank
from .protocols import ENGINES, EnginePairs

NON_INFERIORITY_MARGIN = -0.02
FEW_LINEAGES = bootstrap.MIN_GROUPS_HEADLINE


class Run(NamedTuple):
    labels: C.KnownAnswerLabels
    pairs: EnginePairs


@dataclass(frozen=True)
class RankObs:
    pair_id: str
    lineage: str
    rank: float | None
    pool: int
    hit: dict[int, float]
    rr: float
    ndcg: float | None


@dataclass(frozen=True)
class DeltaSummary:
    """Paired difference (treatment - baseline) of one metric over pairs both engines completed."""
    metric: str
    pairs: int
    lineages: int
    delta: C.Interval
    sd: float | None             # of per-lineage mean differences
    min_detectable: float | None  # two-sided alpha 0.05, power 0.8, at this n and sd
    power: float | None           # of the observed difference at this n and sd
    non_inferior: bool | None     # lower bound > NON_INFERIORITY_MARGIN; None when anti-conservative or undefined


def to_interval(iv: boot.Interval) -> C.Interval:
    if iv.point is None:
        return C.Interval(undefined=True, anti_conservative=iv.anti_conservative)
    return C.Interval(point=r12(iv.point), lo=None if iv.lo is None else r12(iv.lo),
                      hi=None if iv.hi is None else r12(iv.hi), anti_conservative=iv.anti_conservative)


def ratio_interval(per_lineage: Mapping[str, tuple[int, int]], b_count: int, seed) -> boot.Interval:
    """Lineage-bootstrap interval of sum(numerator) / sum(denominator); per_lineage = lineage -> (num, den)."""
    groups = sorted(per_lineage)

    def ratio(chosen: Iterable[str]) -> float | None:
        num = den = 0
        for g in chosen:
            num += per_lineage[g][0]
            den += per_lineage[g][1]
        return num / den if den else None

    vals = [v for draw in bootstrap.draws(groups, b_count, seed) if (v := ratio(draw)) is not None]
    return boot._finish(vals, ratio(groups), b_count, 0.05, len(groups))


# ---- fix sets and rank observations -------------------------------------------------------------------------------

def fix_set(labels: C.KnownAnswerLabels) -> tuple[str | None, tuple[C.FunctionLabel, ...]]:
    case = labels.case
    mutation = case.get('mutation_case')
    if isinstance(mutation, Mapping):
        population, names = ('planted', {mutation.get('target_function')}) if mutation.get('kind') == 'semantic' \
            else (None, set())
    else:
        declared = case.get('declared_changed')
        population, names = 'real-fix', set(declared) if isinstance(declared, list) else set()
    fix = tuple(f for f in labels.functions
                if f.name in names and f.label == 'changed' and f.identity == 'same')
    return (population, fix) if fix else (None, ())


def rank_observation(run: Run, fix: Sequence[C.FunctionLabel]) -> RankObs:
    ranks = change.flagged_ranks(run.pairs)

    def rank_of(f: C.FunctionLabel) -> float | None:
        return ranks.get((f.old_rva, f.new_rva))

    fix_keys = {(f.old_rva, f.new_rva) for f in fix}
    found = [r for f in fix if (r := rank_of(f)) is not None]
    best = min(found) if found else None
    relevant = [(rank_of(f), 2 if (f.old_rva, f.new_rva) in fix_keys else 1)
                for f in run.labels.functions if f.label == 'changed' and f.identity == 'same']
    m = rank.pair_metrics(best, relevant)
    return RankObs(run.labels.pair_id, run.labels.lineage, best, change.pool_size(run.pairs),
                   {k: m[f'hit@{k}'] for k in rank.HIT_KS}, m['rr'], m['ndcg'])


def rank_observations(runs: Sequence[Run]) -> dict[str, list[RankObs]]:
    """population -> observations (never pooled)."""
    out: dict[str, list[RankObs]] = defaultdict(list)
    for run in runs:
        population, fix = fix_set(run.labels)
        if population is not None:
            out[population].append(rank_observation(run, fix))
    return out


def _lineage_values(obs: Sequence[RankObs], value: Callable[[RankObs], float | None]) -> boot.Obs:
    return {o.pair_id: (o.lineage, v) for o in obs if (v := value(o)) is not None}


def rank_block(population: str, obs: Sequence[RankObs], b_count: int, seed: str) -> C.RankBlock:
    def interval(name: str, value: Callable[[RankObs], float | None]) -> C.Interval:
        return to_interval(boot.lineage_bootstrap(_lineage_values(obs, value), b_count, f'{seed}|{name}'))

    summary = rank.summarise([o.rank for o in obs], [o.pool for o in obs])
    return C.RankBlock(
        population=population, pairs=len(obs), lineages=len({o.lineage for o in obs}),
        pool_median=summary['pool_median'], found_in_pool=summary['found_in_pool'],
        hit_at={str(k): interval(f'hit@{k}', lambda o, k=k: o.hit[k]) for k in rank.HIT_KS},
        mrr=interval('rr', lambda o: o.rr),
        mean_rank=None if summary['mean_rank'] is None else r12(summary['mean_rank']),
        ndcg10=interval('ndcg', lambda o: o.ndcg))


# ---- paired deltas -----------------------------------------------------------------------------------------------

def metric_value(metric: str) -> Callable[[RankObs], float | None]:
    if metric.startswith('hit@'):
        k = int(metric[4:])
        return lambda o: o.hit[k]
    return {'rr': lambda o: o.rr, 'ndcg': lambda o: o.ndcg}[metric]


def paired_delta(treatment: Sequence[RankObs], baseline: Sequence[RankObs], metric: str, b_count: int,
                 seed: str, margin: float = NON_INFERIORITY_MARGIN) -> DeltaSummary:
    """Same lineage draws for both arms; only pairs both completed and with a defined value in both arms count."""
    value = metric_value(metric)
    t, b = _lineage_values(treatment, value), _lineage_values(baseline, value)
    common = sorted(set(t) & set(b))
    t, b = {i: t[i] for i in common}, {i: b[i] for i in common}
    iv = boot.paired_delta_bootstrap(t, b, b_count, f'{seed}|{metric}')
    per_lineage: dict[str, list[float]] = defaultdict(list)
    for i in common:
        per_lineage[t[i][0]].append(t[i][1] - b[i][1])
    means = [math.fsum(v) / len(v) for v in per_lineage.values()]
    sd = power.lineage_sd(means)
    n = len(means)
    return DeltaSummary(
        metric=metric, pairs=len(common), lineages=n, delta=to_interval(iv),
        sd=None if sd is None else r12(sd),
        min_detectable=None if sd is None else r12(power.min_detectable_delta(n, sd)),
        power=None if sd is None or iv.point is None else r12(power.power_for_delta(iv.point, n, sd)),
        non_inferior=boot.non_inferior(iv, margin))


# ---- blocks -----------------------------------------------------------------------------------------------------

def label_cells(runs: Sequence[Run], b_count: int, seed: str) -> dict[str, C.LabelCell]:
    """truth label -> cell, over the given runs of one engine and stratum (labels with no record are left out)."""
    per_run = [(r.labels.lineage, change.count_by_label(identity.classify(r.labels.functions, r.pairs)))
               for r in runs]
    total = change.merge_counts([c for _, c in per_run])
    cells = {}
    for label, count in total.items():
        if not any(count._tuple()):
            continue
        per_lineage: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for lineage, counts in per_run:
            per_lineage[lineage][0] += counts[label].flagged
            per_lineage[lineage][1] += counts[label].paired_correct
        iv = ratio_interval({g: (v[0], v[1]) for g, v in per_lineage.items()}, b_count, f'{seed}|{label}')
        cells[label] = C.LabelCell(paired_correct=count.paired_correct, paired_wrong=count.paired_wrong,
                                   unpaired=count.unpaired, abstained=count.abstained, flagged=count.flagged,
                                   rate=to_interval(iv))
    return cells


def coverage_rows(attempts: Iterable[tuple[str, str, str]]) -> tuple[C.CoverageRow, ...]:
    """attempts = (engine, stratum, status) per pair and engine; status in ok / blocked / failed."""
    tally: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: dict.fromkeys(('ok', 'blocked', 'failed'), 0))
    for engine, stratum, status in attempts:
        tally[(engine, stratum)][status] += 1
    order = {e: i for i, e in enumerate(ENGINES)}
    return tuple(C.CoverageRow(engine=e, stratum=s, attempted=sum(t.values()), completed=t['ok'], blocked=t['blocked'],
                               failed=t['failed'])
                 for (e, s), t in sorted(tally.items(), key=lambda kv: (order[kv[0][0]], kv[0][1])))


def scope_ids(docs: Iterable[C.KnownAnswerLabels], symbols: str) -> tuple[str, ...]:
    """Closed-vocabulary caveats the evaluator itself can establish (the claim text is the report layer's)."""
    docs = list(docs)
    ids = {'no-windows-system-binaries'}
    if len({d.lineage for d in docs}) < FEW_LINEAGES:
        ids.add('few-lineages')
    if symbols == 'hidden':
        ids.add('symbols-hidden-only')
    if any(d.stratum == 'mutation' for d in docs):
        ids.add('planted-changes-synthetic')
    return tuple(sorted(ids))


def shift_block(docs: Sequence[C.KnownAnswerLabels], shift_lineages: Collection[str]) -> C.ShiftBlock | None:
    """Descriptors of the declared shift lineages against the size range of all the others; None without a shift set."""
    shifted = [d for d in docs if d.lineage in shift_lineages]
    rest = [d for d in docs if d.lineage not in shift_lineages]
    return descriptors.shift_block(shifted, descriptors.reference_size_range(rest)) if shifted and rest else None


def build_blocks(docs: Sequence[C.KnownAnswerLabels], runs_by_engine: Mapping[str, Sequence[Run]],
                 attempts: Iterable[tuple[str, str, str]], *, symbols: str, shift_lineages: Collection[str] = (),
                 b_count: int = boot.B_COUNT) -> tuple[dict, dict]:
    """(report fields, paired deltas). Fields are plain JSON data ready for `TierRReport`; deltas are keyed
    stratum -> population -> 'a vs b' -> metric (engines in contract order, a before b)."""
    order = {e: i for i, e in enumerate(ENGINES)}
    labels_block: dict = {}
    rank_block_: dict = {}
    curve_blocks = []
    observed: dict[tuple[str, str], dict[str, list[RankObs]]] = defaultdict(dict)  # (stratum, population) -> engine
    for engine in sorted(runs_by_engine, key=order.__getitem__):
        runs = runs_by_engine[engine]
        by_stratum: dict[str, list[Run]] = defaultdict(list)
        for run in runs:
            by_stratum[run.labels.stratum].append(run)
        for stratum in sorted(by_stratum):
            seed = f'tier-r-report/1|{stratum}|{engine}'
            cells = label_cells(by_stratum[stratum], b_count, seed)
            if cells:
                labels_block.setdefault(stratum, {})[engine] = {k: v.model_dump(mode='json') for k, v in cells.items()}
            populations = rank_observations(by_stratum[stratum])
            if len(populations) > 1:
                raise C.ContractError(f'stratum {stratum} mixes populations {sorted(populations)}; never pooled')
            for population, obs in populations.items():
                rank_block_.setdefault(stratum, {})[engine] = rank_block(population, obs, b_count, seed).model_dump(
                    mode='json')
                observed[(stratum, population)][engine] = obs
        curve = curves.native_precision_curve(engine, runs)
        if curve is not None:
            curve_blocks.append(curve.model_dump(mode='json'))
    deltas: dict = {}
    for (stratum, population), per_engine in sorted(observed.items()):
        names = sorted(per_engine, key=order.__getitem__)
        for i, a in enumerate(names):
            for b in names[i + 1:]:
                deltas.setdefault(stratum, {}).setdefault(population, {})[f'{a} vs {b}'] = {
                    m: paired_delta(per_engine[a], per_engine[b], m, b_count, f'tier-r-report/1|{stratum}|{a} vs {b}')
                    for m in ('hit@10', 'ndcg')}
    fields = {'curves': curve_blocks, 'coverage': [c.model_dump(mode='json') for c in coverage_rows(attempts)],
              'lineages': len({d.lineage for d in docs}), 'scope_ids': list(scope_ids(docs, symbols))}
    shift = shift_block(docs, shift_lineages)
    if shift is not None:
        fields['shift'] = shift.model_dump(mode='json')
    if labels_block:
        fields['labels'] = labels_block
    if rank_block_:
        fields['rank'] = rank_block_
    return fields, deltas
