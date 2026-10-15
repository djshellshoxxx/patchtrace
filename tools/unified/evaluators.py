"""Evaluators of the gates that read `unified-outcomes/1` (08-evaluation s1): G-U1 (A/A null) and G-U2 (planted mutations).

Each returns `(status, reasons, observed)`; the gate report adds the gate's identity. Statuses follow `gates_u`: `fail` is a
verdict on data, `insufficient-data` means the data cannot decide (a pair without an outcome, fewer than 20 mutants in a
class), `pending` means a part of the corpus is not built yet. A missing outcome is never a pass, nothing is averaged
across pairs or classes, and a failure in any run is a failure. Thresholds are the [inf] values of 08 s1.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from typing import Any

from tools.unified.corpus import manifest as corpus_manifest
from tools.unified.mutations import classes

from .outcomes import OutcomeSet, PairOutcome

REVIEW_MAX_FRACTION = 0.001         # P0: `review` <= 0.1 % of rows
RECALL_MIN = 0.95                   # per class
MIN_MUTANTS_PER_CLASS = 20
LEAKS = ('unchanged', 'cosmetic')
Result = tuple[str, list[str], dict[str, Any]]


def forward(sets: Sequence[OutcomeSet], pair_id: str) -> list[tuple[str, PairOutcome]]:
    """(run, outcome) for every run that has the pair in its recorded orientation."""
    return [(s.run, p) for s in sets for p in s.pairs if p.pair_id == pair_id and p.orientation == 'forward']


def _x_vs_x_problems(outcome: PairOutcome) -> list[str]:
    bad = Counter(f'{r.decision}/{r.materiality}' for r in outcome.rows
                  if not (r.decision == 'matched' and r.materiality == 'unchanged'))
    return [f'{n} rows {kind}' for kind, n in sorted(bad.items())]


def _aa_problems(role: str, outcome: PairOutcome) -> list[str]:
    counts = Counter(r.materiality for r in outcome.rows)
    out = []
    if counts['material']:
        out.append(f'{counts["material"]} material rows')
    if role == 'P0' and counts['review'] > REVIEW_MAX_FRACTION * len(outcome.rows):
        out.append(f'{counts["review"]} review rows of {len(outcome.rows)} (limit {REVIEW_MAX_FRACTION:.1%})')
    return out


def g_u1(manifest: corpus_manifest.CorpusManifest, sets: Sequence[OutcomeSet]) -> Result:
    pairs = [p for p in manifest.pairs if p.role in ('P0', 'P1') and p.gated]
    reasons: list[str] = []
    evaluated: dict[str, str] = {}
    failed = missing = False
    for pair in pairs:
        runs = forward(sets, pair.pair_id)
        if not runs:
            reasons.append(f'{pair.pair_id}: no outcome supplied for this A/A pair')
            evaluated[pair.pair_id], missing = 'missing', True
            continue
        state = 'pass'
        for run, outcome in runs:
            problems = ([f'no rows in the result of run {run}'] if not outcome.rows else
                        _x_vs_x_problems(outcome) if pair.x_vs_x else _aa_problems(pair.role, outcome))
            if not outcome.rows:
                missing, state = True, 'insufficient-data'
            elif problems:
                failed, state = True, 'fail'
            reasons += [f'{pair.pair_id} ({pair.role}{" X vs X" if pair.x_vs_x else ""}) run {run}: {p}' for p in problems]
        evaluated[pair.pair_id] = state
    if not pairs:
        reasons.append('the corpus manifest has no gated A/A pair (P0 or P1)')
    observed = {'evaluated': dict(sorted(evaluated.items())), 'p2_not_gated': sum(1 for p in manifest.pairs if p.role == 'P2')}
    waiting = [f'pending: {p.item} ({p.reason.split(";")[0]})' for p in manifest.pending if p.item.startswith('P1:')]
    if failed:
        return 'fail', reasons, observed
    if missing or not pairs:
        return 'insufficient-data', reasons, observed
    return ('pending' if waiting else 'pass'), waiting, observed


def _verdict(outcome: PairOutcome) -> str:
    """What the unified result says about the planted function: the materiality of the row that pairs it with its
    counterpart, `unpaired` when no row holds it, `mispaired` when its row pairs it with another function."""
    planted = outcome.planted
    row = next((r for r in outcome.rows if planted.older_rva in r.older), None)
    if row is None:
        return 'unpaired'
    return row.materiality if planted.newer_rva in row.newer else 'mispaired'


def g_u2(manifest: corpus_manifest.CorpusManifest, sets: Sequence[OutcomeSet]) -> Result:
    reasons: list[str] = []
    per_class: dict[str, dict[str, Any]] = {}
    failed = short = False
    for cls in classes.CLASSES:
        mutants = [p for p in manifest.pairs if p.mutation and p.mutation.unified_class == cls.id]
        seen = Counter()
        for pair in mutants:
            for run, outcome in forward(sets, pair.pair_id):
                if outcome.planted is None:
                    reasons.append(f'{pair.pair_id}: the outcome carries no planted function')
                    failed = True
                    continue
                verdict = _verdict(outcome)
                seen['runs'] += 1
                if verdict in LEAKS:
                    seen['leaks'] += 1
                    failed = True
                    reasons.append(f'{pair.pair_id} run {run}: leak, the planted function is {verdict} '
                                   '(a normaliser bug; becomes a fixture)')
                if verdict in pair.mutation.verdicts:
                    seen['detected'] += 1
                seen['mispaired'] += verdict == 'mispaired'
            seen['mutants'] += bool(forward(sets, pair.pair_id))
        n = seen['runs']
        recall = round(seen['detected'] / n, 4) if n else None
        per_class[cls.id] = {'manifest': len(mutants), 'mutants': seen['mutants'], 'detected': seen['detected'],
                             'leaks': seen['leaks'], 'mispaired': seen['mispaired'], 'recall': recall}
        if seen['mutants'] < MIN_MUTANTS_PER_CLASS:
            short = True
            reasons.append(f'{cls.id}: {seen["mutants"]} mutants with an outcome, {MIN_MUTANTS_PER_CLASS} are needed')
        elif recall is not None and recall < RECALL_MIN:
            failed = True
            reasons.append(f'{cls.id}: recall {recall:.1%} is below {RECALL_MIN:.0%} '
                           f'({seen["detected"]} of {n} in {sorted(set(_accepted(manifest, cls.id)))})')
    observed = {'classes': per_class}
    waiting = [f'pending: class {p.item.split(":", 1)[1]} ({p.reason.split(":")[0]})' for p in manifest.pending
               if p.item.startswith('mutation:')]
    if failed:
        return 'fail', reasons, observed
    if short:
        return 'insufficient-data', reasons, observed
    return ('pending' if waiting else 'pass'), waiting, observed


def _accepted(manifest: corpus_manifest.CorpusManifest, class_id: str) -> tuple[str, ...]:
    return tuple(v for p in manifest.pairs if p.mutation and p.mutation.unified_class == class_id for v in p.mutation.verdicts)
