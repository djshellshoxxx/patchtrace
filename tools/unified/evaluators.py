"""Evaluators of the gates that read `unified-outcomes/1` (08-evaluation s1): G-U1 (A/A null), G-U2 (planted mutations) and G-U4 (determinism, symmetry).

Each returns `(status, reasons, observed)`; the gate report adds the gate's identity. Statuses follow `gates_u`: `fail` is a
verdict on data, `insufficient-data` means the data cannot decide (a pair without an outcome, fewer than 20 mutants in a
class), `pending` means a part of the corpus is not built yet. A missing outcome is never a pass, nothing is averaged
across pairs or classes, and a failure in any run is a failure. Thresholds are the [inf] values of 08 s1.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from typing import Any

from tools.unified.corpus import aa
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
    covered = {p.variant for p in pairs if p.role == 'P1'}
    waiting = [f'pending: P1:{kind} (no pair of this variant in the corpus manifest: not built, or not yet supplied)'
               for kind in aa.P1_KINDS if kind not in covered]
    observed['p1_variants'] = {kind: kind in covered for kind in aa.P1_KINDS}
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


FLIP = {'older-only': 'newer-only', 'newer-only': 'older-only'}
PAIRING = ('matched', 'older-only', 'newer-only')
NON_SEMANTIC = ('unchanged', 'cosmetic')
CHAIN_WAIT = ('pending: no 3-build chain (A-B, B-C and A-C over three distinct images of one project) is in the corpus '
              'manifest; P1 chains come from `corpus aa`, release chains need a third consecutive version per project '
              '(the catalogue has two)')


def _pairing(rows, mirror: bool) -> frozenset:
    if mirror:
        return frozenset((r.newer, r.older, FLIP.get(r.decision, r.decision)) for r in rows if r.decision in PAIRING)
    return frozenset((r.older, r.newer, r.decision) for r in rows if r.decision in PAIRING)


def g_u4(sets: Sequence[OutcomeSet], manifest: corpus_manifest.CorpusManifest | None = None) -> Result:
    """Equal row digests for the same pair across runs (two runs, Linux against Windows, permuted input), and the
    swapped orientation of a pair mirrors the forward one: the same matched set, older-only and newer-only trade places."""
    reasons: list[str] = []
    notes: list[str] = []
    compared: dict[str, str] = {}
    mirrored: dict[str, str] = {}
    not_comparable: dict[str, list[str]] = {}
    for pair_id in sorted({p.pair_id for s in sets for p in s.pairs}):
        runs = forward(sets, pair_id)
        buckets: dict[str, list[tuple[str, PairOutcome]]] = {}
        for run, outcome in runs:
            buckets.setdefault(outcome.labels_sha256, []).append((run, outcome))
        if len(buckets) > 1:
            not_comparable[pair_id] = [r for r, _ in runs]
            notes.append(f'{pair_id}: runs {", ".join(r for r, _ in runs)} built other image bytes '
                         '(label digests differ), not compared')
        for group in buckets.values():
            if len(group) < 2:
                continue
            same = len({o.rows_sha256 for _, o in group}) == 1
            compared[pair_id] = 'equal' if same and compared.get(pair_id) != 'differs' else 'differs'
            if not same:
                reasons.append(f'{pair_id}: the rows differ between runs {", ".join(r for r, _ in group)}')
        for run, back in ((s.run, p) for s in sets for p in s.pairs if p.pair_id == pair_id and p.orientation == 'swapped'):
            ahead = next((o for r, o in runs if r == run), None)
            if ahead is None:
                continue
            ok = _pairing(ahead.rows, True) == _pairing(back.rows, False)
            mirrored[pair_id] = 'mirrored' if ok else 'not-mirrored'
            if not ok:
                reasons.append(f'{pair_id} run {run}: the swapped orientation is not the mirror image of the forward one')
    chain_reasons, chain_notes, chains = _chains(manifest, sets)
    rows_all = [(s.run, p.pair_id, r) for s in sets for p in s.pairs for r in p.rows]
    pseudo = [f'{pid} run {run}: a COS-PSEUDO/1 row holds a cheap-tier semantic delta'
              for run, pid, r in rows_all if r.proof == 'COS-PSEUDO/1' and r.cheap_semantic]
    observed = {'compared': compared, 'mirrored': mirrored, 'not_comparable': not_comparable, 'chains': chains,
                'pseudo_rows': sum(1 for _, _, r in rows_all if r.proof == 'COS-PSEUDO/1'), 'pseudo_violations': len(pseudo)}
    if reasons or chain_reasons or pseudo:
        return 'fail', [*reasons, *chain_reasons, *pseudo], observed
    if not compared and not mirrored:
        return 'insufficient-data', ['no pair has two runs over the same bytes or a swapped orientation to compare',
                                     *notes], observed
    if not chains['found']:
        return 'pending', [*notes, CHAIN_WAIT], observed
    if chain_notes or not chains['composable']:
        return 'insufficient-data', [*notes, *chain_notes, *([] if chains['composable'] else [
            'no function is cosmetic or unchanged on both legs of a chain, so the check had nothing to compose'])], observed
    return 'pass', notes, observed


def _rows_by(rows, side: str) -> dict:
    """Matched one-to-one rows keyed by the RVA of the named side."""
    return {getattr(r, side)[0]: r for r in rows if r.decision == 'matched' and len(r.older) == 1 and len(r.newer) == 1}


def find_chains(manifest: corpus_manifest.CorpusManifest | None) -> list[tuple[str, str, str]]:
    """(A-B, B-C, A-C) pair ids over three distinct images of one project, read from the image digests."""
    if manifest is None:
        return []
    pairs = sorted((p for p in manifest.pairs if p.gated and not p.x_vs_x), key=lambda p: p.pair_id)
    found = []
    for ab in pairs:
        for bc in (p for p in pairs if p.project == ab.project and p.older.sha256 == ab.newer.sha256):
            for ac in (p for p in pairs if p.project == ab.project and p.older.sha256 == ab.older.sha256
                       and p.newer.sha256 == bc.newer.sha256):
                if len({ab.older.sha256, ab.newer.sha256, bc.newer.sha256}) == 3:
                    found.append((ab.pair_id, bc.pair_id, ac.pair_id))
    return found


def _chain_run(ab: PairOutcome, bc: PairOutcome, ac: PairOutcome) -> tuple[int, list[str]]:
    """(functions that are non-semantic on both legs, those whose A-C verdict is `material`)."""
    by_old_bc, by_old_ac = _rows_by(bc.rows, 'older'), _rows_by(ac.rows, 'older')
    composable, material = 0, []
    for r1 in _rows_by(ab.rows, 'older').values():
        r2, r3 = by_old_bc.get(r1.newer[0]), by_old_ac.get(r1.older[0])
        if r2 is None or r3 is None or r1.materiality not in NON_SEMANTIC or r2.materiality not in NON_SEMANTIC \
                or r3.newer != r2.newer:
            continue
        composable += 1
        if r3.materiality == 'material':
            material.append(f'{r1.older[0]:#x}')
    return composable, material


def _chains(manifest, sets: Sequence[OutcomeSet]) -> tuple[list[str], list[str], dict[str, Any]]:
    found = find_chains(manifest)
    reasons: list[str] = []
    notes: list[str] = []
    state: dict[str, str] = {}
    composable = 0
    for legs in found:
        name = '|'.join(legs)
        got = [dict(forward(sets, pid)) for pid in legs]
        runs = sorted(set(got[0]) & set(got[1]) & set(got[2]))
        if not runs:
            notes.append(f'chain {name}: no run holds all three legs, not evaluated')
            state[name] = 'missing'
            continue
        state[name] = 'pass'
        for run in runs:
            n, material = _chain_run(got[0][run], got[1][run], got[2][run])
            composable += n
            if material:
                state[name] = 'fail'
                reasons.append(f'chain {name} run {run}: cosmetic from A to B and from B to C yet material from A to C '
                               f'at {", ".join(material[:5])}')
    return reasons, notes, {'found': len(found), 'composable': composable, 'evaluated': dict(sorted(state.items()))}
