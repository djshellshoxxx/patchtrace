"""Evaluators of the gates that read the truth of rows: G-U3 (L1 precision), G-U6 (noise against legacy) and G-U7 (the
independence assumption), over `unified-outcomes/1` joined to the corpus manifest (08-evaluation s1).

Same contract as `evaluators`: `(status, reasons, observed)`, `fail` is a verdict on data, `insufficient-data` means the data
cannot decide, `blocked` means something outside the code. Only one-to-one rows with a known truth are counted (`unknown` is
not a vote); nothing is averaged across gates' strata; every interval resamples whole lineages (`cluster`, B = 2000). Each pair
is counted once, from the first run (by name) that holds it, because G-U4 already requires the runs to agree. Thresholds are
the [inf] values of 08 s1. A pair of the manifest without an outcome makes the gate `insufficient-data`, never a pass.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Sequence
from fractions import Fraction
from typing import Any

from tools.unified.corpus import manifest as corpus_manifest

from . import cluster
from .outcomes import OutcomeRow, OutcomeSet, PairOutcome

PRECISION_MIN = 0.995           # G-U3: matched-pair precision
PRECISION_CI_LOW_MIN = 0.99     # G-U3: lower bound of the lineage-cluster interval
PASS_DEMOTE_BELOW = 0.98        # G-U3: a pass whose interval starts below this is demoted one tier
FALSE_LEAD_REDUCTION_MIN = Fraction(1, 5)  # G-U6: material false leads fewer than the legacy tool's by at least this share
MIN_PAIR_ROWS = 30              # G-U7: classes with fewer B+B rows are insufficient-data
ERROR_RATIO_MAX = 2.0           # G-U7: B+B error rate against the tier-A error rate
TIER_ORDER = 'MABCW'
G6_ROLES = ('mutation', 'P0', 'P1')
BINDIFF_BLOCK = ('the BinDiff oracle part of G-U3 (MD index to 12 decimals on functions with n_bb >= 5, agreement on tier A/B '
                 'pairs) is not run: tools/bindiff_pin.json has no verified assets')
Result = tuple[str, list[str], dict[str, Any]]


def first_run(sets: Sequence[OutcomeSet], pair_id: str) -> PairOutcome | None:
    found = sorted(((s.run, p) for s in sets for p in s.pairs if p.pair_id == pair_id and p.orientation == 'forward'),
                   key=lambda item: item[0])
    return found[0][1] if found else None


def best_tier(row: OutcomeRow) -> str:
    tiers = [b.tier for b in row.basis if b.tier in TIER_ORDER]
    return min(tiers, key=TIER_ORDER.index) if tiers else ''


def _known(row: OutcomeRow) -> bool:
    return row.decision == 'matched' and row.truth in ('right', 'wrong')


def _outcomes(pairs: Sequence, sets: Sequence[OutcomeSet]) -> tuple[list[tuple[Any, PairOutcome]], list[str]]:
    have, missing = [], []
    for pair in pairs:
        got = first_run(sets, pair.pair_id)
        if got is None:
            missing.append(pair.pair_id)
        else:
            have.append((pair, got))
    return have, missing


def _rate_stat(sums: tuple[float, ...]) -> float | None:
    return sums[0] / sums[1] if sums and sums[1] else None


# ---- G-U3 -----------------------------------------------------------------------------------------------------------------

def _g3_precision(have: list[tuple[Any, PairOutcome]]) -> tuple[dict[str, list[float]], dict[str, dict[str, list[float]]]]:
    overall: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0])
    per_pass: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(lambda: [0.0, 0.0]))
    for pair, outcome in have:
        for row in (r for r in outcome.rows if _known(r)):
            ok = row.truth == 'right'
            overall[pair.lineage][0] += ok
            overall[pair.lineage][1] += 1
            for key in sorted({f'{b.source}:{b.step}' for b in row.basis}):
                per_pass[key][pair.lineage][0] += ok
                per_pass[key][pair.lineage][1] += 1
    return overall, per_pass


def _g3_aa(have: list[tuple[Any, PairOutcome]]) -> dict[str, Any]:
    contradicted, ghidriff = [], []
    for pair, outcome in have:
        contradicted += [f'{pair.pair_id} {r.older[0]:#x}->{r.newer[0]:#x}' for r in outcome.rows
                         if _known(r) and r.truth == 'wrong' and best_tier(r) == 'A']
        ghidriff += [f'{pair.pair_id} {r.older}->{r.newer} is {r.decision}' for r in outcome.rows
                     if r.ghidriff_exact and r.decision not in ('matched', 'contested')]
    return {'tier_a_contradicted': contradicted, 'ghidriff_exact_unmatched': ghidriff}


def g_u3(manifest: corpus_manifest.CorpusManifest, sets: Sequence[OutcomeSet]) -> Result:
    release = [p for p in manifest.pairs if 'G-U3' in p.gates and p.gated]
    aa = [p for p in manifest.pairs if p.role in ('P0', 'P1') and p.gated]
    have, missing = _outcomes(release, sets)
    aa_have, aa_missing = _outcomes(aa, sets)
    reasons = [f'{pid}: no outcome supplied for this pair' for pid in (*missing, *aa_missing)]
    if not release:
        reasons.append('the corpus manifest has no pair that feeds G-U3')
    overall, per_pass = _g3_precision(have)
    total = int(sum(v[1] for v in overall.values()))
    interval = cluster.ci(overall, _rate_stat, seed='G-U3') if total else None
    table = {}
    for key in sorted(per_pass):
        ci = cluster.ci(per_pass[key], _rate_stat, seed=f'G-U3:{key}')
        n = int(sum(v[1] for v in per_pass[key].values()))
        demote = key.startswith('pt-ladder:') and ci['lo'] is not None and ci['lo'] < PASS_DEMOTE_BELOW
        table[key] = {'rows': n, 'precision': ci['point'], 'ci_low': ci['lo'], 'ci_high': ci['hi'], 'demote': demote}
    aa_facts = _g3_aa(aa_have)
    observed = {'rows': total, 'precision': interval, 'per_pass': table,
                'demote': [k for k, v in table.items() if v['demote']], **aa_facts,
                'oracle': 'blocked', 'thresholds': {'precision': PRECISION_MIN, 'ci_low': PRECISION_CI_LOW_MIN,
                                                    'demote_below': PASS_DEMOTE_BELOW}}
    failed = False
    if interval and interval['point'] is not None:
        if interval['point'] < PRECISION_MIN:
            failed = True
            reasons.append(f'matched-pair precision {interval["point"]:.4f} is below {PRECISION_MIN} ({total} rows)')
        if interval['lo'] is not None and interval['lo'] < PRECISION_CI_LOW_MIN:
            failed = True
            reasons.append(f'the lower bound {interval["lo"]:.4f} of the lineage-cluster interval is below '
                           f'{PRECISION_CI_LOW_MIN}')
    for item in aa_facts['tier_a_contradicted']:
        failed = True
        reasons.append(f'tier-A pair contradicted by the truth on an A/A pair: {item}')
    for item in aa_facts['ghidriff_exact_unmatched']:
        failed = True
        reasons.append(f'Ghidriff SymbolsHash/ExactBytes pair neither matched nor contested on an A/A pair: {item}')
    if failed:
        return 'fail', reasons, observed
    if not total or missing or aa_missing or not release:
        return 'insufficient-data', reasons or ['no one-to-one row with a known truth'], observed
    if interval['anti_conservative']:
        return 'insufficient-data', [f'{interval["groups"]} lineages: fewer than {cluster.MIN_GROUPS_HEADLINE}, the '
                                     'interval is anti-conservative and cannot decide'], observed
    return 'blocked', [BINDIFF_BLOCK, *[f'demote one tier: {k}' for k in observed['demote']]], observed


# ---- G-U6 -----------------------------------------------------------------------------------------------------------------

def _planted_row(outcome: PairOutcome) -> OutcomeRow | None:
    planted = outcome.planted
    return None if planted is None else next((r for r in outcome.rows if planted.older_rva in r.older), None)


def _g6_counts(have: list[tuple[Any, PairOutcome]], tool: str) -> dict[str, list[float]]:
    """Per lineage, over the pairs the tool ran on: [unified false leads, tool false leads, planted, unified hits, tool hits]."""
    groups: dict[str, list[float]] = defaultdict(lambda: [0.0] * 5)
    for pair, outcome in have:
        if tool not in outcome.legacy_tools:
            continue
        cell = groups[pair.lineage]
        for row in (r for r in outcome.rows if r.edited == 'not-edited'):
            cell[0] += row.materiality == 'material'
            cell[1] += tool in row.legacy
        row = _planted_row(outcome)
        if outcome.planted is not None:
            cell[2] += 1
            cell[3] += row is not None and row.materiality in ('material', 'review')
            cell[4] += row is not None and tool in row.legacy
    return groups


def _reduction(sums: tuple[float, ...]) -> float | None:
    return 1 - sums[0] / sums[1] if sums and sums[1] else None


def g_u6(manifest: corpus_manifest.CorpusManifest, sets: Sequence[OutcomeSet]) -> Result:
    pairs = [p for p in manifest.pairs if p.role in G6_ROLES and p.gated]
    have, missing = _outcomes(pairs, sets)
    reasons = [f'{pid}: no outcome supplied for this pair' for pid in missing]
    tools = sorted({t for _, o in have for t in o.legacy_tools})
    per_tool: dict[str, Any] = {}
    failed = undecided = False
    for tool in tools:
        groups = _g6_counts(have, tool)
        total = [int(sum(g[i] for g in groups.values())) for i in range(5)]
        interval = cluster.ci(groups, _reduction, seed=f'G-U6:{tool}')
        fl_u, fl_t, planted, hit_u, hit_t = total
        per_tool[tool] = {'pairs': sum(1 for _, o in have if tool in o.legacy_tools), 'false_leads_unified': fl_u,
                          'false_leads_legacy': fl_t, 'reduction': interval, 'planted': planted,
                          'recall_unified': cluster.rate(hit_u, planted), 'recall_legacy': cluster.rate(hit_t, planted)}
        if interval['anti_conservative']:
            undecided = True
            reasons.append(f'{tool}: {interval["groups"]} lineages, fewer than {cluster.MIN_GROUPS_HEADLINE}: the '
                           'interval is anti-conservative and cannot decide')
        if not fl_t:
            if fl_u:
                failed = True
                reasons.append(f'{tool}: no false lead, the unified result has {fl_u}')
            else:
                undecided = True
                reasons.append(f'{tool}: no false lead on either side, a {float(FALSE_LEAD_REDUCTION_MIN):.0%} reduction cannot be shown')
            continue
        if fl_t - fl_u < FALSE_LEAD_REDUCTION_MIN * fl_t:
            failed = True
            reasons.append(f'{tool}: material false leads {fl_u} against {fl_t} is a reduction of {1 - fl_u / fl_t:.1%}, '
                           f'below {float(FALSE_LEAD_REDUCTION_MIN):.0%}')
        if hit_u < hit_t:
            failed = True
            reasons.append(f'{tool}: planted recall fell, {hit_u} of {planted} against {hit_t} for the legacy output')
    observed = {'legacy_tools': tools, 'per_tool': per_tool,
                'not_supplied': [t for t in ('ghidriff', 'bindiff', 'rz-diff') if t not in tools],
                'thresholds': {'reduction': float(FALSE_LEAD_REDUCTION_MIN)}}
    if failed:
        return 'fail', reasons, observed
    if missing or undecided or not tools or not pairs:
        return 'insufficient-data', reasons or ['no legacy output was supplied with the outcomes'], observed
    return 'pass', [], observed


# ---- G-U7 -----------------------------------------------------------------------------------------------------------------

def class_key(row: OutcomeRow) -> str | None:
    """`K03+K07|E-BODY+E-CFG` for a row whose whole support is exactly two tier-B atoms, else None."""
    if len(row.basis) != 2 or any(b.tier != 'B' for b in row.basis):
        return None
    first, second = sorted(row.basis, key=lambda b: (b.component, b.cls))
    return f'{first.component}+{second.component}|{first.cls}+{second.cls}'


def g_u7(manifest: corpus_manifest.CorpusManifest, sets: Sequence[OutcomeSet]) -> Result:
    pairs = [p for p in manifest.pairs if 'G-U7' in p.gates and p.gated]
    have, missing = _outcomes(pairs, sets)
    reasons = [f'{pid}: no outcome supplied for this pair' for pid in missing]
    classes: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(lambda: [0.0, 0.0]))
    tier_a: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0])
    for pair, outcome in have:
        for row in (r for r in outcome.rows if _known(r)):
            wrong = row.truth == 'wrong'
            key = class_key(row)
            cell = tier_a[pair.lineage] if best_tier(row) == 'A' else classes[key][pair.lineage] if key else None
            if cell is not None:
                cell[0] += wrong
                cell[1] += 1
    a_rows = int(sum(v[1] for v in tier_a.values()))
    a_rate = sum(v[0] for v in tier_a.values()) / a_rows if a_rows else None
    table: dict[str, Any] = {}
    failed = short = False
    for key in sorted(classes):
        n = int(sum(v[1] for v in classes[key].values()))
        if n < MIN_PAIR_ROWS:
            short = True
            table[key] = {'rows': n, 'status': 'insufficient-data'}
            reasons.append(f'{key}: {n} B+B rows, {MIN_PAIR_ROWS} are needed; never assumed safe')
            continue
        ci = cluster.ci(classes[key], _rate_stat, seed=f'G-U7:{key}')
        bound = None if a_rate is None else ERROR_RATIO_MAX * a_rate
        bad = bound is not None and ci['point'] > bound
        failed |= bad
        thin = not bad and ci['anti_conservative']
        short |= thin
        table[key] = {'rows': n, 'error_rate': ci['point'], 'ci_low': ci['lo'], 'ci_high': ci['hi'],
                      'bound': None if bound is None else round(bound, 6),
                      'status': 'fail' if bad else 'insufficient-data' if thin else 'pass'}
        if thin:
            reasons.append(f'{key}: {ci["groups"]} lineages, fewer than {cluster.MIN_GROUPS_HEADLINE}: the interval is '
                           'anti-conservative; never assumed safe')
        if bad:
            reasons.append(f'{key}: B+B error rate {ci["point"]:.4f} exceeds {ERROR_RATIO_MAX:g}x the tier-A rate '
                           f'{a_rate:.4f}; join these two components by configuration')
    observed = {'tier_a': {'rows': a_rows, 'error_rate': None if a_rate is None else round(a_rate, 6)},
                'class_pairs': table, 'thresholds': {'ratio': ERROR_RATIO_MAX, 'min_rows': MIN_PAIR_ROWS}}
    if failed:
        return 'fail', reasons, observed
    if missing or short or not table or a_rate is None or not pairs:
        return 'insufficient-data', reasons or ['no tier-A row with a known truth, or no B+B row'], observed
    return 'pass', [], observed


EVALUATORS: dict[str, Callable[[corpus_manifest.CorpusManifest, Sequence[OutcomeSet]], Result]] = {
    'G-U3': g_u3, 'G-U6': g_u6, 'G-U7': g_u7}
