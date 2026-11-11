"""LBL-11b: rank blocks, lineage bootstrap, paired deltas, curves, coverage and their wiring into tier-r-report/1."""
from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from tools.calibration.evalcore import curves, protocols, report
from tools.calibration.evalcore.protocols import EnginePair, EnginePairs
from tools.calibration.evalcore.report import RankObs, Run
from tools.calibration.tier_r import contracts as C
from tools.calibration.tier_r import evaluate as E

FIXTURE = Path(__file__).parent / 'fixtures' / 'known_answer' / 'synergy-1'
F07 = (0x1090, 0x1090)


def _labels() -> C.KnownAnswerLabels:
    return C.load_labels((FIXTURE / 'labels.json').read_bytes())


def _engine_docs() -> dict[str, dict]:
    doc = json.loads((FIXTURE / 'engines.json').read_text(encoding='utf-8'))
    return {e['engine']: e for e in doc['engines']}


def _output(name: str) -> E.EngineOutput:
    """Synthetic engine output rebuilt from the hand-written fixture rows (never live evidence)."""
    doc = _engine_docs()[name]
    paired = [r for r in doc['pairs'] if r['identity'] == 'paired']
    keyed = name == 'unified'
    return E.EngineOutput(
        name, 'ok', version=doc['version'],
        predictions=tuple(E.Prediction(r['old_rva'], r['new_rva'], r['flag'],
                                       None if r['native'] is None else round(r['native'] * 1000),
                                       old_name=r['order_key'][1] if r['order_key'] and not keyed else None,
                                       order_key=tuple(r['order_key']) if keyed and r['order_key'] else None)
                          for r in paired),
        new_only=frozenset(r['new_rva'] for r in doc['pairs'] if r['identity'] == 'unpaired'),
        implicit_unchanged=doc['implicit_unchanged'])


def _obs(pid: str, lineage: str, rk, *, pool: int = 5) -> RankObs:
    m = report.rank.pair_metrics(rk)
    return RankObs(pid, lineage, rk, pool, {k: m[f'hit@{k}'] for k in report.rank.HIT_KS}, m['rr'], m['ndcg'])


# ---- fix sets --------------------------------------------------------------------------------------------

def test_fix_set_card_names_declared_changed_functions():
    population, fix = report.fix_set(_labels())
    assert population == 'real-fix' and [f.name for f in fix] == ['read_len']


@pytest.mark.parametrize('case, expected', [
    ({'mutation_case': {'kind': 'semantic', 'target_function': 'read_len'}}, 'planted'),
    ({'mutation_case': {'kind': 'cosmetic', 'target_function': 'read_len'}}, None),
    ({'declared_changed': []}, None),
    ({}, None),
    ({'declared_changed': ['absent']}, None),
], ids=['planted', 'cosmetic-mutant', 'control', 'no-case', 'declared-but-absent'])
def test_fix_set_populations(case, expected):
    doc = _labels().model_dump(mode='json')
    doc['case'] = case
    population, fix = report.fix_set(C.KnownAnswerLabels.model_validate_json(C.dump_json(doc)))
    assert population == expected and bool(fix) == (expected is not None)


# ---- rank observation: the s5 numbers through the report path ------------------------------------------------

@pytest.mark.parametrize('engine, rk, hit1, hit3, rr, ndcg, pool', [
    ('ghidriff', 4, 0, 0, 0.25, 0.4307, 5), ('rz-diff', 3, 0, 1, 1 / 3, 0.5, 6), ('unified', 2, 0, 1, 0.5, 0.6309, 3)])
def test_rank_observation_matches_plan_s5(engine, rk, hit1, hit3, rr, ndcg, pool):
    labels = _labels()
    pairs = protocols.pairs_from_doc(_engine_docs()[engine])
    obs = report.rank_observation(Run(labels, pairs), report.fix_set(labels)[1])
    assert (obs.rank, obs.hit[1], obs.hit[3], obs.pool) == (rk, hit1, hit3, pool)
    assert obs.rr == pytest.approx(rr, abs=1e-12) and round(obs.ndcg, 4) == ndcg


def test_fix_not_flagged_is_not_found_in_pool():
    labels = _labels()
    pairs = EnginePairs('rz-diff', 'v', 'hidden', (EnginePair(0x1000, 0x1000, True, 0.5, (0.5,)),))
    obs = report.rank_observation(Run(labels, pairs), report.fix_set(labels)[1])
    assert (obs.rank, obs.hit[20], obs.rr, obs.ndcg) == (None, 0, 0.0, 0.0)


def test_wrongly_paired_fix_is_not_credited():
    labels = _labels()
    pairs = EnginePairs('rz-diff', 'v', 'hidden', (EnginePair(F07[0], 0x1000, True, 0.1, (0.1,)),))
    assert report.rank_observation(Run(labels, pairs), report.fix_set(labels)[1]).rank is None


# ---- rank block ----------------------------------------------------------------------------------------------

def test_rank_block_point_values_hand_computed():
    obs = [_obs('p1', 'A', 1), _obs('p2', 'B', 2), _obs('p3', 'C', 4), _obs('p4', 'D', None)]
    block = report.rank_block('planted', obs, 200, 'seed')
    assert (block.pairs, block.lineages, block.found_in_pool, block.pool_median) == (4, 4, 3, 5)
    assert block.mean_rank == pytest.approx(7 / 3, abs=1e-11)
    assert [block.hit_at[k].point for k in ('1', '3', '5', '10', '20')] == [0.25, 0.5, 0.75, 0.75, 0.75]
    assert block.mrr.point == pytest.approx((1 + 0.5 + 0.25) / 4, abs=1e-11)
    assert all(iv.anti_conservative for iv in (block.mrr, block.ndcg10, *block.hit_at.values()))
    for iv in block.hit_at.values():
        assert iv.lo <= iv.point <= iv.hi


def test_rank_block_is_byte_stable_and_seed_sensitive():
    obs = [_obs(f'p{i}', f'L{i % 7}', [1, 2, 3, None, 5][i % 5]) for i in range(20)]
    a = report.rank_block('real-fix', obs, 100, 's')
    assert a == report.rank_block('real-fix', obs, 100, 's')
    assert a != report.rank_block('real-fix', obs, 100, 't')


def test_thirty_lineages_are_not_anti_conservative():
    obs = [_obs(f'p{i}', f'L{i}', 1 + i % 3) for i in range(30)]
    assert not report.rank_block('planted', obs, 50, 's').mrr.anti_conservative
    assert report.rank_block('planted', obs[:29], 50, 's').mrr.anti_conservative


# ---- ratio interval --------------------------------------------------------------------------------------

def test_ratio_interval_pools_counts_not_rates():
    iv = report.ratio_interval({'A': (1, 2), 'B': (3, 4)}, 200, 's')
    assert iv.point == pytest.approx(4 / 6) and 0.5 <= iv.lo <= iv.point <= iv.hi <= 0.75 and iv.anti_conservative


def test_ratio_interval_undefined_without_denominator():
    iv = report.ratio_interval({'A': (0, 0)}, 50, 's')
    assert iv.point is None and report.to_interval(iv).undefined


# ---- paired deltas ---------------------------------------------------------------------------------------

def test_paired_delta_hand_computed():
    # per-lineage hit@1 differences are [1, 0, 1]: mean 2/3, sd sqrt(1/3), sd/sqrt(n) = 1/3
    t = [_obs('p1', 'A', 1), _obs('p2', 'B', 2), _obs('p3', 'C', 1)]
    b = [_obs('p1', 'A', 3), _obs('p2', 'B', 2), _obs('p3', 'C', 5)]
    got = report.paired_delta(t, b, 'hit@1', 200, 's')
    assert (got.pairs, got.lineages) == (3, 3) and got.delta.point == pytest.approx(2 / 3, abs=1e-11)
    assert got.sd == pytest.approx(math.sqrt(1 / 3), abs=1e-11)
    assert got.min_detectable == pytest.approx(2.8015851 / 3, abs=1e-6)  # (z_.975 + z_.8) * sd / sqrt(n)
    assert got.non_inferior is None  # three lineages: anti-conservative, never a claim
    assert 0 < got.power <= 1


def test_paired_delta_uses_only_common_pairs():
    t = [_obs('p1', 'A', 1), _obs('p2', 'B', 1)]
    b = [_obs('p2', 'B', 5), _obs('p9', 'C', 1)]
    got = report.paired_delta(t, b, 'hit@1', 50, 's')
    assert (got.pairs, got.lineages, got.delta.point) == (1, 1, 1.0) and got.sd is None and got.power is None


def test_paired_delta_non_inferior_needs_thirty_lineages():
    t = [_obs(f'p{i}', f'L{i}', 1) for i in range(30)]
    b = [_obs(f'p{i}', f'L{i}', 1) for i in range(30)]
    got = report.paired_delta(t, b, 'ndcg', 100, 's')
    assert got.delta.point == 0 and got.non_inferior is True and got.sd == 0


# ---- curves and coverage -------------------------------------------------------------------------------

def test_native_precision_curve_bins_hand_computed():
    labels = _labels()
    rows = (EnginePair(0x1000, 0x1000, False, 0.5), EnginePair(0x1010, 0x1020, True, 0.51, (0.51,)),  # wrong pair
            EnginePair(0x1030, 0x1030, False, 1.0), EnginePair(0x9000, 0x9000, False, 0.1),  # unlabelled: skipped
            EnginePair(0x1040, 0x1040, None, None))  # no native score: skipped
    block = curves.native_precision_curve('rz-diff', [(labels, EnginePairs('rz-diff', 'v', 'hidden', rows))])
    assert len(block.bins) == 15 and block.kind == 'native-precision'
    by_n = {i: (b.n, b.precision) for i, b in enumerate(block.bins) if b.n}
    assert by_n == {7: (2, 0.5), 14: (1, 1.0)}  # 0.5 and 0.51 share bin 7 = [7/15, 8/15)
    assert block.bins[0].precision is None and block.bins[7].lo == pytest.approx(7 / 15)


def test_no_curve_without_native_scores():
    labels = _labels()
    pairs = protocols.pairs_from_doc(_engine_docs()['unified'])
    assert curves.native_precision_curve('unified', [(labels, pairs)]) is None


def test_coverage_rows_count_every_attempt():
    rows = report.coverage_rows([('rz-diff', 'cve', 'ok'), ('rz-diff', 'cve', 'blocked'), ('ghidriff', 'cve', 'failed'),
                                 ('rz-diff', 'aa', 'ok')])
    got = [(r.engine, r.stratum, r.attempted, r.completed, r.blocked, r.failed) for r in rows]
    assert got == [('rz-diff', 'aa', 1, 1, 0, 0), ('rz-diff', 'cve', 2, 1, 1, 0), ('ghidriff', 'cve', 1, 0, 0, 1)]


# ---- wired into tier-r-report/1 --------------------------------------------------------------------------

def _providers(*names):
    return [E.StaticProvider(n, {_labels().pair_id: _output(n)}) for n in names]


def test_evaluate_emits_label_rank_curve_and_coverage_blocks():
    doc = E.evaluate([_labels()], _providers('ghidriff', 'rz-diff', 'unified'), b_count=100)
    loaded = C.load_report(C.dump_json(doc))
    assert loaded.lineages == 1 and 'few-lineages' in loaded.scope_ids
    assert 'no-windows-system-binaries' in loaded.scope_ids and 'symbols-hidden-only' in loaded.scope_ids
    cell = doc['labels']['cve']['ghidriff']['unchanged']
    assert (cell['paired_correct'], cell['flagged']) == (9, 3)
    assert cell['rate']['point'] == pytest.approx(1 / 3) and cell['rate']['anti_conservative']
    assert doc['labels']['cve']['unified']['unchanged']['flagged'] == 2
    assert doc['labels']['cve']['rz-diff']['cosmetic']['flagged'] == 1
    rk = doc['rank']['cve']
    assert {e: (b['population'], b['hit_at']['3']['point'], b['pairs']) for e, b in rk.items()} == {
        'ghidriff': ('real-fix', 0.0, 1), 'rz-diff': ('real-fix', 1.0, 1), 'unified': ('real-fix', 1.0, 1)}
    assert rk['unified']['ndcg10']['point'] == pytest.approx(0.630929753571, abs=1e-9)
    assert [c['engine'] for c in doc['curves']] == ['rz-diff', 'ghidriff']
    assert {(c['engine'], c['attempted'], c['completed']) for c in doc['coverage']} == {
        ('rz-diff', 1, 1), ('ghidriff', 1, 1), ('unified', 1, 1)}


def test_evaluate_twice_is_byte_identical():
    first = E.evaluate([_labels()], _providers('ghidriff', 'rz-diff', 'unified'), b_count=100)
    second = E.evaluate([_labels()], _providers('unified', 'rz-diff', 'ghidriff'), b_count=100)
    assert C.dump_json(first) == C.dump_json(second) and first['report_sha256'] == second['report_sha256']


def test_report_never_pools_engines():
    both = E.evaluate([_labels()], _providers('ghidriff', 'rz-diff'), b_count=100)
    alone = E.evaluate([_labels()], _providers('ghidriff'), b_count=100)
    # adding an engine changes nothing in another engine's blocks, and no block is keyed by a combined source
    assert both['rank']['cve']['ghidriff'] == alone['rank']['cve']['ghidriff']
    assert both['labels']['cve']['ghidriff'] == alone['labels']['cve']['ghidriff']
    engines = set(C.Engine.__args__)
    for block in ('labels', 'rank'):
        assert all(set(per_engine) <= engines for per_engine in both[block].values())
    assert all(c['engine'] in engines for c in both['curves'])


def test_paired_deltas_are_returned_beside_the_report():
    doc, deltas = E.evaluate_full([_labels()], _providers('ghidriff', 'rz-diff'), b_count=100)
    d = deltas['cve']['real-fix']['rz-diff vs ghidriff']['ndcg']
    assert d.delta.point == pytest.approx(0.5 - 0.430676558073, abs=1e-9) and d.non_inferior is None


def test_blocked_engine_is_coverage_not_a_zero():
    blocked = E.StaticProvider('bindiff', {})
    doc = E.evaluate([_labels()], [*_providers('rz-diff'), blocked], b_count=50)
    row = next(c for c in doc['coverage'] if c['engine'] == 'bindiff')
    assert (row['attempted'], row['completed'], row['blocked']) == (1, 0, 1)
    assert 'bindiff' not in doc['rank']['cve'] and any('below 90%' in n for n in doc['notes'])


def test_shift_block_only_with_a_declared_shift_set():
    other = _labels().model_dump(mode='json')
    other.update(pair_id='synergy-1-other', lineage='L-other')
    other['digest_sha256'] = '0' * 64
    other = C.finalize_labels(other)
    docs = [_labels(), C.load_labels(C.dump_json(other))]
    provs = [E.StaticProvider('rz-diff', {d.pair_id: _output('rz-diff') for d in docs})]
    assert E.evaluate(docs, provs, b_count=20)['shift'] is None
    shifted = E.evaluate(docs, provs, shift_lineages={'L-other'}, b_count=20)
    assert shifted['shift']['n_lineages'] == 1 and shifted['shift']['descriptors']['function-size']['n'] == 23


def test_markdown_lists_blocks_per_engine_and_marks_anti_conservative():
    text = E.render_markdown(E.evaluate([_labels()], _providers('ghidriff', 'rz-diff'), b_count=20))
    assert '## Per-label outcomes, stratum cve' in text and '## Fix rank, stratum cve' in text
    assert '| ghidriff | unchanged | 9 | 0 | 0 | 0 | 3 | 0.333' in text and '(anti-conservative)' in text
    assert '## Coverage (lineages: 1)' in text
