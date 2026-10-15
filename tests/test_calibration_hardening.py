"""Audit 20261014-C: label-training hardening (leakage, statistics, label noise, robustness, honest scope).

Each test is the regression for one finding in docs/audits/20261014-C-label-training.md. Synthetic data only.
"""
from __future__ import annotations

import copy
import datetime as dt
import math
import sys
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from test_tier_r_eval_metrics import FUNCS, make_labels

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from patchtrace.calibration.policy import MIN_LINEAGES_FOR_CLAIM  # noqa: E402
from tools.calibration import agree, gates, guards, lineage  # noqa: E402
from tools.calibration import fit as fit_module  # noqa: E402
from tools.calibration.common import Row  # noqa: E402
from tools.calibration.cv import CVConfig, grouped_kfold  # noqa: E402
from tools.calibration.evalcore import boot, power, rank  # noqa: E402
from tools.calibration.evaluate import evaluate_profile  # noqa: E402
from tools.calibration.label import consolidate  # noqa: E402
from tools.calibration.mutations import coverage as mcov  # noqa: E402
from tools.calibration.report import SYNTHETIC_CLAIM, make_report  # noqa: E402
from tools.calibration.synth import make_world  # noqa: E402
from tools.calibration.tier_r import manifest as M  # noqa: E402

CREATED = dt.date(2026, 10, 14)
NAMES = ['G.ratio', 'R.similarity']
FAST = settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])


def _rows(n_groups=6, per_group=4, seed='h'):
    w = make_world(n_groups=n_groups, per_group=per_group, beta=(0.5, 1.0, 1.0, 0.0), seed=seed)
    return [Row(r.id, r.group, r.x[:2], r.y, r.w, r.stratum) for r in w.rows]


def _run(rows, **kw):
    return fit_module.run_pipeline(rows, names=NAMES, kinds=['num', 'num'], profile='G+R',
                                   cfg=CVConfig(k_outer=2, k_inner=2, c_grid=(1.0,)), b_count=40,
                                   created=CREATED, model_id='h', null_sims=20, **kw)


# ---- (d) robustness: bad inputs fail closed with a named error ------------------------------------------------

def test_duplicate_row_ids_are_rejected_not_silently_overwritten():
    rows = _rows()
    with pytest.raises(guards.RowError, match='duplicate row ids'):
        _run(rows + [rows[0]])


@pytest.mark.parametrize('mutate, message', [
    (lambda r: Row(r.id, r.group, r.x, r.y, 0.0), 'weights'),
    (lambda r: Row(r.id, r.group, r.x, r.y, float('inf')), 'weights'),
    (lambda r: Row(r.id, r.group, (float('nan'), 1.0), r.y), 'non-finite'),
    (lambda r: Row(r.id, r.group, r.x, 2), 'labels'),
    (lambda r: Row(r.id, r.group, r.x, 1), 'one class'),
], ids=['zero-w', 'inf-w', 'nan-x', 'bad-y', 'single-class'])
def test_unusable_rows_raise_row_error(mutate, message):
    with pytest.raises(guards.RowError, match=message):
        _run([mutate(r) for r in _rows()])


def test_empty_rows_and_empty_natural_stratum_raise_row_error():
    with pytest.raises(guards.RowError):
        _run([])
    adversarial = [Row(r.id, r.group, r.x, r.y, 1.0, 'adversarial') for r in _rows()]
    with pytest.raises(guards.RowError, match='natural'):
        evaluate_profile(adversarial, {r.id: 0.5 for r in adversarial}, tau=None)


def test_predictions_must_be_finite_probabilities():
    rows = _rows()
    with pytest.raises(guards.RowError, match='probabilities'):
        evaluate_profile(rows, {r.id: 1.5 for r in rows}, tau=None)
    with pytest.raises(guards.RowError, match='no prediction'):
        evaluate_profile(rows, {}, tau=None)


def test_tiny_and_imbalanced_corpora_never_pass_any_gate_and_stay_experimental():
    tiny = _run(_rows(4, 3))
    rare = [Row(r.id, r.group, r.x, int(i % 33 == 0), r.w) for i, r in enumerate(_rows(10, 20))]
    imbalanced = _run(rare)
    for res in (tiny, imbalanced):
        assert all(g['status'] != 'pass' for g in res.report['gates'].values())
        assert res.artifact['status'] == 'experimental' and res.artifact['policy']['display'] == 'none'
        assert 'SYNTHETIC' in res.report['claim']


def test_shifted_corpus_runs_and_is_reported_synthetic():
    w = make_world(n_groups=8, per_group=6, beta=(0.5, 1.0, 1.0, 0.0), seed='shift', shift=3.0)
    rows = [Row(r.id, r.group, r.x[:2], r.y, r.w) for r in w.rows]
    res = _run(rows)
    assert res.artifact['status'] == 'experimental'


# ---- (a) leakage: split audit ------------------------------------------------------------------------------------

def _bin(bid, sha, git, pdb=None, ts=None):
    return {'id': bid, 'tier': 'R', 'sha256': sha * 64, 'source': {'git': git, 'commit': 'c' * 40},
            'pdb': {'name': pdb} if pdb else None, 'winbindex': {'timestamp': ts} if ts is not None else None}


def _manifest(**over):
    doc = {'binaries': [_bin('b1', 'a', 'g:x'), _bin('b2', 'b', 'g:x'), _bin('b3', 'c', 'g:y'), _bin('b4', 'd', 'g:y')],
           'lineages': [{'id': 'L-x', 'members': ['b1', 'b2'], 'family': 'f'},
                        {'id': 'L-y', 'members': ['b3', 'b4'], 'family': 'f'}],
           'pairs': [{'id': 'p1', 'older': 'b1', 'newer': 'b2', 'kind': 'adjacent-patch', 'lineage': 'L-x',
                      'family_tags': ['f', 'stratum:release'], 'role': None},
                     {'id': 'p2', 'older': 'b3', 'newer': 'b4', 'kind': 'adjacent-patch', 'lineage': 'L-y',
                      'family_tags': ['f'], 'role': None}],
           'split': {'salt': 'c9-v1', 'shift_test_lineages': []}}
    doc.update(over)
    return doc


def test_clean_manifest_has_no_violations():
    assert guards.audit_manifest(_manifest())['violations'] == []


def test_source_project_on_both_sides_of_the_split_is_a_violation():
    doc = _manifest()
    doc['binaries'][2] = _bin('b3', 'c', 'g:x')           # lineage L-y shares the source project of L-x
    roles = {'L-x': 'dev', 'L-y': 'locked-test'}
    out = guards.audit_manifest(doc, roles)
    assert any('project g:x is on both sides' in v for v in out['violations'])
    assert guards.audit_manifest(doc, {'L-x': 'dev', 'L-y': 'dev'})['violations'] == []


def test_same_image_pdb_name_and_lineage_across_roles_are_violations():
    doc = _manifest()
    doc['binaries'][2] = _bin('b3', 'a', 'g:y', pdb='K.PDB')   # same image bytes as b1
    doc['binaries'][0] = _bin('b1', 'a', 'g:x', pdb='k.pdb')
    roles = {'L-x': 'dev', 'L-y': 'locked-test'}
    text = ' '.join(guards.audit_manifest(doc, roles)['violations'])
    assert 'sha256' in text and 'pdb k.pdb' in text
    split_lineage = _manifest(pairs=[dict(_manifest()['pairs'][0]), dict(_manifest()['pairs'][1], lineage='L-x')])
    assert guards.audit_manifest(split_lineage, {'L-x': 'dev', 'L-y': 'locked-test'})['violations']


def test_recorded_pair_role_must_match_the_lineage_role():
    doc = _manifest()
    roles = lineage.assign_roles(['L-x', 'L-y'], 'c9-v1')
    wrong = next(r for r in ('dev', 'locked-test', 'shift-test') if r != roles['L-x'])
    doc['pairs'][0]['role'] = wrong
    assert any('recorded role' in v for v in guards.audit_manifest(doc)['violations'])


def test_time_inverted_adjacent_patch_pair_is_flagged():
    doc = _manifest()
    doc['binaries'][0] = _bin('b1', 'a', 'g:x', ts=200)
    doc['binaries'][1] = _bin('b2', 'b', 'g:x', ts=100)
    assert any('time-inverted' in v for v in guards.audit_manifest(doc)['violations'])


def test_tiny_corpus_warns_about_empty_roles():
    out = guards.audit_manifest(_manifest(), {'L-x': 'dev', 'L-y': 'dev'})
    assert any('locked-test' in w for w in out['warnings']) and any('shift-test' in w for w in out['warnings'])


def test_control_pairs_must_inherit_the_base_lineage():
    doc = _manifest()
    doc['pairs'].append({'id': 'm1', 'older': 'b1', 'newer': 'b2', 'kind': 'adjacent-patch', 'lineage': 'L-y',
                         'family_tags': ['f', 'stratum:mutation'], 'role': None})
    out = guards.audit_manifest(doc, {'L-x': 'dev', 'L-y': 'dev'})
    assert any('must inherit the lineage' in v for v in out['violations'])


# ---- (a) A/A and planted pairs are controls, never evidence ------------------------------------------------------

def test_aa_noise_and_mutation_pairs_are_excluded_from_evidence_pairs():
    docs = [make_labels(FUNCS, pair_id='syn-rel', stratum='release'),
            make_labels(FUNCS, pair_id='syn-aa', stratum='aa')]
    doc = M.build_manifest(docs)
    tags = {p['id']: p['family_tags'] for p in doc['pairs']}
    assert 'stratum:aa' in tags['syn-aa'] and 'stratum:release' in tags['syn-rel']
    assert [p['id'] for p in guards.evidence_pairs(doc)] == ['syn-rel']
    assert guards.audit_manifest(doc)['violations'] == []   # controls share the base lineage
    assert doc['lineages'][0]['family'] == 'synthetic'      # tags did not leak into the lineage family


# ---- (e) reproducibility: canonical manifest hash ----------------------------------------------------------------

def test_canonical_manifest_hash_ignores_order_and_provenance_but_not_content():
    doc = _manifest()
    shuffled = copy.deepcopy(doc)
    shuffled['binaries'].reverse()
    shuffled['pairs'].reverse()
    shuffled['lineages'][0]['members'].reverse()
    shuffled['pairs'][0]['family_tags'].reverse()
    shuffled['created'], shuffled['tool_git'] = '2030-01-01T00:00:00Z', 'zzz'
    assert guards.canonical_manifest_sha256(doc) == guards.canonical_manifest_sha256(shuffled)
    changed = copy.deepcopy(doc)
    changed['binaries'][0]['sha256'] = 'e' * 64
    assert guards.canonical_manifest_sha256(doc) != guards.canonical_manifest_sha256(changed)


def test_pipeline_report_is_byte_identical_for_the_same_seed():
    rows = _rows(8, 6)
    assert _run(rows).report['report_sha256'] == _run(list(reversed(rows))).report['report_sha256']


# ---- (c) label noise ---------------------------------------------------------------------------------------------

def _pairs(n, groups, flip_every=0):
    out = []
    for i in range(n):
        a = 'same' if i % 3 else 'different'
        b = a if not flip_every or i % flip_every else ('different' if a == 'same' else 'same')
        out.append((a, b, f'L{i % groups}', 'N1' if i % 10 == 0 else None))
    return out


def test_kappa_cannot_pass_with_too_few_items_or_lineages():
    small = agree.agreement_report(_pairs(40, 40), b_count=100)
    assert small['overall']['kappa'] == 1.0 and small['meets_threshold'] is False
    assert any('double-labelled' in r for r in small['insufficient_reasons'])
    few_lineages = agree.agreement_report(_pairs(300, 5), b_count=100)
    assert few_lineages['meets_threshold'] is False
    assert any('lineages' in r for r in few_lineages['insufficient_reasons'])


def test_kappa_passes_at_the_spec_minimums_and_fails_on_noisy_labels():
    assert agree.agreement_report(_pairs(300, 40), b_count=100)['meets_threshold'] is True
    noisy = agree.agreement_report(_pairs(300, 40, flip_every=6), b_count=100)
    assert noisy['meets_threshold'] is False and noisy['insufficient_reasons'] == []


def test_subtypes_below_sixty_items_are_marked_insufficient():
    rep = agree.agreement_report(_pairs(300, 40), b_count=50)
    assert rep['subtypes']['N1']['n'] == 30 and rep['subtypes']['N1']['insufficient'] is True


def test_adjudication_by_a_blind_annotator_is_rejected():
    meta = {('p', 'm'): {'older': {'rva': 1, 'size': 1, 'body_sha256': 'a' * 64},
                         'newer': {'rva': 1, 'size': 1, 'body_sha256': 'b' * 64},
                         'sampling': {'stratum': 'natural', 'stage': 'S1', 'p_incl': 0.5}}}
    ev = [{'pair': 'p', 'match_id': 'm', 'annotator': 'a1', 'phase': 'blind', 'A': 'same'},
          {'pair': 'p', 'match_id': 'm', 'annotator': 'a2', 'phase': 'blind', 'A': 'different'},
          {'pair': 'p', 'match_id': 'm', 'annotator': 'a1', 'phase': 'adjudication', 'A': 'same'}]
    records, stats = consolidate(ev, meta)
    assert records == [] and stats['pending'] == [('p', 'm')] and stats['rejected_adjudications'] == [('p', 'm')]
    ev[-1]['annotator'] = 'a3'
    records, stats = consolidate(ev, meta)
    assert [r['A'] for r in records] == ['same'] and stats['rejected_adjudications'] == []


# ---- (b) statistics: power formulas ------------------------------------------------------------------------------

def test_two_sided_power_at_zero_effect_is_alpha_and_one_sided_signed():
    assert power.power_for_delta(0.0, 25, 1.0, alpha=0.05) == pytest.approx(0.05, abs=1e-12)
    assert power.power_for_delta(0.0, 25, 1.0, alpha=0.05, one_sided=True) == pytest.approx(0.05, abs=1e-12)
    assert power.power_for_delta(-0.5, 25, 1.0, one_sided=True) < 0.05      # wrong-direction effect
    assert power.power_for_delta(-0.5, 25, 1.0) == power.power_for_delta(0.5, 25, 1.0)


def test_power_inputs_are_validated():
    for bad in (dict(alpha=0.0), dict(alpha=1.0), dict(power=1.0), dict(power=0.0)):
        with pytest.raises(ValueError):
            power.lineages_needed(0.1, 0.3, **bad)
    with pytest.raises(ValueError):
        power.min_detectable_delta(10, float('nan'))
    with pytest.raises(ValueError):
        power.power_for_delta(0.1, 0, 0.3)


def test_t_correction_matches_guenther_and_is_never_smaller():
    n_z = power.lineages_needed(0.5, 1.0)           # (1.96 + 0.8416)^2 * 4 = 31.4 -> 32
    assert n_z == 32
    assert power.lineages_needed_t(0.5, 1.0) == 32 + math.ceil(1.959963984540054 ** 2 / 2) == 34
    assert power.lineages_needed_t(0.5, 1.0, one_sided=True) >= power.lineages_needed(0.5, 1.0, one_sided=True)


@given(st.floats(0.01, 2), st.floats(0.05, 3), st.integers(1, 400))
@FAST
def test_power_round_trip_and_monotonicity(delta, sd, n):
    mdd = power.min_detectable_delta(n, sd)
    assert power.power_for_delta(mdd, n, sd) == pytest.approx(0.8, abs=2e-3)   # far tail adds < 0.002
    assert power.power_for_delta(delta, n + 1, sd) >= power.power_for_delta(delta, n, sd) - 1e-12
    need = power.lineages_needed(delta, sd)
    assert power.power_for_delta(delta, need, sd) >= 0.8 - 1e-9
    assert power.lineages_needed_t(delta, sd) >= need


# ---- (g) hypothesis: evalcore ------------------------------------------------------------------------------------

@given(st.lists(st.integers(0, 6), min_size=1, max_size=25), st.randoms(use_true_random=False))
@FAST
def test_midranks_sum_range_and_permutation_invariance(keys, rnd):
    r = rank.midranks(keys)
    n = len(keys)
    assert math.fsum(r) == pytest.approx(n * (n + 1) / 2)
    assert all(1 <= v <= n for v in r)
    order = list(range(n))
    rnd.shuffle(order)
    r2 = rank.midranks([keys[i] for i in order])
    assert [r2[j] for j in range(n)] == [r[i] for i in order]
    for i in range(n):
        for j in range(n):
            assert (keys[i] < keys[j]) == (r[i] < r[j])


@given(st.one_of(st.none(), st.floats(1, 50)), st.integers(1, 30))
@FAST
def test_hit_at_k_is_monotone_in_k_and_rr_bounded(r, k):
    assert rank.hit_at_k(r, k) <= rank.hit_at_k(r, k + 1)
    assert 0.0 <= rank.reciprocal_rank(r) <= 1.0


def _obs(values):
    return {f'p{i}': (f'L{i % 7}', v) for i, v in enumerate(values)}


@given(st.lists(st.floats(0, 1), min_size=2, max_size=40), st.integers(0, 10**6))
@FAST
def test_lineage_bootstrap_is_ordered_seeded_and_bounded(values, seed):
    obs = _obs(values)
    a = boot.lineage_bootstrap(obs, 60, seed)
    assert a == boot.lineage_bootstrap(obs, 60, seed)
    assert a.lo <= a.hi and min(values) - 1e-9 <= a.lo and a.hi <= max(values) + 1e-9
    assert a.lo - 1e-9 <= a.point <= a.hi + 1e-9 or a.anti_conservative


@given(st.lists(st.floats(0, 1), min_size=2, max_size=30), st.integers(0, 10**6))
@FAST
def test_paired_delta_of_identical_arms_is_exactly_zero(values, seed):
    obs = _obs(values)
    d = boot.paired_delta_bootstrap(obs, obs, 40, seed)
    assert d.point == 0.0 and d.lo == 0.0 and d.hi == 0.0


# ---- (g) hypothesis: splitters ------------------------------------------------------------------------------------

_bins = st.lists(st.tuples(st.sampled_from(['a.dll', 'b.dll', 'c.sys', 'd.exe', 'e.dll']),
                           st.one_of(st.none(), st.sampled_from(['P1', 'P2', 'P3'])),
                           st.frozensets(st.sampled_from(list('uvwxyz')), max_size=4)),
                 min_size=1, max_size=12)


def _infos(items):
    return [lineage.BinaryInfo(f'b{i:02d}', f, p, None, h) for i, (f, p, h) in enumerate(items)]


@given(_bins, st.randoms(use_true_random=False))
@FAST
def test_cluster_is_a_partition_independent_of_input_order_and_keeps_projects_together(items, rnd):
    infos = _infos(items)
    res = lineage.cluster(infos)
    members = [m for ms in res.lineages.values() for m in ms]
    assert sorted(members) == sorted(b.id for b in infos)
    shuffled = list(infos)
    rnd.shuffle(shuffled)
    assert lineage.cluster(shuffled).lineages == res.lineages
    owner = {m: lid for lid, ms in res.lineages.items() for m in ms}
    for a in infos:
        for b in infos:
            if (a.project and a.project == b.project) or a.file_name.lower() == b.file_name.lower():
                assert owner[a.id] == owner[b.id]


@given(st.lists(st.text('abc123', min_size=1, max_size=4), min_size=1, max_size=40, unique=True), st.text(max_size=5))
@FAST
def test_roles_depend_only_on_lineage_and_salt_and_forced_shift_wins(ids, salt):
    roles = lineage.assign_roles(ids, salt)
    for lid in ids:
        assert lineage.assign_roles([lid], salt)[lid] == roles[lid]
    forced = lineage.assign_roles(ids, salt, shift_test=ids[:1])
    assert forced[ids[0]] == 'shift-test' and all(forced[i] == roles[i] for i in ids[1:])


@given(st.lists(st.tuples(st.sampled_from(['L1', 'L2', 'L3', 'L4', 'L5']),
                          st.frozensets(st.sampled_from(['i1', 'i2', 'i3', 'i4']), max_size=3)),
                min_size=1, max_size=15))
@FAST
def test_identity_groups_never_share_a_non_hub_identity_across_groups(items):
    cands = [lineage.CandidateIdentity(f'c{i}', ln, tuple(sorted(ids))) for i, (ln, ids) in enumerate(items)]
    grouping = lineage.identity_groups(cands, hub_max_lineages=3)
    by_identity: dict[str, set[str]] = {}
    for c in cands:
        for ident in c.identities:
            if ident not in grouping.hub_identities:
                by_identity.setdefault(ident, set()).add(grouping.group_of[c.id])
    assert all(len(groups) == 1 for groups in by_identity.values())
    lineage_group: dict[str, set[str]] = {}
    for c in cands:
        lineage_group.setdefault(c.lineage, set()).add(grouping.group_of[c.id])
    assert all(len(g) == 1 for g in lineage_group.values())


@given(st.integers(2, 12), st.integers(1, 6), st.integers(0, 10**6))
@FAST
def test_grouped_kfold_partitions_whole_lineages(n_groups, per_group, seed):
    k = min(3, n_groups)
    rows = [Row(f'{g}-{i}', f'L{g}', (0.0,), (g + i) % 2) for g in range(n_groups) for i in range(per_group)]
    folds = grouped_kfold(rows, k, seed)
    flat = [g for f in folds for g in f]
    assert sorted(flat) == sorted({r.group for r in rows}) and len(flat) == len(set(flat))
    assert grouped_kfold(rows, k, seed) == folds


# ---- (f) honest scope ---------------------------------------------------------------------------------------------

def test_tier_r_dataset_can_never_produce_a_real_world_claim():
    rep = make_report(prereg_sha=None, corpus_manifest_sha=None, label_set_sha=None, tool_git='t',
                      dataset={'tier': 'R', 'n_rows': 3}, per_profile={}, synthetic=False)
    assert rep['claim'] == SYNTHETIC_CLAIM


def test_promote_refuses_forged_gates_that_the_report_numbers_do_not_reproduce():
    claimed = {'G0': 'pass', 'G2': 'pass', 'G3': 'pass'}
    thin = {'dataset': {'n_natural': 10}, 'per_profile': {'G+R': {'n_groups': 3}}}
    with pytest.raises(fit_module.PromotionError, match='does not reproduce'):
        fit_module._reproduce_gates(thin, 'G+R', claimed)
    with pytest.raises(fit_module.PromotionError, match='no profile'):
        fit_module._reproduce_gates(thin, 'other', claimed)


def test_display_level_floor_matches_the_g0_lineage_minimum():
    assert MIN_LINEAGES_FOR_CLAIM == gates.G0_MIN['n_lineages']


def test_ece_and_sample_size_failures_block_the_numeric_gate():
    base = {'n_dev_natural': 5000, 'dev_neg': 400, 'dev_lineages': 50, 'n_groups': 50,
            'precision': {'point': 0.97, 'lo': 0.95, 'hi': 0.99}, 'ltt': {'certified': True},
            'coverage': {'point': 0.6, 'lo': 0.5}, 'brier_skill': {'lo': 0.1}, 'fdr_reduction': {'lo': 0.1, 'relative': 0.5},
            'strata_min_lo': 0.9, 'ood_reduced': True, 'ablation_reported': True,
            'ece_null': {'excess': 0.01, 'excess_hi': 0.02}, 'slope': {'lo': 0.9, 'hi': 1.1},
            'intercept': {'lo': -0.1, 'hi': 0.1}, 'shift_precision': 0.95}
    ok = gates._level(base, gates.L2, True).result()
    assert ok['status'] == 'pass'
    bad_ece = dict(base, ece_null={'excess': 0.04, 'excess_hi': 0.02})
    assert gates._level(bad_ece, gates.L2, True).result()['status'] == 'fail'
    few = dict(base, n_groups=12)
    assert gates._level(few, gates.L2, True).result()['status'] == 'fail'
    assert gates._level(dict(base, ece_null=None), gates.L2, True).result()['status'] == 'insufficient-data'


# ---- (d) planted-mutation coverage per weakness class -------------------------------------------------------------

def test_every_semantic_operator_maps_to_a_weakness_class():
    assert mcov.unmapped_operators() == []


def test_coverage_reports_missing_and_thin_classes_and_hard_negatives():
    planted = ['cmp-flip'] * 5 + ['off-by-one'] * 2 + ['dead-code'] * 3
    rep = mcov.coverage(planted)
    assert rep['per_class']['CWE-697'] == 5 and rep['per_class']['CWE-193'] == 2
    assert 'CWE-193' in rep['thin'] and 'CWE-119' in rep['missing'] and rep['complete'] is False
    assert rep['hard_negatives'] == 3 and rep['semantic'] == 7
    full = mcov.coverage([o for o in mcov.OPERATOR_CWE for _ in range(5)])
    assert full['complete'] is True and full['missing'] == []
    with pytest.raises(ValueError):
        mcov.coverage(['no-such-operator'])
