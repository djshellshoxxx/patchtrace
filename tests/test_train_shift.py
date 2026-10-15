"""Shift ladder (LBL-15): rungs, held-out hygiene, floors, degradation, conservative deltas, determinism. All rows come
from `synth.make_world` (generated data with known ground truth): it checks the arithmetic and the guards, never a real
engine or real binaries."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration import shift as SH  # noqa: E402
from tools.calibration.cv import CVConfig  # noqa: E402
from tools.calibration.synth import make_world  # noqa: E402

CV = CVConfig(k_outer=3, k_inner=3, c_grid=(1.0,), seed=1)
LAD = SH.LadderConfig(b_count=60, null_sims=30)
BETA = (0.0, 2.0, -1.5)
BASE = {'precision': 0.9, 'precision_lo': 0.85, 'precision_hi': 0.95, 'coverage': 0.6}


def world(prefix: str, n_groups: int, beta=BETA, per_group: int = 20):
    return make_world(n_groups=n_groups, per_group=per_group, beta=beta, seed=prefix, group_prefix=prefix).rows


def labelled(parts: dict[str, tuple[str, str]], rows) -> dict[str, SH.RowInfo]:
    """prefix -> (toolchain, family); lineage = group."""
    return {r.id: SH.RowInfo(parts[r.group[0]][0], parts[r.group[0]][1], r.group) for r in rows}


def three_toolchains(**kw):
    rows = world('A', 10, **kw) + world('B', 10, **kw) + world('M', 10, **kw)
    info = labelled({'A': ('mingw-gcc', 'f0'), 'B': ('mingw-clang', 'f1'), 'M': ('msvc-free', 'f2')}, rows)
    return list(rows), info


def ladder(rows, info, tau=0.8, baseline=BASE):
    return SH.run_ladder(rows, info, kinds=['num', 'num'], cv=CV, tau=tau, baseline=baseline, cfg=LAD)


def by_rung(doc, rung):
    return {r['held_out']: r for r in doc['rungs'] if r['rung'] == rung}


@pytest.fixture(scope='module')
def clean():
    rows, info = three_toolchains()
    return rows, info, ladder(rows, info)


def test_all_rung_kinds_are_present_and_tier_w_is_not_run_in_the_cloud(clean):
    doc = clean[2]
    assert doc['contract'] == 'calibration-shift/1'
    assert set(by_rung(doc, 'grouped-cv-within-toolchain')) == {'mingw-gcc', 'mingw-clang', 'msvc-free'}
    assert set(by_rung(doc, 'leave-one-toolchain-out')) == {'mingw-gcc', 'mingw-clang', 'msvc-free'}
    assert set(by_rung(doc, 'leave-one-family-out')) == {'f0', 'f1', 'f2'}
    tier_w = by_rung(doc, 'tier-w')[None]
    assert tier_w['status'] == 'not-run' and 'owner' in tier_w['reason'] and tier_w['n_rows'] == 0
    assert doc['rungs'][-1]['rung'] == 'tier-w'


def test_scored_rungs_report_intervals_ece_excess_ood_and_forced_accuracy(clean):
    rung = by_rung(clean[2], 'leave-one-toolchain-out')['msvc-free']
    assert rung['status'] == 'ok' and rung['n_lineages'] == 10 and rung['n_rows'] == 200
    assert 0 <= rung['precision']['lo'] <= rung['precision']['point'] <= rung['precision']['hi'] <= 1
    assert rung['precision']['anti_conservative']                 # 10 lineages: below the 30-lineage headline floor
    assert rung['ece_excess'] is not None and 0 <= rung['ood_flag_rate'] <= 1
    assert rung['forced_accuracy'] > 0.6 and rung['ood_abstain_accuracy'] is not None


def test_degradation_is_the_headline_minus_the_rung_with_conservative_bounds(clean):
    rung = by_rung(clean[2], 'leave-one-toolchain-out')['mingw-gcc']
    p = rung['precision']
    assert rung['delta_precision'] == pytest.approx(BASE['precision'] - p['point'])
    assert rung['delta_precision_lo'] == pytest.approx(BASE['precision_lo'] - p['hi'])
    assert rung['delta_precision_hi'] == pytest.approx(BASE['precision_hi'] - p['lo'])
    assert rung['delta_coverage'] == pytest.approx(BASE['coverage'] - rung['coverage']['point'])


def test_concept_shift_in_the_held_out_toolchain_shows_as_forced_accuracy_loss():
    rows = world('A', 10) + world('B', 10) + world('M', 10, beta=(0.0, -2.0, 1.5))     # msvc: the relation inverts
    doc = ladder(list(rows), labelled({'A': ('mingw-gcc', 'f0'), 'B': ('mingw-clang', 'f1'), 'M': ('msvc-free', 'f2')},
                                      rows))
    loto = by_rung(doc, 'leave-one-toolchain-out')
    assert loto['msvc-free']['forced_accuracy'] < 0.4        # trained on the other relation, it is worse than chance
    assert by_rung(doc, 'grouped-cv-within-toolchain')['msvc-free']['forced_accuracy'] > 0.6   # learnable inside


def test_held_out_groups_never_reach_the_training_side(monkeypatch):
    rows, info = three_toolchains()
    seen = []
    real = SH.final_model

    def spy(train, cv, seed=None):
        seen.append({r.group for r in train})
        return real(train, cv, seed)
    monkeypatch.setattr(SH, 'final_model', spy)
    ladder(rows, info)
    assert len(seen) == 6                                              # 3 toolchains + 3 families
    for groups, held in zip(seen, ['B', 'A', 'M', 'A', 'B', 'M'], strict=True):
        assert not any(g.startswith(held) for g in groups) and len(groups) == 20


def test_a_group_spanning_two_toolchains_leaves_the_training_side_and_is_counted():
    rows, info = three_toolchains()
    straddle = next(r for r in rows if r.group.startswith('A'))
    info = dict(info)
    for r in rows:
        if r.group == straddle.group and r.id.endswith(('0', '1', '2')):
            info[r.id] = SH.RowInfo('msvc-free', 'f0', r.group)             # same group, now partly msvc
    rung = by_rung(ladder(rows, info), 'leave-one-toolchain-out')['msvc-free']
    assert rung['excluded_shared_groups'] == 1


@pytest.mark.parametrize('keep,needle', [
    pytest.param(30, 'held-out rows 30 < 50', id='few-held-rows'),
    pytest.param(0, 'held-out rows 0 < 50', id='no-held-rows')])
def test_floor_violations_report_the_reason_and_no_numbers(keep, needle):
    rows, info = three_toolchains()
    msvc = [r for r in rows if r.group.startswith('M')][:keep]
    rows = [r for r in rows if not r.group.startswith('M')] + msvc
    doc = ladder(rows, info)
    loto = by_rung(doc, 'leave-one-toolchain-out')
    if keep:
        rung = loto['msvc-free']
        assert rung['status'] == 'insufficient-data' and needle in rung['reason']
        assert rung['precision'] is None and rung['forced_accuracy'] is None and rung['ece_excess'] is None
    else:
        assert 'msvc-free' not in loto


def test_single_toolchain_corpus_has_nothing_to_hold_out_against():
    rows = world('A', 12)
    doc = ladder(list(rows), labelled({'A': ('mingw-gcc', 'f0')}, rows))
    loto = by_rung(doc, 'leave-one-toolchain-out')['mingw-gcc']
    assert loto['status'] == 'insufficient-data' and 'no other toolchain' in loto['reason']
    assert by_rung(doc, 'leave-one-family-out')['f0']['status'] == 'insufficient-data'


def test_without_a_certified_tau_precision_is_absent_not_zero():
    rows, info = three_toolchains()
    rung = by_rung(ladder(rows, info, tau=None, baseline={}), 'leave-one-toolchain-out')['mingw-gcc']
    assert rung['status'] == 'ok' and rung['precision'] is None and 'no certified tau' in rung['reason']
    assert rung['delta_precision'] is None and rung['forced_accuracy'] is not None


def test_ladder_is_deterministic(clean):
    rows, info, doc = clean
    assert ladder(list(reversed(rows)), info) == doc


def test_ladder_not_run_lists_every_rung_with_the_reason():
    doc = SH.ladder_not_run('no fit was run: natural rows 3 < 200')
    assert [r['status'] for r in doc['rungs']] == ['insufficient-data'] * 3 + ['not-run']
    assert all('no fit' in r['reason'] for r in doc['rungs'][:3])
    SH.ShiftLadder.model_validate_json(json.dumps(doc))


def test_ladder_schema_is_strict():
    rung = SH.tier_w_rung().model_dump(mode='json')
    with pytest.raises(ValidationError):
        SH.ShiftRung.model_validate({**rung, 'surprise': 1})
    with pytest.raises(ValidationError):
        SH.ShiftRung.model_validate({**rung, 'status': 'passed'})
