"""Tier R report wording and invariants (LBL-15): the claim is the shipped constant, only G1 is evaluated, a synthetic
corpus can never read as real-world accuracy. Data are generated; nothing here measures a real engine."""
from __future__ import annotations

import copy
import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from patchtrace.calibration import scope  # noqa: E402
from tools.calibration import report as R  # noqa: E402
from tools.calibration import shift as SH  # noqa: E402
from tools.calibration import train as T  # noqa: E402
from tools.calibration.common import canonical_json  # noqa: E402

EXACT_CLAIM = 'Measured on test builds of open-source code; says nothing about Windows system files'
GATE_STATUS = {'status': 'insufficient-data', 'reasons': ()}


def tier_r_report(**over):
    per = {'G+R': {'gates': {g: dict(GATE_STATUS, reasons=('x',)) for g in ('G0', 'G1', 'G2', 'G3')},
                   'shift': SH.ladder_not_run('no fit was run')}}
    args = dict(prereg_sha=None, corpus_manifest_sha=None, label_set_sha=None, tool_git='t',
                dataset={'n_rows': 3}, per_profile=per)
    args.update(over)
    return R.make_tier_r_report(**args)


def resign(report):
    report = {k: v for k, v in report.items() if k != 'report_sha256'}
    report['report_sha256'] = hashlib.sha256(canonical_json(report)).hexdigest()
    return report


def test_claim_is_the_shipped_constant_with_the_required_text():
    assert R.TIER_R_CLAIM is scope.TIER_R_CLAIM
    assert scope.TIER_R_CLAIM.rstrip('.') == EXACT_CLAIM


def test_tier_r_report_forces_tier_claim_and_g0_g2_g3_insufficient():
    rep = tier_r_report(dataset={'tier': 'W', 'n_rows': 3})
    assert rep['claim'] == scope.TIER_R_CLAIM and rep['dataset']['tier'] == 'R'
    assert {g: rep['gates'][g]['status'] for g in ('G0', 'G2', 'G3')} == dict.fromkeys(('G0', 'G2', 'G3'),
                                                                                       'insufficient-data')
    assert R.verify_report(rep)
    R.verify_tier_r_report(rep)


def test_a_passing_g2_in_the_inputs_is_overridden_not_believed():
    per = {'G+R': {'gates': {'G0': {'status': 'pass', 'reasons': ()}, 'G1': {'status': 'pass', 'reasons': ()},
                             'G2': {'status': 'pass', 'reasons': ()}, 'G3': {'status': 'pass', 'reasons': ()}}}}
    rep = tier_r_report(per_profile=per)
    assert [rep['gates'][g]['status'] for g in ('G0', 'G1', 'G2', 'G3')] == [
        'insufficient-data', 'pass', 'insufficient-data', 'insufficient-data']


@pytest.mark.parametrize('damage', [
    pytest.param('claim', id='claim'), pytest.param('tier', id='tier'), pytest.param('g2', id='g2-pass'),
    pytest.param('g1-missing', id='g1-missing'), pytest.param('sha', id='sha'),
    pytest.param('wording', id='wording')])
def test_verify_tier_r_report_rejects_overstatement(damage):
    rep = copy.deepcopy(tier_r_report())
    if damage == 'claim':
        rep['claim'] = R.SYNTHETIC_CLAIM
    elif damage == 'tier':
        rep['dataset']['tier'] = 'W'
    elif damage == 'g2':
        rep['gates']['G2'] = {'status': 'pass', 'reasons': []}
    elif damage == 'g1-missing':
        del rep['gates']['G1']
    elif damage == 'wording':
        rep['claim'] = 'Accurate on Windows system files'
    if damage != 'sha':
        rep = resign(rep)
    else:
        rep['tool_git'] = 'edited'
    with pytest.raises(R.TierRReportError):
        R.verify_tier_r_report(rep)


def test_generic_make_report_still_forces_the_synthetic_claim_for_tier_r():
    rep = R.make_report(prereg_sha=None, corpus_manifest_sha=None, label_set_sha=None, tool_git='t',
                        dataset={'tier': 'R'}, per_profile={}, synthetic=False)
    assert rep['claim'] == R.SYNTHETIC_CLAIM != scope.TIER_R_CLAIM


def test_fixed_prose_obeys_the_scope_copy_rules():
    texts = [scope.TIER_R_CLAIM, *R.TIER_R_LIMITS, SH.TIER_W_REASON, SH.FIRST_LOOK_NOTE, *T.G023_REASON.values()]
    for text in texts:
        low = text.lower()
        assert '%' not in text and not [s for s in R.TIER_R_FORBIDDEN if s in low], text
    assert len(set(R.TIER_R_LIMITS)) == len(R.TIER_R_LIMITS)


def test_every_limit_is_in_the_report_and_the_markdown_leads_with_the_claim():
    rep = tier_r_report()
    assert set(R.TIER_R_LIMITS) <= set(rep['blind_spots'])
    text = R.render_markdown(rep)
    assert text.splitlines()[2] == f'> {scope.TIER_R_CLAIM}'
    assert '### Shift ladder' in text and '| tier-w |' in text


def test_a_synthetic_world_run_never_phrases_itself_as_accuracy(tmp_path):
    from test_train_helpers import write_world
    labels, outputs = write_world(tmp_path, n_lineages=14)
    res = T.run_training(T.build_from_labels(labels, outputs), T.TrainConfig.smoke_config())
    text = canonical_json(res.report).decode().lower() + R.render_markdown(res.report).lower()
    for phrase in ('accurate', 'validated for windows', 'real-world accuracy', 'windows accuracy'):
        assert phrase not in text
    assert res.report['dataset']['claim_scope'] == 'pipeline-check-on-test-builds'
    R.verify_tier_r_report(res.report)
