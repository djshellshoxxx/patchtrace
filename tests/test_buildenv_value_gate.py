"""G-DIE-1 value gate over synthetic Tier R M4 style pairs: counts checked against hand-computed goldens (DIE plan s10).

The pairs are synthetic stand-ins for the M4 strata, so the numbers prove the counting rules, never effectiveness.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import buildenv_value_gate as gate  # noqa: E402


def fn(fid, verdict, classes, truth, omitted=0):
    return {'id': fid, 'group': 'g', 'verdict': verdict, 'classes': classes, 'truth': truth, 'deltas_omitted': omitted}


# Hand-computed from the table in each test (toolchain-variant stratum, toolchain differs):
#   f1 review frame same      -> tagged, noise            f5 review frame+size-only changed -> tagged, LEAK
#   f2 review cfg cosmetic    -> tagged, noise            f6 material frame changed         -> not flagged, not tagged
#   f3 review callee same     -> flagged, untagged        f7 review eh+size-only same, 1 omitted -> untagged
#   f4 review constant changed-> flagged, untagged        f8 review frame unknown truth     -> tagged, no vote
VARIANT = {'pair_id': 'variant', 'stratum': 'toolchain-variant', 'toolchain': 'differs', 'functions': [
    fn('f1', 'review', ['frame'], 'same'), fn('f2', 'review', ['cfg'], 'cosmetic'),
    fn('f3', 'review', ['callee'], 'same'), fn('f4', 'review', ['constant'], 'changed'),
    fn('f5', 'review', ['frame', 'size-only'], 'changed'), fn('f6', 'material', ['frame'], 'changed'),
    fn('f7', 'review', ['eh', 'size-only'], 'same', omitted=1), fn('f8', 'review', ['frame'], 'unknown')]}
AA = {'pair_id': 'aa', 'stratum': 'aa', 'toolchain': 'same', 'functions': [fn('a1', 'review', ['frame'], 'same')]}
OPT = {'pair_id': 'opt', 'stratum': 'o0-vs-o2', 'toolchain': 'unknown',
       'functions': [fn('o1', 'review', ['frame'], 'cosmetic'), fn('o2', 'review', ['cfg'], 'same')]}


def doc(*pairs):
    return {'schema': 'buildenv-value-gate-input/1', 'pairs': [copy.deepcopy(p) for p in pairs]}


def stratum(report, name):
    return next(s for s in report['strata'] if s['stratum'] == name)


def test_golden_counts():
    report = gate.evaluate(doc(VARIANT, AA, OPT))
    variant = stratum(report, 'toolchain-variant')
    assert (variant['pairs'], variant['flagged_noise'], variant['tagged_noise']) == (1, 4, 2)
    assert (variant['flagged_changed'], variant['tagged_changed']) == (2, 1)
    assert (variant['tagged_unknown'], variant['tagged_total']) == (1, 4)
    assert stratum(report, 'aa')['tagged_total'] == 0
    assert stratum(report, 'o0-vs-o2')['tagged_total'] == 0
    assert (stratum(report, 'o0-vs-o2')['flagged_noise']) == 2


def test_checks_are_met_and_leakage_is_not_met_on_the_golden():
    checks = {c['id']: c for c in gate.evaluate(doc(VARIANT, AA, OPT))['checks']}
    assert checks['zero-tags-on-controls']['status'] == 'met'
    assert checks['semantic-leakage-zero']['status'] == 'not-met'
    assert checks['semantic-leakage-zero']['observed'] == {'tagged_changed': 1, 'flagged_changed': 2}


def test_a_tag_on_a_control_pair_fails_the_control_check():
    bad = copy.deepcopy(OPT)
    bad['toolchain'] = 'differs'
    checks = {c['id']: c for c in gate.evaluate(doc(VARIANT, AA, bad))['checks']}
    assert checks['zero-tags-on-controls']['status'] == 'not-met'
    assert checks['zero-tags-on-controls']['observed'] == {'tagged_total': 2}


def test_no_data_is_not_a_pass():
    checks = {c['id']: c['status'] for c in gate.evaluate(doc(VARIANT))['checks']}
    assert checks['zero-tags-on-controls'] == 'no-data'
    only_aa = {c['id']: c['status'] for c in gate.evaluate(doc(AA))['checks']}
    assert only_aa['semantic-leakage-zero'] == 'no-data'


def test_unknown_toolchain_tags_nothing():
    unknown = copy.deepcopy(VARIANT)
    unknown['toolchain'] = 'unknown'
    assert stratum(gate.evaluate(doc(unknown)), 'toolchain-variant')['tagged_total'] == 0


def test_report_is_deterministic_and_makes_no_reduction_claim():
    first = gate.evaluate(doc(VARIANT, AA, OPT))
    second = gate.evaluate(doc(OPT, AA, VARIANT))
    assert first == second and len(first['report_sha256']) == 64
    assert first['claims'] == 'counts only; no false-lead-reduction claim'
    assert 'effective' not in json.dumps(first).lower()


@pytest.mark.parametrize('mutate', [
    lambda d: d.update(schema='x'),
    lambda d: d['pairs'][0].update(stratum='nope'),
    lambda d: d['pairs'][0]['functions'][0].update(truth='maybe'),
    lambda d: d['pairs'][0]['functions'][0].update(classes=['frame'] * 40),
    lambda d: d['pairs'].append(copy.deepcopy(d['pairs'][0])),
], ids=['schema', 'stratum', 'truth', 'classes', 'duplicate-pair'])
def test_invalid_input_is_rejected(mutate):
    data = doc(VARIANT)
    mutate(data)
    with pytest.raises(gate.GateInputError):
        gate.evaluate(data)


def test_cli_writes_the_report_and_exits_by_status(tmp_path):
    source = tmp_path / 'in.json'
    source.write_text(json.dumps(doc(VARIANT, AA, OPT)), encoding='utf-8')
    out = tmp_path / 'report.json'
    assert gate.main(['--input', str(source), '--out', str(out)]) == 0
    assert json.loads(out.read_text(encoding='utf-8'))['schema'] == 'buildenv-value-gate/1'
    source.write_text('{', encoding='utf-8')
    assert gate.main(['--input', str(source), '--out', str(out)]) == 2
