"""P-2 (PREREG 8.5 ii): the frozen constants in tools/calibration equal the preregistration. A failure names the
constant; fix the document before the lock or the code deliberately, never silence the test."""
from __future__ import annotations

import inspect
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration import ablation, agree, cv, ece_null, evaluate, fit, gates, lineage, metrics, threshold  # noqa: E402
from tools.calibration.stats import ltt_start_n  # noqa: E402
from tools.calibration.tier_r import manifest as tier_r_manifest  # noqa: E402
from tools.calibration.tier_w import pairs as tier_w_pairs  # noqa: E402

PREREG = ROOT / 'docs' / 'plans' / 'c9-preregistration-v1.md'
TEXT = PREREG.read_text(encoding='utf-8')


def row(label: str) -> str:
    """Frozen-value cell of the section 5 table row whose first cell starts with `label`."""
    section = TEXT.split('## 5. Frozen analysis configuration', 1)[1].split('\n## 6.', 1)[0]
    for line in section.splitlines():
        cells = [c.strip() for c in line.strip().strip('|').split('|')]
        if len(cells) >= 3 and cells[0].startswith(label):
            return cells[1]
    raise AssertionError(f'prereg section 5 has no row {label!r}')


def numbers(cell: str) -> list[float]:
    return [float(x) for x in re.findall(r'\d+(?:\.\d+)?', cell.replace(',', ''))]


def default_of(func, name: str):
    return inspect.signature(func).parameters[name].default


def check(name: str, actual, expected) -> None:
    assert actual == expected, f'{name}: code has {actual!r}, preregistration says {expected!r}'


def test_cv_config_matches_prereg():
    cfg = cv.CVConfig()
    check('cv.CVConfig.k_outer', cfg.k_outer, int(numbers(row('Outer CV'))[0]))
    check('cv.CVConfig.k_inner', cfg.k_inner, int(numbers(row('Inner CV'))[0]))
    check('cv.CVConfig.c_grid', cfg.c_grid, tuple(numbers(row('C grid'))))
    check('cv.CVConfig.seed', cfg.seed, int(numbers(row('CV seed'))[0]))
    check('cv.ISOTONIC_MIN_EFFECTIVE', cv.ISOTONIC_MIN_EFFECTIVE, int(numbers(row('Calibrator'))[0]))


def test_ece_constants_match_prereg():
    check('metrics.ECE_BINS', metrics.ECE_BINS, int(numbers(row('ECE'))[0]))
    gate = row('ECE gate')
    check('ece_null.NULL_SIMS', ece_null.NULL_SIMS, int(numbers(gate)[0]))
    assert '0 when undefined' in gate
    check('ece_null.RHO_UNDEFINED', ece_null.RHO_UNDEFINED, 0.0)


def test_seeds_match_prereg():
    expected = dict(re.findall(r'(bootstrap|ECE null|ablation|agreement)[^0-9]*(\d+)', row('Seeds')))
    check('evaluate.evaluate_profile seed (bootstrap)', default_of(evaluate.evaluate_profile, 'seed'),
          int(expected['bootstrap']))
    check('ece_null.ece_null seed', default_of(ece_null.ece_null, 'seed'), int(expected['ECE null']))
    check('ablation.run_ablations seed', default_of(ablation.run_ablations, 'seed'), int(expected['ablation']))
    check('agree.kappa_ci seed', default_of(agree.kappa_ci, 'seed'), int(expected['agreement']))
    check('agree.agreement_report seed', default_of(agree.agreement_report, 'seed'), int(expected['agreement']))


def test_bootstrap_count_matches_prereg():
    expected = int(re.search(r'B = (\d+)', row('Bootstrap')).group(1))
    check('evaluate.evaluate_profile b_count', default_of(evaluate.evaluate_profile, 'b_count'), expected)
    check('agree.kappa_ci b_count', default_of(agree.kappa_ci, 'b_count'), expected)
    check('agree.agreement_report b_count', default_of(agree.agreement_report, 'b_count'), expected)


def test_threshold_constants_match_prereg():
    check('threshold.TAU_GRID[0]', threshold.TAU_GRID[0], 0.999)
    check('threshold.TAU_GRID[-1]', threshold.TAU_GRID[-1], 0.5)
    check('threshold.TAU_GRID length', len(threshold.TAU_GRID), 500)
    check('threshold.TAU_LOW_GRID[0]', threshold.TAU_LOW_GRID[0], 0.001)
    check('threshold.TAU_LOW_GRID[-1]', threshold.TAU_LOW_GRID[-1], 0.5)
    prec = numbers(row('Precision target'))
    check('threshold.TARGET_PRECISION', threshold.TARGET_PRECISION, prec[0])
    check('threshold.DELTA vs alpha', threshold.DELTA, prec[1])
    check('threshold.TARGET_NPV', threshold.TARGET_NPV, numbers(row('NPV target'))[0])
    check('threshold.DELTA (Learn-then-Test)', threshold.DELTA, numbers(row('Learn-then-Test'))[0])
    check('threshold.RHO_UNDEFINED', threshold.RHO_UNDEFINED, 1.0)
    assert 'undefined = 1.0' in row('Effective n')


def test_ltt_start_matches_prereg():
    check('stats.ltt_start_n(alpha, delta)', ltt_start_n(round(1 - threshold.TARGET_PRECISION, 12), threshold.DELTA),
          int(numbers(row('LTT start'))[0]))


def test_ablation_reference_coverage_matches_prereg():
    check('fit.ABLATION_REFERENCE_COVERAGE', fit.ABLATION_REFERENCE_COVERAGE, numbers(row('Ablation reference'))[0])


def test_roles_and_salt_match_prereg():
    check('lineage.ROLE_CUTS', lineage.ROLE_CUTS, ((0.60, 'dev'), (0.85, 'locked-test'), (1.01, 'shift-test')))
    check('lineage.THRESHOLDS', lineage.THRESHOLDS, (0.15, 0.30, 0.50))
    check('tier_w.pairs.SALT', tier_w_pairs.SALT, 'c9-v1')
    check('tier_r.manifest.SPLIT salt', tier_r_manifest.SPLIT['salt'], 'c9-v1')
    assert 'salt `c9-v1`' in TEXT, 'prereg no longer names salt c9-v1'


def test_hub_max_lineages_must_be_explicit():
    check('lineage.identity_groups hub_max_lineages default', default_of(lineage.identity_groups, 'hub_max_lineages'),
          None)
    assert 'hub_max_lineages = 3' in TEXT


@pytest.mark.parametrize('name, expected', [
    ('n_natural', 12000), ('n_locked_natural', 3000), ('locked_eff_neg', 150), ('n_lineages', 40),
    ('n_families', 10), ('locked_lineages', 12), ('locked_families', 5), ('tier_w_families', 6),
    ('toolchain_profiles', 2), ('shift_lineages', 1)], ids=lambda v: str(v))
def test_g0_minimums_match_prereg(name, expected):
    check(f'gates.G0_MIN[{name}]', gates.G0_MIN[name], expected)


@pytest.mark.parametrize('name, expected', [('n_dev_natural', 2000), ('dev_neg', 100), ('dev_lineages', 12)],
                         ids=lambda v: str(v))
def test_profile_minimums_match_prereg(name, expected):
    check(f'gates.PROFILE_MIN[{name}]', gates.PROFILE_MIN[name], expected)


def test_gate_thresholds_match_prereg():
    check('gates.L1', gates.L1, {'prec': 0.95, 'prec_lo': 0.90, 'prec_width': 0.10, 'cov': 0.40, 'cov_lo': 0.30,
                                 'stratum_lo': 0.85})
    check('gates.L2', gates.L2, {'prec': 0.95, 'prec_lo': 0.93, 'prec_width': 0.06, 'cov': 0.50, 'cov_lo': 0.40,
                                 'stratum_lo': 0.88, 'ece_excess': 0.03, 'ece_excess_hi': 0.05, 'fdr_rel': 0.25,
                                 'shift_prec': 0.90})
    check('gates.SUBTYPES_REQUIRED', gates.SUBTYPES_REQUIRED, tuple(f'N{i}' for i in range(1, 12)))
