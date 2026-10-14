"""Go/no-go gate evaluator (spec §12). `insufficient-data` is never `pass` and is treated as fail.

G0 data minimums; G1 pipeline on Tier R / synthetic meets the L2 numbers; G2 = L1 bands; G3 = L2 numbers.
Decision O2: without a confirmed second annotator, G3 cannot pass (claims capped at bands).
"""
from __future__ import annotations

from collections.abc import Mapping

ORDER = {'pass': 0, 'insufficient-data': 1, 'fail': 2}
L1 = {'prec': 0.95, 'prec_lo': 0.90, 'prec_width': 0.10, 'cov': 0.40, 'cov_lo': 0.30, 'stratum_lo': 0.85}
# ECE limits are on the EXCESS over the null-simulated ECE of a perfectly calibrated model at the same
# predictions, weights and lineage clustering (ece_null.py), not on the raw plug-in value.
L2 = {'prec': 0.95, 'prec_lo': 0.93, 'prec_width': 0.06, 'cov': 0.50, 'cov_lo': 0.40, 'stratum_lo': 0.88,
      'ece_excess': 0.03, 'ece_excess_hi': 0.05, 'fdr_rel': 0.25, 'shift_prec': 0.90}
G0_MIN = {'n_natural': 12000, 'n_locked_natural': 3000, 'locked_eff_neg': 150, 'n_lineages': 40, 'n_families': 10,
          'locked_lineages': 12, 'locked_families': 5, 'tier_w_families': 6, 'toolchain_profiles': 2,
          'shift_lineages': 1}
PROFILE_MIN = {'n_dev_natural': 2000, 'dev_neg': 100, 'dev_lineages': 12}
SUBTYPES_REQUIRED = tuple(f'N{i}' for i in range(1, 12))


class _Check:
    def __init__(self):
        self.status, self.reasons = 'pass', []

    def require(self, label: str, value, ok) -> None:
        if value is None:
            self._set('insufficient-data', f'{label}: missing')
        elif not ok(value):
            self._set('fail', f'{label}: {value!r}')

    def _set(self, status: str, reason: str) -> None:
        self.reasons.append(reason)
        if ORDER[status] > ORDER[self.status]:
            self.status = status

    def absorb(self, other: dict, label: str) -> None:
        if other['status'] != 'pass':
            self._set(other['status'] if other['status'] == 'fail' else 'insufficient-data', f'{label} not passed')

    def result(self) -> dict:
        return {'status': self.status, 'reasons': tuple(self.reasons)}


def _get(m: Mapping | None, *path):
    for key in path:
        if not isinstance(m, Mapping):
            return None
        m = m.get(key)
    return m


def g0(dataset: Mapping) -> dict:
    c = _Check()
    for key, minimum in G0_MIN.items():
        c.require(key, dataset.get(key), lambda v, m=minimum: v >= m)
    kinds = dataset.get('tier_w_kinds')
    c.require('tier_w_kinds', kinds, lambda v: {'kernel', 'usermode-dll', 'driver'} <= set(v))
    if dataset.get('second_annotator'):
        c.require('kappa', dataset.get('kappa'), lambda v: v >= 0.80)
        c.require('kappa_lo', dataset.get('kappa_lo'), lambda v: v >= 0.70)
    else:
        c.require('test_retest_kappa', dataset.get('test_retest_kappa'), lambda v: v >= 0.80)
    c.require('indeterminate_rate', dataset.get('indeterminate_rate'), lambda v: v <= 0.05)
    c.require('symbol_audit_error', dataset.get('symbol_audit_error'), lambda v: v <= 0.02)
    counts = dataset.get('adversarial_subtype_counts')
    c.require('adversarial subtypes N1-N11 >= 30', counts,
              lambda v: all(v.get(s, 0) >= 30 for s in SUBTYPES_REQUIRED))
    return c.result()


def _level(profile: Mapping, t: Mapping, numeric: bool) -> _Check:
    c = _Check()
    for key, minimum in PROFILE_MIN.items():
        c.require(key, profile.get(key), lambda v, m=minimum: v >= m)
    c.require('n_groups for bootstrap (>=30)', profile.get('n_groups'), lambda v: v >= 30)
    c.require('H2 precision', _get(profile, 'precision', 'point'), lambda v: v >= t['prec'])
    c.require('H2 precision CI lower', _get(profile, 'precision', 'lo'), lambda v: v >= t['prec_lo'])
    c.require('H2 Learn-then-Test certified at frozen tau', _get(profile, 'ltt', 'certified'), bool)
    lo, hi = _get(profile, 'precision', 'lo'), _get(profile, 'precision', 'hi')
    c.require('H2 precision CI width', None if lo is None or hi is None else hi - lo, lambda v: v <= t['prec_width'])
    c.require('H3 coverage', _get(profile, 'coverage', 'point'), lambda v: v >= t['cov'])
    c.require('H3 coverage CI lower', _get(profile, 'coverage', 'lo'), lambda v: v >= t['cov_lo'])
    c.require('H1 Brier skill CI lower', _get(profile, 'brier_skill', 'lo'), lambda v: v > 0)
    c.require('H4 FDR reduction CI lower', _get(profile, 'fdr_reduction', 'lo'), lambda v: v > 0)
    c.require('H5 worst stratum precision CI lower', profile.get('strata_min_lo'), lambda v: v >= t['stratum_lo'])
    ood_ok = profile.get('ood_reduced') or (profile.get('ood_risk_ratio_lo') or 0) > 1
    c.require('OOD validated or reduced', ood_ok if 'ood_reduced' in profile or 'ood_risk_ratio_lo' in profile
              else None, bool)
    c.require('ablations reported', profile.get('ablation_reported'), bool)
    if numeric:
        c.require('H1 ECE15 excess over null', _get(profile, 'ece_null', 'excess'), lambda v: v <= t['ece_excess'])
        c.require('H1 ECE15 CI-upper excess over null', _get(profile, 'ece_null', 'excess_hi'),
                  lambda v: v <= t['ece_excess_hi'])
        c.require('H1 slope CI contains 1', profile.get('slope'), lambda v: v['lo'] <= 1 <= v['hi'])
        c.require('H1 intercept CI contains 0', profile.get('intercept'), lambda v: v['lo'] <= 0 <= v['hi'])
        c.require('H4 relative FDR reduction', _get(profile, 'fdr_reduction', 'relative'),
                  lambda v: v >= t['fdr_rel'])
        c.require('shift-test precision', profile.get('shift_precision'), lambda v: v >= t['shift_prec'])
    return c


def evaluate_gates(dataset: Mapping, profile: Mapping, *, pipeline: Mapping | None = None,
                   conditions: Mapping | None = None) -> dict[str, dict]:
    """dataset: G0 inputs; profile: locked-test results for one profile; pipeline: Tier R / synthetic results
    (same shape as profile) for G1; conditions: non-statistical L2 conditions (owner sign-off etc.)."""
    conditions = conditions or {}
    gates = {'G0': g0(dataset)}
    gates['G1'] = (_level(pipeline, L2, True).result() if pipeline is not None
                   else {'status': 'insufficient-data', 'reasons': ('no Tier R pipeline results',)})
    c2 = _level(profile, L1, False)
    c2.absorb(gates['G0'], 'G0')
    gates['G2'] = c2.result()
    c3 = _level(profile, L2, True)
    c3.absorb(gates['G2'], 'G2')
    c3.require('second independent annotator (decision O2)', dataset.get('second_annotator'), bool)
    for key in ('reproducibility_check', 'owner_signoff', 'frozen_exe_smoke', 'independence_caveat_shown'):
        c3.require(key, conditions.get(key), bool)
    gates['G3'] = c3.result()
    return gates


def combine(per_profile: Mapping[str, Mapping[str, dict]]) -> dict[str, dict]:
    """Conservative top-level gates: the worst status of each gate over profiles."""
    out = {}
    for gate in ('G0', 'G1', 'G2', 'G3'):
        results = [g[gate] for g in per_profile.values()]
        if not results:
            out[gate] = {'status': 'insufficient-data', 'reasons': ('no profiles',)}
            continue
        worst = max(results, key=lambda r: ORDER[r['status']])
        out[gate] = {'status': worst['status'], 'reasons': tuple(r for res in results for r in res['reasons'])}
    return out
