"""Deterministic `calibration-report/1` (spec §9.7): same inputs -> byte-identical report.json; report.md
is rendered from it. Gates that lack data are `insufficient-data`, never `pass`."""
from __future__ import annotations

import hashlib
import math
import sys
from collections.abc import Mapping, Sequence

from .common import canonical_json, r12
from .contracts import CalibrationReport
from .gates import combine

SYNTHETIC_CLAIM = ('SYNTHETIC/PIPELINE VALIDATION ONLY: computed on generated data with known ground truth. '
                   'Makes no claim about real Windows binaries, Ghidriff, BinDiff or rz-diff accuracy.')
# Datasets whose ground truth is generated or built from open-source test builds: never a real-world claim,
# whatever the caller passes as `synthetic`.
SYNTHETIC_TIERS = frozenset({'synthetic', 'R', 'tier-r', 'r'})
REAL_CLAIM = ('Function-match correctness (target A) only, within the stated calibration domain; never a '
              'vulnerability probability.')


def _clean(value):
    """Round floats to 12 significant digits, tuples->lists, drop non-finite (as None)."""
    if isinstance(value, float):
        return r12(value) if math.isfinite(value) else None
    if isinstance(value, Mapping):
        return {str(k): _clean(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_clean(v) for v in value]
    return value


def blind_spots(per_profile: Mapping[str, Mapping]) -> list[str]:
    out = []
    for profile, res in sorted(per_profile.items()):
        for key, s in sorted((res.get('strata') or {}).items()):
            if s.get('insufficient'):
                out.append(f'{profile}/{key}: insufficient data (n_weighted < 200); abstains by default')
        for gate, g in sorted((res.get('gates') or {}).items()):
            if g['status'] != 'pass':
                out.append(f'{profile}/{gate}: {g["status"]}')
    return out


def make_report(*, prereg_sha: str | None, corpus_manifest_sha: str | None, label_set_sha: str | None,
                tool_git: str, dataset: Mapping, per_profile: Mapping[str, Mapping], synthetic: bool,
                known_limits: Sequence[str] = (), amendments: Sequence[str] = ()) -> dict:
    synthetic = synthetic or str(dataset.get('tier', '')).lower() in {t.lower() for t in SYNTHETIC_TIERS}
    report = {'contract': 'calibration-report/1', 'claim': SYNTHETIC_CLAIM if synthetic else REAL_CLAIM,
              'prereg_sha256': prereg_sha, 'corpus_manifest_sha256': corpus_manifest_sha,
              'label_set_sha256': label_set_sha, 'tool_git': tool_git,
              'python_version': f'{sys.version_info.major}.{sys.version_info.minor}',
              'dataset': _clean(dataset), 'per_profile': _clean(per_profile),
              'gates': _clean(combine({k: v['gates'] for k, v in per_profile.items() if 'gates' in v})),
              'blind_spots': sorted(blind_spots(per_profile)) + list(known_limits), 'amendments': list(amendments)}
    report['report_sha256'] = hashlib.sha256(canonical_json(report)).hexdigest()
    CalibrationReport.model_validate_json(canonical_json(report))
    return report


def verify_report(report: Mapping) -> bool:
    body = {k: v for k, v in report.items() if k != 'report_sha256'}
    return hashlib.sha256(canonical_json(body)).hexdigest() == report.get('report_sha256')


def render_markdown(report: Mapping) -> str:
    lines = [f'# Calibration report {report["report_sha256"][:12]}', '', f'> {report["claim"]}', '',
             f'- preregistration: `{report["prereg_sha256"]}`', f'- corpus manifest: `{report["corpus_manifest_sha256"]}`',
             f'- label set: `{report["label_set_sha256"]}`', f'- tool git: `{report["tool_git"]}`', '', '## Gates', '']
    for gate, g in sorted(report['gates'].items()):
        lines.append(f'- **{gate}**: {g["status"]}' + (f' ({"; ".join(g["reasons"][:6])})' if g['reasons'] else ''))
    for profile, res in sorted(report['per_profile'].items()):
        lines += ['', f'## Profile {profile}', '', '| metric | point | 95% CI |', '|---|---|---|']
        for name in ('brier', 'brier_skill', 'ece', 'ece_eqmass10', 'auc', 'logloss', 'slope', 'intercept',
                     'precision', 'coverage'):
            m = res.get(name)
            if isinstance(m, Mapping):
                lines.append(f'| {name} | {m.get("point")} | [{m.get("lo")}, {m.get("hi")}] |')
        lines.append(f'\ntau = {res.get("tau")}, tau_low = {res.get("tau_low")}, n_groups = {res.get("n_groups")}')
    lines += ['', '## Blind spots', ''] + [f'- {b}' for b in report['blind_spots']] or ['- none listed']
    return '\n'.join(lines) + '\n'
