"""Deterministic `calibration-report/1` (spec §9.7): same inputs -> byte-identical report.json; report.md
is rendered from it. Gates that lack data are `insufficient-data`, never `pass`."""
from __future__ import annotations

import hashlib
import math
import sys
from collections.abc import Mapping, Sequence

from patchtrace.calibration.scope import BANNED_STEMS, TIER_R_CLAIM

from .common import canonical_json, r12
from .contracts import CalibrationReport
from .gates import combine

SYNTHETIC_CLAIM = ('SYNTHETIC/PIPELINE VALIDATION ONLY: computed on generated data with known ground truth. '
                   'Makes no claim about real Windows binaries, Ghidriff, BinDiff or rz-diff accuracy.')
# Datasets whose ground truth is generated or built from open-source test builds: never a real-world claim,
# whatever the caller passes as `synthetic`.
SYNTHETIC_TIERS = frozenset({'synthetic', 'R', 'tier-r', 'r'})
# Fixed prose of every Tier R report (LBL integration plan 7.3, 7.8). Same wording rules as the shipped scope copy:
# no percent sign and none of the banned stems; the claim itself is `scope.TIER_R_CLAIM`, never re-typed here.
TIER_R_LIMITS = (
    'Tier R is built from test builds of open-source code with known answers; a pass here only shows that the '
    'pipeline recovers those answers.',
    'Tier R alone cannot evaluate G0, G2 or G3; they stay insufficient-data by construction (no Tier W families, '
    'kinds, symbol audit or second annotator).',
    'The artifact written from a Tier R run is experimental, displays nothing and is never bundled.',
    'The shift ladder Tier W rung is not-run: it needs the owner machine.')
TIER_R_FORBIDDEN = tuple(BANNED_STEMS) + ('accurate', 'validated for windows')
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


def _num(value) -> str:
    return '-' if value is None else (f'{value:.3f}' if isinstance(value, float) else str(value))


def _shift_lines(shift: Mapping) -> list[str]:
    lines = ['', '### Shift ladder', '', f'tau = {shift.get("tau")}; {shift.get("note", "")}', '',
             '| rung | held out | status | rows | precision (lo, hi) | coverage | ECE excess | OOD flagged | forced | note |',
             '|---|---|---|---|---|---|---|---|---|---|']
    for r in shift.get('rungs', ()):
        prec = r.get('precision') or {}
        interval = f'{_num(prec.get("point"))} ({_num(prec.get("lo"))}, {_num(prec.get("hi"))})' if prec else '-'
        cov = (r.get('coverage') or {}).get('point')
        lines.append(f'| {r["rung"]} | {r.get("held_out") or "-"} | {r["status"]} | {r.get("n_rows", 0)} | {interval} | '
                     f'{_num(cov)} | {_num(r.get("ece_excess"))} | {_num(r.get("ood_flag_rate"))} | '
                     f'{_num(r.get("forced_accuracy"))} | {str(r.get("reason") or "")[:80]} |')
    return lines


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
        if res.get('precision_basis'):
            lines.append(f'\nprecision and coverage basis: {res["precision_basis"]} (tau was chosen on the same '
                         'out-of-fold rows that give these numbers; they are not held-out values)')
        lines += _undefined_lines(res.get('bootstrap_undefined')) + _indeterminate_lines(res.get('indeterminate'))
        if isinstance(res.get('shift'), Mapping):
            lines += _shift_lines(res['shift'])
    lines += ['', '## Blind spots', ''] + [f'- {b}' for b in report['blind_spots']] or ['- none listed']
    return '\n'.join(lines) + '\n'


def _undefined_lines(block) -> list[str]:
    bad = sorted(k for k, v in (block or {}).items() if v.get('refused'))
    shares = [v['share'] for v in (block or {}).values() if v.get('share') is not None]
    if not shares:
        return []
    return ['', f'bootstrap resamples with an undefined statistic: largest share {max(shares):.4f}'
            + (f'; refused intervals: {", ".join(bad)}' if bad else '')]


def _indeterminate_lines(block) -> list[str]:
    if not block or not block.get('strata'):
        return []
    lines = ['', f'### Indeterminate candidates (flag above {block["flag_share"]})', '',
             '| stratum | kept | indeterminate | share | flagged | precision | worst case precision | worst case coverage |',
             '|---|---|---|---|---|---|---|---|']
    for name, s in sorted(block['strata'].items()):
        worst = s.get('worst_case') or {}
        point = s.get('point') or {}
        lines.append(f'| {name} | {s["rows"]} | {s["excluded_indeterminate"]} | {s["share"]:.4f} | '
                     f'{"yes" if s["flagged"] else "no"} | {point.get("precision")} | {worst.get("precision")} | '
                     f'{worst.get("coverage")} |')
    return lines


# ---- Tier R report (LBL-15) ---------------------------------------------------------------------------------------

class TierRReportError(ValueError):
    """A Tier R report that would overstate what the evidence licenses."""


def _tier_r_problems(report: Mapping) -> list[str]:
    problems = []
    if report.get('claim') != TIER_R_CLAIM:
        problems.append('claim is not TIER_R_CLAIM')
    if str((report.get('dataset') or {}).get('tier')) != 'R':
        problems.append("dataset.tier is not 'R'")
    gates = report.get('gates') or {}
    for gate in ('G0', 'G2', 'G3'):
        if (gates.get(gate) or {}).get('status') != 'insufficient-data':
            problems.append(f'{gate} must be insufficient-data for Tier R alone')
    if 'G1' not in gates:
        problems.append('G1 missing')
    for text in (report.get('claim', ''), *(t for t in report.get('blind_spots', ()) if t in TIER_R_LIMITS)):
        hit = [stem for stem in TIER_R_FORBIDDEN if stem in str(text).lower()]
        if hit:
            problems.append(f'forbidden wording {hit} in {str(text)[:40]!r}')
    return problems


def verify_tier_r_report(report: Mapping) -> None:
    """Raises `TierRReportError` unless the report carries the Tier R claim, evaluates only G1 and verifies."""
    problems = _tier_r_problems(report)
    if not verify_report(report):
        problems.append('report SHA does not verify')
    if problems:
        raise TierRReportError('; '.join(problems))


def make_tier_r_report(*, prereg_sha: str | None, corpus_manifest_sha: str | None, label_set_sha: str | None,
                       tool_git: str, dataset: Mapping, per_profile: Mapping[str, Mapping],
                       known_limits: Sequence[str] = (), amendments: Sequence[str] = ()) -> dict:
    """`calibration-report/1` for a Tier R run: claim = TIER_R_CLAIM, dataset.tier = 'R', G1 as evaluated by the
    caller, G0/G2/G3 forced to insufficient-data (they need Tier W evidence), fixed limits prose appended."""
    base = make_report(prereg_sha=prereg_sha, corpus_manifest_sha=corpus_manifest_sha, label_set_sha=label_set_sha,
                       tool_git=tool_git, dataset=dict(dataset, tier='R'), per_profile=per_profile, synthetic=True,
                       known_limits=list(known_limits) + list(TIER_R_LIMITS), amendments=amendments)
    base['claim'] = TIER_R_CLAIM
    base.pop('report_sha256')
    for gate, reason in (('G0', 'Tier R carries no Tier W families, kinds, symbol audit or second annotator'),
                         ('G2', 'Tier R is never used for G2'), ('G3', 'Tier R is never used for G3')):
        base['gates'][gate] = {'status': 'insufficient-data', 'reasons': [reason]}
    base['gates'].setdefault('G1', {'status': 'insufficient-data', 'reasons': ['no Tier R pipeline results']})
    base['report_sha256'] = hashlib.sha256(canonical_json(base)).hexdigest()
    CalibrationReport.model_validate_json(canonical_json(base))
    verify_tier_r_report(base)
    return base
