"""Fit pipeline and artifact builder/promoter (spec §8, §10.4).

`build_artifact` always writes status `experimental` (display none). Only `promote` raises the status, and
only from a report whose SHA matches and whose gates pass: G2 -> bands-ok, G3 -> numeric-ok.
`python -m tools.calibration.fit --synthetic OUT` runs the whole pipeline on a generated world.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import statistics
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from patchtrace.calibration.artifact import CONTRACT, digest, parse_artifact
from patchtrace.calibration.features import FEATURE_SCHEMA

from .ablation import run_ablations
from .baselines import all_baselines
from .common import Row, canonical_json, r12
from .cv import CVConfig, FittedModel, final_model, nested_cv
from .evaluate import evaluate_profile
from .gates import evaluate_gates
from .ood_fit import ood_fit, reduce_spec
from .report import SYNTHETIC_CLAIM, make_report, verify_report
from .stats import kish_n
from .threshold import choose_tau, choose_tau_low


class PromotionError(ValueError):
    pass


def medians(dicts: Sequence[Mapping[str, float | None]], names: Sequence[str]) -> dict[str, float]:
    out = {}
    for n in names:
        vals = sorted(v for d in dicts if (v := d.get(n)) is not None)
        out[n] = statistics.median(vals) if vals else 0.0
    return out


def impute(d: Mapping[str, float | None], names: Sequence[str], med: Mapping[str, float]) -> tuple[float, ...]:
    return tuple(med[n] if d.get(n) is None else float(d[n]) for n in names)


def build_artifact(*, model: FittedModel, profile: str, names: Sequence[str], kinds: Sequence[str],
                   med: Mapping[str, float], ood: Mapping, tau: float | None, tau_low: float | None,
                   domain: Mapping, evidence: Mapping, model_id: str, created: dt.date) -> dict:
    cal = model.calibrator
    calibrator = ({'type': 'platt', 'a': r12(cal[1]), 'b': r12(cal[2])} if cal[0] == 'platt'
                  else {'type': 'isotonic', 'knots': [[r12(s), r12(p)] for s, p in cal[1]]})
    doc = {'contract': CONTRACT, 'model_id': model_id, 'status': 'experimental', 'target': 'A',
           'feature_schema': FEATURE_SCHEMA, 'profile': profile,
           'features': [{'name': n, 'kind': k, 'median': r12(med[n]), 'mean': r12(m), 'sd': r12(s), 'coef': r12(c)}
                        for n, k, m, s, c in zip(names, kinds, model.mu, model.sd, model.beta[1:], strict=True)],
           'intercept': r12(model.beta[0]), 'base': 'l2-logistic', 'C': model.c, 'calibrator': calibrator,
           'policy': {'tau': tau, 'tau_low': tau_low, 'display': 'none', 'bands': []}, 'ood': dict(ood),
           'calibration_domain': dict(domain), 'evidence': dict(evidence), 'created': created.isoformat(),
           'expires': (created + dt.timedelta(days=365)).isoformat()}
    doc['digest_sha256'] = digest(doc)
    return doc


def _reproduce_gates(report: Mapping, profile: str, claimed: Mapping[str, str]) -> None:
    """Never trust a gate status that the report's own numbers do not reproduce (sample size, ECE excess, CIs).
    Non-statistical conditions (owner sign-off etc.) are not in a report, so they are assumed true here."""
    res = report['per_profile'].get(profile)
    if not res:
        raise PromotionError(f'report has no profile {profile}')
    cond = dict.fromkeys(('reproducibility_check', 'owner_signoff', 'frozen_exe_smoke', 'independence_caveat_shown'),
                         True)
    again = evaluate_gates(report['dataset'], res, pipeline=res, conditions=cond)
    for gate in ('G0', 'G2', 'G3'):
        if claimed.get(gate) == 'pass' and again[gate]['status'] != 'pass':
            raise PromotionError(f'{gate} does not reproduce from the report numbers: {again[gate]["reasons"][:3]}')


def promote(artifact: Mapping, report: Mapping, *, profile_gates: Mapping[str, Mapping] | None = None) -> dict:
    """Raise status only on matching, passing report evidence; never edits a report."""
    if not verify_report(report):
        raise PromotionError('report SHA does not verify')
    dom = artifact['calibration_domain']
    if ('tier-w' not in dom.get('evidence_tiers', ()) or dom.get('windows_system_binaries', 'none') == 'none'
            or 'no-windows-system-binaries' in dom.get('scope_ids', ())):
        raise PromotionError('Tier R-only (synthetic) evidence cannot be promoted: Tier W domain required')
    if report.get('claim') == SYNTHETIC_CLAIM:
        raise PromotionError('a synthetic/Tier R report makes no real-world claim and cannot be promoted')
    gates = profile_gates or report['per_profile'].get(artifact['profile'], {}).get('gates') or {}
    status = {k: v['status'] for k, v in gates.items()}
    _reproduce_gates(report, artifact['profile'], status)
    if status.get('G0') == status.get('G2') == status.get('G3') == 'pass':
        level, display = 'numeric-ok', 'number'
    elif status.get('G0') == status.get('G2') == 'pass':
        level, display = 'bands-ok', 'band'
    else:
        raise PromotionError(f'gates do not pass: {status}')
    doc = json.loads(canonical_json(artifact))
    doc['status'] = level
    doc['policy']['display'] = display
    doc['evidence'].update({'report_sha256': report['report_sha256'], 'preregistration_sha256':
                            report['prereg_sha256'], 'gates': status})
    doc['digest_sha256'] = digest(doc)
    return doc


ABLATION_REFERENCE_COVERAGE = 0.5  # preregistered: used only when no tau was certified


def validated_ood(spec: Mapping, risk_ratio_lo: float | None) -> tuple[dict, bool]:
    """Keep the Mahalanobis test only if flagged rows err more than unflagged ones (lineage-bootstrap risk
    ratio lower bound > 1); otherwise apply the preregistered fallback (range/unseen-level only)."""
    if risk_ratio_lo is not None and risk_ratio_lo > 1:
        return dict(spec), False
    return reduce_spec(spec), True


def dev_negatives(rows: Sequence[Row]) -> float:
    """Effective number of natural y = 0 rows (Kish n). A sum of inverse-inclusion weights would count a handful of
    heavily weighted negatives as a hundred and pass the `dev_neg >= 100` minimum."""
    return kish_n([r.w for r in rows if r.stratum == 'natural' and not r.y])


def reference_tau(rows: Sequence[Row], oof: Mapping[str, float],
                  coverage: float = ABLATION_REFERENCE_COVERAGE) -> float:
    nat = sorted((r for r in rows if r.stratum == 'natural'), key=lambda r: (-oof[r.id], r.id))
    total = math.fsum(r.w for r in nat)
    acc = 0.0
    for r in nat:
        acc += r.w
        if acc >= coverage * total:
            return oof[r.id]
    return oof[nat[-1].id]


@dataclass
class PipelineResult:
    oof: dict[str, float]
    model: FittedModel
    tau: dict | None
    tau_low: dict | None
    evaluation: dict
    artifact: dict
    report: dict


def run_pipeline(rows: Sequence[Row], *, names: Sequence[str], kinds: Sequence[str], profile: str,
                 cfg: CVConfig, b_count: int = 2000, created: dt.date, model_id: str,
                 domain: Mapping | None = None, synthetic: bool = True, dataset: Mapping | None = None,
                 baselines: Mapping[str, Mapping[str, float]] | None = None, with_m1: bool = False,
                 null_sims: int = 1000, ablate: bool = False) -> PipelineResult:
    """dev rows -> nested grouped CV OOF -> frozen tau/tau_low -> final model -> OOD -> artifact + report."""
    rows = sorted(rows, key=lambda r: r.id)
    continuous_idx = [j for j, k in enumerate(kinds) if k == 'num']
    nested = nested_cv(rows, cfg, ood_columns=continuous_idx)
    tau = choose_tau(rows, nested.oof)
    tau_low = choose_tau_low(rows, nested.oof, tau['tau'] if tau else None)
    if baselines is None:
        baselines = all_baselines(rows, names, cfg if with_m1 else None)
    model = final_model(rows, cfg)
    med = {n: statistics.median(r.x[j] for r in rows) for j, n in enumerate(names)}
    continuous = [n for n, k in zip(names, kinds, strict=True) if k == 'num']
    idx = {n: j for j, n in enumerate(names)}
    ood = ood_fit([{n: r.x[idx[n]] for n in continuous} for r in rows], [1.0] * len(rows), continuous, [], [])
    evaluation = evaluate_profile(rows, nested.oof, tau=tau['tau'] if tau else None,
                                  tau_low=tau_low['tau_low'] if tau_low else None, baselines=baselines,
                                  ood_hard=nested.ood_hard if continuous_idx else None,
                                  b_count=b_count, null_sims=null_sims)
    evaluation['n_dev_natural'] = sum(r.stratum == 'natural' for r in rows)
    evaluation['dev_neg'] = dev_negatives(rows)
    evaluation['dev_lineages'] = evaluation['n_groups']
    evaluation['tau_selection'] = {'tau': tau, 'tau_low': tau_low}
    ood, evaluation['ood_reduced'] = validated_ood(ood, evaluation.get('ood_risk_ratio_lo'))
    evaluation['ablation_reported'] = False
    if ablate:
        ref_tau = tau['tau'] if tau else reference_tau(rows, nested.oof)
        evaluation['ablations'] = run_ablations(rows, names, cfg, full_oof=nested.oof, tau=ref_tau, b_count=b_count)
        evaluation['ablation_reference_tau'] = ref_tau
        evaluation['ablation_reported'] = True
    dataset = dict(dataset or {'tier': 'synthetic', 'n_rows': len(rows)})
    evaluation['gates'] = evaluate_gates(dataset, evaluation, pipeline=evaluation)
    report = make_report(prereg_sha=None, corpus_manifest_sha=None, label_set_sha=None, tool_git='synthetic',
                         dataset=dataset, per_profile={profile: evaluation}, synthetic=synthetic)
    domain = dict(domain or {'engines': {}, 'toolchains': [], 'arch': [], 'corpus_id': 'synthetic',
                             'n_pairs': 0, 'n_lineages': evaluation['n_groups'],
                             'prevalence': r12(evaluation['prevalence']),
                             'known_blind_spots': ['synthetic data only; no real-binary domain']})
    artifact = build_artifact(model=model, profile=profile, names=names, kinds=kinds, med=med, ood=ood,
                              tau=tau['tau'] if tau else None, tau_low=tau_low['tau_low'] if tau_low else None,
                              domain=domain, evidence={'preregistration_sha256': None,
                                                       'report_sha256': report['report_sha256'],
                                                       'corpus_manifest_sha256': None, 'label_set_sha256': None,
                                                       'tool_git': 'synthetic', 'gates': {}},
                              model_id=model_id, created=created)
    parse_artifact(canonical_json(artifact), today=created)  # the shipped loader must accept what we build
    return PipelineResult(nested.oof, model, tau, tau_low, evaluation, artifact, report)


def main(argv: Sequence[str] | None = None) -> int:  # pragma: no cover - thin CLI over run_pipeline
    from .synth import make_world
    parser = argparse.ArgumentParser(description='Run the calibration pipeline on a synthetic world.')
    parser.add_argument('--synthetic', type=Path, required=True, help='output directory')
    parser.add_argument('--created', default='2026-10-14')
    args = parser.parse_args(argv)
    world = make_world(n_groups=40, per_group=40, beta=(2.0, 1.5, -1.0, 0.5), seed='cli')
    names = ['G.ratio', 'R.similarity', 'S.size_ratio']
    res = run_pipeline(world.rows, names=names, kinds=['num'] * 3, profile='G+R',
                       cfg=CVConfig(k_outer=5, k_inner=4, c_grid=(0.1, 1.0)), b_count=500,
                       created=dt.date.fromisoformat(args.created), model_id='synthetic-demo')
    args.synthetic.mkdir(parents=True, exist_ok=True)
    from .report import render_markdown
    (args.synthetic / 'report.json').write_bytes(canonical_json(res.report) + b'\n')
    (args.synthetic / 'report.md').write_text(render_markdown(res.report), encoding='utf-8')
    (args.synthetic / 'artifact.json').write_bytes(canonical_json(res.artifact) + b'\n')
    print(json.dumps({'report_sha256': res.report['report_sha256'], 'gates': res.report['gates']}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
