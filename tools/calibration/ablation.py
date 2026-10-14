"""Required ablations (spec §6.4b): leave-one-family-out (non-G families), drop every feature that depends on
the Ghidra database (D_ghidra), and drop everything symbol-derived (D_symbols). Each ablated model is refit
with the same grouped nested CV; the reported quantity is FDR(ablated) - FDR(full) at the full model's
coverage under the same lineage resamples (positive = the dropped features help). A family whose interval
does not exclude 0 does not improve H4 and is removed from the profile (spec §12)."""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from patchtrace.calibration.features import family_dependencies

from .baselines import restrict
from .bootstrap import fdr_reduction_stat, paired_delta
from .common import Row
from .cv import CVConfig, nested_cv


def family_of(name: str) -> str:
    return name.split('.', 1)[0]


def ablation_sets(names: Sequence[str], binexport_producer: str = 'ghidra') -> dict[str, list[str]]:
    deps = family_dependencies(binexport_producer)
    fams = sorted({family_of(n) for n in names})
    sets = {f'drop-{f}': [n for n in names if family_of(n) != f] for f in fams if f != 'G'}
    sets['drop-D_ghidra'] = [n for n in names if 'D_ghidra' not in deps[family_of(n)]]
    sets['drop-D_symbols'] = [n for n in names if 'D_symbols' not in deps[family_of(n)]
                              and not n.startswith('P.symbols')]
    return sets


def run_ablations(rows: Sequence[Row], names: Sequence[str], cfg: CVConfig, *, full_oof: Mapping[str, float],
                  tau: float, b_count: int, seed=41, binexport_producer: str = 'ghidra') -> dict[str, dict]:
    nat = [r for r in rows if r.stratum == 'natural']
    out = {}
    for key, keep in sorted(ablation_sets(names, binexport_producer).items()):
        if not keep:
            out[key] = {'status': 'no-features-left'}
            continue
        if len(keep) == len(names):
            out[key] = {'status': 'nothing-dropped'}
            continue
        oof = nested_cv(restrict(rows, names, keep), cfg).oof
        delta = paired_delta(nat, full_oof, oof, fdr_reduction_stat(tau), b_count, (seed, key))
        out[key] = dict(delta, status='ok', kept=len(keep), improves_h4=bool(delta['lo'] is not None
                                                                              and delta['lo'] > 0))
    return out
