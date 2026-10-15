"""A/A pairs for gate G-U1 (08-evaluation s1, s2) under SPEC-31's names, built by the SPEC-32 factory (s9).

P0 is the same commit rebuilt in another scratch directory (X versus X when the two images are byte-identical, which
the factory reports). P1 is nuisance that must not change a verdict; what the factory builds today is link order
(reversed and rotated). P2 is stress (optimisation levels, compilers): expected to be `induced`, reported, never
gated. The other P1 nuisances (`NUISANCES`: ICF toggle, timestamp, GUID, scratch path) are `BuildSpec.nuisance` variants
of the same source; each is a P1 pair whose case names it, and the gate wants every kind covered.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from tools.calibration.tier_r import factory as F
from tools.calibration.tier_r.build import NUISANCES

METHOD_CLASS = {'aa-rebuild': 'P0', 'aa-layout': 'P1', 'toolchain-noise': 'P2'}
P1_KINDS = ('link-order', *NUISANCES)       # what G-U1 wants covered; a kind with no pair keeps the gate pending


@dataclass
class AaResult:
    docs: list[dict] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)       # noise variants that could not be built here, with why


def classify(doc) -> str | None:
    """P0 / P1 / P2 from a label document (model or dict), None for any other method."""
    method = doc.get('method') if isinstance(doc, dict) else doc.method
    return METHOD_CLASS.get(method)


def run(session: F.Session, base: F.BaseSource, *, opt: str = 'O2') -> AaResult:
    docs = F.run_aa(session, base, opt=opt, layout=True)
    nuisance, unbuilt = F.run_nuisance(session, base, NUISANCES, opt=opt)
    noise, skipped = F.run_noise(session, base)
    return AaResult([*docs, *nuisance, *noise], [*unbuilt, *skipped])


def variant_of(doc) -> str:
    """The P1 kind of a label document: a nuisance name, `link-order`, or '' for any other pair."""
    case = doc.get('case') if isinstance(doc, dict) else doc.case
    kind = case.get('kind')
    return case.get('nuisance', '') if kind == 'nuisance' else 'link-order' if kind == 'link-order' else ''
