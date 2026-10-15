"""A/A pairs for gate G-U1 (08-evaluation s1, s2) under SPEC-31's names, built by the SPEC-32 factory (s9).

P0 is the same commit rebuilt in another scratch directory (X versus X when the two images are byte-identical, which
the factory reports). P1 is nuisance that must not change a verdict; what the factory builds today is link order
(reversed and rotated). P2 is stress (optimisation levels, compilers): expected to be `induced`, reported, never
gated. The other P1 nuisances of the spec need link flags the SPEC-32 builder takes no argument for yet.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from tools.calibration.tier_r import factory as F

METHOD_CLASS = {'aa-rebuild': 'P0', 'aa-layout': 'P1', 'toolchain-noise': 'P2'}
P1_PENDING_REASON = ('the SPEC-32 builder (BuildSpec) takes no link flags, so the variant cannot be built; the '
                     'integrator ask is one link-flag field on BuildSpec and the recipe digest')
P1_PENDING = (('icf-toggle', 'link once with /opt:icf and once with /opt:noicf'),
              ('timestamp', 'link without /Brepro so the PE timestamp differs'),
              ('guid', 'link without /Brepro so the debug GUID differs'),
              ('path', 'build without the path maps so the scratch path reaches the image'))


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
    noise, skipped = F.run_noise(session, base)
    return AaResult([*docs, *noise], skipped)
