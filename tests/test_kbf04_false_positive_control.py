"""KBF-04 false-positive-control guard-locks (docs/specs/kb/cve-to-function-matching-spec.md section 5 and 6).

Section 5 of that spec names several regression tests as "NEW" (red tests to write) that guard BUILT
behaviour so a later change cannot silently turn an honest "no fit" into a finding, double-count a lineage,
or leak a calibrated-looking number into the leads/KB view. Those named tests did not exist on main; this
module writes them. They are guard-locks for behaviour that already holds, so they pass today and a
one-line mutation of the guard they cover must fail at least one of them.

Covered, by the spec's own test names:
  * ``test_leads_unexplained_never_a_finding``  (s5: an all-unexplained CVE stays class ``queue``)
  * ``test_anchor_lineage_counts_once``         (s5: the same component from two advisory lineages is one family)
  * ``test_pilot_and_kb_import_no_calibration`` (s6.3: pilot/ and kbcorrelation/ never import calibration)

Synthetic data only; nothing here is live evidence.
"""
from __future__ import annotations

import subprocess
import sys

from pilot_localize_support import (
    CVE_A,
    advisory_entry,
    build,
    candidate,
    context,
    hypothesis,
    leads_of,
    observation,
    run,
)

from patchtrace.enrichment.identity import domain_id
from patchtrace.intelligence.contracts import Anchor
from patchtrace.pilot.fusion import _phrases
from patchtrace.pilot.report import _EXPLAINED


def _component_anchor(value: str, source: str, pointer: str) -> Anchor:
    """A production-shaped component anchor (same recipe as intelligence.anchors._anchor): the id binds the
    provenance (kind, value, source, pointer), so the same component from two advisory lineages has two ids."""
    return Anchor(anchor_id=domain_id('anchor', 1, {'kind': 'component', 'value': value, 'source': source,
                                                     'pointer': pointer}),
                  kind='component', value=value, source=source, pointer=pointer, quality='derived',
                  label=f'component {value}')


def _scenario(observations, *, anchors=()):
    """One candidate against CVE_A with every tool channel available; returns (assessment, its lead)."""
    cand = candidate(1, 'Handler')
    inputs = build([cand], [(cand, o) for o in observations], cves={CVE_A: (hypothesis(),)},
                   contexts=[context(CVE_A)], anchors=anchors, entries={CVE_A: (advisory_entry(),)},
                   capa='available', strings='available', build_state='available')
    assessment = run(inputs)
    return assessment, leads_of(assessment, CVE_A).get(cand.candidate_key)


# --- s5: an all-unexplained CVE is counted, never presented as a located fix ------------------------------------------

def test_leads_unexplained_never_a_finding():
    """A changed function that fits no hypothesis is ``queue``/``unexplained`` and is counted but never promoted
    to an explained finding class. Spec s5 row "CVE where every candidate is unexplained shown as a finding"."""
    assessment, lead = _scenario([observation('str:added', role='context', ref='s')])

    assert lead is not None
    assert (lead.lead_class, lead.mechanism) == ('queue', 'unexplained')
    # "queue" is never one of the explained classes that get a Why block / finding treatment.
    assert 'queue' not in _EXPLAINED
    assert lead.lead_class not in _EXPLAINED

    # Scoped to the applicable CVE: no candidate is presented as a located fix (fit/review/partial); the
    # changed-but-unfitting function stays in the honest "changed, no fit" queue, counted and never a finding.
    cve_leads = list(leads_of(assessment, CVE_A).values())
    assert cve_leads, 'the candidate must appear under the applicable CVE'
    assert all(cl.lead_class not in ('fit', 'review', 'partial') for cl in cve_leads)
    assert any(cl.lead_class == 'queue' and cl.mechanism == 'unexplained' for cl in cve_leads)


# --- s5: the same component from two advisory lineages is one family, not doubled support -----------------------------

def test_anchor_lineage_counts_once():
    """The same component named in both a CSAF and a CVRF advisory is two anchor ids (provenance differs) but a
    single independence family: it never adds an independent witness and never appears twice as a search phrase.
    Spec s5 row "the same anchor twice from CSAF and CVRF doubling support"."""
    csaf = _component_anchor('IPv6 Fragment Reassembly', 'csaf-title', '/vulnerabilities/0/title')
    cvrf = _component_anchor('IPv6 Fragment Reassembly', 'cvrf-title', '/Vulnerability/0/Title')

    # Distinct provenance ids, identical (kind, value): independence is by value/lineage, not by anchor id.
    assert csaf.anchor_id != cvrf.anchor_id
    assert (csaf.kind, csaf.value) == (cvrf.kind, cvrf.value)

    # The phrase layer collapses them to one: locality cannot double-count the component.
    assert len(_phrases((csaf, cvrf))) == 1
    assert _phrases((csaf, cvrf)) == _phrases((csaf,))

    # And at fusion: a real code change that fits still has exactly two witnesses (code + advisory text);
    # the duplicated advisory lineage does not inflate the independent-component count.
    _, lead = _scenario([observation('b1:BND', ref='x', line=7)], anchors=(csaf, cvrf))
    assert lead is not None
    assert (lead.components.count, lead.components.tags) == (2, ('D_ghidra', 'D_vendor_text'))


# --- s6.3: the leads/KB localization layer never imports the calibration machinery ------------------------------------

def test_pilot_and_kb_import_no_calibration():
    """``pilot/`` and ``kbcorrelation/`` must not import ``patchtrace.calibration`` (spec s6.3): advisory
    localization carries no calibrated quantity, so no calibration seam may leak into these packages. Checked in
    a fresh interpreter over every submodule of both packages."""
    code = (
        'import importlib, pkgutil, sys\n'
        'import patchtrace.pilot, patchtrace.kbcorrelation\n'
        'for pkg in (patchtrace.pilot, patchtrace.kbcorrelation):\n'
        '    for info in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):\n'
        '        importlib.import_module(info.name)\n'
        'bad = sorted(m for m in sys.modules\n'
        '             if m == "patchtrace.calibration" or m.startswith("patchtrace.calibration."))\n'
        'sys.stderr.write(",".join(bad))\n'
        'raise SystemExit(1 if bad else 0)\n'
    )
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True)
    assert result.returncode == 0, f'calibration imported by: {result.stderr}\n{result.stdout}'
