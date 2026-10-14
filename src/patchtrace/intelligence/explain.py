"""The ``intelligence explain`` report builder (SPEC-28 section L). Pure: no I/O, no Qt, no network.

``build_report`` joins what the other modules already derived into one ``IntelligenceReport``: the stored
advisories that list the CVE (vendor claims with JSON pointers), the OLD/NEW applicability, the CWE profile,
the rule hypotheses and the search anchors. It adds no claim of its own. Three rules keep it honest:

* Every stored document that lists the CVE is reported, superseded revisions included, so contradictions
  across revisions and VEX files stay visible. Applicability sees all of them.
* The CWE profile is classified from current documents only. When several are current the one with the
  strongest evidence is used (explicit CWE, then derived, weak, vague, none), then advisories before VEX files,
  then the newest release. The choice is named in the profile's limitations, and a vendor-stated CWE that
  differs between current documents is recorded as a disagreement, never resolved.
* Everything the evidence cannot settle is listed in ``unknowns`` (an unmapped artifact, an unverified
  mapping, unverified bytes, an unauthenticated file, no usable CWE). Missing is unknown, not a negative vote.

Advisory text stays verbatim in the report; it is escaped only when exported (``reports.py``).
"""
from __future__ import annotations

import re
import threading
from collections.abc import Sequence
from typing import Protocol

from .anchors import anchors_for
from .contracts import (
    AdvisoryFacts,
    AdvisorySource,
    ApplicabilityReport,
    ArtifactIdentity,
    CVEFact,
    CweProfile,
    HypothesisSet,
    IntelError,
    IntelligenceReport,
    SourceSummary,
)
from .csaf.applicability import resolve, supersession
from .csaf.validate import parse_date_time
from .hypotheses import hypotheses_for
from .lexicon import classify

CVE_ID = re.compile(r'CVE-[0-9]{4}-[0-9]{4,19}')
MAX_CVE_CHARS = 24  # the contract's CveId bound
REPORT_LIMITATIONS = (
    'This report restates vendor claims and PatchTrace rule hypotheses with their sources; it does not show that '
    'this CVE is present in, or fixed by, any function or binary.',
)
_STATUS_RANK = {'explicit': 0, 'derived': 1, 'weak': 2, 'vague': 3, 'none': 4}


class AdvisoryLike(Protocol):
    """What the builder reads of ``storage.StoredAdvisory`` (kept structural so this module does no I/O)."""

    @property
    def source(self) -> AdvisorySource: ...

    @property
    def facts(self) -> AdvisoryFacts: ...

    @property
    def superseded(self) -> bool: ...


def _check(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise IntelError('PT-INTEL-CANCEL', 'explain cancelled', recoverable=True)


def _label(advisory: AdvisoryLike) -> str:
    return f'{advisory.facts.tracking_id} revision {advisory.facts.revision}'


def _order(advisory: AdvisoryLike) -> tuple:
    facts = advisory.facts
    return (facts.tracking_id, facts.current_release_date, advisory.source.sha256)


def _timestamp(value: str) -> float:
    parsed = parse_date_time(value)
    return parsed.timestamp() if parsed is not None else 0.0


def _stated(profile: CweProfile) -> set[str]:
    """CWE ids the vendor itself states (CSAF field or id written in the text), not vocabulary matches."""
    return {c.cwe_id for c in profile.classifications if c.assessment == 'advisory-claim'}


def _cwe_profile(cve: str, current: list[tuple[AdvisoryLike, CVEFact]], others: int) -> CweProfile:
    profiles = [(advisory, classify(fact)) for advisory, fact in current]
    chosen_advisory, chosen = min(profiles, key=lambda item: (
        _STATUS_RANK[item[1].status], item[0].facts.document_category != 'csaf_security_advisory',
        -_timestamp(item[0].facts.current_release_date), item[0].facts.tracking_id, item[0].source.sha256))
    mine = _stated(chosen)
    disagreements = set(chosen.disagreements)
    for advisory, profile in profiles:
        theirs = _stated(profile)
        if advisory is not chosen_advisory and mine and theirs and theirs != mine:
            disagreements.add(f'{_label(advisory)} states {", ".join(sorted(theirs))} while '
                              f'{_label(chosen_advisory)} states {", ".join(sorted(mine))}; both are kept and '
                              'neither is resolved')
    limitations = list(chosen.limitations)
    if others:
        limitations.append(f'CWE profile derived from {_label(chosen_advisory)} '
                           f'({chosen_advisory.source.sha256[:12]}); {others} other stored document(s) listing '
                           f'{cve} were not used (superseded, or only compared for disagreements)')
    if disagreements == set(chosen.disagreements) and len(limitations) == len(chosen.limitations):
        return chosen
    return chosen.model_copy(update={'disagreements': tuple(sorted(disagreements)),
                                     'limitations': tuple(limitations)})


def _unknowns(applicability: ApplicabilityReport, profile: CweProfile, hypotheses: HypothesisSet,
              relevant: Sequence[AdvisoryLike], cve: str) -> tuple[str, ...]:
    found = set(hypotheses.unknowns)
    for side in (applicability.older, applicability.newer):
        who = f'{side.side} artifact'
        if side.identity.facts_state == 'record-only':
            found.add(f'{who}: artifact bytes were not verified; only the recorded SHA-256 was used')
        if side.product_mapping_status == 'unknown':
            found.add(f'{who}: no advisory product could be tied to it; applicability is unknown')
        elif side.resolution in ('unknown', 'ambiguous', 'contradictory'):
            found.add(f'{who}: applicability is {side.resolution}')
        elif side.product_mapping_status == 'candidate':
            found.add(f'{who}: the product mapping is a candidate, not verified')
    if profile.status in ('weak', 'vague', 'none'):
        found.add(f'weakness class: the CWE profile is {profile.status}, so no patch motif is expected')
    if any(a.source.authenticity_state == 'unverified-local-file' for a in relevant):
        found.add('advisory authenticity is unverified: a local file was imported and signatures are not checked')
    # Store-level supersession counts every stored document; applicability counts only those listing the CVE.
    local = supersession([a.facts for a in relevant])
    for advisory in relevant:
        if advisory.superseded and not local[advisory.facts.facts_id]:
            found.add(f'{_label(advisory)}: a newer stored revision no longer lists {cve}; this older revision is '
                      'shown, but its statuses are not marked superseded')
    return tuple(sorted(found))


def build_report(cve: str, advisories: Sequence[AdvisoryLike], older: ArtifactIdentity, newer: ArtifactIdentity,
                 *, cancel: threading.Event | None = None) -> IntelligenceReport:
    """The explain report for ``cve``. ``advisories`` are stored advisories (any listing order); only those that
    list the CVE are used. Raises ``PT-INTEL-INPUT`` (bad CVE or swapped sides), ``PT-INTEL-NOTFOUND`` (no stored
    advisory lists it) or ``PT-INTEL-CANCEL``."""
    if not isinstance(cve, str) or len(cve) > MAX_CVE_CHARS or CVE_ID.fullmatch(cve) is None:
        raise IntelError('PT-INTEL-INPUT', 'the CVE must look like CVE-YYYY-NNNN')
    unique = {a.source.sha256: a for a in advisories if a.facts.vulnerability(cve) is not None}
    relevant = sorted(unique.values(), key=_order)
    if not relevant:
        raise IntelError('PT-INTEL-NOTFOUND', f'no stored advisory lists {cve}')
    _check(cancel)
    applicability = resolve(cve, [a.facts for a in relevant], older, newer)
    _check(cancel)
    current = [a for a in relevant if not a.superseded] or relevant
    pairs = [(a, a.facts.vulnerability(cve)) for a in current]
    profile = _cwe_profile(cve, pairs, len(relevant) - 1)
    _check(cancel)
    hypotheses = hypotheses_for(profile)
    anchors = anchors_for(cve, [a.facts for a in current], (older, newer), hypotheses)
    _check(cancel)
    limitations = list(REPORT_LIMITATIONS)
    for group in (applicability.limitations, profile.limitations, hypotheses.limitations, anchors.limitations):
        limitations += [item for item in group if item not in limitations]
    return IntelligenceReport(
        cve=cve,
        sources=tuple(SourceSummary(source=a.source, facts_id=a.facts.facts_id, superseded=a.superseded,
                                    cves=a.facts.cves(), validation_warnings=len(a.facts.validation.warnings))
                      for a in relevant),
        facts=tuple(a.facts.vulnerability(cve) for a in relevant),
        applicability=applicability, cwe_profile=profile, hypotheses=hypotheses, anchors=anchors,
        unknowns=_unknowns(applicability, profile, hypotheses, relevant, cve), limitations=tuple(limitations))
