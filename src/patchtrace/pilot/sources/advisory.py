"""The advisory side of a CVE context (PIL-integration-plan.md s4, s7 "CVE gate", s9 PIL-A2).

Adapts K's `IntelligenceReport` (or a CVE record without product data, see `snapshot.py`) into what the localization core
needs about one CVE: the applicability gate, the CWE summary, the rule hypotheses, search anchors, the advisory's own
ledger entries and plain-text limitations. Nothing here looks at code: an advisory statement is context that can never raise
a tier by itself, and every repetition of it (an advisory, an NVD or MSRC record) is one origin (`D_vendor_text`), counted once.

The gate (s7), read from the strongest statement down:
  conflict        any contradiction, or a side that resolves `contradictory`: leads are capped at review;
  not-applicable  the older side is not affected, the newer side is still affected, or both sides are already fixed
                  or not affected: no leads for this CVE;
  unverified      a side is unmapped, or resolves unknown, ambiguous or under investigation: capped at tentative;
  applies         older affected and newer fixed or not affected.
An analyst assumption (`--assume-applies`) only fills the gap: it turns `unverified` into `asserted` and never overrides
what the advisory states, so a conflict or a not-applicable gate stays, and the assumption is reported as not used.

Pure: loaded inputs in, immutable values out. No I/O, no Qt, no network; advisory text is untrusted and reaches a record
only through `contracts.clean_line`.
"""
from __future__ import annotations

import threading
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ...intelligence.contracts import (
    Anchor,
    ApplicabilityReport,
    ArtifactIdentity,
    CVEFact,
    CweClassification,
    CweProfile,
    IntelError,
    IntelligenceReport,
    PatchHypothesis,
)
from ...intelligence.explain import AdvisoryLike, build_report
from ...intelligence.hypotheses import hypotheses_for
from ...intelligence.lexicon import classify
from ..contracts import (
    MAX_CWE_IDS,
    MAX_NOTES,
    MAX_SOURCES,
    ApplicabilitySummary,
    ChannelStatus,
    Confounding,
    ContextGate,
    CveContext,
    CweSummary,
    Kev,
    LeadCounts,
    Observation,
    ObsRef,
    clean_line,
)
from ..keys import make_observation
from ..limits import PilotError
from ..origins import DefaultOriginRegistry

if TYPE_CHECKING:
    from ..ports import OriginRegistry

ASSUMED = 'The analyst assumed that this CVE applies to these builds; the advisory could not tie it to them.'
ASSUMPTION_NOT_NEEDED = ('The assumption that this CVE applies was not needed: '
                         'the advisory already ties it to these builds.')
ASSUMPTION_IGNORED = ('The assumption that this CVE applies was not used: '
                      'the advisory states otherwise or conflicts with itself.')
NO_APPLICABILITY = 'The record carries no product applicability, so nothing ties it to these builds.'
_FIXED_LIKE = frozenset({'fixed', 'not_affected'})
_UNSETTLED = frozenset({'unknown', 'ambiguous', 'under_investigation'})
_REGISTRY = DefaultOriginRegistry()


def notes_left_out(count: int) -> str:
    return f'{count} further notes were left out'


def sources_left_out(count: int) -> str:
    return f'{count} further advisory sources were left out of the source list'


@dataclass(frozen=True, slots=True)
class AdvisoryContext:
    """The advisory-side input of one CVE. `source_ids` and `facts_ids` are the content digests of the documents used
    (the second feeds `PilotInputs.advisory_facts_ids`); `hypotheses` are K's rule hypotheses, best first; `anchors`
    are K's search hints; `observations` are the advisory's ledger entries, sorted by id."""
    cve: str
    gate: ContextGate
    applicability: ApplicabilitySummary
    cwe: CweSummary
    source_ids: tuple[str, ...]
    facts_ids: tuple[str, ...]
    hypotheses: tuple[PatchHypothesis, ...]
    anchors: tuple[Anchor, ...]
    observations: tuple[Observation, ...]
    limitations: tuple[str, ...]


# --- the gate and the summaries ------------------------------------------------------------------------------------

def applicability_summary(report: ApplicabilityReport) -> ApplicabilitySummary:
    older, newer = report.older, report.newer
    return ApplicabilitySummary(older=older.resolution, newer=newer.resolution,
                                older_mapping=older.product_mapping_status, newer_mapping=newer.product_mapping_status,
                                contradictions=len(report.contradictions))


def _stated_gate(summary: ApplicabilitySummary) -> ContextGate:
    """What the advisory itself supports, before any analyst assumption."""
    older, newer = summary.older, summary.newer
    if summary.contradictions or 'contradictory' in (older, newer):
        return 'conflict'
    if older == 'not_affected' or newer == 'affected' or (older in _FIXED_LIKE and newer in _FIXED_LIKE):
        return 'not-applicable'
    if older in _UNSETTLED or newer in _UNSETTLED or 'unknown' in (summary.older_mapping, summary.newer_mapping):
        return 'unverified'
    return 'applies'


def cve_gate(summary: ApplicabilitySummary, *, assumed: bool = False) -> ContextGate:
    """The CVE gate of s7 for one applicability summary; `assumed` is the analyst's `--assume-applies`."""
    stated = _stated_gate(summary)
    return 'asserted' if assumed and stated == 'unverified' else stated


def cwe_summary(profile: CweProfile) -> CweSummary:
    """Status and CWE ids of K's profile: usable (explicit or phrase-matched) ids, or the weak ones when only those
    exist; vague and empty text list none. At most 16 ids, the first in K's order."""
    if profile.status in ('vague', 'none'):
        return CweSummary(status=profile.status, ids=())
    usable = [c.cwe_id for c in profile.classifications if c.confidence != 'weak']
    ids = usable or [c.cwe_id for c in profile.classifications]
    return CweSummary(status=profile.status, ids=tuple(sorted(set(ids[:MAX_CWE_IDS]))))


# --- the advisory's ledger entries ---------------------------------------------------------------------------------

def _detail(classification: CweClassification, noun: str) -> str:
    if classification.assessment != 'advisory-claim':
        text = f'{classification.cwe_id} inferred from the {noun} wording ({classification.family})'
    elif classification.basis == 'explicit-csaf-cwe':
        text = f'{classification.cwe_id} as stated by the {noun}'
    else:
        text = f'{classification.cwe_id} named in the {noun}'
    return clean_line(text)


def _cwe_observations(cve: str, profile: CweProfile, *, noun: str, ref_kind: str,
                      owner: Callable[[str | None], str | None],
                      registry: OriginRegistry) -> tuple[Observation, ...]:
    """One context entry per usable CWE: a stated one is the vendor's claim, a vocabulary match is PatchTrace's
    interpretation of the vendor's words. Both derive from the vendor text, so both carry its one origin."""
    found: dict[str, Observation] = {}
    for item in profile.classifications:
        if item.confidence == 'weak':
            continue
        stated = item.assessment == 'advisory-claim'
        pointer = item.pointers[0] if item.pointers else None
        observation = make_observation(
            channel='advisory', kind='adv:cwe-stated' if stated else 'adv:cwe-derived', role='context',
            verification='advisory-claim' if stated else 'rule-hypothesis',
            origins=registry.tags_for('advisory-text'), evidence_class='E-TEXT', anchor_ids=(f'cwe:{item.cwe_id}',),
            ref=ObsRef(kind=ref_kind, id=cve, pointer=pointer, sha256=owner(pointer)), detail=_detail(item, noun))
        found[observation.obs_id] = observation
    return tuple(found[obs_id] for obs_id in sorted(found))


def _pointers(fact: CVEFact) -> set[str]:
    """The JSON pointers K's lexicon reads text from, hence the ones a CWE classification can name."""
    found = {f'{fact.pointer}/title'} if fact.title else set()
    if fact.cwe is not None:
        found.add(fact.cwe.pointer)
    found.update(note.pointer for note in fact.notes)
    found.update(f'{threat.pointer}/details' for threat in fact.threats)
    return found


def _owner_in(report: IntelligenceReport) -> Callable[[str | None], str | None]:
    """pointer -> SHA-256 of the one current document that holds it, else None: when several current documents have
    the pointer the digest is left out rather than guessed."""
    summaries = report.sources
    current = {s.source.source_id for s in summaries if not s.superseded} or {s.source.source_id for s in summaries}
    held = [(fact.source_id, _pointers(fact)) for fact in report.facts if fact.source_id in current]

    def owner(pointer: str | None) -> str | None:
        holders = {source_id for source_id, pointers in held if pointer in pointers}
        return next(iter(holders)) if len(holders) == 1 else None
    return owner


# --- limitations ---------------------------------------------------------------------------------------------------

def _assumption_notes(summary: ApplicabilitySummary, assumed: bool) -> tuple[str, ...]:
    if not assumed:
        return ()
    stated = _stated_gate(summary)
    return ({'unverified': ASSUMED, 'applies': ASSUMPTION_NOT_NEEDED}.get(stated, ASSUMPTION_IGNORED),)


def _bounded_notes(lines: Iterable[str]) -> tuple[str, ...]:
    """Plain, de-duplicated lines in order, at most `MAX_NOTES`; the last one says how many were left out."""
    cleaned = list(dict.fromkeys(line for line in map(clean_line, lines) if line))
    if len(cleaned) <= MAX_NOTES:
        return tuple(cleaned)
    kept = cleaned[:MAX_NOTES - 1]
    return (*kept, notes_left_out(len(cleaned) - len(kept)))


# --- contexts ------------------------------------------------------------------------------------------------------

def _registry(registry: OriginRegistry | None) -> OriginRegistry:
    return _REGISTRY if registry is None else registry


def context_from_report(report: IntelligenceReport, *, assume_applies: bool = False,
                        registry: OriginRegistry | None = None) -> AdvisoryContext:
    """The advisory context of one K report. `registry` supplies the origin tags (PIL's default table)."""
    summary = applicability_summary(report.applicability)
    source_ids = sorted({s.source.source_id for s in report.sources})
    omitted = [sources_left_out(len(source_ids) - MAX_SOURCES)] if len(source_ids) > MAX_SOURCES else []
    notes = (*_assumption_notes(summary, assume_applies), *omitted, *report.unknowns,
             *report.cwe_profile.disagreements, *report.limitations)
    return AdvisoryContext(
        cve=report.cve, gate=cve_gate(summary, assumed=assume_applies), applicability=summary,
        cwe=cwe_summary(report.cwe_profile), source_ids=tuple(source_ids[:MAX_SOURCES]),
        facts_ids=tuple(sorted({s.facts_id for s in report.sources})), hypotheses=report.hypotheses.hypotheses,
        anchors=report.anchors.anchors,
        observations=_cwe_observations(report.cve, report.cwe_profile, noun='advisory', ref_kind='csaf-fact',
                                       owner=_owner_in(report), registry=_registry(registry)),
        limitations=_bounded_notes(notes))


def context_from_fact(fact: CVEFact, *, assume_applies: bool = False, registry: OriginRegistry | None = None,
                      limitations: Sequence[str] = ()) -> AdvisoryContext:
    """The advisory context of a CVE record without product data (a B3 snapshot or an excerpt, via `snapshot.py`).

    K's lexicon and rules classify the record like an advisory, but nothing ties it to the two builds: both sides are
    unmapped, so the gate is `unverified`, or `asserted` when the analyst assumes the CVE applies. `limitations` are
    the source's own notes (`snapshot.snapshot_limitations`)."""
    if fact.cve is None:
        raise PilotError('PT-PILOT-INPUT', 'A CVE record needs a CVE id', reason='record-cve')
    found = classify(fact)
    hypotheses = hypotheses_for(found)
    summary = ApplicabilitySummary(older='unknown', newer='unknown', older_mapping='unknown', newer_mapping='unknown')
    notes = (*_assumption_notes(summary, assume_applies), NO_APPLICABILITY, *limitations, *found.disagreements,
             *found.limitations, *hypotheses.unknowns, *hypotheses.limitations)
    return AdvisoryContext(
        cve=fact.cve, gate=cve_gate(summary, assumed=assume_applies), applicability=summary,
        cwe=cwe_summary(found), source_ids=(fact.source_id,), facts_ids=(fact.source_id,),
        hypotheses=hypotheses.hypotheses, anchors=(),
        observations=_cwe_observations(fact.cve, found, noun='CVE record', ref_kind='cve-record',
                                       owner=lambda _pointer: fact.source_id, registry=_registry(registry)),
        limitations=_bounded_notes(notes))


def cve_context(context: AdvisoryContext, *, kev: Kev, confounding: Confounding, counts: LeadCounts) -> CveContext:
    """The persisted `CveContext` record: this advisory context plus the KEV state, the window and the lead counts."""
    return CveContext(cve=context.cve, source_ids=context.source_ids, gate=context.gate,
                      applicability=context.applicability, cwe=context.cwe, kev=kev, confounding=confounding,
                      counts=counts, limitations=context.limitations)


# --- stored advisories as the AdvisorySource port -------------------------------------------------------------------

def _group(advisory: AdvisoryLike) -> tuple[str, str]:
    return advisory.facts.publisher_namespace, advisory.facts.tracking_id


class StoredAdvisorySource:
    """`ports.AdvisorySource` over LOADED stored advisories (`intelligence.storage.AdvisoryStore.advisories()`) and the
    two artifact identities: one K report per CVE, built on first use. Owned by one worker thread.

    `cves` narrows the universe to the CVEs of a run. `facts_ids()` then names the documents behind them and every
    other revision of the same tracking id, because a revision that withdrew a CVE still supersedes the older one and
    so changes what the report says. `warnings` are the store's own (rows or files it had to skip)."""

    def __init__(self, advisories: Sequence[AdvisoryLike], older: ArtifactIdentity, newer: ArtifactIdentity, *,
                 cves: Iterable[str] | None = None, warnings: Sequence[str] = (),
                 cancel: threading.Event | None = None):
        if older.side != 'older' or newer.side != 'newer':
            raise PilotError('PT-PILOT-ORIENTATION', 'The artifact identities must be given as (older, newer)',
                             reason='identities-swapped')
        self._advisories = tuple(advisories)
        self._older, self._newer, self._cancel = older, newer, cancel
        self._warnings = tuple(warnings)
        listed = {cve for a in self._advisories for cve in a.facts.cves()}
        self._cves = tuple(sorted(listed if cves is None else listed & set(cves)))
        groups = {_group(a) for a in self._advisories if set(a.facts.cves()) & set(self._cves)}
        self._facts_ids = tuple(sorted({a.facts.facts_id for a in self._advisories if _group(a) in groups}))
        self._reports: dict[str, IntelligenceReport] = {}

    def cves(self) -> tuple[str, ...]:
        return self._cves

    def report(self, cve: str) -> IntelligenceReport | None:
        if cve not in self._cves:
            return None
        if cve not in self._reports:
            self._reports[cve] = self._build(cve)
        return self._reports[cve]

    def facts_ids(self) -> tuple[str, ...]:
        return self._facts_ids

    def status(self) -> ChannelStatus:
        """The advisory channel: missing or skipped advisories are unknown evidence, never a negative vote."""
        if not self._advisories:
            if self._warnings:
                return ChannelStatus(channel='advisory', state='failed', reason='no stored advisory could be used')
            return ChannelStatus(channel='advisory', state='not-run', reason='no advisory is loaded')
        if self._warnings:
            return ChannelStatus(channel='advisory', state='partial',
                                 reason=f'{len(self._warnings)} stored advisory item(s) could not be used')
        return ChannelStatus(channel='advisory', state='available')

    def _build(self, cve: str) -> IntelligenceReport:
        try:
            return build_report(cve, self._advisories, self._older, self._newer, cancel=self._cancel)
        except IntelError as exc:
            if exc.code == 'PT-INTEL-CANCEL':
                raise PilotError('PT-PILOT-CANCEL', 'Patch-intent localization was cancelled',
                                 reason='cancelled') from None
            raise PilotError('PT-PILOT-INPUT', 'The advisory report could not be built',
                             reason=exc.code.lower()) from None
