"""The inputs of one localization run, assembled from what a project already stores (PIL-integration-plan.md s4, s8).

`collect` is the one place that knows where each channel comes from: Ghidriff rows with the PE image layouts, B1 signals
(the stored default profile when current, else computed in memory), the current unified result (unless switched off) or
the secondary engines' verdicts for the pairing, call labels with the PE import delta, and the stored CSAF advisories with
their CVE contexts. A source that is missing becomes a channel that is not run (or failed), never a negative vote.
Stored capa/FLOSS/DiE results, CISA KEV and the KB window are not read yet: their channels say so, and the CSAF-derived
count feeds the confounded window. Owner thread only (it reads the project database); nothing is run, sent or executed.

`universe` decides which stored CVEs a run computes: `--cve` chooses what is shown and never what is computed, so a result
does not depend on the question asked of it.
"""
from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass

from ..enrichment.contracts import EnrichmentError
from ..enrichment.storage import EnrichmentStore
from . import keys, store
from .contracts import ChannelStatus, CveContext, Kev, LeadCounts
from .limits import DEFAULT_LIMITS, Budget, PilotError

CONFIG = keys.default_config()
NO_RUN = 'No comparison result yet. Run the analysis first; leads are computed from stored results only.'
TOOLS_NOT_READ = 'stored capa, FLOSS and Detect It Easy results are not read by this command yet'


class _Down:
    """A source that gave nothing: it reports why through its channel states and observes nothing (never a negative vote)."""

    def __init__(self, *states: ChannelStatus):
        self._states = states

    def status(self) -> ChannelStatus:
        return self._states[0]

    def statuses(self) -> tuple[ChannelStatus, ...]:
        return self._states

    def observations(self, _candidate_keys) -> Iterator:
        return iter(())

    def pair_observations(self) -> tuple:
        return ()

    def cache_keys(self) -> tuple:
        return ()


class _NoCatalog:
    """`KevSource` without a catalog: every answer is `unknown`, which says nothing about exploitation."""

    def lookup(self, _cve: str) -> Kev:
        return Kev(state='unknown')

    def snapshot_id(self) -> None:
        return None


def universe(stored: Sequence[str], named: Sequence[str], *, cap: int = DEFAULT_LIMITS.p03_cves
             ) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(CVEs a run computes, CVEs it shows). The confounded window counts every stored CVE fixed in these builds, so the
    run computes all of them. Only when the stored CVEs exceed what a run can hold (P-03) are the named ones all it
    computes (and all it can show)."""
    have, asked = tuple(sorted(set(stored))), tuple(sorted(set(named)))
    missing = [cve for cve in asked if cve not in have]
    if missing:
        raise PilotError('PT-PILOT-NOTFOUND', f'No stored advisory lists {missing[0]}', reason='cve-not-stored')
    if len(have) <= cap:
        return have, asked or have
    if not asked or len(asked) > cap:
        raise PilotError('PT-PILOT-INPUT', f'{len(have)} CVEs have stored advisories and a run covers at most {cap}: '
                         f'name up to {cap} with --cve', reason='too-many-cves')
    return asked, asked


@dataclass(frozen=True)
class Collected:
    """The `LocalizeInputs` of one run: the ports and contexts `service.localize` reads, and notes for the analyst."""
    project_id: str
    revision: int
    older_sha256: str
    newer_sha256: str
    ghidriff_run_id: str
    raw_sha256: str
    advisory: object
    changes: object
    tools: object
    kev: object
    calls: object
    pairing: object
    contexts: tuple[CveContext, ...]
    advisory_observations: Mapping[str, tuple]
    notes: tuple[str, ...]


def _cancelled() -> PilotError:
    return PilotError('PT-PILOT-CANCEL', 'Patch-intent localization was cancelled', reason='cancelled')


def _overview(service, artifact, cancel: threading.Event):
    """The bounded PE parse of a hash-verified artifact, or None when its bytes cannot be verified or read."""
    from ..artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
    from ..pe_overview import inspect_pe
    try:
        with VerifiedArtifactReader.open_artifact(artifact, service.root, cancel=cancel.is_set) as reader:
            overview = inspect_pe(reader, cancel=cancel.is_set)
    except ArtifactBytesError as exc:
        if exc.code == 'cancelled':
            raise _cancelled() from None
        return None
    if overview.status == 'cancelled':
        raise _cancelled()
    return overview


def _signal_sets(service, enrichment: EnrichmentStore, cancel: threading.Event):
    """B1 signals of the default profile: the stored ones when current, else computed in memory. Returns the sets and the
    reason they are unavailable (None when they are)."""
    from ..enrichment import pipeline
    try:
        sets = pipeline.load_default(enrichment, service.project)[1]
        return sets or pipeline.run(service.project, pipeline.PipelineOptions(), cancel).signal_sets, None
    except EnrichmentError as exc:
        if exc.code == 'PT-ENRICH-CANCEL':
            raise _cancelled() from None
        return (), f'B1 signals could not be computed ({exc.code})'


def _secondary_sets(enrichment: EnrichmentStore) -> tuple:
    from ..secondary.store import current_sets
    try:
        return tuple(match_set for _entry, match_set in current_sets(enrichment))
    except (EnrichmentError, ValueError, sqlite3.Error):
        return ()


def _unified(service, enrichment: EnrichmentStore, older: str, newer: str, budget: Budget):
    """(pairing, typed facts, note) of the current unified result; (None, None, None) when there is none, and a note
    saying why when there is one that cannot be used (a stale result is never combined with the Ghidriff pairing)."""
    from ..unified import pipeline as unified
    from ..unified.limits import UnifiedError
    from .sources.unified import UnifiedFacts, UnifiedPairing, UnifiedView
    try:
        if not enrichment.entries('unified-result', on_corrupt=lambda _id: None):
            return None, None, None  # none was ever computed: the plan (a PE read of both builds) is not needed
        loaded = unified.load_current(service, unified.make_plan(service))
        if loaded.state == 'none':
            return None, None, None
        view = UnifiedView.read(loaded, older_sha256=older, newer_sha256=newer, budget=budget)
    except (UnifiedError, PilotError, EnrichmentError, sqlite3.Error) as exc:
        if getattr(exc, 'code', '') == 'PT-PILOT-CANCEL':
            raise
        reason = getattr(exc, 'reason', None) or getattr(exc, 'code', type(exc).__name__)
        return None, None, f'The unified result could not be used ({reason}); pairing verdicts come from Ghidriff.'
    return UnifiedPairing(view), UnifiedFacts(view), None


def _contexts(source, computed: Sequence[str], assume: Sequence[str]):
    from .sources.advisory import context_from_report, cve_context
    from .sources.kev import NO_CATALOG
    from .sources.window import confounding
    unknown = [cve for cve in assume if cve not in computed]
    if unknown:
        raise PilotError('PT-PILOT-INPUT', f'--assume-applies names {unknown[0]}, which no stored advisory of this run '
                         'lists', reason='assume-unknown-cve')
    found = [context_from_report(source.report(cve), assume_applies=cve in assume) for cve in computed]
    window = confounding({c.cve: c.gate for c in found}, min_cves=CONFIG.confounded_min_cves)
    zero = LeadCounts(fit=0, review=0, partial=0, code=0, queue=0)
    return (tuple(cve_context(c, kev=NO_CATALOG, confounding=window, counts=zero) for c in found),
            {c.cve: c.observations for c in found})


def collect(service, enrichment: EnrichmentStore, *, named: Sequence[str] = (), assume: Sequence[str] = (),
            unified: bool = True, cancel: threading.Event) -> Collected:
    """Assemble the inputs of `localize` from the stored data of the project (see the module docstring). Raises
    `PT-PILOT-NOTFOUND` without a completed run or for a named CVE no stored advisory lists, `PT-PILOT-INPUT` for an
    assumption about a CVE the run does not hold, and `PT-PILOT-CANCEL`."""
    from ..intelligence.csaf.identity import project_identities
    from ..intelligence.storage import AdvisoryStore
    from .sources import pe
    from .sources.advisory import StoredAdvisorySource
    from .sources.calls import GhidriffCalls
    from .sources.code import B1Evidence, CodeEvidence, GhidriffPairing, GhidriffRows
    project = service.project
    run = store.completed_run(project)
    if run is None:
        raise PilotError('PT-PILOT-NOTFOUND', NO_RUN, reason='no-run')
    by_side = {a.side: a for a in project.artifacts}
    older_sha, newer_sha = by_side['older'].sha256, by_side['newer'].sha256
    budget = Budget.after(None, cancel)
    older, newer = _overview(service, by_side['older'], cancel), _overview(service, by_side['newer'], cancel)
    both = older is not None and newer is not None
    rows = GhidriffRows.resolve(older_sha, newer_sha, [m for m in project.matches if m.run_id == run.id],
                                pe.address_map(older, newer) if both else None, budget=budget)
    sets, down = _signal_sets(service, enrichment, cancel)
    lexical = _Down(ChannelStatus(channel='code', state='failed', reason=down)) if down else B1Evidence(
        rows, sets, budget=budget)
    pairing, typed, note = _unified(service, enrichment, older_sha, newer_sha, budget) if unified else (None, None, None)
    advisories, warnings = AdvisoryStore(service.root, enrichment, project.id, project.revision).advisories()
    older_id, newer_id = project_identities(project.artifacts, service.root, {}, cancel)
    computed, _shown = universe(sorted({cve for a in advisories for cve in a.facts.cves()}), named)
    source = StoredAdvisorySource(advisories, older_id, newer_id, cves=computed, warnings=warnings, cancel=cancel)
    contexts, entries = _contexts(source, computed, assume)
    tools = _Down(*(ChannelStatus(channel=c, state='not-run', reason=TOOLS_NOT_READ)
                    for c in ('strings', 'capa', 'build')))
    return Collected(
        project_id=project.id, revision=project.revision, older_sha256=older_sha, newer_sha256=newer_sha,
        ghidriff_run_id=run.id, raw_sha256=run.raw_sha256, advisory=source, changes=CodeEvidence(lexical, typed),
        tools=tools, kev=_NoCatalog(),
        calls=GhidriffCalls(rows, pe.import_delta(older, newer) if both else None, budget=budget),
        pairing=pairing or GhidriffPairing(rows, _secondary_sets(enrichment)), contexts=contexts,
        advisory_observations=entries, notes=(note,) if note else ())
