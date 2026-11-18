"""Retained project CVRF fields as conservative pilot context, never a fabricated CSAF report.

`capture` is owner-thread I/O; everything after it consumes immutable values. The
project holds import-time field bindings, not raw advisory objects. Their recorded
SHA/pointers are preserved without claiming a fresh byte or authenticity check.
See program-e/pilot-retained-cvrf-context.md for selection, bounds and precedence.
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace

from ...enrichment.contracts import EnrichmentError
from ...enrichment.identity import domain_id
from ...intelligence.contracts import AnchorSet, HypothesisSet
from ...kbcorrelation.card_provenance import FIELDS, fact_key
from ...kbcorrelation.context import ContextBundle, context_key
from ...kbcorrelation.wiring import IntelligenceRules
from ..contracts import MAX_SOURCES, ApplicabilitySummary, ChannelStatus
from ..limits import Budget, PilotError
from . import advisory

MAX_ROWS = 1000
MAX_BYTES = 16 * 1024 * 1024
MAX_NODES, MAX_DEPTH = 100_000, 32
MAX_CARDS, MAX_REFS = 4096, 16_384
_SHA = re.compile(r'[0-9a-f]{64}')
_CVE_POINTER = re.compile(r'(/Vulnerability/[0-9]+)/CVE|(/vulnerabilities/[0-9]+)/cve')
RECORDED = ('Raw source bytes and upstream freshness were not reverified; this is retained documentary context. '
            'Import authenticity is not established.')
NO_LOCALITY = 'Retained CVRF fields do not establish binary applicability, a fix boundary or code locality.'
CSAF_FIRST = ('Retained CVRF context also lists this CVE; CSAF takes precedence, including negative, conflicting '
              'and withdrawn statements. Repeated vendor text adds no independent support.')


class _Unavailable(Exception):
    """A fixed, plain reason for withholding the fallback, never untrusted source text."""


@dataclass(frozen=True, slots=True)
class ContextSnapshot:
    bundles: tuple[ContextBundle, ...] = ()
    digest: str | None = None
    warnings: tuple[str, ...] = ()
    unavailable: bool = False
    withdrawn: tuple[str, ...] = ()

    @property
    def cves(self) -> tuple[str, ...]:
        if self.unavailable:
            return ()
        return tuple(sorted({card.cve for bundle in self.bundles for card in bundle.context.cards
                             if card.source_kind == 'cvrf'} - set(self.withdrawn)))


def _bounded(entries, budget: Budget) -> None:
    """Bound decoded structure before Pydantic allocates the richer context records."""
    nodes = cards = refs = 0
    for entry in entries:
        body = entry.body
        if not isinstance(body, dict):
            raise _Unavailable('a retained context has no object body')
        cards += len(body.get('context', {}).get('cards', ())) if isinstance(body.get('context'), dict) else 0
        refs += len(body.get('card_facts', ())) if isinstance(body.get('card_facts', ()), (list, tuple)) else 0
        if cards > MAX_CARDS or refs > MAX_REFS:
            raise _Unavailable('retained context exceeds the card or field-reference limit')
        stack = [(body, 0)]
        while stack:
            value, depth = stack.pop()
            nodes += 1
            budget.tick()
            if nodes > MAX_NODES or depth > MAX_DEPTH:
                raise _Unavailable('retained context exceeds the structure limit')
            children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
            if len(children) + len(stack) + nodes > MAX_NODES:
                raise _Unavailable('retained context exceeds the structure limit')
            stack.extend((child, depth + 1) for child in children)


def _key(bundle: ContextBundle) -> str:
    return context_key(investigation_id=bundle.investigation_id, base_revision=bundle.base_revision,
                       edge_set_digest=bundle.edge_set_digest, sources=bundle.sources,
                       rules_digest=bundle.rules_digest, lexicon_digest=bundle.lexicon_digest,
                       older_sha=bundle.older_sha, newer_sha=bundle.newer_sha, scope_id=bundle.scope_id)


def _fields(bundle: ContextBundle, budget: Budget) -> None:
    sources = {s.doc_id: s for s in bundle.sources}
    if len(sources) != len(bundle.sources) or any(
            source.doc_id != domain_id('kbc.source', 1, {'kind': source.kind, 'sha256': source.sha256})
            for source in bundle.sources):
        raise _Unavailable('a retained source document identity is inconsistent')
    if bundle.context.cards and not bundle.card_facts:
        raise _Unavailable('the retained context has no exact field bindings; legacy evidence stays unknown')
    by_cve = {}
    for ref in bundle.card_facts:
        by_cve.setdefault(ref.cve, []).append(ref)
    for card in bundle.context.cards:
        budget.check()
        by_doc = {}
        for ref in by_cve.get(card.cve, ()):
            by_doc.setdefault(ref.doc_id, []).append(ref)
        if len(by_doc) > MAX_SOURCES:
            raise _Unavailable('a retained card exceeds the advisory source limit')
        for group in by_doc.values():
            cve_refs = [r for r in group if r.field == 'cve']
            if len(cve_refs) != 1 or any(getattr(card, field) is not None and not any(
                    r.field == field for r in group) for field in FIELDS):
                raise _Unavailable('a retained source lacks a complete CVE field binding')
            match = _CVE_POINTER.fullmatch(cve_refs[0].pointer)
            if match is None:
                raise _Unavailable('a retained field has an unsupported original JSON location')
            native = match[1] is not None
            base = match[1] or match[2]
            patterns = ({'cve': re.escape(base) + '/CVE', 'title': re.escape(base) + '/Title/Value',
                         'stated_cwe': re.escape(base) + r'/CWE/[0-9]+/ID'} if native else
                        {'cve': re.escape(base) + '/cve', 'title': re.escape(base) + '/title',
                         'stated_cwe': re.escape(base) + '/cwe/id'})
            if any(r.field not in patterns or re.fullmatch(patterns[r.field], r.pointer) is None for r in group):
                raise _Unavailable('a retained field is not bound to its original CVE field location')


def _heads(entries, project, budget: Budget) -> tuple[tuple[ContextBundle, ...], tuple[str, ...]]:
    groups: dict[str, list[ContextBundle]] = {}
    sides = {a.side: a.sha256 for a in project.artifacts}
    for entry in entries:
        budget.check()
        bundle = ContextBundle.model_validate_json(entry.body_json)
        expected_id = 'kb-context:' + bundle.context_key
        if (entry.kind != 'kb-context' or entry.id != expected_id or entry.guard.project_id != project.id
                or entry.guard.run_id != 'kb' or entry.guard.input_digest != expected_id
                or _SHA.fullmatch(entry.guard.raw_sha256) is None
                or type(entry.project_revision) is not int or not 0 <= entry.project_revision <= project.revision):
            raise _Unavailable('a retained context row does not belong to this project and context identity')
        if entry.status != 'ok' or entry.stale:
            raise _Unavailable('a retained context is failed or explicitly stale; older cards are withheld')
        uuid.UUID(bundle.investigation_id)
        groups.setdefault(bundle.investigation_id, []).append(bundle)
    selected, withdrawn = [], set()
    for _investigation, versions in sorted(groups.items()):
        revision = max(b.base_revision for b in versions)
        newest = [b for b in versions if b.base_revision == revision]
        if len(newest) != 1:
            raise _Unavailable('retained contexts have divergent heads at the same investigation revision')
        head = newest[0]
        if head.context_key != _key(head):
            raise _Unavailable('a retained context key does not match its recorded inputs')
        if (head.older_sha, head.newer_sha) != (sides.get('older'), sides.get('newer')):
            raise _Unavailable('the newest retained context belongs to another ordered file pair')
        _fields(head, budget)
        current = {card.cve for card in head.context.cards}
        withdrawn.update({card.cve for b in versions for card in b.context.cards} - current)
        selected.append(head)
    # A project does not retain enough revision metadata to order competing monthly snapshots.
    # Refuse ambiguity rather than treating digest order as publication chronology.
    revisions: dict[tuple[str, str], set[str]] = {}
    cards = {}
    for bundle in selected:
        for source in bundle.sources:
            if source.kind == 'cvrf-month' and source.release_id:
                revisions.setdefault((source.kind, source.release_id), set()).add(source.sha256)
        for card in bundle.context.cards:
            if card.source_kind != 'cvrf' or card.cve in withdrawn:
                continue
            value = card.title, card.stated_cwe, card.severity_context
            if card.cve in cards and cards[card.cve] != value:
                raise _Unavailable('current retained CVRF cards disagree; their claims are withheld')
            cards[card.cve] = value
    if any(len(shas) > 1 for shas in revisions.values()):
        raise _Unavailable('retained monthly source revisions cannot be ordered from the project context')
    return tuple(selected), tuple(sorted(withdrawn))


def capture(service, enrichment, *, project=None, budget: Budget | None = None) -> ContextSnapshot:
    """Bounded owner-thread read; the immutable result is also the current-input comparison seam.

    All-context identity is deliberately conservative. A corrupt/ambiguous row
    withholds CVRF instead of silently selecting an older or convenient prefix.
    No source object, workspace, second project or external process is opened.
    """
    budget = budget or Budget.after(None, check_every=64)
    budget.check()
    project = service.project if project is None else project
    sides = {a.side: a.sha256 for a in project.artifacts}
    identity = {'project': project.id, 'older': sides.get('older'), 'newer': sides.get('newer')}
    try:
        if 'enrichment_entries' not in enrichment._tables():
            return ContextSnapshot()
        metadata = enrichment._db.execute(
            'SELECT substr(id,1,160),length(id),length(CAST(body AS BLOB)),substr(body_sha256,1,65) '
            'FROM enrichment_entries WHERE kind=? ORDER BY id LIMIT ?', ('kb-context', MAX_ROWS + 1)).fetchall()
        if not metadata:
            return ContextSnapshot()
        identity['rows'] = metadata
        if len(metadata) > MAX_ROWS or sum(row[2] for row in metadata) > MAX_BYTES:
            raise _Unavailable('retained context exceeds the row or byte limit')
        corrupt = []
        entries = enrichment.entries('kb-context', on_corrupt=corrupt.append)
        budget.check()
        identity['corrupt'] = tuple(sorted(hashlib.sha256(s.encode()).hexdigest() for s in corrupt))
        if corrupt or len(entries) != len(metadata):
            raise _Unavailable('a retained context failed row integrity; older cards are withheld')
        if sum(len(e.body_json.encode()) for e in entries) > MAX_BYTES:
            raise _Unavailable('retained context exceeds the byte limit')
        identity['guards'] = [(e.id, e.guard.project_id, e.guard.run_id, e.guard.raw_sha256,
                               e.guard.input_digest, e.project_revision, e.status, e.stale)
                              for e in sorted(entries, key=lambda e: e.id)]
        _bounded(entries, budget)
        heads, withdrawn = _heads(entries, project, budget)
        identity['state'] = 'available'
        notes = ('A newer retained context withdrew earlier CVE cards; older copies do not restore them.',
                 ) if withdrawn else ()
        return ContextSnapshot(heads, domain_id('pilot-kb-context', 1, identity), notes, False, withdrawn)
    except (EnrichmentError, sqlite3.Error, ValueError, TypeError, RecursionError, _Unavailable) as exc:
        reason = str(exc) if isinstance(exc, _Unavailable) else 'a retained context failed validation'
        identity['state'] = 'unavailable'
        identity['reason'] = reason
        return ContextSnapshot(digest=domain_id('pilot-kb-context', 1, identity),
                               warnings=(reason + '; CVRF evidence is unknown.',), unavailable=True)


def available_cves(snapshot: ContextSnapshot, csaf_cves: Iterable[str], *, csaf_readable: bool = True
                   ) -> tuple[str, ...]:
    """The identical universe for localization and current-input subset comparison.

    An unreadable CSAF universe cannot authorize a fallback that might override a
    lost negative or withdrawn statement. Valid CSAF remains independently usable.
    """
    return tuple(sorted(set(csaf_cves) | (set(snapshot.cves) if csaf_readable else set())))


def fallback_facts_ids(snapshot: ContextSnapshot, csaf_cves: Iterable[str], selected: Iterable[str], *,
                       csaf_readable: bool = True
                       ) -> tuple[str, ...]:
    """Exact recorded source SHA values for the admitted subset, excluding every CSAF overlap."""
    if not csaf_readable:
        return ()
    use = set(selected) & set(snapshot.cves) - set(csaf_cves)
    found = {ref.source_sha256 for b in snapshot.bundles for ref in b.card_facts
             if ref.cve in use and ref.source_kind == 'cvrf' and ref.field == 'cve'}
    if len(found) > MAX_SOURCES:
        raise PilotError('PT-PILOT-LIMIT', 'Retained CVRF context exceeds the advisory source limit',
                         reason='advisory-sources')
    return tuple(sorted(found))


@dataclass(frozen=True, slots=True)
class _RuleView:
    hypotheses: HypothesisSet
    anchors: AnchorSet


def _prepare(snapshot: ContextSnapshot, cve: str, budget: Budget):
    cards = [(bundle, card) for bundle in snapshot.bundles for card in bundle.context.cards
             if card.cve == cve and card.source_kind == 'cvrf']
    card = cards[0][1]  # capture already rejected disagreeing current cards
    refs = tuple(sorted({ref for bundle, _card in cards for ref in bundle.card_facts if ref.cve == cve},
                        key=fact_key))
    rules = IntelligenceRules()
    budget.check()
    profile, hypotheses = rules.interpret(card, refs)
    observations = {}
    for source_id in sorted({r.source_sha256 for r in refs}):
        budget.check()
        per_source = tuple(r for r in refs if r.source_sha256 == source_id)
        found, _ = rules.interpret(card, per_source)
        for observation in advisory._cwe_observations(
                cve, found, noun='retained CVRF card', ref_kind='cvrf-card-fact',
                owner=lambda _pointer, sha=source_id: sha, registry=advisory._REGISTRY):
            observations[observation.obs_id] = observation
    source_ids = tuple(sorted({r.source_sha256 for r in refs}))
    summary = ApplicabilitySummary(older='unknown', newer='unknown', older_mapping='unknown', newer_mapping='unknown')
    notes = (RECORDED, NO_LOCALITY, advisory.NO_APPLICABILITY,
             *(note for b, _c in cards for note in (*b.context.unknowns, *b.context.limitations)),
             *profile.disagreements, *profile.limitations, *hypotheses.unknowns, *hypotheses.limitations)
    result = advisory.AdvisoryContext(
        cve=cve, gate='unverified', applicability=summary, cwe=advisory.cwe_summary(profile),
        source_ids=source_ids, facts_ids=source_ids, hypotheses=hypotheses.hypotheses, anchors=(),
        observations=tuple(observations[k] for k in sorted(observations)),
        limitations=advisory._bounded_notes(notes))
    return _RuleView(hypotheses, AnchorSet(cve=cve, limitations=(NO_LOCALITY,))), result


class ProjectAdvisorySource:
    """Loaded CSAF plus retained CVRF fallback. No I/O after construction; CSAF always wins overlap."""

    def __init__(self, csaf: advisory.StoredAdvisorySource, snapshot: ContextSnapshot,
                 selected: Sequence[str], *, budget: Budget | None = None):
        self.csaf, self.snapshot = csaf, snapshot
        readable = csaf.status().state not in ('failed', 'partial')
        self._cves = tuple(sorted(set(selected) & set(available_cves(snapshot, csaf.cves(),
                                                                   csaf_readable=readable))))
        self._budget = budget or Budget.after(None, check_every=64)
        self._prepared = {}
        self.kb_link_digest = snapshot.digest
        self._facts_ids = tuple(sorted(set(csaf.facts_ids()) | set(
            fallback_facts_ids(snapshot, csaf.cves(), self._cves, csaf_readable=readable))))
        if len(self._facts_ids) > MAX_SOURCES:
            raise PilotError('PT-PILOT-LIMIT', 'Combined advisory context exceeds the source limit',
                             reason='advisory-sources')

    def cves(self) -> tuple[str, ...]:
        return self._cves

    def facts_ids(self) -> tuple[str, ...]:
        return self._facts_ids

    def _fallback(self, cve):
        if cve not in self._prepared:
            self._prepared[cve] = _prepare(self.snapshot, cve, self._budget)
        return self._prepared[cve]

    def report(self, cve):
        if cve not in self._cves:
            return None
        return self.csaf.report(cve) if cve in self.csaf.cves() else self._fallback(cve)[0]

    def context(self, cve: str, *, assume_applies: bool = False) -> advisory.AdvisoryContext:
        if cve not in self._cves:
            raise PilotError('PT-PILOT-NOTFOUND', 'No usable current advisory context lists this CVE',
                             reason='cve-not-stored')
        if cve in self.csaf.cves():
            result = advisory.context_from_report(self.csaf.report(cve), assume_applies=assume_applies)
            notes = (CSAF_FIRST,) if cve in self.snapshot.cves else ()
        else:
            result = self._fallback(cve)[1]
            notes = advisory._assumption_notes(result.applicability, assume_applies)
            result = replace(result, gate=advisory.cve_gate(result.applicability, assumed=assume_applies))
        return replace(result, limitations=advisory._bounded_notes((*notes, *result.limitations,
                                                                   *self.snapshot.warnings)))

    def status(self) -> ChannelStatus:
        state = self.csaf.status()
        if self.snapshot.digest is None:
            return state
        usable = bool(self._cves)
        gaps = self.snapshot.warnings or state.state in ('failed', 'partial')
        if gaps:
            return ChannelStatus(channel='advisory', state='partial' if usable else 'failed',
                                 reason='some retained advisory context could not be used; missing evidence is unknown')
        return ChannelStatus(channel='advisory', state='available' if usable else 'not-run',
                             reason=None if usable else 'no eligible advisory context is retained')
