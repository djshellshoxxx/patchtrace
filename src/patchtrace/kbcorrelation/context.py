"""Documentary context of an investigation (KB-integration-plan 7.2 `ContextReport`, 7.4 keys; slice K3). Pure.

The context records what advisory documents state about the CVEs of a lead (title, vendor-stated CWE with its source
kind, the curated hypothesis a stated CWE implies) and what could not be checked (applicability to the two files,
KEV, product mapping). It never claims that a changed function addresses a vulnerability.

``ContextBundle`` is the persisted body of a ``kb-context:<context_key>`` row. The CWE profile and hypotheses come
from the reused ``intelligence`` rules through the :class:`RulesPort` that ``wiring`` binds; a CVRF-only CVE has no
``intelligence/1`` report (that needs a CSAF source), so the profile and hypothesis set travel beside the
``ContextReport`` instead of inside it.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import Annotated, Protocol

from pydantic import Field, model_validator

from ..intelligence.contracts import CweProfile, HypothesisSet
from .card_provenance import FIELDS, CardFactRef, bind_consensus, fact_key
from .contracts import (
    CONTRACT,
    ContextReport,
    Contract,
    Coverage,
    CveCard,
    Lead,
    Record,
    SearchScope,
    Sha256,
    Short,
    Uuid,
    domain_id,
)
from .index import ReverseIndex
from .products import clean_text
from .sources.scope import build_coverage, corpus_digest

BUNDLE_VERSION = 1
CONTEXT_KEY_VERSION = 3  # New field attribution; old bundles remain readable as recorded.
HOOKS = ('kb.meaning.coverage', 'kb.meaning.hypothesis', 'kb.meaning.kev', 'kb.meaning.relation',
         'kb.next.run_comparison')
LIMITATION = ('The context records what advisory documents state and which checks could not be made; it does not '
              'show that any changed function addresses a vulnerability.')
APPLICABILITY = 'unknown (no loaded document states applicability to these two files)'
_VULN = re.compile(r'^(/vulnerabilities/[0-9]+)')


class RulesPort(Protocol):
    """The reused CWE classifier and hypothesis rules (``intelligence``), bound by ``wiring``."""
    rules_digest: str
    lexicon_digest: str

    def interpret(self, card: CveCard, facts: tuple[CardFactRef, ...]) -> tuple[CweProfile, HypothesisSet]: ...


class SourceDigest(Record):
    doc_id: Sha256
    sha256: Sha256
    kind: Short
    release_id: Short | None = None


class ContextBundle(Contract):
    context_key: Sha256
    investigation_id: Uuid
    base_revision: Annotated[int, Field(ge=1)]
    lead: Lead
    scope_id: Sha256 | None = None
    pair_id: Sha256 | None = None
    older_sha: Sha256 | None = None
    newer_sha: Sha256 | None = None
    edge_set_digest: Sha256
    rules_digest: Sha256
    lexicon_digest: Sha256
    sources: tuple[SourceDigest, ...] = ()
    context: ContextReport
    cwe_profiles: tuple[CweProfile, ...] = ()
    hypotheses: tuple[HypothesisSet, ...] = ()
    card_facts: tuple[CardFactRef, ...] = ()  # Absent in legacy bundles; never backfill invented provenance.

    @model_validator(mode='after')
    def _same_cves(self):
        cves = [c.cve for c in self.context.cards]
        if [p.cve for p in self.cwe_profiles] != cves or [h.cve for h in self.hypotheses] != cves:
            raise ValueError('profiles and hypotheses must follow the cards, one each')
        if self.card_facts:
            sources = {s.doc_id: s for s in self.sources}
            cards = {c.cve: c for c in self.context.cards}
            if tuple(sorted(set(self.card_facts), key=fact_key)) != self.card_facts:
                raise ValueError('card facts must be unique and canonical')
            for ref in self.card_facts:
                card, source = cards.get(ref.cve), sources.get(ref.doc_id)
                if card is None or source is None or card.source_kind != ref.source_kind \
                        or source.sha256 != ref.source_sha256 or getattr(card, ref.field) != ref.value \
                        or source.kind != ('cvrf-month' if ref.source_kind == 'cvrf' else 'csaf'):
                    raise ValueError('card fact must match its displayed value and retained source')
            for card in cards.values():
                for field in FIELDS:
                    if getattr(card, field) is not None and not any(r.cve == card.cve and r.field == field
                                                                 for r in self.card_facts):
                        raise ValueError('displayed advisory field has no source reference')
            for profile, hypotheses in zip(self.cwe_profiles, self.hypotheses, strict=True):
                refs = [r for r in self.card_facts if r.cve == profile.cve and r.field != 'cve']
                pointers = {r.pointer for r in refs}
                used = {p for item in profile.classifications for p in item.pointers}
                hits = [h for item in profile.classifications for h in item.hits]
                used.update(h.pointer for h in (*hits, *profile.negated_hits, *profile.effect_hits))
                if not used <= pointers:
                    raise ValueError('classification pointer has no card field source')
                expected = ('explicit-csaf-cwe' if cards[profile.cve].source_kind == 'csaf'
                            else 'explicit-advisory-cwe')
                for item in profile.classifications:
                    if item.basis.startswith('explicit-') and (item.basis != expected or not any(
                            r.field == 'stated_cwe' and r.value == item.cwe_id and r.pointer in item.pointers
                            for r in refs)):
                        raise ValueError('explicit classification lacks its stated CWE source')
                classified = {(item.cwe_id, item.basis) for item in profile.classifications}
                if any((item.cwe_id, item.basis) not in classified for item in hypotheses.hypotheses):
                    raise ValueError('hypothesis lacks its source-bound classification')
        return self


def context_key(*, investigation_id: str, base_revision: int, edge_set_digest: str, sources: Sequence[SourceDigest],
                rules_digest: str, lexicon_digest: str, older_sha: str | None, newer_sha: str | None,
                scope_id: str | None) -> str:
    """Plan 7.4 context key; ``kev_snapshot_sha`` is None until the KEV adapter (K8) loads a snapshot."""
    return domain_id('kbc.context', CONTEXT_KEY_VERSION, {
        'inv': investigation_id, 'revision': base_revision, 'edge_set_digest': edge_set_digest,
        'advisory_sources': [d.model_dump(mode='json') for d in sorted(sources, key=lambda d: d.doc_id)],
        'rules_digest': rules_digest, 'lexicon_digest': lexicon_digest,
        'kev_snapshot_sha': None, 'older': older_sha, 'newer': newer_sha, 'scope_id': scope_id,
        'versions': {'contract': CONTRACT, 'bundle': BUNDLE_VERSION}})


def vulnerability_pointer(pointer: str) -> str:
    """The ``/vulnerabilities/N`` prefix of an edge pointer (the item the CVE's text came from), else the root."""
    match = _VULN.match(pointer)
    return match.group(1) if match else '/'


def saved_search_scope(lead: Lead, coverage: Sequence[Coverage]) -> SearchScope | None:
    """Validate the saved selector without replacing coverage or guessing a wider scope.

    Pair-only local investigations may have no advisory coverage. The service translates ValueError
    to PT-KBC-SCOPE before making decisions or changing investigation/project state.
    """
    if not coverage and lead.kind == 'pair':
        return None
    if len(coverage) != 1:
        raise ValueError('one saved search coverage is required')
    saved, = coverage
    scope = saved.scope
    if (saved.state == 'unknown_scope'
            or (scope.kind in ('cached_corpus', 'provided_files') and scope.months)
            or (scope.kind == 'selected_months' and scope.doc_ids)
            or (scope.kind == 'mixed' and (not scope.months or not scope.doc_ids))
            or (scope.kind == 'cached_corpus' and scope.corpus_digest != corpus_digest(scope.doc_ids))):
        raise ValueError('the saved search selector is contradictory')
    rebuilt = build_coverage(
        source_kind=saved.source_kind, scope=scope, requested=saved.requested_ids, inspected=saved.inspected_ids,
        failed=((f.id, f.reason) for f in saved.failed), unfetchable=saved.unfetchable_ids,
        watermark=saved.watermark_current_release_date, retrieved_at=saved.retrieved_at,
        stale=saved.state == 'stale_cache')
    if rebuilt != saved:
        raise ValueError('the saved coverage identity is inconsistent')
    if scope.kind != 'cached_corpus' and set(saved.requested_ids) != set(scope.months) | set(scope.doc_ids):
        raise ValueError('the saved coverage contradicts its selector')
    return scope


def build_bundle(*, investigation_id: str, base_revision: int, lead: Lead, cves: Iterable[str], index: ReverseIndex,
                 rules: RulesPort, now: str, coverage: Sequence[Coverage], scope_id: str | None,
                 pair_id: str | None, older_sha: str | None, newer_sha: str | None,
                 mention_only: Iterable[str] = ()) -> ContextBundle:
    search_scope = saved_search_scope(lead, coverage)
    index = index.within_scope(search_scope) if search_scope is not None else ReverseIndex()
    if search_scope is not None:
        saved, = coverage
        current = index.coverage(search_scope, now=now)
        if ((current.requested_ids, current.inspected_ids) != (saved.requested_ids, saved.inspected_ids)
                or (search_scope.kind == 'cached_corpus'
                    and set(search_scope.doc_ids) != {d.doc_id for d in index.documents})):
            raise ValueError('the saved search coverage cannot be reproduced; repeat the search')
    cards: list[CveCard] = []
    profiles: list[CweProfile] = []
    hypotheses: list[HypothesisSet] = []
    facts: list[CardFactRef] = []
    docs: dict[str, SourceDigest] = {}
    unknowns: list[str] = ['KEV listing was not loaded, so exploitation status is unknown.']
    for cve in sorted(set(cves)):
        lookup = index.lookup_cve(cve, scope=search_scope, scope_id=scope_id, now=now)
        unknowns.extend(w for w in lookup.warnings if w.startswith('CARD_FACT_CONFLICT:'))
        for doc_id in lookup.card_doc_ids:
            source = index.get(doc_id).source
            docs[doc_id] = SourceDigest(doc_id=doc_id, sha256=source.sha256, kind=source.kind,
                                       release_id=source.release_id)
        card = next((c for c in lookup.cards if c.source_kind == 'cvrf'), None) or next(iter(lookup.cards), None)
        if card is None or not lookup.edges:
            unknowns.append(f'{cve} has no advisory text in the loaded documents; no interpretation was made.')
            continue
        # Eligibility still requires an association; its edge never locates an advisory card field.
        card, refs, missing = bind_consensus(card, (index.get(doc_id) for doc_id in lookup.card_doc_ids))
        if missing:
            unknowns.append(f'CARD_FACT_SOURCE_MISSING: {cve} {", ".join(missing)} has no complete JSON '
                            'field provenance; unavailable fields were withheld')
        if card is None:
            continue
        shown = card.model_copy(update={'title': clean_text(card.title, 1000) if card.title else None,
                                        'applicability': APPLICABILITY})
        profile, hypothesis = rules.interpret(shown, refs)
        cards.append(shown)
        profiles.append(profile)
        hypotheses.append(hypothesis)
        facts.extend(refs)
    unknowns += [f'{cve} is mentioned in advisory text only and is left out of the context.'
                 for cve in sorted(set(mention_only))]
    unknowns.append('Applicability of the advisory to these two files is unverified until you confirm the product.'
                    if scope_id is None else
                    'The product was chosen by you; no document verifies that these two files belong to it.')
    report = ContextReport(cards=tuple(cards), coverage=tuple(coverage), unknowns=tuple(unknowns),
                           limitations=(LIMITATION,), hooks=HOOKS)
    key = context_key(investigation_id=investigation_id, base_revision=base_revision,
                      edge_set_digest=index.edge_set_digest(),
                      sources=tuple(docs.values()),
                      rules_digest=rules.rules_digest, lexicon_digest=rules.lexicon_digest, older_sha=older_sha,
                      newer_sha=newer_sha, scope_id=scope_id)
    return ContextBundle(
        context_key=key, investigation_id=investigation_id, base_revision=base_revision, lead=lead,
        scope_id=scope_id, pair_id=pair_id, older_sha=older_sha, newer_sha=newer_sha,
        edge_set_digest=index.edge_set_digest(), rules_digest=rules.rules_digest,
        lexicon_digest=rules.lexicon_digest, sources=tuple(sorted(docs.values(), key=lambda d: d.doc_id)),
        context=report, cwe_profiles=tuple(profiles), hypotheses=tuple(hypotheses),
        card_facts=tuple(sorted(facts, key=fact_key)))
