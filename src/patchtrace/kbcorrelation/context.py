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
from .contracts import (
    CONTRACT,
    ContextReport,
    Contract,
    Coverage,
    CveCard,
    Lead,
    Record,
    Sha256,
    Short,
    Uuid,
    domain_id,
)
from .index import ReverseIndex
from .products import clean_text

BUNDLE_VERSION = 1
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

    def interpret(self, card: CveCard, pointer: str, source_sha256: str) -> tuple[CweProfile, HypothesisSet]: ...


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

    @model_validator(mode='after')
    def _same_cves(self):
        cves = [c.cve for c in self.context.cards]
        if [p.cve for p in self.cwe_profiles] != cves or [h.cve for h in self.hypotheses] != cves:
            raise ValueError('profiles and hypotheses must follow the cards, one each')
        return self


def context_key(*, investigation_id: str, base_revision: int, edge_set_digest: str, csaf_shas: Sequence[str],
                rules_digest: str, lexicon_digest: str, older_sha: str | None, newer_sha: str | None,
                scope_id: str | None) -> str:
    """Plan 7.4 context key; ``kev_snapshot_sha`` is None until the KEV adapter (K8) loads a snapshot."""
    return domain_id('kbc.context', 1, {
        'inv': investigation_id, 'revision': base_revision, 'edge_set_digest': edge_set_digest,
        'csaf_source_shas': sorted(csaf_shas), 'rules_digest': rules_digest, 'lexicon_digest': lexicon_digest,
        'kev_snapshot_sha': None, 'older': older_sha, 'newer': newer_sha, 'scope_id': scope_id,
        'versions': {'contract': CONTRACT, 'bundle': BUNDLE_VERSION}})


def vulnerability_pointer(pointer: str) -> str:
    """The ``/vulnerabilities/N`` prefix of an edge pointer (the item the CVE's text came from), else the root."""
    match = _VULN.match(pointer)
    return match.group(1) if match else '/'


def build_bundle(*, investigation_id: str, base_revision: int, lead: Lead, cves: Iterable[str], index: ReverseIndex,
                 rules: RulesPort, now: str, coverage: Sequence[Coverage], scope_id: str | None,
                 pair_id: str | None, older_sha: str | None, newer_sha: str | None,
                 mention_only: Iterable[str] = ()) -> ContextBundle:
    cards: list[CveCard] = []
    profiles: list[CweProfile] = []
    hypotheses: list[HypothesisSet] = []
    docs: dict[str, SourceDigest] = {}
    unknowns: list[str] = ['KEV listing was not loaded, so exploitation status is unknown.']
    for cve in sorted(set(cves)):
        lookup = index.lookup_cve(cve, scope_id=scope_id, now=now)
        card = next((c for c in lookup.cards if c.source_kind == 'cvrf'), None) or next(iter(lookup.cards), None)
        edge = next(iter(lookup.edges), None)
        if card is None or edge is None:
            unknowns.append(f'{cve} has no advisory text in the loaded documents; no interpretation was made.')
            continue
        source = index.get(edge.ref.doc_id).source
        docs[source.doc_id] = SourceDigest(doc_id=source.doc_id, sha256=source.sha256, kind=source.kind,
                                           release_id=source.release_id)
        shown = card.model_copy(update={'title': clean_text(card.title, 1000) if card.title else None,
                                        'applicability': APPLICABILITY})
        profile, hypothesis = rules.interpret(shown, vulnerability_pointer(edge.ref.pointer), source.sha256)
        cards.append(shown)
        profiles.append(profile)
        hypotheses.append(hypothesis)
    unknowns += [f'{cve} is mentioned in advisory text only and is left out of the context.'
                 for cve in sorted(set(mention_only))]
    unknowns.append('Applicability of the advisory to these two files is unverified until you confirm the product.'
                    if scope_id is None else
                    'The product was chosen by you; no document verifies that these two files belong to it.')
    report = ContextReport(cards=tuple(cards), coverage=tuple(coverage), unknowns=tuple(unknowns),
                           limitations=(LIMITATION,), hooks=HOOKS)
    key = context_key(investigation_id=investigation_id, base_revision=base_revision,
                      edge_set_digest=index.edge_set_digest(),
                      csaf_shas=[d.sha256 for d in docs.values() if d.kind == 'csaf'],
                      rules_digest=rules.rules_digest, lexicon_digest=rules.lexicon_digest, older_sha=older_sha,
                      newer_sha=newer_sha, scope_id=scope_id)
    return ContextBundle(
        context_key=key, investigation_id=investigation_id, base_revision=base_revision, lead=lead,
        scope_id=scope_id, pair_id=pair_id, older_sha=older_sha, newer_sha=newer_sha,
        edge_set_digest=index.edge_set_digest(), rules_digest=rules.rules_digest,
        lexicon_digest=rules.lexicon_digest, sources=tuple(sorted(docs.values(), key=lambda d: d.doc_id)),
        context=report, cwe_profiles=tuple(profiles), hypotheses=tuple(hypotheses))
