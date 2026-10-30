"""In-memory local reverse index: KB -> CVE -> product scope (KB-integration-plan 7.3, 8.1 `search`; slice K1). Pure.

The index holds :class:`ImportedDocument` results. It answers "which CVEs and product scopes does this KB belong to,
and what was actually checked", nothing more: no file, no fetch, no sqlite (the durable workspace is slice K2; this
class is its in-memory counterpart and the reference for its lookups).

Honest answers:

* every lookup carries a `Coverage` computed against an explicit, finite scope (default: the whole loaded corpus,
  stated as `cached_corpus` with its digest); "not observed" is the strongest negative, and an empty result under
  partial coverage is `partial`, never "this KB has no CVEs";
* `edges` are vendor-remediation / vendor-association rows only. Mention-only rows (a KB named in a known-issue
  text) and disputed rows (a negative product status contradicts the fix) are listed apart; neither counts as a fix;
* a revised document replaces an older one for the same release month (or CSAF tracking id) as the *active*
  revision; the older snapshot stays in the index and is reported as `superseded`, never silently dropped;
* edges are product-scoped: a `scope_id` filter leaves other scopes out and reports how many, with no cross-join.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .contracts import (
    Coverage,
    CveCard,
    KbCveEdge,
    ProductScope,
    ProductStatus,
    SearchScope,
    SourceRef,
    domain_id,
)
from .ids import canonical_kb, cve_sort_key, is_cve, kb_sort_key
from .products import merge_scopes
from .sources.cvrf import StatusRow
from .sources.importer import ImportedDocument
from .sources.scope import (
    REVISION_LAG_NOTE,
    STALE_AFTER_DAYS,
    build_coverage,
    corpus_digest,
    coverage_text,
    release_ordinal,
)

REMEDIATION_RELATIONS = ('vendor-remediation', 'vendor-association')
EXIT_BY_STATUS = {'found': 0, 'not_observed': 4, 'partial': 3, 'not_searched': 3}


@dataclass(frozen=True)
class EdgeGroup:
    """Edges that differ only by source position, shown once (S05); every position stays in ``refs``."""
    kb: str
    cve: str
    scope_id: str
    relation: str
    refs: tuple[SourceRef, ...]
    edge_ids: tuple[str, ...]
    release_ids: tuple[str, ...]
    fixed_builds: tuple[str, ...]
    product_status: ProductStatus | None


@dataclass(frozen=True)
class TimelineEntry:
    doc_id: str
    release_id: str | None
    current_release_date: str | None
    active: bool
    kbs: tuple[str, ...]
    relations: tuple[str, ...]
    status_values: tuple[str, ...]


@dataclass(frozen=True)
class Lookup:
    query_kind: str  # 'kb' | 'cve'
    query: str
    status: str  # found | not_observed | partial | not_searched
    coverage: Coverage
    edges: tuple[KbCveEdge, ...]
    groups: tuple[EdgeGroup, ...]
    mention_only: tuple[KbCveEdge, ...]
    disputed: tuple[KbCveEdge, ...]
    superseded: tuple[KbCveEdge, ...]
    scopes: tuple[ProductScope, ...]
    excluded: tuple[tuple[str, int], ...]
    cards: tuple[CveCard, ...]
    warnings: tuple[str, ...]

    @property
    def exit_code(self) -> int:
        return EXIT_BY_STATUS[self.status]

    @property
    def text(self) -> str:
        return coverage_text(self.coverage)


def _label(doc: ImportedDocument) -> str:
    """The id a document carries on the coverage's document axis: its release month, else its document id."""
    return doc.source.release_id or doc.source.doc_id


def _group_key(doc: ImportedDocument) -> tuple:
    s = doc.source
    return ('cvrf-month', s.release_id) if s.kind == 'cvrf-month' else (s.kind, doc.tracking_id or s.doc_id)


def _instant(value: str | None) -> datetime:
    """The UTC instant of a stored release timestamp; the earliest instant when absent or unreadable."""
    try:
        return datetime.fromisoformat(value).astimezone(UTC) if value else datetime.min.replace(tzinfo=UTC)
    except (ValueError, OverflowError):
        return datetime.min.replace(tzinfo=UTC)


def _revision_key(doc: ImportedDocument) -> tuple:
    """Newer release instant wins, ties by document id. Instants, not strings: '...00.5Z' sorted before '...00Z'
    and '10:00+05:00' after '08:00Z' as text (issue #105 BUG-KBC-6)."""
    return (_instant(doc.source.current_release_date), doc.source.doc_id)


def distinct_groups(edges: Iterable[KbCveEdge]) -> tuple[EdgeGroup, ...]:
    grouped: dict[tuple, list[KbCveEdge]] = {}
    for edge in edges:
        grouped.setdefault((edge.kb, edge.cve, edge.scope_id, edge.relation), []).append(edge)
    out = []
    for (kb, cve, scope_id, relation), items in grouped.items():
        items.sort(key=lambda e: (e.ref.doc_id, e.ref.pointer))
        statuses = sorted((e.product_status for e in items if e.product_status),
                          key=lambda s: (s.value, s.pointer))
        out.append(EdgeGroup(
            kb=kb, cve=cve, scope_id=scope_id, relation=relation, refs=tuple(e.ref for e in items),
            edge_ids=tuple(e.edge_id for e in items),
            release_ids=tuple(sorted({e.release_id for e in items if e.release_id})),
            fixed_builds=tuple(sorted({e.fixed_build for e in items if e.fixed_build})),
            product_status=statuses[0] if statuses else None))
    return tuple(sorted(out, key=lambda g: (cve_sort_key(g.cve), kb_sort_key(g.kb), g.scope_id, g.relation)))


class ReverseIndex:
    """A set of imported documents with scope-aware lookups. Adding the same document twice changes nothing."""

    def __init__(self) -> None:
        self._docs: dict[str, ImportedDocument] = {}

    # ------------------------------------------------------------------------------------------ contents

    def add(self, doc: ImportedDocument) -> bool:
        """Add a document; False when this exact document (kind and SHA-256) is already present."""
        if doc.doc_id in self._docs:
            return False
        self._docs[doc.doc_id] = doc
        return True

    def get(self, doc_id: str) -> ImportedDocument | None:
        return self._docs.get(doc_id)

    @property
    def documents(self) -> tuple[ImportedDocument, ...]:
        def key(d: ImportedDocument):
            s = d.source
            order = release_ordinal(s.release_id) if s.release_id else -1
            return (s.kind, order, s.current_release_date or '', s.doc_id)
        return tuple(sorted(self._docs.values(), key=key))

    def active_ids(self) -> frozenset[str]:
        """Per release month (or CSAF tracking id) the revision with the newest release date, ties by document id."""
        best: dict[tuple, ImportedDocument] = {}
        for doc in self._docs.values():
            have = best.get(_group_key(doc))
            if have is None or _revision_key(doc) > _revision_key(have):
                best[_group_key(doc)] = doc
        return frozenset(d.doc_id for d in best.values())

    def corpus_digest(self) -> str:
        return corpus_digest(self._docs)

    def cached_scope(self) -> SearchScope:
        ids = tuple(sorted(self._docs))
        if not ids:
            return SearchScope(kind='cached_corpus', corpus_digest=self.corpus_digest())
        return SearchScope(kind='cached_corpus', doc_ids=ids, corpus_digest=self.corpus_digest())

    def scopes(self) -> tuple[ProductScope, ...]:
        return merge_scopes(s for d in self.documents for s in d.scopes)

    # ------------------------------------------------------------------------------------------ coverage

    def _select(self, scope: SearchScope) -> tuple[set[str], set[str], list[ImportedDocument], bool]:
        """(requested labels, inspected labels, documents in scope incl. superseded revisions, explicit files)."""
        docs = list(self._docs.values())
        active = self.active_ids()
        if scope.kind == 'selected_months':
            requested = set(scope.months)
            picked = [d for d in docs if d.source.release_id in requested]
        elif scope.kind == 'provided_files':
            requested = set(scope.doc_ids)
            picked = [d for d in docs if d.doc_id in requested]
        elif scope.kind == 'mixed':
            requested = set(scope.months) | set(scope.doc_ids)
            picked = [d for d in docs if d.source.release_id in requested or d.doc_id in requested]
        else:  # cached_corpus
            picked = docs
            requested = {_label(d) for d in docs if d.doc_id in active}
        inspected = set()
        for d in picked:
            if d.doc_id in active or scope.kind in ('provided_files', 'mixed'):
                inspected.add(d.doc_id if d.doc_id in requested else _label(d))
        return requested, inspected & requested, picked, scope.kind == 'cached_corpus'

    def coverage(self, scope: SearchScope | None = None, *, now: str) -> Coverage:
        return self._coverage(scope or self.cached_scope(), now)[0]

    def _coverage(self, scope: SearchScope, now: str) -> tuple[Coverage, list[ImportedDocument]]:
        requested, inspected, picked, corpus = self._select(scope)
        in_scope = [d for d in picked if (d.doc_id in inspected) or (_label(d) in inspected)]
        sources = {d.source.kind for d in in_scope}
        kind = 'csaf' if sources == {'csaf'} else 'cvrf-month'
        marks = [d.source.current_release_date for d in in_scope if d.source.current_release_date]
        stamps = [d.source.retrieved_at for d in in_scope]
        stale = corpus and (scope.corpus_digest != self.corpus_digest() or _older_than(max(stamps, default=None), now))
        coverage = build_coverage(source_kind=kind, scope=scope, requested=requested, inspected=inspected,
                                  watermark=max(marks, default=None), retrieved_at=max(stamps, default=now),
                                  stale=bool(stale and requested and requested == inspected))
        return coverage, picked

    # ------------------------------------------------------------------------------------------ lookups

    def lookup_kb(self, kb: str, *, scope: SearchScope | None = None, scope_id: str | None = None,
                  now: str) -> Lookup:
        """CVEs and product scopes of one canonical KB id. ``scope`` None means the whole loaded corpus."""
        canonical_kb(kb)
        return self._lookup('kb', kb, lambda e: e.kb == kb, scope, scope_id, now)

    def lookup_cve(self, cve: str, *, scope: SearchScope | None = None, scope_id: str | None = None,
                   now: str) -> Lookup:
        """KBs per product scope of one CVE (no cross-join of KBs between scopes)."""
        if not is_cve(cve):
            raise ValueError('not a canonical CVE id')
        return self._lookup('cve', cve, lambda e: e.cve == cve, scope, scope_id, now)

    def _lookup(self, query_kind: str, query: str, match, scope: SearchScope | None, scope_id: str | None,
                now: str) -> Lookup:
        scope = scope or self.cached_scope()
        coverage, picked = self._coverage(scope, now)
        active = self.active_ids()
        chosen: list[KbCveEdge] = []
        old: list[KbCveEdge] = []
        named = set(scope.doc_ids) if scope.kind in ('provided_files', 'mixed') else set()
        named_old: list[str] = []  # explicitly named files that are superseded yet match (#105 KBC-12)
        for doc in picked:
            rows = [e for e in doc.edges if match(e)]
            (chosen if doc.doc_id in active else old).extend(rows)
            if rows and doc.doc_id in named and doc.doc_id not in active:
                named_old.append(doc.doc_id)
        excluded: dict[str, int] = {}
        if scope_id is not None:
            for edge in chosen:
                if edge.scope_id != scope_id:
                    excluded[edge.scope_id] = excluded.get(edge.scope_id, 0) + 1
            chosen = [e for e in chosen if e.scope_id == scope_id]
            old = [e for e in old if e.scope_id == scope_id]
        key = lambda e: (cve_sort_key(e.cve), kb_sort_key(e.kb), e.scope_id, e.relation, e.ref.doc_id, e.ref.pointer)  # noqa: E731
        edges = tuple(sorted((e for e in chosen if e.relation in REMEDIATION_RELATIONS), key=key))
        mention = tuple(sorted((e for e in chosen if e.relation == 'mention-only'), key=key))
        disputed = tuple(sorted((e for e in chosen if e.relation == 'disputed'), key=key))
        superseded = tuple(sorted(old, key=key))
        status = self._status(coverage, edges)
        used = {e.scope_id for e in (*edges, *mention, *disputed, *superseded)}
        scopes = tuple(s for s in self.scopes() if s.scope_id in used)
        cards = ()
        if query_kind == 'cve':
            seen: dict[str, CveCard] = {}
            for doc in picked:
                for card in doc.cards:
                    if card.cve == query and doc.doc_id in active:
                        seen.setdefault(card.source_kind, card)
            cards = tuple(seen[k] for k in sorted(seen))
        return Lookup(query_kind=query_kind, query=query, status=status, coverage=coverage, edges=edges,
                      groups=distinct_groups(edges), mention_only=mention, disputed=disputed,
                      superseded=superseded, scopes=scopes, excluded=tuple(sorted(excluded.items())), cards=cards,
                      warnings=self._warnings(coverage, picked, edges, mention, disputed, superseded, status,
                                              sorted(named_old)))

    @staticmethod
    def _status(coverage: Coverage, edges: tuple[KbCveEdge, ...]) -> str:
        if coverage.state in ('not_searched', 'unknown_scope'):
            return 'not_searched'
        if coverage.state == 'partial_in_scope':
            return 'partial'
        return 'found' if edges else 'not_observed'

    @staticmethod
    def _warnings(coverage, picked, edges, mention, disputed, superseded, status, named_old=()) -> tuple[str, ...]:
        out = []
        if status == 'partial':
            out.append('PARTIAL: some requested documents are not loaded or unreadable; absence proves nothing')
        if status == 'not_searched':
            out.append('NOT_SEARCHED: no document is loaded for this scope')
        if coverage.state == 'stale_cache':
            out.append(f'STALE_CACHE: the loaded corpus is older than {STALE_AFTER_DAYS} days or changed since the '
                       'scope was written')
        inspected = [d for d in picked if d.doc_id in set(coverage.inspected_ids) or _label(d) in
                     set(coverage.inspected_ids)]
        if inspected and all(d.vulnerabilities == 0 for d in inspected):
            out.append('EMPTY_DOCUMENTS: the inspected documents contain no vulnerability rows; this is not "0 CVEs"')
        if status == 'not_observed' and mention:
            out.append('MENTION_ONLY: the KB appears only in known-issue text, which is not a remediation')
        if disputed:
            out.append('DISPUTED: a negative product status contradicts the fix; the row is left out of leads')
        if superseded:
            out.append('SUPERSEDED: older revisions of a loaded document are retained and listed apart')
        if named_old:
            shown = ', '.join(d[:12] for d in named_old[:5]) + (f' and {len(named_old) - 5} more' if len(named_old) > 5 else '')
            out.append(f'NAMED_SUPERSEDED: {shown} named in the scope is not the active revision of its month; its '
                       'matching rows are listed under superseded and are not counted in the status')
        out.append(REVISION_LAG_NOTE[0].upper() + REVISION_LAG_NOTE[1:])
        return tuple(out)

    # ------------------------------------------------------------------------------------------ timeline

    def timeline(self, cve: str, scope_id: str) -> tuple[TimelineEntry, ...]:
        """Every loaded revision that says something about this CVE and product scope, oldest first (S15)."""
        active = self.active_ids()
        out = []
        for doc in self.documents:
            edges = [e for e in doc.edges if e.cve == cve and e.scope_id == scope_id]
            statuses = [s for s in doc.statuses if s.cve == cve and s.scope_id == scope_id]
            if not edges and not statuses:
                continue
            out.append(TimelineEntry(
                doc_id=doc.doc_id, release_id=doc.source.release_id,
                current_release_date=doc.source.current_release_date, active=doc.doc_id in active,
                kbs=tuple(sorted({e.kb for e in edges}, key=kb_sort_key)),
                relations=tuple(sorted({e.relation for e in edges})),
                status_values=tuple(sorted({s.value for s in statuses}))))
        return tuple(sorted(out, key=lambda t: (t.current_release_date or '', t.release_id or '', t.doc_id)))

    def status_rows(self, cve: str) -> tuple[StatusRow, ...]:
        active = self.active_ids()
        return tuple(sorted((s for d in self.documents if d.doc_id in active for s in d.statuses if s.cve == cve),
                            key=lambda s: (s.scope_id, s.value, s.pointer)))

    def edge_set_digest(self) -> str:
        """Digest of the edge identities of the active documents (a context key input, plan 7.4)."""
        active = self.active_ids()
        return domain_id('kbc.edgeset', 1, sorted(e.edge_id for d in self._docs.values() if d.doc_id in active
                                                  for e in d.edges))


def _older_than(stamp: str | None, now: str) -> bool:
    if stamp is None:
        return False
    try:
        then = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        current = datetime.fromisoformat(now.replace('Z', '+00:00'))
    except ValueError:
        return False
    if then.tzinfo is None:
        then = then.replace(tzinfo=UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current - then > timedelta(days=STALE_AFTER_DAYS)
