"""OLD/NEW product applicability for one CVE (SPEC-28 section G). Pure and deterministic.

The result restates vendor claims for the products that can be tied to each artifact, labelled with how the tie
was made. Identity comes from verified facts only (file hash in the advisory, verified component relationships,
exact file-version equality) or from explicit analyst assertions; a file name never maps anything, and
``product_version_range`` names are not evaluated against file versions (a fixed Windows file usually keeps a
revision below the fixed OS build). A missing status never means affected. Contradictions across revisions,
documents and VEX statements, and an older/newer orientation conflict, are reported and never resolved by
picking a winner.
"""
from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence

from ..contracts import (
    STATUS_CLASS,
    AdvisoryFacts,
    ApplicabilityReport,
    ArtifactIdentity,
    Contradiction,
    IntelError,
    ProductMapping,
    SideApplicability,
    StatusEvidence,
)
from .validate import parse_date_time, revision_precedence

LIMITATIONS = (
    'Applicability restates vendor claims for products tied to each artifact; it is not a binary verification.',
    'File versions are matched to product_version names by exact equality only; product_version_range entries are '
    'not evaluated because a Windows file version is not an operating-system build.',
    'CSAF document signatures are not checked; fetched documents are tied to an allowlisted HTTPS host only.',
)
_TIER = {'verified': 0, 'candidate': 1}
_BASIS_ORDER = ('advisory-file-hash', 'relationship-from-verified-component', 'asserted-product-id',
                'file-version-equals-product-version', 'same-product-name')


def product_key(name: str) -> str:
    return ' '.join(name.split()).casefold()


def _numeric(version: str) -> tuple[int, ...] | None:
    if not re.fullmatch(r'[0-9]{1,9}(\.[0-9]{1,9}){1,5}', version.strip()):
        return None
    return tuple(int(part) for part in version.strip().split('.'))


def supersession(documents: Sequence[AdvisoryFacts]) -> dict[str, bool]:
    """facts_id -> superseded. Per (publisher namespace, tracking id) the newest revision (current release date,
    then version precedence) is current; equal newest revisions are all current."""
    groups: dict[tuple[str, str], list[AdvisoryFacts]] = defaultdict(list)
    for doc in documents:
        groups[(doc.publisher_namespace, doc.tracking_id)].append(doc)

    def key(doc: AdvisoryFacts) -> tuple:
        return (parse_date_time(doc.current_release_date), revision_precedence(doc.revision) or ())

    out = {}
    for docs in groups.values():
        newest = max(key(d) for d in docs)
        for doc in docs:
            out[doc.facts_id] = key(doc) != newest
    return out


class _Side:
    def __init__(self, identity: ArtifactIdentity):
        self.identity = identity
        self.mappings: dict[tuple[str, str], ProductMapping] = {}
        self.why: list[str] = []

    def add(self, mapping: ProductMapping) -> None:
        key = (mapping.source_id, mapping.product_id)
        current = self.mappings.get(key)
        if current is None or _BASIS_ORDER.index(mapping.basis) < _BASIS_ORDER.index(current.basis):
            self.mappings[key] = mapping


def _direct_mappings(side: _Side, doc: AdvisoryFacts) -> None:
    identity = side.identity
    hashed = set()
    for product in doc.products:
        if any(h.sha256 == identity.sha256 for h in product.identification.sha256_hashes):
            verified = identity.facts_state == 'verified-bytes'
            side.add(ProductMapping(
                source_id=doc.source_id, product_id=product.product_id, product_name=product.name,
                status='verified' if verified else 'candidate', basis='advisory-file-hash',
                detail=('artifact SHA-256 equals a file hash in the advisory product identification helper'
                        + ('' if verified else '; the artifact bytes were not re-verified (recorded hash only)'))))
            hashed.add(product.product_id)
    for product in doc.products:
        rel = product.relationship
        if rel is not None and rel.product_reference in hashed:
            platform = doc.product(rel.relates_to_product_reference)
            side.add(ProductMapping(
                source_id=doc.source_id, product_id=product.product_id, product_name=product.name,
                status='candidate', basis='relationship-from-verified-component',
                detail=(f'{rel.category} of {platform.name if platform else rel.relates_to_product_reference}; '
                        'the platform itself is not verified')[:500]))
    for pid in identity.asserted_product_ids:
        product = doc.product(pid)
        if product is not None:
            side.add(ProductMapping(source_id=doc.source_id, product_id=pid, product_name=product.name,
                                    status='candidate', basis='asserted-product-id',
                                    detail='analyst assertion; not verified by PatchTrace'))
    file_version = _numeric(identity.file_version) if identity.file_version else None
    if file_version is not None:
        for product in doc.products:
            if product.version is not None and _numeric(product.version) == file_version:
                side.add(ProductMapping(
                    source_id=doc.source_id, product_id=product.product_id, product_name=product.name,
                    status='candidate', basis='file-version-equals-product-version',
                    detail=f'verified file version {identity.file_version} equals the product_version name; '
                           'a file version may differ from the product build the advisory means'))


def _name_mappings(side: _Side, documents: Sequence[AdvisoryFacts]) -> None:
    names: dict[str, ProductMapping] = {}
    for mapping in side.mappings.values():
        names.setdefault(product_key(mapping.product_name), mapping)
    for doc in documents:
        for product in doc.products:
            origin = names.get(product_key(product.name))
            if origin is not None and origin.source_id != doc.source_id and \
                    (doc.source_id, product.product_id) not in side.mappings:
                side.add(ProductMapping(
                    source_id=doc.source_id, product_id=product.product_id, product_name=product.name,
                    status='candidate', basis='same-product-name',
                    detail=f'same product name as {origin.product_id} in another document ({origin.basis})'[:500]))


def _evidence(doc: AdvisoryFacts, cve: str, superseded: bool, product_ids: Iterable[str] | None = None
              ) -> list[StatusEvidence]:
    item = doc.vulnerability(cve)
    if item is None:
        return []
    wanted = None if product_ids is None else set(product_ids)
    out = []
    for claim in item.product_status:
        if wanted is not None and claim.product_id not in wanted:
            continue
        product = doc.product(claim.product_id)
        out.append(StatusEvidence(source_id=doc.source_id, tracking_id=doc.tracking_id, revision=doc.revision,
                                  document_category=doc.document_category, product_id=claim.product_id,
                                  product_name=product.name if product else claim.product_id, status=claim.status,
                                  status_class=STATUS_CLASS.get(claim.status), pointer=claim.pointer,
                                  superseded=superseded))
    return out


def _evidence_key(e: StatusEvidence) -> tuple:
    return (e.superseded, e.tracking_id, e.source_id, e.product_id, e.status, e.pointer)


def _decided(classes: set[str]) -> set[str]:
    return {c for c in classes if c != 'under_investigation'}


def _contradictions(cve: str, documents: Sequence[AdvisoryFacts], superseded: dict[str, bool]) -> list[Contradiction]:
    out: list[Contradiction] = []
    by_tracking: dict[tuple[str, str], list[AdvisoryFacts]] = defaultdict(list)
    for doc in documents:
        by_tracking[(doc.publisher_namespace, doc.tracking_id)].append(doc)
    for docs in by_tracking.values():  # cross-revision: same product id, decided classes differ
        current = [d for d in docs if not superseded[d.facts_id]]
        older = [d for d in docs if superseded[d.facts_id]]
        for now in current:
            now_claims = defaultdict(list)
            for e in _evidence(now, cve, False):
                if e.status_class:
                    now_claims[e.product_id].append(e)
            for old in older:
                for e in _evidence(old, cve, True):
                    if e.status_class is None or e.product_id not in now_claims:
                        continue
                    new_classes = {c.status_class for c in now_claims[e.product_id]}
                    if e.status_class == 'under_investigation' or not _decided(new_classes) \
                            or e.status_class in new_classes:
                        continue
                    out.append(Contradiction(
                        kind='cross-revision', product_name=e.product_name,
                        claims=tuple(sorted([e, *now_claims[e.product_id]], key=_evidence_key)),
                        explanation=f'revision {e.revision} said {e.status}, current revision {now.revision} says '
                                    f'{", ".join(sorted({c.status for c in now_claims[e.product_id]}))}'[:1000]))
    names: dict[str, list[StatusEvidence]] = defaultdict(list)  # across documents: same product name
    for doc in documents:
        if not superseded[doc.facts_id]:
            for e in _evidence(doc, cve, False):
                if e.status_class:
                    names[product_key(e.product_name)].append(e)
    for claims in names.values():
        by_source: dict[str, set[str]] = defaultdict(set)
        for e in claims:
            by_source[e.source_id].add(e.status_class)
        if len(by_source) < 2 or len(_decided({c for s in by_source.values() for c in s})) < 2:
            continue
        categories = {e.document_category == 'csaf_vex' for e in claims}
        kind = 'vex-vs-advisory' if categories == {True, False} else 'cross-document'
        out.append(Contradiction(kind=kind, product_name=claims[0].product_name,
                                 claims=tuple(sorted(claims, key=_evidence_key)),
                                 explanation='documents state different status classes for the same product name: '
                                             + '; '.join(f'{e.tracking_id} r{e.revision}: {e.status}'
                                                         for e in sorted(claims, key=_evidence_key))[:900]))
    return sorted(out, key=lambda c: (c.kind, c.product_name or '', c.explanation))


def _withdrawals(cve: str, relevant: Sequence[AdvisoryFacts], documents: Sequence[AdvisoryFacts],
                 superseded: dict[str, bool]) -> dict[str, str]:
    """facts_id -> note, for documents that list ``cve`` although every current revision of their tracking id no
    longer does: the vendor dropped the entry, so its earlier statements are superseded and nothing replaces them
    (audit C-03). The cause is a missing statement, reported as unknown, never as a status."""
    groups: dict[tuple[str, str], list[AdvisoryFacts]] = defaultdict(list)
    for doc in relevant:
        groups[(doc.publisher_namespace, doc.tracking_id)].append(doc)
    notes: dict[str, str] = {}
    for (namespace, tracking_id), docs in groups.items():
        if not all(superseded[d.facts_id] for d in docs):
            continue
        heads = sorted({d.revision for d in documents if (d.publisher_namespace, d.tracking_id) == (namespace, tracking_id)
                        and not superseded.get(d.facts_id, True)})
        replaced_by = f'revision {", ".join(heads)}' if heads else 'a newer revision'
        text = (f'{tracking_id}: {replaced_by} no longer lists {cve}; the statements of revision '
                f'{", ".join(sorted({d.revision for d in docs}))} are superseded and nothing replaces them')[:300]
        notes.update({d.facts_id: text for d in docs})
    return notes


def _side_result(side: _Side, cve: str, documents: Sequence[AdvisoryFacts], superseded: dict[str, bool],
                 contradictions: list[Contradiction], known_ids: set[str],
                 withdrawn: dict[str, str]) -> SideApplicability:
    identity = side.identity
    why = list(side.why)
    for pid in identity.asserted_product_ids:
        if pid not in known_ids:
            why.append(f'asserted product id {pid} is not defined in any stored document for {cve}')
    mappings = sorted(side.mappings.values(), key=lambda m: (m.source_id, m.product_id, m.basis))
    if not mappings:
        why.append('no product in the advisory could be tied to this artifact by verified identity or an analyst '
                   'assertion; abstaining (the file name is never used)')
        return SideApplicability(side=identity.side, identity=identity, product_mapping_status='unknown',
                                 resolution='unknown', why=tuple(why), assessment='unknown')
    by_doc = {doc.source_id: doc for doc in documents}
    statuses: list[StatusEvidence] = []
    for mapping in mappings:
        doc = by_doc[mapping.source_id]
        why.append(f'mapping {mapping.status}: {mapping.product_id} in {doc.tracking_id} r{doc.revision} '
                   f'({mapping.basis})'[:300])
        if doc.facts_id in withdrawn and withdrawn[doc.facts_id] not in why:
            why.append(withdrawn[doc.facts_id])
        statuses += _evidence(doc, cve, superseded[doc.facts_id], [mapping.product_id])
    statuses.sort(key=_evidence_key)
    carrying = {(e.source_id, e.product_id) for e in statuses}
    tiers = [m.status for m in mappings if (m.source_id, m.product_id) in carrying] or [m.status for m in mappings]
    mapping_status = min(tiers, key=_TIER.__getitem__)
    current = [e for e in statuses if not e.superseded]
    classes = {e.status_class for e in current if e.status_class}
    recommended = any(e.status == 'recommended' for e in current)
    involved = {(e.source_id, e.product_id) for e in statuses}
    conflicted = [c for c in contradictions if c.kind != 'orientation'
                  and any((e.source_id, e.product_id) in involved for e in c.claims)]
    for e in statuses:
        why.append(f'{"superseded " if e.superseded else ""}status: {e.product_id} {e.status} in {e.tracking_id} '
                   f'r{e.revision} at {e.pointer}'[:300])
    if conflicted:
        resolution = 'contradictory'
        why.append(f'{len(conflicted)} contradiction(s) involve the mapped products; not resolved')
    elif not classes:
        resolution = 'unknown'
        why.append('the mapped products have no status for this CVE; a missing status never means affected')
    elif len(classes) == 1:
        resolution = next(iter(classes))
    else:
        resolution = 'ambiguous'
        why.append(f'mapped products disagree ({", ".join(sorted(classes))}); refine the mapping')
    return SideApplicability(side=identity.side, identity=identity, product_mapping_status=mapping_status,
                             mappings=tuple(mappings), resolution=resolution, recommended=recommended,
                             statuses=tuple(statuses), why=tuple(why),
                             assessment='unknown' if resolution == 'unknown' else 'advisory-claim')


def resolve(cve: str, documents: Sequence[AdvisoryFacts], older: ArtifactIdentity, newer: ArtifactIdentity, *,
            superseded: Mapping[str, bool] | None = None) -> ApplicabilityReport:
    """Applicability of ``cve`` for both sides over every stored document that lists the CVE.

    Pass every stored document, not only those that list the CVE: a newer revision that no longer lists it still
    supersedes the older one, and its absence is reported instead of the older claims staying current (audit C-03).
    A caller that holds only the documents listing the CVE can pass the store-wide ``superseded`` map
    (``facts_id`` to flag, as ``AdvisoryStore.advisories`` derives it), which then decides for the ids it names."""
    if older.side != 'older' or newer.side != 'newer':
        raise IntelError('PT-INTEL-INPUT', 'identities must be (older, newer)')
    relevant = sorted((d for d in documents if d.vulnerability(cve) is not None),
                      key=lambda d: (d.tracking_id, d.current_release_date, d.revision, d.source_id))
    if not relevant:
        raise IntelError('PT-INTEL-NOTFOUND', f'no stored advisory lists {cve}')
    state = {**supersession(list(documents)), **(superseded or {})}
    withdrawn = _withdrawals(cve, relevant, documents, state)
    contradictions = _contradictions(cve, relevant, state)
    known_ids = {p.product_id for d in relevant for p in d.products}
    sides = []
    for identity in (older, newer):
        side = _Side(identity)
        for doc in relevant:
            _direct_mappings(side, doc)
        _name_mappings(side, relevant)
        sides.append(_side_result(side, cve, relevant, state, contradictions, known_ids, withdrawn))
    old, new = sides
    if old.resolution in ('fixed', 'not_affected') and new.resolution == 'affected':
        contradictions.append(Contradiction(
            kind='orientation', claims=tuple(sorted((*old.statuses, *new.statuses), key=_evidence_key)),
            explanation=f'older resolves {old.resolution} while newer resolves affected: check the build order '
                        'and the product mapping'))
    return ApplicabilityReport(
        cve=cve, older=old, newer=new,
        contradictions=tuple(sorted(contradictions, key=lambda c: (c.kind, c.product_name or '', c.explanation))),
        sources=tuple(sorted({d.source_id for d in relevant})),
        superseded_sources=tuple(sorted({d.source_id for d in relevant if state[d.facts_id]})),
        limitations=(*LIMITATIONS, *sorted(set(withdrawn.values()))))

