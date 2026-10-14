"""Canonical view of one validated CSAF 2.0 document (SPEC-28 section F). Pure; input must come from
``validate.load_document`` (the structure is trusted only after validation).

Every normalized claim keeps the RFC 6901 pointer of the exact source value, so any statement PatchTrace
shows can be traced back to the original bytes (kept unmodified as the source sidecar). Advisory text is
kept verbatim: it is data, escaped only when exported, never interpreted or executed.
"""
from __future__ import annotations

import hashlib
import re
import threading
from collections import defaultdict
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

from pydantic import ValidationError

from ...enrichment.identity import domain_id
from ..contracts import (
    PRODUCT_STATUSES,
    AdvisoryFacts,
    AdvisorySource,
    BranchStep,
    CVEFact,
    CweRef,
    FileHash,
    Flag,
    Identification,
    IntelError,
    Note,
    Product,
    ProductGroup,
    RelationshipRef,
    Remediation,
    Score,
    StatusClaim,
    Threat,
    ValidationReport,
    VulnerabilityId,
)
from .validate import VALIDATOR_VERSION, escape_token, iter_branches

NORMALIZER_VERSION = 1
_CANCEL_EVERY = 1024


def pointer(base: str, *tokens: str | int) -> str:
    return base + ''.join('/' + escape_token(t) for t in tokens)


def csaf_filename(tracking_id: str) -> str:
    """CSAF 2.0 §5.1: lower case, then every run outside [+\\-a-z0-9] becomes one underscore, plus .json."""
    return re.sub(r'[^+\-a-z0-9]+', '_', tracking_id.lower()) + '.json'


def facts_id_for(source_sha256: str) -> str:
    return domain_id('advisory-facts', NORMALIZER_VERSION, {'sha256': source_sha256, 'validator': VALIDATOR_VERSION})


def _cancelled(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise IntelError('PT-INTEL-CANCEL', 'normalization cancelled', recoverable=True)


def make_source(doc: dict, raw: bytes, *, origin: str, uri: str | None, file_name: str, retrieved_at: str,
                authenticity_state: str | None = None) -> AdvisorySource:
    """The provenance record of one acquisition of exact bytes (local import or consented fetch)."""
    document = doc['document']
    tracking = document['tracking']
    publisher = document['publisher']
    sha = hashlib.sha256(raw).hexdigest()
    state = authenticity_state or ('unverified-local-file' if origin == 'local-import' else 'tls-allowlisted-host')
    matches = None
    if origin == 'https-fetch' and uri:
        matches = uri.rsplit('/', 1)[-1] == csaf_filename(tracking['id'])
    self_urls = tuple(sorted({r['url'] for r in document.get('references') or () if r.get('category') == 'self'}))
    retrieval = domain_id('advisory-retrieval', 1, {'sha256': sha, 'origin': origin, 'uri': uri,
                                                     'file_name': file_name, 'retrieved_at': retrieved_at})
    try:
        return AdvisorySource(
            source_id=sha, retrieval_id=retrieval, origin=origin, uri=uri, file_name=file_name,
            retrieved_at=retrieved_at, sha256=sha, size=len(raw), tracking_id=tracking['id'],
            revision=tracking['version'], tracking_status=tracking['status'],
            initial_release_date=tracking['initial_release_date'],
            current_release_date=tracking['current_release_date'], schema_version=document['csaf_version'],
            document_category=document['category'], publisher_name=publisher['name'],
            publisher_namespace=publisher['namespace'], publisher_category=publisher['category'],
            authenticity_state=state, self_urls=self_urls[:64], filename_matches_tracking_id=matches,
            raw_path=f'intelligence/csaf/sources/{sha}.json')
    except ValidationError as exc:
        raise IntelError('PT-INTEL-INPUT', f'source record rejected: {_first_error(exc)}') from None


def _first_error(exc: ValidationError) -> str:
    error = exc.errors()[0]
    location = '.'.join(str(part) for part in error.get('loc', ()))
    return f'{location}: {error.get("msg", "invalid")}'[:200]


def _identification(product: dict) -> Identification:
    helper = product.get('product_identification_helper') or {}
    hashes = []
    for entry in helper.get('hashes') or ():
        for file_hash in entry.get('file_hashes') or ():
            value = str(file_hash.get('value', ''))
            if file_hash.get('algorithm', '').lower() == 'sha256' and re.fullmatch(r'[0-9a-fA-F]{64}', value):
                hashes.append(FileHash(file_name=entry['filename'], sha256=value.lower()))
    unique = sorted({(h.sha256, h.file_name): h for h in hashes}.values(), key=lambda h: (h.sha256, h.file_name))
    return Identification(cpe=helper.get('cpe'), purl=helper.get('purl'), sha256_hashes=tuple(unique))


def _notes(items, base: str) -> tuple[Note, ...]:
    return tuple(Note(category=item['category'], title=item.get('title'), audience=item.get('audience'),
                      text=item['text'], pointer=pointer(base, index)) for index, item in enumerate(items or ()))


def _scoped(item: dict, groups: dict[str, tuple[str, ...]]) -> dict:
    direct = tuple(sorted(set(item.get('product_ids') or ())))
    group_ids = tuple(sorted(set(item.get('group_ids') or ())))
    reached = {pid for gid in group_ids for pid in groups.get(gid, ())}
    return {'product_ids': direct, 'group_ids': group_ids, 'via_groups': tuple(sorted(reached - set(direct))),
            'date': item.get('date')}


def _score_text(value) -> str:
    try:
        return str(Decimal(repr(value)).quantize(Decimal('0.1'), rounding=ROUND_HALF_UP))
    except InvalidOperation:  # pragma: no cover - the validator guarantees a finite number in 0..10
        raise IntelError('PT-INTEL-FORMAT', 'invalid CVSS base score') from None


def _scores(items, base: str) -> tuple[Score, ...]:
    out = []
    for index, item in enumerate(items or ()):
        products = tuple(sorted(set(item['products'])))
        for key in ('cvss_v3', 'cvss_v2'):
            cvss = item.get(key)
            if isinstance(cvss, dict):
                out.append(Score(cvss_version=cvss['version'], base_score=_score_text(cvss['baseScore']),
                                 base_severity=cvss.get('baseSeverity'), vector=cvss.get('vectorString'),
                                 products=products, pointer=pointer(base, index, key)))
    return tuple(out)


def _vulnerability(item: dict, index: int, source_id: str, groups: dict[str, tuple[str, ...]]) -> CVEFact:
    base = pointer('', 'vulnerabilities', index)
    claims = []
    for status in PRODUCT_STATUSES:
        for position, pid in enumerate((item.get('product_status') or {}).get(status) or ()):
            claims.append(StatusClaim(product_id=pid, status=status,
                                      pointer=pointer(base, 'product_status', status, position)))
    claims.sort(key=lambda c: (c.product_id, c.status, c.pointer))
    cwe = item.get('cwe')
    return CVEFact(
        source_id=source_id, cve=item.get('cve'), pointer=base, title=item.get('title'),
        cwe=CweRef(id=cwe['id'], name=cwe['name'], pointer=pointer(base, 'cwe')) if cwe else None,
        notes=_notes(item.get('notes'), pointer(base, 'notes')), product_status=tuple(claims),
        remediations=tuple(
            Remediation(category=r['category'], details=r['details'], url=r.get('url'),
                        restart_required=(r.get('restart_required') or {}).get('category'),
                        pointer=pointer(base, 'remediations', k), **_scoped(r, groups))
            for k, r in enumerate(item.get('remediations') or ())),
        threats=tuple(Threat(category=t['category'], details=t['details'], pointer=pointer(base, 'threats', k),
                             **_scoped(t, groups)) for k, t in enumerate(item.get('threats') or ())),
        scores=_scores(item.get('scores'), pointer(base, 'scores')),
        flags=tuple(Flag(label=f['label'], pointer=pointer(base, 'flags', k), **_scoped(f, groups))
                    for k, f in enumerate(item.get('flags') or ())),
        ids=tuple(VulnerabilityId(system_name=i['system_name'], text=i['text'], pointer=pointer(base, 'ids', k))
                  for k, i in enumerate(item.get('ids') or ())))


def normalize(doc: dict, report: ValidationReport, source_sha256: str, *,
              cancel: threading.Event | None = None) -> AdvisoryFacts:
    """``AdvisoryFacts`` for an accepted document. Raises IntelError (LIMIT when a value exceeds the
    normalized contract bounds, which follow CSAF Appendix C; CANCEL; INPUT for a rejected report)."""
    if not report.valid:
        raise IntelError('PT-INTEL-INPUT', 'only validated documents can be normalized')
    _cancelled(cancel)
    try:
        return _normalize(doc, report, source_sha256, cancel)
    except ValidationError as exc:
        raise IntelError('PT-INTEL-LIMIT', f'a value exceeds the normalized contract bounds ({_first_error(exc)})') \
            from None


def _normalize(doc: dict, report: ValidationReport, source_sha256: str,
               cancel: threading.Event | None) -> AdvisoryFacts:
    tree = doc.get('product_tree') or {}
    groups: dict[str, tuple[str, ...]] = {}
    member_of: dict[str, set[str]] = defaultdict(set)
    group_records = []
    for index, group in enumerate(tree.get('product_groups') or ()):
        members = tuple(sorted(set(group['product_ids'])))
        groups[group['group_id']] = members
        for pid in members:
            member_of[pid].add(group['group_id'])
        group_records.append(ProductGroup(group_id=group['group_id'], product_ids=members,
                                          summary=group.get('summary'),
                                          pointer=pointer('', 'product_tree', 'product_groups', index)))
    products: list[Product] = []

    def add(product: dict, at: str, definition: str, **extra) -> None:
        if len(products) % _CANCEL_EVERY == 0:
            _cancelled(cancel)
        pid = product['product_id']
        products.append(Product(product_id=pid, name=product['name'], definition=definition, pointer=at,
                                group_ids=tuple(sorted(member_of.get(pid, ()))),
                                identification=_identification(product), **extra))

    for branch, at, path in iter_branches(doc):
        product = branch.get('product')
        if not isinstance(product, dict):
            continue
        steps = tuple(BranchStep(category=category, name=name) for category, name in path)
        version = next((name for category, name in reversed(path) if category == 'product_version'), None)
        version_range = next((name for category, name in reversed(path) if category == 'product_version_range'), None)
        add(product, f'{at}/product', 'branch', branch_path=steps, version=version, version_range=version_range)
    for index, item in enumerate(tree.get('full_product_names') or ()):
        add(item, pointer('', 'product_tree', 'full_product_names', index), 'full_product_name')
    for index, rel in enumerate(tree.get('relationships') or ()):
        add(rel['full_product_name'], pointer('', 'product_tree', 'relationships', index, 'full_product_name'),
            'relationship', relationship=RelationshipRef(
                category=rel['category'], product_reference=rel['product_reference'],
                relates_to_product_reference=rel['relates_to_product_reference']))
    products.sort(key=lambda p: p.product_id)
    vulnerabilities = []
    for index, item in enumerate(doc.get('vulnerabilities') or ()):
        if index % 64 == 0:
            _cancelled(cancel)
        vulnerabilities.append(_vulnerability(item, index, source_sha256, groups))
    document = doc['document']
    return AdvisoryFacts(
        facts_id=facts_id_for(source_sha256), normalizer_version=NORMALIZER_VERSION, source_id=source_sha256,
        tracking_id=document['tracking']['id'], revision=document['tracking']['version'],
        current_release_date=document['tracking']['current_release_date'], document_category=document['category'],
        publisher_namespace=document['publisher']['namespace'], title=document['title'],
        document_notes=_notes(document.get('notes'), '/document/notes'), products=tuple(products),
        groups=tuple(sorted(group_records, key=lambda g: g.group_id)), vulnerabilities=tuple(vulnerabilities),
        validation=report)
