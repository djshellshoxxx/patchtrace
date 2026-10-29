"""Local import of one source document (KB-integration-plan 7.2 `SourceDoc`, 8.1 `kb index import`; slice K1). Pure.

``import_bytes`` takes exact bytes (optionally gzip-wrapped, bounded), decides what the document is, parses it
offline and returns an :class:`ImportedDocument`: the `SourceDoc` record plus the scopes, edges, cards and status rows
it contributes. Nothing is written and nothing is fetched here.

Authenticity: a local file is ALWAYS ``unverified-local-file``, whatever its publisher fields say (S16, plan row
"local file claiming to be Microsoft"); the lineage ``msrc`` only names the document family for the one-lineage rule.

CSAF documents are validated and normalised by the ``intelligence`` package behind ``AdvisoryPort``; without a bound
port a CSAF file is refused with ``PT-KBC-UNSUPPORTED`` (a CSAF-only edge never comes from an unvalidated parse).
"""
from __future__ import annotations

import hashlib
import zlib
from dataclasses import dataclass

from pydantic import ValidationError

from ..contracts import CveCard, KbCveEdge, ProductScope, SourceDoc, domain_id
from ..limits import DEFAULT_LIMITS, KbcLimits
from ..ports import AdvisoryPort
from ..products import safe_label
from .csaf_bridge import BRIDGE_VERSION, bridge_facts, facts_meta
from .csaf_bridge import DIALECT as CSAF_DIALECT
from .cvrf import (
    PARSER_VERSION,
    DocumentEdges,
    Problem,
    SourceError,
    StatusRow,
    build_edges,
    load_json,
    parse_cvrf,
    parse_json_document,
    sniff_guard,
)

CSAF_DOC_BYTES = 16 * 1024 * 1024  # CSAF reuses the intelligence package's limit (plan 7.4)
MINOR_RELATIONS = ('mention-only', 'disputed')


@dataclass(frozen=True)
class ImportedDocument:
    source: SourceDoc
    scopes: tuple[ProductScope, ...]
    edges: tuple[KbCveEdge, ...]
    cards: tuple[CveCard, ...]
    statuses: tuple[StatusRow, ...]
    problems: tuple[Problem, ...]
    vulnerabilities: int
    tracking_id: str | None = None

    @property
    def doc_id(self) -> str:
        return self.source.doc_id

    def counts(self) -> dict[str, int]:
        """`edges` counts the vendor-remediation and vendor-association rows; mention-only and disputed rows are
        counted apart, and ``edge_rows`` is the total (the baseline month is 4 edges + 1 mention-only = 5 rows)."""
        rows = self.edges
        return {'vulnerabilities': self.vulnerabilities,
                'edges': sum(1 for e in rows if e.relation not in MINOR_RELATIONS),
                'mention_only': sum(1 for e in rows if e.relation == 'mention-only'),
                'disputed': sum(1 for e in rows if e.relation == 'disputed'),
                'edge_rows': len(rows), 'scopes': len({s.scope_id for s in self.scopes}),  # distinct (#105 KBC-13)
                'problems': sum(1 for p in self.problems if p.level != 'info')}

    def summary(self) -> dict:
        s = self.source
        return {'doc_id': s.doc_id, 'kind': s.kind, 'sha256': s.sha256, 'size': s.size, 'release_id': s.release_id,
                'current_release_date': s.current_release_date, 'dialect': s.dialect,
                'authenticity': s.authenticity, **self.counts()}


def gunzip_bounded(data: bytes, limit: int) -> bytes:
    """Decompress one gzip member without ever holding more than ``limit`` + 1 bytes (zip-bomb guard, NEG-26)."""
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = inflater.decompress(data, limit + 1)
    except zlib.error:
        raise SourceError('PT-KBC-SOURCE', 'the document is not valid gzip') from None
    if len(out) > limit or inflater.unconsumed_tail:
        raise SourceError('PT-KBC-LIMIT', f'the decompressed document exceeds {limit} bytes')
    if not inflater.eof:
        raise SourceError('PT-KBC-SOURCE', 'the gzip stream is truncated')
    if inflater.unused_data:
        raise SourceError('PT-KBC-SOURCE', 'the gzip file has trailing data after its stream')
    return out


def _source_doc(kind: str, raw: bytes, *, now: str, release_id: str | None, current: str | None, dialect: str,
                parser_version: int) -> SourceDoc:
    sha = hashlib.sha256(raw).hexdigest()
    return SourceDoc(
        doc_id=domain_id('kbc.source', 1, {'kind': kind, 'sha256': sha}), kind=kind, sha256=sha, size=len(raw),
        origin='local-import', uri=None, retrieved_at=now, release_id=release_id, current_release_date=current,
        dialect=dialect, parser_version=parser_version, authenticity='unverified-local-file', lineage='msrc',
        object_path=f'objects/{sha[:2]}/{sha}.gz')


def import_bytes(raw: bytes, *, now: str, advisory: AdvisoryPort | None = None,
                 limits: KbcLimits = DEFAULT_LIMITS) -> ImportedDocument:
    """Parse ``raw`` (CVRF month, JSON or XML, or a CSAF 2.0 document) into an :class:`ImportedDocument`.

    Raises :class:`SourceError` (INPUT, SOURCE, LIMIT, UNSUPPORTED); nothing is returned for a damaged source, so a
    caller that stores results can leave its index unchanged."""
    if type(raw) is not bytes:
        raise SourceError('PT-KBC-INPUT', 'a source document must be bytes')
    if raw[:2] == b'\x1f\x8b':
        raw = gunzip_bounded(raw, limits.cvrf_doc_bytes)
    if len(raw) > limits.cvrf_doc_bytes:
        raise SourceError('PT-KBC-LIMIT', f'the document is {len(raw)} bytes; the limit is {limits.cvrf_doc_bytes}')
    try:
        return _import_plain(raw, now, advisory, limits)
    except ValidationError:
        raise SourceError('PT-KBC-SOURCE', 'a value in the document exceeds the kbcorrelation/1 bounds') from None


def _import_plain(raw: bytes, now: str, advisory: AdvisoryPort | None, limits: KbcLimits) -> ImportedDocument:
    sniff_guard(raw)
    head = raw.lstrip(b' \t\r\n')[:1]
    if head == b'<':
        return _from_cvrf(parse_cvrf(raw, limits), raw, now, limits)
    if head != b'{':
        raise SourceError('PT-KBC-SOURCE', 'CVRF dialect unknown: the document is neither a JSON object nor XML')
    value = load_json(raw, limits)
    document = value.get('document') if isinstance(value, dict) else None
    if isinstance(value, dict) and 'dialect' not in value and isinstance(document, dict) \
            and 'csaf_version' in document:
        return _from_csaf(raw, now, advisory)
    return _from_cvrf(parse_json_document(value, limits), raw, now, limits)


def _from_cvrf(parsed, raw: bytes, now: str, limits: KbcLimits) -> ImportedDocument:
    source = _source_doc('cvrf-month', raw, now=now, release_id=parsed.release_id,
                         current=parsed.current_release_date, dialect=parsed.dialect, parser_version=PARSER_VERSION)
    built = build_edges(parsed, source.doc_id, limits)
    return _assemble(source, built, parsed.tracking_id)


def _from_csaf(raw: bytes, now: str, advisory: AdvisoryPort | None) -> ImportedDocument:
    if len(raw) > CSAF_DOC_BYTES:
        raise SourceError('PT-KBC-LIMIT', f'a CSAF document is limited to {CSAF_DOC_BYTES} bytes')
    if advisory is None:
        raise SourceError('PT-KBC-UNSUPPORTED', 'CSAF import needs the advisory port (bound by the kb command); '
                          'no CSAF parser is bound here', recoverable=True)
    sha = hashlib.sha256(raw).hexdigest()
    try:
        facts = advisory.parse_csaf(raw, source_sha256=sha)
    except Exception as exc:
        raise SourceError('PT-KBC-SOURCE', 'the CSAF document was rejected: '
                          f'{safe_label(getattr(exc, "code", type(exc).__name__), 40)}: '
                          f'{safe_label(str(exc), 200)}', details={'cause': safe_label(type(exc).__name__, 60)}
                          ) from None
    if facts.get('source_id') != sha:
        raise SourceError('PT-KBC-SOURCE', 'the advisory port returned facts for a different document')
    meta = facts_meta(facts)
    source = _source_doc('csaf', raw, now=now, release_id=None, current=meta['current_release_date'],
                         dialect=CSAF_DIALECT, parser_version=BRIDGE_VERSION)
    return _assemble(source, bridge_facts(facts, source.doc_id), meta['tracking_id'])


def _assemble(source: SourceDoc, built: DocumentEdges, tracking_id: str | None) -> ImportedDocument:
    return ImportedDocument(source=source, scopes=built.scopes, edges=built.edges, cards=built.cards,
                            statuses=built.statuses, problems=built.problems, vulnerabilities=built.vulnerabilities,
                            tracking_id=tracking_id)
