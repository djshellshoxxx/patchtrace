"""CVRF monthly document -> KB/CVE/product edges (KB-integration-plan 6, 7.2; slice K1). Pure and offline.

What is parsed, and what is not
-------------------------------
Only DIALECTS the parser knows are read: ``cvrf-json/0`` and ``cvrf-xml/0``. Both are SYNTHETIC project placeholders
whose shape follows RK1 section 3 (``Remediations[Type==2]`` carries the KB, ``Type 5`` is a known issue). The real
MSRC CVRF JSON shape is unobserved until live probe L1, so a document in any other shape is refused with
``PT-KBC-SOURCE`` ("dialect unknown"); a parser never guesses, and an unknown dialect is never read as an empty month.

Safety: duplicate JSON keys, non-finite numbers, byte-order marks and invalid UTF-8 are refused; nesting, node and
string sizes are bounded (`KbcLimits`); XML containing any markup declaration (DOCTYPE, ENTITY, ...) or a non-UTF-8
encoding is refused before the parser sees it, so no entity is ever expanded and nothing external is read. Advisory
text is untrusted data: it is cleaned of controls and bidirectional marks, kept as plain text, never used to build a
URL, and never placed in an error message.

Edge rules (guards of plan section 6)
-------------------------------------
* ``Remediations[Type==2]`` only: every line of ``description`` must itself be a KB id (``normalise_kb_edge``); a
  line that is not (prose, a build number, a slash or control character) produces a problem and no edge.
* Every other remediation type, and a Type 2 line that merely contains an exact ``KB`` token, produces
  ``mention-only`` edges: a known issue never becomes a fix.
* One edge per (KB, CVE, product scope); several product ids of one row give several edges with one source pointer;
  identical rows at different positions keep separate pointers (display deduplication is the index's job).
* A product id that is not in the product tree is never a wildcard: it is a problem and produces no edge.
* A remediation whose product the same vulnerability lists under a negative status ("Not affected") becomes a
  ``disputed`` edge that cites both pointers; it is left out of leads and shown with its conflict.
* A CVE that is malformed or occurs in several vulnerability rows is ambiguous: no edge for any of its rows.
* Text outside remediation descriptions is not scanned for KB numbers.
"""
from __future__ import annotations

import json
import math
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from pydantic import ValidationError

from ..contracts import (
    CveCard,
    KbCveEdge,
    ProductScope,
    ProductStatus,
    SourceRef,
    domain_id,
)
from ..errors import KbcIssue
from ..ids import KbSyntaxError, cve_sort_key, find_kb_tokens, is_cve, kb_sort_key, normalise_kb_edge
from ..limits import DEFAULT_LIMITS, KbcLimits
from ..products import clean_text, safe_label, scope_for

PARSER_VERSION = 1
DIALECT_JSON = 'cvrf-json/0'
DIALECT_XML = 'cvrf-xml/0'
DIALECTS = (DIALECT_JSON, DIALECT_XML)
XML_NS = 'https://example.invalid/synthetic-cvrf/1'  # synthetic placeholder namespace (fixtures, not Microsoft)
MAX_STRING = 1_048_576
REMEDIATION_VENDOR_FIX = 2

_RELEASE_ID = re.compile(r'^[0-9]{4}-(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$')
_DATE = re.compile(r'^([0-9]{4}-[0-9]{2}-[0-9]{2})$')
_STAMP = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$')
_BUILD2 = re.compile(r'^([0-9]{1,6})\.([0-9]{1,6})$')
_BUILD4 = re.compile(r'^[0-9]{1,6}\.[0-9]{1,6}\.([0-9]{1,6})\.([0-9]{1,6})$')
_CWE = re.compile(r'^CWE-[1-9][0-9]{0,5}$')
_MARKUP_DECL = re.compile(r'<!(?!--|\[CDATA\[)')
_XML_DECL_ENCODING = re.compile(r'^<\?xml[^>]*\bencoding\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_NEGATIVE = frozenset({'not affected', 'known not affected'})
_FIXED = frozenset({'fixed', 'first fixed'})
_AFFECTED = frozenset({'affected', 'known affected', 'first affected', 'last affected'})


class SourceError(Exception):
    """A source that cannot be read at all (shape, size, safety). The message never echoes document text."""

    def __init__(self, code: str, message: str, *, recoverable: bool = True, details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.recoverable = recoverable
        self.details = details

    def issue(self, source_id: str | None = None) -> KbcIssue:
        return KbcIssue(code=self.code, message=self.message[:500], recoverable=self.recoverable,
                        source_id=source_id, details=self.details)


@dataclass(frozen=True)
class Problem:
    """A row-level anomaly. The source stays usable; the row (or the product) is skipped and reported."""
    code: str
    pointer: str
    detail: str
    level: str = 'warning'  # 'warning' | 'info'

    def as_dict(self) -> dict[str, str]:
        return {'code': self.code, 'pointer': self.pointer, 'detail': self.detail, 'level': self.level}


@dataclass(frozen=True)
class RawProduct:
    product_id: str
    name: str
    family_hint: str | None
    arch_hint: str | None
    pointer: str


@dataclass(frozen=True)
class RawRemediation:
    index: int
    pointer: str
    type: int
    description: str
    product_ids: tuple[str, ...]
    fixed_build: str | None
    supersedes: tuple[str, ...]
    sub_type: str | None


@dataclass(frozen=True)
class RawStatus:
    value: str
    product_id: str
    pointer: str


@dataclass(frozen=True)
class RawVulnerability:
    index: int
    pointer: str
    cve: str
    title: str | None
    cwe: str | None
    remediations: tuple[RawRemediation, ...]
    statuses: tuple[RawStatus, ...]


@dataclass(frozen=True)
class CvrfDocument:
    dialect: str
    tracking_id: str | None
    release_id: str
    current_release_date: str | None
    products: tuple[RawProduct, ...]
    vulnerabilities: tuple[RawVulnerability, ...]
    problems: tuple[Problem, ...]
    ambiguous_cves: frozenset[str] = frozenset()


@dataclass(frozen=True)
class StatusRow:
    cve: str
    scope_id: str
    value: str
    klass: str
    pointer: str


@dataclass(frozen=True)
class DocumentEdges:
    """Everything one document contributes to the reverse index."""
    edges: tuple[KbCveEdge, ...] = ()
    scopes: tuple[ProductScope, ...] = ()
    cards: tuple[CveCard, ...] = ()
    statuses: tuple[StatusRow, ...] = ()
    problems: tuple[Problem, ...] = ()
    vulnerabilities: int = 0


# ---------------------------------------------------------------------------------------------- vocabulary

def escape_token(token: object) -> str:
    """RFC 6901 reference token."""
    return str(token).replace('~', '~0').replace('/', '~1')


def pointer(*tokens: object) -> str:
    return ''.join('/' + escape_token(t) for t in tokens)


def status_class(value: str) -> str:
    """negative / fixed / affected / investigating / unknown. Unknown names never become "affected"."""
    key = re.sub(r'[\s_-]+', ' ', value.strip().lower())
    if key in _NEGATIVE:
        return 'not_affected'
    if key in _FIXED:
        return 'fixed'
    if key in _AFFECTED:
        return 'affected'
    if key in ('under investigation', 'recommended'):
        return 'investigating'
    return 'unknown'


def parse_fixed_build(text: object) -> str | None:
    """``build.UBR`` from ``26100.9001`` or from a four-part version ``10.0.26100.9001``; anything else is None."""
    if not isinstance(text, str):
        return None
    value = text.strip()
    if _BUILD2.fullmatch(value):
        return value
    match = _BUILD4.fullmatch(value)
    return f'{match.group(1)}.{match.group(2)}' if match else None


def normal_timestamp(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    if _DATE.fullmatch(value):
        return value + 'T00:00:00Z'
    return value if _STAMP.fullmatch(value) else None


def make_edge(*, kb: str, cve: str, scope_id: str, relation: str, doc_id: str, ptr: str, assertion: str,
              release_id: str | None = None, fixed_build: str | None = None, supersedes: tuple[str, ...] = (),
              sub_type: str | None = None, product_status: ProductStatus | None = None) -> KbCveEdge:
    """The one place an edge and its identity are built (CVRF and CSAF share it)."""
    edge_id = domain_id('kbc.edge', 1, {'kb': kb, 'cve': cve, 'scope_id': scope_id, 'relation': relation,
                                        'doc_id': doc_id, 'pointer': ptr})
    return KbCveEdge(edge_id=edge_id, kb=kb, cve=cve, scope_id=scope_id, relation=relation,
                     ref=SourceRef(doc_id=doc_id, pointer=ptr, assertion=assertion), release_id=release_id,
                     fixed_build=fixed_build, supersedes=tuple(sorted(set(supersedes) - {kb}, key=kb_sort_key)),
                     sub_type=sub_type, product_status=product_status)


def edge_sort_key(edge: KbCveEdge) -> tuple:
    return (cve_sort_key(edge.cve), kb_sort_key(edge.kb), edge.scope_id, edge.relation, edge.ref.doc_id,
            edge.ref.pointer)


# ---------------------------------------------------------------------------------------------- strict JSON

class _DuplicateKey(ValueError):
    pass


class _BadNumber(ValueError):
    pass


def _strict_loads(text: str):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise _DuplicateKey(key)
            value[key] = item
        return value

    def constant(name):
        raise _BadNumber(name)

    def finite(value: str):
        number = float(value)
        if not math.isfinite(number):
            raise _BadNumber(value[:20])
        return number

    def bounded(value: str):
        if len(value) > 4300:
            raise _BadNumber('integer with more than 4300 digits')
        return int(value)

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant, parse_float=finite, parse_int=bounded)


def _check_shape(value, limits: KbcLimits) -> None:
    """Iterative depth/node/string bounds (no recursion: the input is hostile until proven otherwise)."""
    nodes = 0
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > limits.cvrf_json_nodes:
            raise SourceError('PT-KBC-LIMIT', f'the document has more than {limits.cvrf_json_nodes} JSON values')
        if isinstance(item, dict):
            if depth > limits.cvrf_depth:
                raise SourceError('PT-KBC-LIMIT', f'the document nests deeper than {limits.cvrf_depth} levels')
            for key, sub in item.items():
                if len(key) > MAX_STRING:
                    raise SourceError('PT-KBC-LIMIT', 'the document has an over-long key')
                stack.append((sub, depth + 1))
        elif isinstance(item, list):
            if depth > limits.cvrf_depth:
                raise SourceError('PT-KBC-LIMIT', f'the document nests deeper than {limits.cvrf_depth} levels')
            stack.extend((sub, depth + 1) for sub in item)
        elif isinstance(item, str) and len(item) > MAX_STRING:
            raise SourceError('PT-KBC-LIMIT', 'the document has an over-long string')


def decode_utf8(raw: bytes, what: str = 'document') -> str:
    if raw.startswith(b'\xef\xbb\xbf'):
        raise SourceError('PT-KBC-SOURCE', f'the {what} starts with a byte order mark')
    try:
        return raw.decode('utf-8', errors='strict')
    except UnicodeDecodeError as exc:
        raise SourceError('PT-KBC-SOURCE', f'the {what} is not valid UTF-8 (byte {exc.start})') from None


def load_json(raw: bytes, limits: KbcLimits = DEFAULT_LIMITS):
    """Strict JSON for a source document. Raises SourceError (SOURCE or LIMIT); never returns partial data."""
    if type(raw) is not bytes:
        raise SourceError('PT-KBC-INPUT', 'a source document must be bytes')
    if len(raw) > limits.cvrf_doc_bytes:
        raise SourceError('PT-KBC-LIMIT', f'the document is {len(raw)} bytes; the limit is {limits.cvrf_doc_bytes}')
    text = decode_utf8(raw)
    try:
        value = _strict_loads(text)
    except _DuplicateKey as exc:
        raise SourceError('PT-KBC-SOURCE', f'the document has an ambiguous duplicate key {safe_label(exc.args[0])}'
                          ) from None
    except _BadNumber as exc:
        raise SourceError('PT-KBC-SOURCE', f'the document has an invalid number ({safe_label(str(exc), 40)})'
                          ) from None
    except RecursionError:
        raise SourceError('PT-KBC-LIMIT', 'the document nesting exceeds the parser limit') from None
    except ValueError as exc:
        raise SourceError('PT-KBC-SOURCE', f'the document is not valid JSON ({safe_label(str(exc), 80)})') from None
    _check_shape(value, limits)
    return value


# ---------------------------------------------------------------------------------------------- entry point

def sniff_guard(raw: bytes) -> None:
    """Refuse a byte order mark or a UTF-16/32 document before the format is sniffed."""
    if raw.startswith(b'\xef\xbb\xbf'):
        raise SourceError('PT-KBC-SOURCE', 'the document starts with a byte order mark')
    if raw[:2] in (b'\xff\xfe', b'\xfe\xff') or b'\x00' in raw[:8]:
        raise SourceError('PT-KBC-SOURCE', 'the document is not UTF-8 (UTF-16 and UTF-32 are refused)')


def parse_cvrf(raw: bytes, limits: KbcLimits = DEFAULT_LIMITS) -> CvrfDocument:
    """Parse one monthly document (JSON or XML by its first byte). Raises SourceError for an unknown dialect, a
    malformed or hostile file, or a size limit; row-level anomalies are returned as ``problems``."""
    if type(raw) is not bytes:
        raise SourceError('PT-KBC-INPUT', 'a source document must be bytes')
    sniff_guard(raw)
    head = raw.lstrip(b' \t\r\n')[:1]
    if head == b'{':
        return parse_json_document(load_json(raw, limits), limits)
    if head == b'<':
        return _parse_xml(raw, limits)
    raise SourceError('PT-KBC-SOURCE', 'CVRF dialect unknown: the document is neither a JSON object nor XML')


def _unknown_dialect(detail: str = '') -> SourceError:
    return SourceError('PT-KBC-SOURCE', 'CVRF dialect unknown: this parser reads ' + ' and '.join(DIALECTS)
                       + ' only; the real MSRC shape is unverified until live probe L1' + detail)


def _shape(what: str) -> SourceError:
    return SourceError('PT-KBC-SOURCE', f'CVRF dialect unknown or damaged: {what}')


# ---------------------------------------------------------------------------------------------- JSON dialect

def parse_json_document(value, limits: KbcLimits = DEFAULT_LIMITS) -> CvrfDocument:
    if not isinstance(value, dict):
        raise _unknown_dialect()
    if value.get('dialect') != DIALECT_JSON:
        looks_real = 'Vulnerability' in value or 'ProductTree' in value
        raise _unknown_dialect(' (it looks like an MSRC CVRF document)' if looks_real else '')
    document = value.get('document')
    if not isinstance(document, dict):
        raise _shape('/document is not an object')
    release = document.get('release_id')
    if not isinstance(release, str) or not _RELEASE_ID.fullmatch(release):
        raise _shape('/document/release_id is missing or not yyyy-Mmm')
    tree, vulns = value.get('product_tree'), value.get('vulnerabilities')
    if not isinstance(tree, list):
        raise _shape('/product_tree is not an array')
    if not isinstance(vulns, list):
        raise _shape('/vulnerabilities is not an array')
    problems: list[Problem] = []
    stamp = normal_timestamp(document.get('current_release_date'))
    if document.get('current_release_date') is not None and stamp is None:
        problems.append(Problem('DATE_INVALID', '/document/current_release_date', 'not a date'))
    tracking = document.get('tracking_id')
    products = _json_products(tree, problems)
    rows = [_json_vulnerability(i, item, problems, limits) for i, item in enumerate(vulns)]
    return _finish(DIALECT_JSON, tracking if isinstance(tracking, str) else None, release, stamp, products, rows,
                   problems)


def _json_products(tree: list, problems: list[Problem]) -> list[RawProduct]:
    seen: dict[str, int] = {}
    out = []
    for i, item in enumerate(tree):
        at = pointer('product_tree', i)
        pid = item.get('product_id') if isinstance(item, dict) else None
        name = item.get('name') if isinstance(item, dict) else None
        if not isinstance(pid, str) or not pid.strip() or len(pid) > 1000 or not isinstance(name, str):
            problems.append(Problem('PRODUCT_ID_INVALID', at, 'product needs a product_id and a name'))
            continue
        seen[pid] = seen.get(pid, 0) + 1
        family, arch = item.get('family'), item.get('architecture')
        out.append(RawProduct(pid, name, family if isinstance(family, str) else None,
                              arch if isinstance(arch, str) else None, at))
    dup = {p for p, n in seen.items() if n > 1}
    for product in out:
        if product.product_id in dup:
            problems.append(Problem('PRODUCT_DUPLICATE', product.pointer, 'product id defined more than once'))
    return [p for p in out if p.product_id not in dup]


def _string_list(value) -> list[str] | None:
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        return None
    return value


def _json_vulnerability(index: int, item, problems: list[Problem], limits: KbcLimits) -> RawVulnerability | None:
    at = pointer('vulnerabilities', index)
    if not isinstance(item, dict):
        problems.append(Problem('ROW_SHAPE', at, 'vulnerability is not an object'))
        return None
    cve = item.get('cve')
    if not isinstance(cve, str) or not is_cve(cve):
        problems.append(Problem('CVE_INVALID', at, f'not a CVE id: {safe_label(cve)}'))
        return None
    title = item.get('title')
    cwe = item.get('cwe')
    cwe_id = cwe.get('id') if isinstance(cwe, dict) else None
    rems = []
    for ri, rem in enumerate(item.get('remediations') or ()):
        rat = pointer('vulnerabilities', index, 'remediations', ri)
        parsed = _json_remediation(ri, rat, rem, problems, limits)
        if parsed is not None:
            rems.append(parsed)
    statuses = []
    raw_status = item.get('product_statuses') or {}
    if not isinstance(raw_status, dict):
        problems.append(Problem('STATUS_SHAPE', pointer('vulnerabilities', index, 'product_statuses'),
                                'product_statuses is not an object'))
        raw_status = {}
    for name, members in raw_status.items():
        sat = pointer('vulnerabilities', index, 'product_statuses', name)
        if len(name) > 200:
            problems.append(Problem('STATUS_SHAPE', pointer('vulnerabilities', index, 'product_statuses'),
                                    'a status name is longer than 200 characters'))
            continue
        pids = _string_list(members)
        if pids is None:
            problems.append(Problem('STATUS_SHAPE', sat, 'status members are not a list of product ids'))
            continue
        statuses.extend(RawStatus(clean_text(name), pid, sat + '/' + str(k)) for k, pid in enumerate(pids))
    return RawVulnerability(index, at, cve, clean_text(title) if isinstance(title, str) else None,
                            cwe_id if isinstance(cwe_id, str) and _CWE.fullmatch(cwe_id) else None,
                            tuple(rems), tuple(statuses))


def _json_remediation(ri: int, at: str, rem, problems: list[Problem], limits: KbcLimits) -> RawRemediation | None:
    if not isinstance(rem, dict):
        problems.append(Problem('ROW_SHAPE', at, 'remediation is not an object'))
        return None
    kind = rem.get('type')
    if type(kind) is not int:
        problems.append(Problem('TYPE_INVALID', at, 'remediation type is not an integer'))
        return None
    desc = rem.get('description', '')
    pids = _string_list(rem.get('product_ids', []))
    if not isinstance(desc, str) or pids is None:
        problems.append(Problem('ROW_SHAPE', at, 'description or product_ids has the wrong type'))
        return None
    supersedes = rem.get('supersedes', [])
    sup = _string_list(supersedes)
    if sup is None:
        problems.append(Problem('SUPERSEDES_UNPARSED', at, 'supersedes is not a list of KB ids'))
        sup = []
    sub = rem.get('sub_type')
    return RawRemediation(ri, at, kind, desc[:limits.text_field_bytes], tuple(pids), rem.get('fixed_build'),
                          tuple(sup), clean_text(sub) or None if isinstance(sub, str) else None)


# ---------------------------------------------------------------------------------------------- XML dialect

def _check_xml_text(raw: bytes) -> str:
    if raw[:4] in (b'\xff\xfe\x00\x00', b'\x00\x00\xfe\xff') or raw[:2] in (b'\xff\xfe', b'\xfe\xff') \
            or b'\x00' in raw[:8]:
        raise SourceError('PT-KBC-SOURCE', 'the XML document is not UTF-8 (UTF-16 and UTF-32 are refused)')
    text = decode_utf8(raw, 'XML document')
    declared = _XML_DECL_ENCODING.match(text.lstrip())
    if declared and declared.group(1).lower().replace('_', '-') not in ('utf-8', 'utf8'):
        raise SourceError('PT-KBC-SOURCE', 'the XML document declares an encoding other than UTF-8')
    if _MARKUP_DECL.search(text):
        raise SourceError('PT-KBC-SOURCE', 'the XML document contains a markup declaration (DOCTYPE or ENTITY); '
                          'entities are never expanded and the document is refused')
    return text


def _children(element) -> list:
    return [] if element is None else list(element)


def _local(tag: str) -> str:
    return tag.rsplit('}', 1)[-1]


def _xml_root(raw: bytes, limits: KbcLimits) -> ET.Element:
    if len(raw) > limits.cvrf_doc_bytes:
        raise SourceError('PT-KBC-LIMIT', f'the document is {len(raw)} bytes; the limit is {limits.cvrf_doc_bytes}')
    text = _check_xml_text(raw)
    parser = ET.XMLPullParser(events=('start', 'end'))
    nodes = depth = 0
    root = None
    try:
        for start in range(0, len(text), 65536):
            parser.feed(text[start:start + 65536].encode('utf-8'))
            for event, element in parser.read_events():
                if event == 'start':
                    nodes += 1
                    depth += 1
                    root = element if root is None else root
                    if nodes > limits.cvrf_json_nodes or depth > limits.cvrf_depth:
                        raise SourceError('PT-KBC-LIMIT', 'the XML document exceeds the node or depth limit')
                else:
                    depth -= 1
                    if any(len(v) > MAX_STRING for v in element.attrib.values()) \
                            or len(element.text or '') > MAX_STRING:
                        raise SourceError('PT-KBC-LIMIT', 'the XML document has an over-long value')
        parser.close()
    except ET.ParseError as exc:
        raise SourceError('PT-KBC-SOURCE', f'the document is not well-formed XML ({safe_label(str(exc), 80)})'
                          ) from None
    if root is None:
        raise SourceError('PT-KBC-SOURCE', 'the XML document is empty')
    return root


def _parse_xml(raw: bytes, limits: KbcLimits) -> CvrfDocument:
    root = _xml_root(raw, limits)
    if root.tag != f'{{{XML_NS}}}CvrfDoc':
        raise _unknown_dialect()
    release = root.get('ReleaseId')
    if not release or not _RELEASE_ID.fullmatch(release):
        raise _shape('the root ReleaseId is missing or not yyyy-Mmm')
    kids = {_local(c.tag): c for c in root if c.tag.startswith('{' + XML_NS + '}')}
    container = kids.get('Vulnerabilities')
    if container is None:
        raise _shape('the Vulnerabilities container is missing')
    problems: list[Problem] = []
    stamp = normal_timestamp(root.get('CurrentReleaseDate'))
    if root.get('CurrentReleaseDate') is not None and stamp is None:
        problems.append(Problem('DATE_INVALID', '/document/current_release_date', 'not a date'))
    tracking = kids.get('DocumentTracking')
    products = _xml_products(kids.get('ProductTree'), problems)
    rows = [_xml_vulnerability(i, el, problems, limits) for i, el in enumerate(container)]
    return _finish(DIALECT_XML, tracking.get('Identification') if tracking is not None else None, release, stamp,
                   products, rows, problems)


def _xml_products(tree, problems: list[Problem]) -> list[RawProduct]:
    found = []
    if tree is not None:
        for element in tree.iter():
            if _local(element.tag) == 'FullProductName':
                found.append(element)
    seen: dict[str, int] = {}
    out = []
    for i, el in enumerate(found):
        at = pointer('product_tree', i)
        pid = el.get('ProductID')
        if not pid or not pid.strip() or len(pid) > 1000:
            problems.append(Problem('PRODUCT_ID_INVALID', at, 'product needs a ProductID'))
            continue
        seen[pid] = seen.get(pid, 0) + 1
        out.append(RawProduct(pid, el.text or '', el.get('Family'), el.get('Architecture'), at))
    dup = {p for p, n in seen.items() if n > 1}
    for product in out:
        if product.product_id in dup:
            problems.append(Problem('PRODUCT_DUPLICATE', product.pointer, 'product id defined more than once'))
    return [p for p in out if p.product_id not in dup]


def _xml_vulnerability(index: int, el, problems: list[Problem], limits: KbcLimits) -> RawVulnerability | None:
    at = pointer('vulnerabilities', index)
    if _local(el.tag) != 'Vulnerability':
        problems.append(Problem('ROW_SHAPE', at, 'unexpected element in Vulnerabilities'))
        return None
    cve = el.get('CVE')
    if not cve or not is_cve(cve):
        problems.append(Problem('CVE_INVALID', at, f'not a CVE id: {safe_label(cve)}'))
        return None
    kids = {_local(c.tag): c for c in el}
    cwe = kids.get('CWE')
    cwe_id = cwe.get('ID') if cwe is not None else None
    rems = []
    for ri, rem in enumerate(_children(kids.get('Remediations'))):
        rat = pointer('vulnerabilities', index, 'remediations', ri)
        try:
            kind = int(rem.get('Type', ''))
        except ValueError:
            problems.append(Problem('TYPE_INVALID', rat, 'remediation type is not an integer'))
            continue
        desc = next((c.text or '' for c in rem if _local(c.tag) == 'Description'), '')
        pids = tuple(c.text or '' for c in rem if _local(c.tag) == 'ProductID')
        rems.append(RawRemediation(ri, rat, kind, desc[:limits.text_field_bytes], pids, rem.get('FixedBuild'),
                                   tuple((rem.get('Supersedes') or '').split()),
                                   clean_text(rem.get('SubType')) or None))
    statuses = []
    for status in _children(kids.get('ProductStatuses')):
        sat = pointer('vulnerabilities', index, 'product_statuses', status.get('Type', ''))
        for k, member in enumerate(c for c in status if _local(c.tag) == 'ProductID'):
            statuses.append(RawStatus(clean_text(status.get('Type', '')), member.text or '', f'{sat}/{k}'))
    return RawVulnerability(index, at, cve, clean_text(el.get('Title')) or None,
                            cwe_id if cwe_id and _CWE.fullmatch(cwe_id) else None, tuple(rems), tuple(statuses))


def _finish(dialect, tracking, release, stamp, products, rows, problems) -> CvrfDocument:
    rows = [r for r in rows if r is not None]
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.cve] = counts.get(row.cve, 0) + 1
    ambiguous = frozenset(c for c, n in counts.items() if n > 1)
    for row in rows:
        if row.cve in ambiguous:
            problems.append(Problem('CVE_DUPLICATE', row.pointer, f'{row.cve} occurs in several rows; no edges'))
    return CvrfDocument(dialect=dialect, tracking_id=tracking, release_id=release, current_release_date=stamp,
                        products=tuple(products), vulnerabilities=tuple(rows),
                        problems=tuple(sorted(set(problems), key=lambda p: (p.pointer, p.code, p.detail))),
                        ambiguous_cves=ambiguous)


# ---------------------------------------------------------------------------------------------- edges

def build_edges(document: CvrfDocument, doc_id: str, limits: KbcLimits = DEFAULT_LIMITS) -> DocumentEdges:
    """Scopes, edges, cards and status rows of a parsed document, in a canonical order."""
    problems = list(document.problems)
    scope_by_pid: dict[str, ProductScope] = {}
    for product in document.products:
        scope = scope_for(doc_id, product.product_id, product.name, family_hint=product.family_hint,
                          arch_hint=product.arch_hint)
        scope_by_pid[product.product_id] = scope
        if scope.mapping == 'conflicted':
            problems.append(Problem('PRODUCT_HINT_CONFLICT', product.pointer,
                                    'the product name and its family/architecture hint disagree'))
    edges: dict[str, KbCveEdge] = {}
    statuses: dict[tuple, StatusRow] = {}
    cards: list[CveCard] = []
    for vuln in document.vulnerabilities:
        if vuln.cve in document.ambiguous_cves:
            continue
        cards.append(CveCard(cve=vuln.cve, source_kind='cvrf', title=vuln.title or None, stated_cwe=vuln.cwe))
        by_pid: dict[str, list[RawStatus]] = {}
        for status in vuln.statuses:
            by_pid.setdefault(status.product_id, []).append(status)
            scope = scope_by_pid.get(status.product_id)
            if scope is None:
                problems.append(Problem('UNKNOWN_PRODUCT_ID', status.pointer, 'status names an undefined product id'))
                continue
            statuses[(vuln.cve, scope.scope_id, status.value, status.pointer)] = StatusRow(
                vuln.cve, scope.scope_id, status.value, status_class(status.value), status.pointer)
        for rem in vuln.remediations:
            _edges_for_remediation(document, doc_id, vuln, rem, scope_by_pid, by_pid, edges, problems)
            if len(edges) > limits.cvrf_edges_per_doc:
                raise SourceError('PT-KBC-LIMIT', f'the document yields more than {limits.cvrf_edges_per_doc} edges')
    ordered = tuple(sorted(edges.values(), key=edge_sort_key))
    return DocumentEdges(
        edges=ordered,
        scopes=tuple(sorted(scope_by_pid.values(), key=lambda s: s.scope_id)),
        cards=tuple(sorted(cards, key=lambda c: cve_sort_key(c.cve))),
        statuses=tuple(statuses[k] for k in sorted(statuses)),
        problems=tuple(sorted(set(problems), key=lambda p: (p.pointer, p.code, p.detail))),
        vulnerabilities=len(document.vulnerabilities))


def _edges_for_remediation(document, doc_id, vuln, rem, scope_by_pid, by_pid, edges, problems) -> None:
    kbs: list[str] = []
    mentions: list[str] = []
    if rem.type == REMEDIATION_VENDOR_FIX:
        for line in rem.description.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                kbs.append(normalise_kb_edge(line))
            except KbSyntaxError:
                problems.append(Problem('KB_UNPARSED', rem.pointer + '/description',
                                        'a Type 2 line is not a KB id; no remediation edge'))
                mentions.extend(find_kb_tokens(line))
    else:
        mentions.extend(find_kb_tokens(rem.description))
    if not kbs and not mentions:
        return
    build = parse_fixed_build(rem.fixed_build)
    if rem.fixed_build is not None and build is None:
        problems.append(Problem('FIXED_BUILD_UNPARSED', rem.pointer + '/fixed_build', 'not a build number'))
    supersedes = []
    for text in rem.supersedes:
        try:
            supersedes.append(normalise_kb_edge(text))
        except KbSyntaxError:
            problems.append(Problem('SUPERSEDES_UNPARSED', rem.pointer + '/supersedes', 'not a KB id'))
    for k, pid in enumerate(rem.product_ids):
        scope = scope_by_pid.get(pid)
        if scope is None:
            problems.append(Problem('UNKNOWN_PRODUCT_ID', f'{rem.pointer}/product_ids/{k}',
                                    'product id is not in the product tree; no edge'))
            continue
        statuses = sorted(by_pid.get(pid, ()), key=lambda s: (s.value, s.pointer))
        if vuln.statuses and not statuses:
            problems.append(Problem('PRODUCT_STATUS_MISSING', f'{rem.pointer}/product_ids/{k}',
                                    'the vulnerability lists statuses but none for this product', 'info'))
        negative = next((s for s in statuses if status_class(s.value) == 'not_affected'), None)
        shown = negative or (statuses[0] if statuses else None)
        status = ProductStatus(value=shown.value or 'unnamed', pointer=shown.pointer) if shown else None
        try:
            for kb in sorted(set(kbs)):
                relation = 'disputed' if negative is not None else 'vendor-remediation'
                edge = make_edge(kb=kb, cve=vuln.cve, scope_id=scope.scope_id, relation=relation, doc_id=doc_id,
                                 ptr=rem.pointer, assertion='advisory_fact', release_id=document.release_id,
                                 fixed_build=build, supersedes=tuple(supersedes), sub_type=rem.sub_type,
                                 product_status=status)
                edges[edge.edge_id] = edge
            for kb in sorted(set(mentions) - set(kbs)):
                edge = make_edge(kb=kb, cve=vuln.cve, scope_id=scope.scope_id, relation='mention-only',
                                 doc_id=doc_id, ptr=rem.pointer, assertion='advisory_fact',
                                 release_id=document.release_id)
                edges[edge.edge_id] = edge
        except ValidationError:
            problems.append(Problem('ROW_SHAPE', rem.pointer, 'a value exceeds its contract bounds; no edge'))
