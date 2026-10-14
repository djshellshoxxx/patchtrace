"""Normalised CSAF facts -> KB association edges (KB-integration-plan 7.2 `vendor-association`; slice K1). Pure.

CSAF is CVE-first and the standard has no KB field. The bridge therefore consumes the JSON-compatible dump of
``intelligence`` ``AdvisoryFacts`` (``AdvisoryPort.parse_csaf``), which the ``intelligence`` package has already
validated against the CSAF 2.0 schema and mandatory tests; this module never parses raw CSAF and never imports a
sibling package.

Rules (S05, S12, S13, S14, NEG-08):

* a ``vendor_fix`` remediation yields a ``vendor-association`` edge for a KB only when its ``details`` carries an
  exact upper-case ``KB`` + 4-10 digit token, or its ``url`` is ``https://support.microsoft.com/[locale/]help/<digits>``.
  A ``vendor_fix`` with no KB yields no edge (S12, reported as an info problem). The relation is "association", never
  "remediation", until a live capture shows a structured KB field (probe L4);
* the products are ``product_ids`` plus the members of ``group_ids`` (expanded here from the document's groups; an
  unknown group id is a problem, and an edge is built per concrete product, never for the group);
* a product the same vulnerability lists as ``known_not_affected`` gets a ``disputed`` edge instead (NEG-08): no
  affected or fixed assertion is made for it;
* a KB token in any other remediation category is ``mention-only``;
* CVEs that occur in several vulnerability rows are ambiguous and yield no edge.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from ..contracts import CveCard, ProductScope, ProductStatus
from ..ids import cve_sort_key, find_kb_tokens, is_cve
from ..products import clean_text, safe_label, scope_for
from .cvrf import DocumentEdges, Problem, StatusRow, edge_sort_key, make_edge, normal_timestamp, status_class

BRIDGE_VERSION = 1
DIALECT = 'csaf/2.0'
_SUPPORT_URL = re.compile(r'^https://support\.microsoft\.com/(?:[a-z]{2}-[a-z]{2}/)?help/([0-9]{4,10})(?:[/?#].*)?$')
_CWE = re.compile(r'^CWE-[1-9][0-9]{0,5}$')


def facts_meta(facts: Mapping[str, Any]) -> dict[str, str | None]:
    """Header values of a facts dump: tracking id, revision and release timestamp (None when absent or malformed)."""
    return {'tracking_id': facts.get('tracking_id') if isinstance(facts.get('tracking_id'), str) else None,
            'revision': facts.get('revision') if isinstance(facts.get('revision'), str) else None,
            'current_release_date': normal_timestamp(facts.get('current_release_date'))}


def kb_tokens_of(remediation: Mapping[str, Any]) -> tuple[str, ...]:
    """Exact KB ids named by one remediation's ``details`` and ``url``; sorted by (digit count, digits)."""
    found = set(find_kb_tokens(str(remediation.get('details') or '')))
    match = _SUPPORT_URL.match(str(remediation.get('url') or ''))
    if match:
        found.add('KB' + match.group(1))
    return tuple(sorted(found, key=lambda kb: (len(kb), kb)))


def bridge_facts(facts: Mapping[str, Any], doc_id: str) -> DocumentEdges:
    """Scopes, edges, cards and status rows for one document's normalised facts."""
    problems: list[Problem] = []
    scope_by_pid: dict[str, ProductScope] = {}
    for product in facts.get('products') or ():
        pid, name = product.get('product_id'), product.get('name')
        if isinstance(pid, str) and isinstance(name, str):
            scope_by_pid[pid] = scope_for(doc_id, pid, name)
    groups = {g['group_id']: tuple(g.get('product_ids') or ()) for g in facts.get('groups') or ()
              if isinstance(g, Mapping) and isinstance(g.get('group_id'), str)}
    vulns = [v for v in facts.get('vulnerabilities') or () if isinstance(v, Mapping)]
    counts: dict[str, int] = {}
    for v in vulns:
        counts[str(v.get('cve'))] = counts.get(str(v.get('cve')), 0) + 1
    edges: dict[str, Any] = {}
    cards: list[CveCard] = []
    statuses: dict[tuple, StatusRow] = {}
    for position, vuln in enumerate(vulns):
        base = vuln.get('pointer') if isinstance(vuln.get('pointer'), str) else f'/vulnerabilities/{position}'
        cve = vuln.get('cve')
        if not isinstance(cve, str) or not is_cve(cve):
            problems.append(Problem('CVE_INVALID', base, f'not a CVE id: {safe_label(cve)}'))
            continue
        if counts[cve] > 1:
            problems.append(Problem('CVE_DUPLICATE', base, f'{cve} occurs in several rows; no edges'))
            continue
        cwe = vuln.get('cwe') if isinstance(vuln.get('cwe'), Mapping) else {}
        cwe_id = cwe.get('id')
        title = clean_text(vuln.get('title')) or None
        cards.append(CveCard(cve=cve, source_kind='csaf', title=title,
                             stated_cwe=cwe_id if isinstance(cwe_id, str) and _CWE.fullmatch(cwe_id) else None))
        by_pid: dict[str, list[Mapping[str, Any]]] = {}
        for claim in vuln.get('product_status') or ():
            pid = claim.get('product_id')
            scope = scope_by_pid.get(pid)
            if scope is None:
                problems.append(Problem('UNKNOWN_PRODUCT_ID', str(claim.get('pointer') or base),
                                        'status names a product that is not in the product tree'))
                continue
            by_pid.setdefault(pid, []).append(claim)
            value = str(claim.get('status') or '')
            statuses[(cve, scope.scope_id, value, str(claim.get('pointer')))] = StatusRow(
                cve, scope.scope_id, value, status_class(value), str(claim.get('pointer')))
        for remediation in vuln.get('remediations') or ():
            _remediation_edges(remediation, cve, doc_id, scope_by_pid, groups, by_pid, edges, problems)
    return DocumentEdges(
        edges=tuple(sorted(edges.values(), key=edge_sort_key)),
        scopes=tuple(sorted(scope_by_pid.values(), key=lambda s: s.scope_id)),
        cards=tuple(sorted(cards, key=lambda c: cve_sort_key(c.cve))),
        statuses=tuple(statuses[k] for k in sorted(statuses)),
        problems=tuple(sorted(set(problems), key=lambda p: (p.pointer, p.code, p.detail))),
        vulnerabilities=len(vulns))


def _remediation_edges(rem: Mapping[str, Any], cve: str, doc_id: str, scope_by_pid, groups, by_pid, edges,
                       problems: list[Problem]) -> None:
    at = str(rem.get('pointer') or '')
    category = rem.get('category')
    tokens = kb_tokens_of(rem)
    if not tokens:
        if category == 'vendor_fix':
            problems.append(Problem('VENDOR_FIX_NO_KB', at, 'vendor_fix names no KB; no KB association', 'info'))
        return
    pids = set(rem.get('product_ids') or ())
    for gid in rem.get('group_ids') or ():
        if gid not in groups:
            problems.append(Problem('UNKNOWN_GROUP', at, f'group id is not defined: {safe_label(gid)}'))
        else:
            pids.update(groups[gid])
    if not pids:
        problems.append(Problem('NO_PRODUCTS', at, 'the remediation resolves to no product; no edge', 'info'))
        return
    for pid in sorted(pids):
        scope = scope_by_pid.get(pid)
        if scope is None:
            problems.append(Problem('UNKNOWN_PRODUCT_ID', at, f'product id is not in the product tree: '
                                    f'{safe_label(pid)}'))
            continue
        claims = sorted(by_pid.get(pid, ()), key=lambda c: (str(c.get('status')), str(c.get('pointer'))))
        negative = next((c for c in claims if status_class(str(c.get('status'))) == 'not_affected'), None)
        shown = negative or (claims[0] if claims else None)
        status = ProductStatus(value=str(shown.get('status')), pointer=str(shown.get('pointer'))) if shown else None
        if category == 'vendor_fix':
            relation = 'disputed' if negative is not None else 'vendor-association'
        else:
            relation = 'mention-only'
        for kb in tokens:
            try:
                edge = make_edge(kb=kb, cve=cve, scope_id=scope.scope_id, relation=relation, doc_id=doc_id, ptr=at,
                                 assertion='advisory_fact',
                                 product_status=status if relation != 'mention-only' else None)
            except ValidationError:
                problems.append(Problem('ROW_SHAPE', at, 'a value exceeds its contract bounds; no edge'))
                continue
            edges[edge.edge_id] = edge
