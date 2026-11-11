"""Exact JSON field references for accepted cards, independent of remediation rows.

Locators are checked against already accepted card values; this module does not accept documents or invent
facts. XML has no JSON field locators. Stored workspace objects are reparsed, so these references need no DB
migration. ContextBundle persists the same records beside the displayed cards.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Literal, Protocol

from .contracts import CveCard, CveId, Pointer, Record, Sha256, Short, SourceDoc
from .products import clean_text

FIELDS = ('cve', 'title', 'stated_cwe', 'severity_context')


class CardFactRef(Record):
    cve: CveId
    source_kind: Literal['cvrf', 'csaf']
    field: Literal['cve', 'title', 'stated_cwe', 'severity_context']
    doc_id: Sha256
    source_sha256: Sha256
    pointer: Pointer
    value: Short


def fact_key(ref: CardFactRef) -> tuple:
    return ref.cve, ref.source_kind, ref.field, ref.doc_id, ref.pointer, ref.value


def locate_cards(value: dict, source: SourceDoc, cards: Iterable[CveCard]) -> tuple[CardFactRef, ...]:
    """Bind only unique, accepted CVE rows and values that match their real JSON fields."""
    native = source.dialect == 'msrc-cvrf-json/1'
    key, cve_key = ('Vulnerability', 'CVE') if native else ('vulnerabilities', 'cve')
    rows = value.get(key)
    if not isinstance(rows, list):
        return ()
    positions: dict[str, list[tuple[int, dict]]] = {}
    for i, row in enumerate(rows):
        if isinstance(row, dict) and isinstance(row.get(cve_key), str):
            positions.setdefault(row[cve_key], []).append((i, row))
    refs = []
    for card in cards:
        found = positions.get(card.cve, [])
        if len(found) != 1:
            continue
        i, row = found[0]
        base = f'/{key}/{i}'
        values = [('cve', base + '/' + cve_key, row[cve_key])]
        if native:
            title = row.get('Title')
            if isinstance(title, dict):
                values.append(('title', base + '/Title/Value', title.get('Value')))
            cwes = row.get('CWE')
            if isinstance(cwes, list):
                values += [('stated_cwe', f'{base}/CWE/{n}/ID', cwe.get('ID'))
                           for n, cwe in enumerate(cwes) if isinstance(cwe, dict)]
        else:
            values.append(('title', base + '/title', row.get('title')))
            cwe = row.get('cwe')
            if isinstance(cwe, dict):
                values.append(('stated_cwe', base + '/cwe/id', cwe.get('id')))
        for field, pointer, raw in values:
            accepted = getattr(card, field)
            normalized = clean_text(raw) if field == 'title' else raw
            if accepted is not None and isinstance(raw, str) and accepted == normalized:
                refs.append(CardFactRef(cve=card.cve, source_kind=card.source_kind, field=field,
                                       doc_id=source.doc_id, source_sha256=source.sha256,
                                       pointer=pointer, value=accepted))
    return tuple(sorted(set(refs), key=fact_key))


class CardDocument(Protocol):
    source: SourceDoc
    cards: tuple[CveCard, ...]
    card_facts: tuple[CardFactRef, ...]


def bind_consensus(card: CveCard, documents: Iterable[CardDocument]
                   ) -> tuple[CveCard | None, tuple[CardFactRef, ...], tuple[str, ...]]:
    """Require matching locators in every contributing document; never fill gaps using another source."""
    contributors = [doc for doc in documents if any(c.cve == card.cve and c.source_kind == card.source_kind
                                                   for c in doc.cards)]
    refs, missing, withheld = [], [], {}
    for field in FIELDS:
        value = getattr(card, field)
        if value is None:
            continue
        matches = [[ref for ref in doc.card_facts
                    if ref.cve == card.cve and ref.source_kind == card.source_kind and ref.field == field
                    and ref.value == value and ref.doc_id == doc.source.doc_id
                    and ref.source_sha256 == doc.source.sha256] for doc in contributors]
        if not matches or not all(matches):
            missing.append(field)
            withheld[field] = None
        else:
            refs.extend(ref for group in matches for ref in group)
    if 'cve' in missing:
        return None, (), tuple(missing)
    return card.model_copy(update=withheld), tuple(sorted(set(refs), key=fact_key)), tuple(missing)
