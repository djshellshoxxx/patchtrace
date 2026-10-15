"""Groups `adv` (stored CSAF advisories) and `cve` (CVE snapshot descriptions) (WB1 section 7).

Both stores are read through ports (`AdvisoryStore.advisories()` has the `AdvisoryPort` shape), once, on the GUI
thread. Every revision stays indexed: a superseded advisory or an older snapshot is flagged in `extra`, never
dropped. Vendor and database text is an untrusted claim: tags are stripped, each document is capped at 64 KiB,
and the wording stays "advisory text" (no causation is implied). KB and CWE ids become their own documents.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import Any, Protocol

from patchtrace.search.segment import SegmentDoc
from patchtrace.search.sources.base import SourceSpec, skipped

ADV_KINDS = ('advisory', 'cwe', 'kb')
CVE_KINDS = ('cve', 'cwe')
TABLE_SETS = ('text',)
ADVISORY_VERSION = 1
MAX_TEXT_BYTES = 64 * 1024
EXTRA_CHARS = 200
NO_ADVISORIES = 'Advisories are not available for this project.'
NO_SNAPSHOTS = 'CVE records are not available for this project.'
_TAG = re.compile(r'<[^<>]{0,2000}>')
_KB = re.compile(r'\bKB[0-9]{6,8}\b', re.IGNORECASE)


class AdvisoryPort(Protocol):
    def advisories(self) -> tuple[Sequence[Any], Sequence[str]]:
        """Every stored advisory (`.source`, `.facts`, `.superseded`) and the warnings for unusable ones."""


class CveSnapshotPort(Protocol):
    def snapshots(self) -> Sequence[Any]:
        """Every stored `CveSnapshot` row."""


def plain(text: str) -> str:
    """Markup removed (never rendered or executed) and the text cut to 64 KiB on a character boundary."""
    stripped = _TAG.sub(' ', text)
    return stripped.encode('utf-8')[:MAX_TEXT_BYTES].decode('utf-8', 'ignore')


def _join(parts: Iterable[str | None]) -> str:
    return plain('\n'.join(part for part in parts if part))


def _extra(*parts: str) -> str:
    return '; '.join(part for part in parts if part)[:EXTRA_CHARS]


# ------------------------------------------------------------------------------------------------ advisories

def _vulnerability_text(vuln: Any) -> Iterable[str | None]:
    yield vuln.cve
    yield vuln.title
    for note in vuln.notes:
        yield note.title
        yield note.text
    for fix in vuln.remediations:
        yield fix.details
        yield fix.url
    if vuln.cwe:
        yield f'{vuln.cwe.id} {vuln.cwe.name}'


def _advisory_text(facts: Any) -> str:
    parts: list[str | None] = [facts.title]
    for note in facts.document_notes:
        parts += [note.title, note.text]
    for vuln in facts.vulnerabilities:
        parts.extend(_vulnerability_text(vuln))
    parts.extend(product.name for product in facts.products)
    return _join(parts)


def _kb_ids(text: str) -> set[str]:
    return {match.upper() for match in _KB.findall(text)}


def _advisory_rows(advisories: Sequence[Any]) -> list[tuple]:
    rows = []
    for item in advisories:
        facts = item.facts
        cves = ' '.join(facts.cves())
        rows.append((facts.facts_id, facts.tracking_id, facts.revision, bool(item.superseded), cves,
                     item.source.retrieved_at, plain(facts.title), _advisory_text(facts),
                     tuple(sorted((v.cwe.id, v.cwe.name) for v in facts.vulnerabilities if v.cwe))))
    return sorted(rows)


def _advisory_docs(rows: list[tuple]) -> Iterable[SegmentDoc]:
    ref = 0
    cwes: dict[str, str] = {}
    kbs: dict[str, str] = {}
    for _, tracking, revision, superseded, cves, retrieved, title, text, refs in rows:
        extra = _extra('superseded' if superseded else '', f'{tracking} r{revision}', cves, f'retrieved {retrieved}')
        yield SegmentDoc('advisory', None, tracking[:64], title, ref, extra=extra, text_title=title, text_body=text)
        ref += 1
        cwes.update({ident: name for ident, name in refs})
        for kb in _kb_ids(text):
            kbs.setdefault(kb, f'{tracking} r{revision}')
    for ident, name in sorted(cwes.items()):
        yield SegmentDoc('cwe', None, ident, f'{ident} {name}'[:200], ref, extra='named by an advisory',
                         text_title=ident, text_body=plain(name))
        ref += 1
    for kb, where in sorted(kbs.items()):
        yield SegmentDoc('kb', None, kb, kb, ref, extra=_extra('named by', where), text_title=kb, text_body=where)
        ref += 1


def _advisory_spec(port: AdvisoryPort) -> SourceSpec:
    advisories, warnings = port.advisories()
    rows = _advisory_rows(advisories)
    reason = f'{len(warnings)} advisory file(s) could not be used and were skipped.' if warnings else ''
    inputs = {'facts': [(row[0], row[3], row[5]) for row in rows], 'version': ADVISORY_VERSION}
    return SourceSpec('adv', ADV_KINDS, TABLE_SETS, None, inputs, lambda: _advisory_docs(rows), reason=reason)


# ------------------------------------------------------------------------------------------------ snapshots

def _snapshot_rows(snapshots: Sequence[Any]) -> list[tuple]:
    newest: dict[str, tuple[str, str]] = {}
    for snap in snapshots:
        newest[snap.cve_id] = max(newest.get(snap.cve_id, ('', '')), (snap.retrieved_at, snap.snapshot_id))
    rows = []
    for snap in snapshots:
        descriptions = tuple(f'{d.source}: {d.text}' for d in snap.descriptions)
        listed = tuple(f'{v.source}: {v.value}' for v in (*snap.products, *snap.advisories))
        old = newest[snap.cve_id] != (snap.retrieved_at, snap.snapshot_id)
        rows.append((snap.snapshot_id, snap.cve_id, snap.retrieved_at, old, bool(snap.conflicts),
                     tuple(sorted(snap.response_digests)), descriptions, listed,
                     tuple(sorted({(c.value, c.source) for c in snap.cwes}))))
    return sorted(rows)


def _snapshot_docs(rows: list[tuple]) -> Iterable[SegmentDoc]:
    ref = 0
    cwes: dict[str, str] = {}
    for _, cve, retrieved, old, conflict, providers, descriptions, listed, refs in rows:
        extra = _extra('older snapshot' if old else '', 'sources conflict' if conflict else '', f'retrieved {retrieved}',
                       ' '.join(providers))
        shown = f'{cve} {descriptions[0].partition(": ")[2]}' if descriptions else cve
        yield SegmentDoc('cve', None, cve, shown[:200], ref, extra=extra, text_title=cve,
                         text_body=_join((*descriptions, *listed)))
        ref += 1
        for ident, source in refs:
            cwes.setdefault(ident, source)
    for ident, source in sorted(cwes.items()):
        yield SegmentDoc('cwe', None, ident[:64], ident, ref, extra=f'listed by {source}', text_title=ident)
        ref += 1


def _snapshot_spec(port: CveSnapshotPort) -> SourceSpec:
    rows = _snapshot_rows(port.snapshots())
    inputs = {'snapshots': [(row[0], row[2]) for row in rows], 'version': ADVISORY_VERSION}
    return SourceSpec('cve', CVE_KINDS, TABLE_SETS, None, inputs, lambda: _snapshot_docs(rows))


def advisory_specs(advisories: AdvisoryPort | None, snapshots: CveSnapshotPort | None) -> tuple[SourceSpec, ...]:
    """The `adv` and `cve` groups. Call on the GUI thread; a missing port reports its group `unavailable`."""
    return (skipped('adv', ADV_KINDS, None, 'unavailable', NO_ADVISORIES) if advisories is None
            else _advisory_spec(advisories),
            skipped('cve', CVE_KINDS, None, 'unavailable', NO_SNAPSHOTS) if snapshots is None
            else _snapshot_spec(snapshots))
