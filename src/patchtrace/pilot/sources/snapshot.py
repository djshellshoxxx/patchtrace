"""B3 provider snapshots and CVE-record excerpts as K `CVEFact` records (PIL-integration-plan.md s9 PIL-A2; PIL-D1 reads
its advisory fixtures through the same path).

A CVE can be known without a CSAF document: from NVD and MSRC data (a B3 `CveSnapshot`) or from a short excerpt that
holds a CVE id, a CWE and one description. Both become the `CVEFact` that K reads from a CSAF document, so K's lexicon
and rules classify them exactly like an advisory. What the data does not hold is not invented: a record has no product
status, so nothing ties it to the two builds (the gate stays a gap, see `advisory.context_from_fact`).

CWE rule: a CWE is promoted to the explicit field only when the record names exactly one. Several ids (providers that
disagree, or one provider naming two) stay claims in a note, each as a CWE id written in the text, so no provider's
value is chosen over another's.

An excerpt is a JSON object with the keys `cve` (CVE id), `description` (1 to 20,000 characters), and optionally `cwe`
(one `CWE-n`, a list of at most 16, or null) and `title` (1 to 1,000 characters). Unknown keys are refused. Fixtures
stay short excerpts because the licences of full CVE-record and NVD data are unverified.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence

from ...enrichment.contracts import CveSnapshot
from ...enrichment.identity import canonical_json
from ...intelligence.contracts import CVEFact, CweRef, Note
from ...intelligence.lexicon import CWE_NAMES
from ..contracts import MAX_CWE_IDS, clean_line
from ..limits import PilotError

_CVE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,19}')  # the shape of contracts.CveId (ASCII digits only)
_MAX_CVE = 24
_CWE = re.compile(r'CWE-[1-9][0-9]{0,5}')
MAX_DESCRIPTION = 20_000  # B3's cap for one provider text
MAX_TITLE = 1000
EXCERPT_KEYS = frozenset({'cve', 'cwe', 'description', 'title'})
CWE_NOTE_TITLE = 'CWE ids stated by the record'


def _refused(message: str, reason: str) -> PilotError:
    return PilotError('PT-PILOT-INPUT', message, reason=reason)


def _is_cve(value: object) -> bool:
    return isinstance(value, str) and len(value) <= _MAX_CVE and _CVE.fullmatch(value) is not None


def _cwe_ref(cwe_id: str, pointer: str) -> CweRef:
    return CweRef(id=cwe_id, name=CWE_NAMES.get(cwe_id, cwe_id), pointer=pointer)


def _stated(snapshot: CveSnapshot) -> list[tuple[int, str, str]]:
    """(index, provider, CWE id) for every provider value that is a CWE id; other values carry no class."""
    return [(index, clean_line(item.source, 32), item.value) for index, item in enumerate(snapshot.cwes)
            if _CWE.fullmatch(item.value)]


def _by_provider(stated: Sequence[tuple[int, str, str]]) -> str:
    providers: dict[str, list[str]] = {}
    for _, provider, cwe in stated:
        providers.setdefault(provider, [])
        if cwe not in providers[provider]:
            providers[provider].append(cwe)
    return '; '.join(f'{provider}: {", ".join(sorted(ids))}' for provider, ids in sorted(providers.items()))


def fact_from_snapshot(snapshot: CveSnapshot) -> CVEFact:
    """The record of a B3 snapshot: its English descriptions as notes (pointers into the snapshot) and its CWE."""
    stated = _stated(snapshot)
    ids = sorted({cwe for _, _, cwe in stated})
    notes = [Note(category='description', title=clean_line(item.source, 32), text=item.text,
                  pointer=f'/descriptions/{index}')
             for index, item in enumerate(snapshot.descriptions) if item.lang.lower().split('-')[0] == 'en']
    cwe = None
    if len(ids) == 1:
        cwe = _cwe_ref(ids[0], f'/cwes/{next(index for index, _, value in stated if value == ids[0])}')
    elif ids:
        notes.append(Note(category='general', title=CWE_NOTE_TITLE, text=_by_provider(stated), pointer='/cwes'))
    try:
        return CVEFact(source_id=snapshot.snapshot_id, cve=snapshot.cve_id, pointer='', cwe=cwe, notes=tuple(notes))
    except ValueError:  # pydantic's ValidationError, for example a CVE id with non-ASCII digits
        raise _refused('The snapshot is not a usable CVE record', 'snapshot-record') from None


def snapshot_limitations(snapshot: CveSnapshot) -> tuple[str, ...]:
    """Plain-text limitations of the snapshot as a source: providers that state different CWEs, and values that
    were not CWE ids."""
    stated = _stated(snapshot)
    lines: list[str] = []
    if len({cwe for _, _, cwe in stated}) > 1 and any(c.startswith('cwe:') for c in snapshot.conflicts):
        lines.append(f'The providers state different CWEs ({_by_provider(stated)}); '
                     'both are kept and neither is resolved.')
    ignored = len(snapshot.cwes) - len(stated)
    if ignored:
        lines.append(f'{ignored} CWE value(s) in the record are not CWE ids and were ignored.')
    return tuple(clean_line(line) for line in lines)


def _text(value: object, what: str, limit: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= limit:
        raise _refused(f'The CVE excerpt {what} is text of 1 to {limit} characters', f'excerpt-{what}')
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        raise _refused(f'The CVE excerpt {what} must be UTF-8 text', f'excerpt-{what}') from None
    return value


def _excerpt_cwes(value: object) -> list[str]:
    if value is None:
        return []
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, (list, tuple)) or len(items) > MAX_CWE_IDS or not all(
            isinstance(i, str) and _CWE.fullmatch(i) for i in items):
        raise _refused('The CVE excerpt cwe is one CWE id or a short list of them', 'excerpt-cwe')
    return sorted(set(items))


def fact_from_excerpt(excerpt: Mapping[str, object]) -> CVEFact:
    """The record of a CVE excerpt (see the module docstring); malformed input is refused with `PT-PILOT-INPUT`."""
    if not isinstance(excerpt, Mapping):
        raise _refused('The CVE excerpt is a JSON object', 'excerpt-shape')
    if not set(excerpt) <= EXCERPT_KEYS:
        raise _refused('The CVE excerpt has a key outside cve, cwe, description and title', 'excerpt-keys')
    cve = excerpt.get('cve')
    if not _is_cve(cve):
        raise _refused('The CVE excerpt needs a CVE id', 'excerpt-cve')
    description = _text(excerpt.get('description'), 'description', MAX_DESCRIPTION)
    title = None if excerpt.get('title') is None else _text(excerpt['title'], 'title', MAX_TITLE)
    ids = _excerpt_cwes(excerpt.get('cwe'))
    notes = [Note(category='description', text=description, pointer='/description')]
    cwe = None
    if len(ids) == 1:
        cwe = _cwe_ref(ids[0], '/cwe' if isinstance(excerpt['cwe'], str) else '/cwe/0')
    elif ids:
        notes.append(Note(category='general', title=CWE_NOTE_TITLE, text=', '.join(ids), pointer='/cwe'))
    source_id = hashlib.sha256(canonical_json({'cve': cve, 'cwe': ids, 'description': description,
                                               'title': title})).hexdigest()
    return CVEFact(source_id=source_id, cve=cve, pointer='', title=title, cwe=cwe, notes=tuple(notes))
