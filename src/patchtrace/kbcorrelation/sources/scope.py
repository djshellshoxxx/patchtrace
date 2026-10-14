"""Search scope and coverage arithmetic (KB-integration-plan 7.1 rows 4-5, 7.2 `SearchScope`/`Coverage`; slice K1). Pure.

A scope is always explicit and finite. Coverage says what was actually inspected, on two axes:

1. the *document id* axis: which monthly documents (``yyyy-Mmm``) or files were requested and inspected;
2. the *revision* axis: ``watermark_current_release_date``, the newest ``currentReleaseDate`` among the inspected
   documents. A CVE revised after its release stays in its ORIGINAL monthly document, so a KB shipped later for an
   older CVE can sit in a document that a month window did not select (RK1 section 3): ``docs_revised_since`` lists
   those documents, and the coverage text always carries ``REVISION_LAG_NOTE``.

Coverage never claims history: ``exhaustive_for_history`` is the constant False, and an empty result under partial
coverage is never worded "no CVEs for this KB".
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from ..contracts import Coverage, Failure, SearchScope, domain_id
from ..limits import MAX_SEARCH_MONTHS
from .cvrf import SourceError

MONTHS = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')
REVISION_LAG_NOTE = 'revised CVEs may sit in earlier documents'
STALE_AFTER_DAYS = 45  # a cached corpus older than this reads `stale_cache` (a user-visible policy, not credibility)

_RELEASE = re.compile(r'^([0-9]{4})-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$')
_NUMERIC = re.compile(r'^([0-9]{4})-(0[1-9]|1[0-2])$')
_HEX64 = re.compile(r'^[0-9a-f]{64}$')


def _scope_error(message: str) -> SourceError:
    return SourceError('PT-KBC-SCOPE', message)


def release_id_for(year: int, month: int) -> str:
    return f'{year:04d}-{MONTHS[month - 1]}'


def parse_release(text: str) -> tuple[int, int]:
    """``2099-Feb`` or ``2099-02`` -> (2099, 2). Anything else raises PT-KBC-SCOPE."""
    value = text.strip()
    match = _RELEASE.fullmatch(value)
    if match:
        return int(match.group(1)), MONTHS.index(match.group(2)) + 1
    match = _NUMERIC.fullmatch(value)
    if match:
        return int(match.group(1)), int(match.group(2))
    raise _scope_error('a month is written yyyy-MM or yyyy-Mmm')


def normal_release(text: str) -> str:
    return release_id_for(*parse_release(text))


def release_ordinal(release_id: str) -> int:
    year, month = parse_release(release_id)
    return year * 12 + month - 1


def month_range(start: str, end: str) -> tuple[str, ...]:
    """Inclusive, ascending list of release ids from ``start`` to ``end``."""
    first, last = release_ordinal(start), release_ordinal(end)
    if last < first:
        raise _scope_error('the range ends before it starts')
    return tuple(release_id_for(n // 12, n % 12 + 1) for n in range(first, last + 1))


def parse_months(text: str) -> tuple[str, ...]:
    """Comma-separated months -> sorted unique release ids; at most 24 (one plan, plan 7.1 row 4)."""
    items = [part for part in (p.strip() for p in text.split(',')) if part]
    if not items:
        raise _scope_error('no month given')
    months = tuple(sorted({normal_release(i) for i in items}, key=release_ordinal))
    if len(months) > MAX_SEARCH_MONTHS:
        raise _scope_error(f'at most {MAX_SEARCH_MONTHS} months per scope; repeat for more')
    return months


def corpus_digest(doc_ids: Iterable[str]) -> str:
    return domain_id('kbc.corpus', 1, sorted(set(doc_ids)))


def months_scope(months: Sequence[str]) -> SearchScope:
    ids = tuple(sorted({normal_release(m) for m in months}))  # the K0 contract sorts month strings alphabetically
    if len(ids) > MAX_SEARCH_MONTHS:
        raise _scope_error(f'at most {MAX_SEARCH_MONTHS} months per scope; repeat for more')
    return SearchScope(kind='selected_months', months=ids)


def files_scope(doc_ids: Iterable[str]) -> SearchScope:
    return SearchScope(kind='provided_files', doc_ids=tuple(sorted(set(doc_ids))))


def corpus_scope(doc_ids: Iterable[str]) -> SearchScope:
    ids = tuple(sorted(set(doc_ids)))
    return SearchScope(kind='cached_corpus', doc_ids=ids, corpus_digest=corpus_digest(ids))


def parse_scope_file(text: str) -> SearchScope:
    """A scope file lists one id per line: a month (``2099-Feb`` or ``2099-02``) or a 64-hex document id.
    ``#`` starts a comment. Months only -> selected_months; document ids only -> provided_files; both -> mixed.
    Naming a document that is not loaded is allowed: coverage then reads partial."""
    months: set[str] = set()
    docs: set[str] = set()
    lines: list[str] = []
    for line in text.splitlines():
        entry = line.split('#', 1)[0].strip()
        if not entry:
            continue
        lines.append(entry)
        if _HEX64.fullmatch(entry):
            docs.add(entry)
        else:
            months.add(normal_release(entry))
    if not months and not docs:
        raise _scope_error('the scope file names no month or document')
    if len(months) > MAX_SEARCH_MONTHS:
        raise _scope_error(f'at most {MAX_SEARCH_MONTHS} months per scope; repeat for more')
    ordered = tuple(sorted(months))  # K0 contract order (alphabetical); use release_ordinal for chronology
    if months and docs:
        return SearchScope(kind='mixed', months=ordered, doc_ids=tuple(sorted(docs)),
                           corpus_digest=corpus_digest(sorted(months | docs)))
    if months:
        return SearchScope(kind='selected_months', months=ordered)
    return SearchScope(kind='provided_files', doc_ids=tuple(sorted(docs)))


def build_coverage(*, source_kind: str, scope: SearchScope, requested: Iterable[str], inspected: Iterable[str],
                   failed: Iterable[tuple[str, str]] = (), unfetchable: Iterable[str] = (),
                   watermark: str | None = None, retrieved_at: str, scope_known: bool = True,
                   stale: bool = False) -> Coverage:
    """The five-state ``Coverage`` for what was asked and what was checked.

    * nothing requested -> ``not_searched``; nothing inspected -> ``not_searched``;
    * ``scope_known=False`` -> ``unknown_scope`` (the extent of the corpus cannot be stated);
    * requested == inspected, nothing failed or unfetchable -> ``complete_in_scope``, or ``stale_cache`` when the
      caller marks the cached corpus ``stale``;
    * everything else -> ``partial_in_scope``.
    """
    req = tuple(sorted(set(requested)))
    failures = dict(failed)
    insp = tuple(sorted((set(inspected) - set(failures)) & set(req)))
    fails = tuple(Failure(id=i, reason=r) for i, r in sorted(failures.items()) if i in set(req))
    unf = tuple(sorted(set(unfetchable) & set(req)))
    complete = bool(req) and set(req) == set(insp) and not fails and not unf
    if not scope_known:
        state = 'unknown_scope'
    elif not req or not insp:
        state = 'not_searched'
    elif complete:
        state = 'stale_cache' if stale else 'complete_in_scope'
    else:
        state = 'partial_in_scope'
    key = {'source_kind': source_kind, 'scope': scope.model_dump(mode='json'), 'requested': req, 'inspected': insp,
           'failed': [(f.id, f.reason) for f in fails], 'unfetchable': unf, 'watermark': watermark, 'state': state}
    return Coverage(coverage_id=domain_id('kbc.coverage', 1, key), source_kind=source_kind, scope=scope, state=state,
                    requested_ids=req, inspected_ids=insp, failed=fails, unfetchable_ids=unf,
                    watermark_current_release_date=watermark, retrieved_at=retrieved_at)


def _chrono(identifier: str) -> tuple:
    try:
        return (0, release_ordinal(identifier), identifier)
    except SourceError:
        return (1, 0, identifier)


def coverage_text(coverage: Coverage) -> str:
    """The one-line coverage statement shared by CLI and GUI. Never "no CVEs for this KB"."""
    inspected = tuple(sorted(coverage.inspected_ids, key=_chrono))
    span = f' ({inspected[0]} to {inspected[-1]})' if len(inspected) > 1 else (f' ({inspected[0]})' if inspected else '')
    state = coverage.state
    if state == 'not_searched':
        head = 'Nothing was searched: no document is loaded for this scope'
    elif state == 'unknown_scope':
        head = f'Checked {len(inspected)} documents{span}; the extent of the corpus is not known'
    else:
        head = f'Checked {len(inspected)} of {len(coverage.requested_ids)} documents{span}'
        left = len(coverage.requested_ids) - len(inspected)
        if left:
            head += f'; {left} requested document{"s" if left != 1 else ""} not loaded'
    unreadable = len(coverage.failed)
    if unreadable:
        head += f'; {unreadable} unreadable'
    if coverage.unfetchable_ids:
        head += f'; {len(coverage.unfetchable_ids)} unfetchable'
    tail = 'nothing else was checked'
    if coverage.watermark_current_release_date:
        tail += f'; newest revision seen {coverage.watermark_current_release_date[:10]}'
    if state == 'stale_cache':
        tail += '; the cache is older than the staleness policy'
    return f'{head}; {tail}. {REVISION_LAG_NOTE[0].upper()}{REVISION_LAG_NOTE[1:]}.'


def docs_revised_since(documents: Iterable, since: str) -> tuple:
    """Second axis: documents (anything with ``release_id`` and ``current_release_date``) whose release month is
    BEFORE ``since`` (``yyyy-Mmm``) but whose current release date is on or after the first day of that month, i.e.
    documents a month window starting at ``since`` would miss although they were revised inside it."""
    first = release_ordinal(since)
    year, month = first // 12, first % 12 + 1
    start = f'{year:04d}-{month:02d}-01'
    out = []
    for doc in documents:
        if doc.release_id is None or doc.current_release_date is None:
            continue
        if release_ordinal(doc.release_id) < first and doc.current_release_date[:10] >= start:
            out.append(doc)
    return tuple(sorted(out, key=lambda d: (release_ordinal(d.release_id), d.doc_id)))
