"""Search rows for WB1's index from a strings delta (spec WB3 s7 `SearchRow`, A14). Pure: no Qt, no I/O.

The default index holds the changed strings and the moved ones that have a function link; the inventory of all
strings is not indexed, and every row says so in its coverage line. A secret-like string is indexed by kind and
hash only, never by its text.
"""
from __future__ import annotations

from .contracts import SearchRow, Side, StringChange, StringsDelta

STATUS_WORDS = {'only-older': 'Only in older', 'only-newer': 'Only in newer', 'edited': 'Edited',
                'both': 'Moved', 'representation-changed': 'Encoding changed', 'not-compared': 'Not compared',
                'indeterminate': 'Not established'}


def _side(change: StringChange) -> Side:
    return 'older' if change.status == 'only-older' else 'newer'


def _text(change: StringChange) -> str:
    if 'secret-like' in change.cues:
        return f'[redacted secret-like {change.value_sha256[:12]}]'
    return change.display


def _functions(change: StringChange) -> tuple[str, ...]:
    ids = (link.function.project_function_id or link.function.match_id for link in change.links)
    return tuple(dict.fromkeys(i for i in ids if i))


def _row(change: StringChange, coverage: str) -> SearchRow:
    seen = change.older if change.status == 'only-older' else change.newer
    return SearchRow(
        doc_key=f'strings:{change.id}', text=_text(change),
        title=f'{STATUS_WORDS[change.status]} string, review tier R{change.review_tier}', side=_side(change),
        status=change.status, function_ids=_functions(change)[:16], offsets=seen.offsets if seen else (),
        coverage=coverage, flags=(*change.cues, f'tier-R{change.review_tier}'))


def search_rows(delta: StringsDelta) -> tuple[SearchRow, ...]:
    """Rows of a comparable delta; a delta that is not comparable indexes nothing."""
    if not delta.comparable:
        return ()
    coverage = (f'Changed and linked strings only ({len(delta.changes)} rows'
                + (', list truncated' if delta.truncated else '') + '); the inventory is not indexed.')
    return tuple(_row(change, coverage) for change in delta.changes if change.status != 'not-compared')
