"""Pair expansion and locator checks, resolved live from the open project (WB1 section 7), never from an index.

A segment only says "a document with this subject matched"; the pairing, its category, the counterparts, the
attention rank and the validity of a jump target always come from the project as it is now, so a manual
correction or a re-import needs no re-index and a stale cache cannot send the analyst to the wrong place.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from patchtrace.models import ComparisonProject, FunctionMatch, FunctionRecord
from patchtrace.search.contracts import Attention, FunctionRef, Locator, PairExpansion
from patchtrace.search.errors import SearchError
from patchtrace.search.sources.base import selected_run

_ID = re.compile(r'^[A-Za-z0-9._:-]{1,64}$')
ATTENTION_UNAVAILABLE = 'attention/1 rank unavailable: run Rank changes'
STALE_LOCATOR = 'the result no longer matches the project; search again'


@dataclass(frozen=True, slots=True)
class PairIndex:
    """Function id -> (pairing, record, side) for one run of the live project."""
    run_id: str | None
    matches: dict[str, FunctionMatch]
    functions: dict[str, tuple[FunctionMatch, FunctionRecord, str]]
    by_name: dict[tuple[str, str], FunctionMatch]  # (side, name) of names that belong to exactly one pairing

    @classmethod
    def build(cls, project: ComparisonProject, run_id: str | None) -> PairIndex:
        run = selected_run(project, run_id)
        if run is None:
            return cls(None, {}, {}, {})
        matches = {m.id: m for m in project.matches if m.run_id == run.id}
        functions = {f.id[:64]: (m, f, side) for m in matches.values()
                     for side, records in (('older', m.older), ('newer', m.newer)) for f in records}
        owners: dict[tuple[str, str], set[str]] = {}
        for (match, record, side) in functions.values():
            owners.setdefault((side, record.name), set()).add(match.id)
        by_name = {key: matches[next(iter(ids))] for key, ids in owners.items() if len(ids) == 1}
        return cls(run.id, matches, functions, by_name)

    def match_of(self, subject: str) -> FunctionMatch | None:
        found = self.functions.get(subject)
        return found[0] if found else self.matches.get(subject)

    def at_address(self, value: int) -> tuple[str, ...]:
        """Ids of functions whose recorded address (hex text) equals `value`."""
        return tuple(sorted(key for key, (_, record, _) in self.functions.items() if _hex(record.address) == value))


def _hex(address: str | None) -> int | None:
    try:
        return int(address, 16) if address else None
    except ValueError:
        return None


def excerpt_sha256(record: FunctionRecord) -> str:
    """Hash of what a jump would show (the decompiled text, else the name): the locator's freshness check."""
    return hashlib.sha256((record.code or record.name).encode('utf-8', 'surrogatepass')).hexdigest()


def function_ref(record: FunctionRecord, side: str) -> FunctionRef:
    rva = _hex(record.address) if record.address_space == 'relative' else None
    return FunctionRef(function_id=record.id[:64], name=record.name, side=side, rva=rva)


def function_locator(index: PairIndex, subject: str) -> Locator | None:
    """A `function` locator for a live function id; None when the subject is not (or no longer) one."""
    found = index.functions.get(subject)
    if found is None or not _ID.match(subject):
        return None
    _, record, side = found
    return Locator(scheme='function', run_id=index.run_id if _ID.match(index.run_id or '') else None, side=side,
                   function_id=subject, rva=function_ref(record, side).rva, excerpt_sha256=excerpt_sha256(record))


def validate_locator(index: PairIndex, locator: Locator) -> None:
    """Raise `PT-SEARCH-LOCATOR` unless a function locator still names the same function text in the live run."""
    if locator.scheme != 'function' or locator.function_id is None:
        return
    found = index.functions.get(locator.function_id)
    ok = (found is not None and locator.side == found[2] and locator.run_id in (None, index.run_id)
          and locator.excerpt_sha256 in (None, excerpt_sha256(found[1])))
    if not ok:
        raise SearchError('PT-SEARCH-LOCATOR', STALE_LOCATOR, recoverable=True)


def expansion(match: FunctionMatch, rank: Attention | None, attention_note: str = '') -> PairExpansion:
    """Category, counterparts (split, merged and ambiguous ones are all listed, none picked), pairing quality and
    the attention ordinal. An absent rank is unknown, never zero."""
    refs = tuple(function_ref(f, side) for side, records in (('older', match.older), ('newer', match.newer))
                 for f in records)[:16]
    limits = ()
    if rank is None and match.category != 'unchanged':
        limits = (attention_note or ATTENTION_UNAVAILABLE,)
    return PairExpansion(category=match.category, counterparts=refs, match_types=tuple(match.match_types[:8]),
                         quality=match.quality, manual=match.manual, review=match.review, attention=rank,
                         limitations=limits)


def rename_candidates(index: PairIndex) -> tuple[list[FunctionRef], list[FunctionRef]]:
    """Names of removed (older) and added (newer) functions, sorted: the inputs of the rename detective."""
    older = [function_ref(f, 'older') for m in index.matches.values() if m.category == 'removed' for f in m.older]
    newer = [function_ref(f, 'newer') for m in index.matches.values() if m.category == 'added' for f in m.newer]
    return sorted(older, key=lambda r: (r.name, r.function_id)), sorted(newer, key=lambda r: (r.name, r.function_id))
