"""`ImportSource` over `pe_overview` (YRX-integration-plan section 7): the static import table of each build of the pair.

A table that is missing, cut short or partly unreadable is `None` (unavailable), never an empty table: "the build has no
imports" and "we could not read its imports" are different facts, and only the first may say an import is absent. The
rules are the ones of `pe_overview.api_delta` (WBQ S4), which compares the same tables. Delay-load imports are not parsed
by `pe_overview`, so none is offered; IAT slot addresses are not given by it either (`slot_rva` is `None`).
"""
from __future__ import annotations

import re
from collections.abc import Mapping

from ...pe_overview.models import PeOverview
from ..contracts import PairSource, Side
from ..errors import RuleError
from ..ports import ImportEntry, ImportTable

# The only spelling `parse_imports` emits for an import by ordinal; any other '#...' text is an ordinary name.
_ORDINAL = re.compile(r'#(0|[1-9][0-9]{0,4})')


def _placeholder(text: str) -> bool:
    """`parse_imports` stands in `<unreadable ...>` or `<invalid thunk ...>` for entries it could not read."""
    return text.startswith('<') and text.endswith('>')


def table_of(overview: PeOverview) -> ImportTable | None:
    """The import table of one parsed build, or `None` when it cannot be trusted to be complete."""
    info = overview.imports
    if info is None:
        declared = overview.directory('Import')
        return ImportTable(()) if declared is not None and not declared.present else None
    if info.truncated or any(dll.truncated for dll in info.dlls):
        return None
    entries = []
    for dll in info.dlls:
        if _placeholder(dll.name) or any(_placeholder(name) for name in dll.functions):
            return None
        for name in dll.functions:
            ordinal = _ORDINAL.fullmatch(name)
            entries.append(ImportEntry(dll=dll.name, name=None if ordinal else name,
                                       ordinal=int(ordinal.group(1)) if ordinal else None, delay=False, slot_rva=None))
    return ImportTable(tuple(entries))


class PeImports:
    """`overviews` maps a side to the `inspect_pe` result of that build (`None` for a build that was not inspected)."""

    def __init__(self, overviews: Mapping[Side, PeOverview | None]):
        self._overviews = overviews

    def imports(self, pair: PairSource, side: Side) -> ImportTable | None:
        overview = self._overviews.get(side)
        if overview is None:
            return None
        if overview.sha256 != (pair.older_sha256 if side == 'older' else pair.newer_sha256):
            raise RuleError('PT-RULE-STALE', f'The {side} import table belongs to another file than the pair',
                            reason='artifact-moved')
        return table_of(overview)
