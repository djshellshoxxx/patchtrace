"""What panels navigate by: the identity of the open project and the index of its function matches (GUI plan 7).

Pure and duck-typed over `ComparisonProject.matches` (no pydantic import), so it stays cheap to import. The index
is the one place that answers "which match, on which side, holds this function?" for the current run.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import NamedTuple


class ProjectKey(NamedTuple):
    """Everything that makes an on-screen result current. A NamedTuple, not a dataclass: it is the tuple C6's
    `WindowPort.key()` returns, and C6 consumers index it (`key[4]`, `key[:2]`)."""

    root: str
    project_id: str
    revision: int
    run_id: str | None
    older_sha256: str | None
    newer_sha256: str | None

    def identity(self) -> tuple[str, str]:
        """Same project, whatever has changed in it since."""
        return (self.root, self.project_id)


@dataclass(frozen=True, slots=True)
class FunctionHit:
    match_id: str
    side: str  # 'older' or 'newer': the function id already fixes the side


class MatchIndex:
    """Function id -> the matches (and sides) that list it, for the run of one `ProjectKey`.

    More than one hit means the function is ambiguous: a caller must offer candidates, never take the first."""

    __slots__ = ('key', '_functions', '_matches')

    def __init__(self, key: ProjectKey | None, matches: Iterable) -> None:
        self.key = key
        functions: dict[str, list[FunctionHit]] = {}
        ids: set[str] = set()
        run_id = None if key is None else key.run_id
        for match in matches if run_id is not None else ():
            if match.run_id != run_id:
                continue
            ids.add(match.id)
            for side in ('older', 'newer'):
                for function in getattr(match, side):
                    hit = FunctionHit(match.id, side)
                    hits = functions.setdefault(function.id, [])
                    if hit not in hits:
                        hits.append(hit)
        self._functions = {function_id: tuple(hits) for function_id, hits in functions.items()}
        self._matches = frozenset(ids)

    def functions_for(self, function_id: str) -> tuple[FunctionHit, ...]:
        return self._functions.get(function_id, ())

    def has_match(self, match_id: str) -> bool:
        return match_id in self._matches

    def __len__(self) -> int:
        return len(self._functions)


class MatchIndexCache:
    """One index at a time, rebuilt only when the key changes (a revision, run or pair change)."""

    def __init__(self) -> None:
        self._index: MatchIndex | None = None

    def get(self, key: ProjectKey | None, matches: Iterable) -> MatchIndex:
        if self._index is None or self._index.key != key:
            self._index = MatchIndex(key, matches)
        return self._index
