"""Unified-engine rows and the attention ranking as ``leads.EngineView`` (K8).

Read-only. A row is ``modified`` only when both sides exist. A missing rank stays ``None``; a verdict is recorded only
when an engine states one, so silence is never ``unchanged``. Names are untrusted and cleaned.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Protocol

from ...unified.contracts import UnifiedMatch
from ..leads import EngineRow, EngineSignal, EngineView, plain_text

_VERDICTS = frozenset({'changed', 'unchanged', 'unknown'})
_UNIFIED = {'material': 'changed', 'unchanged': 'unchanged'}


class RankedLike(Protocol):
    @property
    def match_id(self) -> str: ...

    @property
    def rank(self) -> int: ...


def _name(match: UnifiedMatch) -> str:
    side = (match.newer or match.older)[0]
    return plain_text(side.name, 200) or f'sub_{side.rva:x}'


def _change(match: UnifiedMatch) -> str:
    if match.older and match.newer:
        return 'modified'
    return 'added' if match.newer else 'removed'


def _verdicts(match: UnifiedMatch, extra: Sequence[tuple[str, str]]) -> tuple[tuple[str, str], ...]:
    found = [(engine, verdict) for engine, verdict in extra if verdict in _VERDICTS]
    stated = _UNIFIED.get(match.materiality)
    if stated is not None:
        found.append(('unified', stated))
    return tuple(sorted(set(found)))


def engine_view(matches: Iterable[UnifiedMatch], ranking: Iterable[RankedLike] | None, *, project_revision: int,
                run_id: str | None, older_sha: str, newer_sha: str,
                signals: Mapping[str, Sequence[EngineSignal]] | None = None,
                verdicts: Mapping[str, Sequence[tuple[str, str]]] | None = None) -> EngineView:
    """Rows keep the unified row order. ``ranking`` entries are matched by ``match_id == row_id``; rows it does not
    mention have no attention order. ``signals`` and ``verdicts`` (other engines) are keyed by row id."""
    ranks = {entry.match_id: entry.rank for entry in ranking or ()}
    signals, verdicts = signals or {}, verdicts or {}
    rows = tuple(
        EngineRow(m.row_id, _name(m), _change(m), ranks.get(m.row_id), tuple(signals.get(m.row_id, ())),
                  _verdicts(m, verdicts.get(m.row_id, ())))
        for m in matches if m.decision != 'unknown')
    return EngineView(project_revision, run_id, older_sha, newer_sha, rows)
