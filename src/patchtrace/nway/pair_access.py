"""Read-only access to one pair project for the Series window (SPEC-09b section 3).

A pair project is opened only long enough to copy out what the view needs (state, stored
default-profile ranking, display names) and is closed again. Nothing here writes a pair
project, and no per-pair problem is raised: it is classified into a `PairSnapshot` state.
No Qt. Heavy modules are imported lazily so importing this module stays cheap.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol

from .contracts import NwayError, PairRef
from .graph import validate_pair

if TYPE_CHECKING:
    from ..enrichment.contracts import RankingResult

PairState = Literal['ok', 'missing', 'unreadable', 'locked', 'mismatch', 'changed', 'no-run']
PROJECT_FILE = 'project.sqlite3'


@dataclass(frozen=True)
class PairSnapshot:
    """Everything the view needs from one pair project, copied out. `reason` is user-safe."""
    state: PairState
    reason: str = ''
    project_id: str | None = None
    revision: int | None = None
    run_id: str | None = None
    ranking: RankingResult | None = field(default=None, repr=False)
    ranking_note: str = ''
    match_names: Mapping[str, str] = field(default_factory=dict)


class PairReader(Protocol):
    def read(self, root: Path, ref: PairRef, older_sha: str, newer_sha: str,
             wanted_match_ids: frozenset[str]) -> PairSnapshot: ...


def _ranking_note(note: str) -> str:
    lowered = note.lower()
    if 'stale' in lowered:
        return 'stored ranking is stale'
    if 'incomplete' in lowered:
        return 'stored ranking is incomplete'
    if 'no completed' in lowered:
        return 'no completed run'
    return 'no stored ranking'


def _display_name(match) -> str:
    side = match.newer or match.older
    return side[0].name if side else ''


class DiskPairReader:
    """Opens each pair project through ProjectService, reads, and always closes it."""

    def read(self, root: Path, ref: PairRef, older_sha: str, newer_sha: str,
             wanted_match_ids: frozenset[str]) -> PairSnapshot:
        from ..service import ProjectService
        root = Path(root).resolve()
        target = (root / ref.path).resolve()
        if not target.is_relative_to(root) or not (target / PROJECT_FILE).is_file():
            return PairSnapshot('missing', 'pair project is missing')
        try:
            service = ProjectService.open(target)
        except ValueError as exc:
            if 'locked' in str(exc).lower():
                return PairSnapshot('locked', 'locked by another PatchTrace window')
            return PairSnapshot('unreadable', 'pair project cannot be opened')
        except (sqlite3.Error, OSError):
            return PairSnapshot('unreadable', 'database cannot be read')
        try:
            return self._snapshot(service, ref, older_sha, newer_sha, wanted_match_ids)
        finally:
            service.close()

    @staticmethod
    def _snapshot(service, ref: PairRef, older_sha: str, newer_sha: str,
                  wanted: frozenset[str]) -> PairSnapshot:
        from ..enrichment.contracts import EnrichmentError
        from ..enrichment.pipeline import load_default
        from ..enrichment.storage import EnrichmentStore
        from .series import current_run_id
        project = service.project
        run_id = current_run_id(project)
        ids = dict(project_id=project.id, revision=project.revision, run_id=run_id)
        try:
            validate_pair(project, older_sha, newer_sha)
        except NwayError:
            return PairSnapshot('mismatch', 'project does not hold this ordered pair of builds', **ids)
        if project.id != ref.project_id:
            return PairSnapshot('mismatch', 'a different project now occupies this path', **ids)
        if (project.revision, run_id) != (ref.revision, ref.run_id):
            state, reason = 'changed', 'project changed since the series was computed'
        elif ref.run_id is None:
            return PairSnapshot('no-run', 'pair has no completed run', **ids)
        else:
            state, reason = 'ok', ''
        names = {m.id: _display_name(m) for m in project.matches if m.id in wanted}
        try:
            ranking, _, note = load_default(EnrichmentStore(service.store), project)
        except (EnrichmentError, ValueError, sqlite3.Error, OSError):
            return PairSnapshot(state, reason, ranking=None, ranking_note='stored ranking unreadable',
                                match_names=names, **ids)
        return PairSnapshot(state, reason, ranking=ranking, ranking_note='' if ranking else _ranking_note(note),
                            match_names=names, **ids)
