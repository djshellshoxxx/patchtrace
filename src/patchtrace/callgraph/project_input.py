"""Read-only view of a comparison project's current run: emitted records, pairs and the manual digest."""
from __future__ import annotations

from dataclasses import dataclass

from ..enrichment.identity import domain_id, parse_address
from ..models import ComparisonProject, FunctionMatch, FunctionRecord
from .contracts import RawMatchesReader, Side
from .limits import GraphError
from .raw_matches import RawMatchesResult, load_raw_matches

_EXTERNAL = 'EXTERNAL:'


@dataclass(frozen=True)
class Entry:
    """One function record Ghidriff emitted (modified, added or removed), with its stored call lists."""
    side: Side
    label: str
    function_id: str
    match_id: str
    address: int | None
    external: bool
    callees: tuple[str, ...]
    callers: tuple[str, ...]


@dataclass(frozen=True)
class EmittedPair:
    match_id: str
    category: str
    older: tuple[str, ...]  # labels
    newer: tuple[str, ...]
    via: str
    manual: bool


@dataclass(frozen=True)
class ProjectInput:
    project_id: str
    revision: int
    run_id: str
    backend_version: str
    raw_sha256: str | None
    older_sha256: str
    newer_sha256: str
    entries: tuple[Entry, ...]
    pairs: tuple[EmittedPair, ...]
    manual_digest: str
    raw: RawMatchesResult

    def side_entries(self, side: Side) -> tuple[Entry, ...]:
        return tuple(e for e in self.entries if e.side == side)


def _is_external(record: FunctionRecord) -> bool:
    return bool(record.metadata.get('external')) or (record.address or '').startswith(_EXTERNAL)


def _entry(record: FunctionRecord, side: Side, match_id: str) -> Entry:
    return Entry(side, record.name, record.id, match_id, parse_address(record.address), _is_external(record),
                 tuple(record.callees), tuple(record.callers))


def _via(match: FunctionMatch) -> str:
    if match.manual:
        return 'manual'
    return f'ghidriff:{match.match_types[0] if match.match_types else match.category}'


def _manual_digest(project: ComparisonProject, run_id: str) -> str:
    matches = [m for m in project.matches if m.run_id == run_id]
    manual = sorted((m.id, m.category, m.review, [f.name for f in m.older], [f.name for f in m.newer])
                    for m in matches if m.manual)
    rejected = sorted(m.id for m in matches if not m.manual and m.review == 'rejected')
    overrides = sorted((a.id, a.target_id, a.text, a.stale)
                       for a in project.annotations if a.kind == 'match-override')
    return domain_id('callgraph-manual', 1, {'manual': manual, 'rejected': rejected, 'overrides': overrides})


def read_project_input(project: ComparisonProject, root: object = None,
                       reader: RawMatchesReader | None = None) -> ProjectInput:
    run = next((r for r in reversed(project.runs) if r.status == 'completed'), None)
    if run is None:
        raise GraphError('PT-GRAPH-INPUT', 'the project has no completed analysis run')
    sides = {a.side: a.sha256 for a in project.artifacts}
    entries: dict[str, Entry] = {}
    pairs: list[EmittedPair] = []
    for match in project.matches:
        if match.run_id != run.id:
            continue
        for side, records in (('older', match.older), ('newer', match.newer)):
            for record in records:
                entries.setdefault(record.id, _entry(record, side, match.id))
        paired = bool(match.older and match.newer) and match.review != 'rejected'
        if paired or match.category in {'added', 'removed'}:
            pairs.append(EmittedPair(match.id, match.category, tuple(f.name for f in match.older),
                                     tuple(f.name for f in match.newer), _via(match), match.manual))
    return ProjectInput(
        project.id, project.revision, run.id, run.backend_version, run.raw_sha256, sides['older'], sides['newer'],
        tuple(entries.values()), tuple(pairs), _manual_digest(project, run.id),
        load_raw_matches(reader, root, project))
