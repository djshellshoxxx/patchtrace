"""Pure worker input for the KB panel; no GUI object, live project service or SQLite connection crosses threads."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from ...enrichment.storage import EnrichmentStore, Entry, Guard
from ...models import ComparisonProject
from ..cli_leads import _elsewhere, default_alignment, engine_view
from ..context import ContextBundle
from ..leads import LeadsReport, build_leads
from ..wiring import build_service

KINDS = ('kb-context', 'pipeline', 'ranking', 'signals')


@dataclass(frozen=True)
class ProjectSnapshot:
    project_json: str
    entries_json: tuple[str, ...]


def capture(service) -> ProjectSnapshot:
    """Owner-thread only: use the current connection and enforce the stored rows' integrity checks."""
    service.store._check_open()
    store = EnrichmentStore(service.store)
    return ProjectSnapshot(service.project.model_dump_json(),
                           tuple(json.dumps(asdict(entry), ensure_ascii=True)
                                 for kind in KINDS for entry in store.entries(kind)))


class _CapturedRows:
    def __init__(self, snapshot: ProjectSnapshot):
        self.rows = []
        for text in snapshot.entries_json:
            row = json.loads(text)
            row['guard'] = Guard(**row['guard'])
            self.rows.append(Entry(**row))

    def entries(self, kind: str, current: Guard | None = None) -> list[Entry]:
        return [replace(row, stale=row.stale or (current is not None and row.guard != current))
                for row in self.rows if row.kind == kind]


def load_snapshot(snapshot: ProjectSnapshot, workspace: Path, token) -> LeadsReport:
    """Worker: render the pinned project snapshot, reading only the independent advisory workspace."""
    token.raise_if_cancelled()
    project = ComparisonProject.model_validate_json(snapshot.project_json)
    rows = _CapturedRows(snapshot)
    bundles = sorted((ContextBundle.model_validate_json(json.dumps(row.body)) for row in rows.entries('kb-context')
                      if row.id.startswith('kb-context:')), key=lambda b: (b.base_revision, b.context_key))
    bundle = bundles[-1] if bundles else None
    view, note = engine_view(project, rows)
    token.raise_if_cancelled()
    elsewhere, mentions, replaced = _elsewhere(build_service(workspace), bundle) if bundle else ([], [], [])
    return build_leads(bundle, view, alignment=default_alignment(), elsewhere=elsewhere,
                       mention_only=mentions, replaced_sources=replaced, engine_note=note)
