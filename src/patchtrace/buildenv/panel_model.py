"""Qt-free parts of the Build environment panel: what a read needs (taken on the GUI thread), how a worker reads it,
and how a view model becomes state, notice and table text. Nothing here touches a widget."""
from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..gui.projection import ProjectKey
from ..gui.state import NoticeModel, StateModel
from ..gui.table_spec import ColumnSpec, TableSpec
from ..gui.text import sanitize_text
from .anchors import anchors_for
from .contracts import BuildFingerprint
from .view_model import BannerView, BuildEnvViewModel

SIDES = ('older', 'newer')
NOTICE_KEY = 'build_env.preflight'
# View-model state -> framework state kind. The words stay the view model's; the kind only drives the layout.
KIND = {'B0': 'no-project', 'B1': 'loading', 'B2': 'partial', 'B3': 'ready', 'B4': 'ready', 'B5': 'partial',
        'B6': 'partial', 'B7': 'stale', 'B8': 'error', 'B9': 'unsupported'}
ACTIONS = {'B2': ('setup',), 'B7': ('refresh',), 'B8': ('retry', 'copy'), 'B9': ('setup',)}

COLUMNS = (
    ColumnSpec('fact', 'Fact', lambda r: r.label, width_em=24),
    ColumnSpec('older', 'OLDER', lambda r: r.older, width_em=26),
    ColumnSpec('newer', 'NEWER', lambda r: r.newer, width_em=26),
    ColumnSpec('status', 'Status', lambda r: r.status, width_em=18),
    ColumnSpec('basis', 'Basis', lambda r: r.basis, width_em=32))
SPEC = TableSpec(row_key=lambda r: r.key, search_text=lambda r: f'{r.label} {r.older} {r.newer}')


@dataclass(frozen=True, slots=True)
class ReadRequest:
    """Immutable input of a worker: no widget, no live service, no connection. `found` holds the stored Detect It
    Easy result per side, read on the GUI thread because the project database is thread-bound."""
    key: ProjectKey
    root: Path
    artifacts: tuple
    found: dict[str, Any]


@dataclass(frozen=True, slots=True)
class Outcome:
    older: BuildFingerprint | None
    newer: BuildFingerprint | None
    stale: bool = False
    error: str | None = None
    cancelled: bool = False


class _Found:
    """The `tools.latest` seam of `cli._fingerprint`, answered from what the GUI thread already read."""

    def __init__(self, found: dict[str, Any]) -> None:
        self._found = found

    def latest(self, _engine: str, side: str):
        return self._found.get(side)


def take_request(service, project, key: ProjectKey) -> ReadRequest:
    """GUI thread: the artifacts and the stored Detect It Easy results of the open project."""
    from ..enrichment.storage import EnrichmentStore
    from ..intelligence.tools.store import ToolStore
    tools = ToolStore(EnrichmentStore(service.store), service.root, project.id, project.revision)
    found = {a.side: tools.latest('diec', a.side) for a in project.artifacts if a.side in SIDES}
    return ReadRequest(key, Path(service.root), tuple(project.artifacts), found)


def read_pair(request: ReadRequest, cancel: threading.Event, report) -> Outcome:
    """Worker: PE header facts of both hash-checked files plus the stored results. Never runs a tool."""
    from .cli import _fingerprint
    by_side = {a.side: a for a in request.artifacts}
    if any(side not in by_side for side in SIDES):
        return Outcome(None, None, error='PT-BUILD-INPUT')
    tools, results = _Found(request.found), []
    for done, side in enumerate(SIDES):
        report(side, done, len(SIDES))
        results.append(_fingerprint(by_side[side], request.root, tools, cancel))
        if results[-1].cancelled or cancel.is_set():
            return Outcome(None, None, cancelled=True)
    older, newer = results
    return Outcome(older.fingerprint, newer.fingerprint, older.stale or newer.stale)


def state_of(view: BuildEnvViewModel) -> StateModel:
    return StateModel(KIND[view.state], sanitize_text(view.state_text, 600), actions=ACTIONS.get(view.state, ()))


def notice_of(banners: tuple[BannerView, ...]) -> NoticeModel | None:
    """One strip line for all cautions of the pair; every banner stays readable in the detail."""
    if not banners:
        return None
    first = next((b for b in banners if b.severity == 'caution'), banners[0])
    more = f' (+{len(banners) - 1} more in Build environment)' if len(banners) > 1 else ''
    detail = '\n'.join(sanitize_text(b.text, 600) for b in banners)
    return NoticeModel(NOTICE_KEY, 'caution' if first.severity == 'caution' else 'notice',
                       sanitize_text(f'{first.glyph} {first.text}', 330) + more, detail)


def card_text(view: BuildEnvViewModel) -> str:
    lines = [view.state_text, *(f'{b.glyph} {b.text}' for b in view.banners)]
    lines += [f'{r.label}: {r.older} -> {r.newer} [{r.status}; {r.basis}]' for r in view.rows]
    return sanitize_text('\n'.join([*lines, view.provenance]), 16_384, multiline=True)


def detail_text(view: BuildEnvViewModel) -> str:
    parts = [*(f'{b.glyph} {b.text}' for b in view.banners), view.provenance, *view.technical]
    return '\n'.join(p for p in parts if p)


def anchor_fact(outcome: Outcome | None, side: str | None, anchor_id: str) -> str | None:
    """The fact key of a `build_fact` anchor on `side`, or None when no read fingerprint holds it."""
    if outcome is None:
        return None
    for name, fp in (('older', outcome.older), ('newer', outcome.newer)):
        if fp is not None and side in (name, 'both', None):
            for found in anchors_for(fp):
                if found.anchor_id == anchor_id:
                    return found.key
    return None
