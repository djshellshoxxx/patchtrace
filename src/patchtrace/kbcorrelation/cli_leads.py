"""`kb leads PROJECT [--cve CVE] [--limit N]` (KB-integration-plan 8.1; slice K4a). Qt-free; read-only.

Reads the project's stored advisory context and the engine's stored ranking and signals, then groups the changed
functions by CVE (:mod:`.leads`). It never fetches and never runs an engine: run ``patchtrace rank PROJECT`` first.
``RealEngine`` and ``default_alignment`` import ``enrichment`` lazily; slice K8 moves them to ``adapters/engine.py``.

``kb leads`` opens the project itself, which only works while nothing else holds it. For a project its owner keeps
open (the desktop), ``read_snapshot`` takes the stored rows on the owner's thread and ``leads_from_snapshot`` builds
the same report from them on any thread, through the same ``leads_report`` (store-threading-spec section 4a).

Hook for ``kbcorrelation/cli.py`` (applied in this slice): ``from . import cli_leads`` plus ``cli_leads.register`` in
``REGISTRARS`` and ``**cli_leads.HANDLERS`` in ``HANDLERS``. ``patchtrace/cli.py`` needs nothing beyond the ``kb`` hook.
"""
from __future__ import annotations

import argparse
import dataclasses
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from .cli_index import add_common, load_index, present
from .context import ContextBundle
from .ids import KbSyntaxError, normalise_cve
from .leads import (
    Alignment,
    EngineRow,
    EngineSignal,
    EngineView,
    ExploitationLookup,
    LeadsReport,
    NotApplicable,
    build_leads,
    plain_text,
    render_text,
)
from .service import TEXT_KB17, KbService, Outcome
from .sources.importer import MINOR_RELATIONS
from .store import DB_NAME, KbcStoreError

if TYPE_CHECKING:
    from ..enrichment.storage import Entry

SIGNAL_SUMMARY = 160
CONTEXT_KIND = 'kb-context'
ENGINE_KINDS = ('pipeline', 'ranking', 'signals')  # every kind ``enrichment.pipeline.load_default`` reads


def default_alignment() -> Alignment:
    from ..enrichment.cve import ALIGNING_CONFIDENCE, CWE_DETECTORS
    return Alignment(dict(CWE_DETECTORS), frozenset(ALIGNING_CONFIDENCE))


def _change(match) -> str:
    return 'added' if not match.older else 'removed' if not match.newer else 'modified'


class RealEngine:
    """``EngineEvidence`` over the stored default-profile ranking and signals (``enrichment.pipeline.load_default``).
    After ``read`` returns None, ``note`` holds the pipeline's reason (empty when nothing was ever ranked)."""

    note = ''

    def read(self, project_dir: str) -> EngineView | None:
        from ..enrichment.storage import EnrichmentStore
        from ..service import ProjectService
        try:
            service = ProjectService.open(Path(project_dir), maintenance=False)
        except Exception:
            raise KbcStoreError('PT-KBC-STORAGE', 'the project cannot be opened') from None
        try:
            return self.view(EnrichmentStore(service.store), service.project)
        finally:
            service.close()

    def view(self, store, project) -> EngineView | None:
        """The view of ``project`` from the rows ``store.entries`` returns; sets ``note``. It opens nothing."""
        from ..enrichment.pipeline import load_default
        from ..enrichment.views import build_views
        result, sets, self.note = load_default(store, project)
        if result is None:
            return None
        views = build_views(project)
        by_match = {s.match_id: s for s in sets}
        ranks = {e.match_id: e.rank for e in result.entries}
        rows = []
        for match in views.matches:
            signals = by_match[match.match_id].signals if match.match_id in by_match else ()
            names = sorted({f.name for f in match.older + match.newer})
            rows.append(EngineRow(
                match_id=match.match_id, name=' / '.join(names), change=_change(match),
                attention_rank=ranks.get(match.match_id),
                signals=tuple(EngineSignal(s.detector, s.confidence, s.group_key,
                                           plain_text(s.rationale, SIGNAL_SUMMARY)) for s in signals)))
        return EngineView(views.revision, views.run_id, views.older_sha256, views.newer_sha256, tuple(rows))


@dataclass(frozen=True)
class KbSnapshot:
    """What ``kb leads`` reads from a project, taken by ``read_snapshot`` on the thread that owns the open project;
    after that any thread may read it (store-threading-spec R1, R2). It holds no store, service or connection."""
    project: Any  # independent ComparisonProject value; no mutable owner state crosses the thread boundary
    rows: tuple[tuple[str, tuple[Entry, ...]], ...]  # (kind, the stored enrichment rows of that kind, newest first)

    def entries(self, kind: str) -> tuple[Entry, ...]:
        """The rows of ``kind``. A kind that was not taken is refused, never read as "no rows"."""
        for taken, found in self.rows:
            if taken == kind:
                return found
        raise KbcStoreError('PT-KBC-STATE', 'the project snapshot does not hold these rows')


SNAPSHOT_BYTES = 16 * 1024 * 1024
SNAPSHOT_NODES = 100_000
SNAPSHOT_ROWS = 1000


def _bound_project(project) -> None:
    """Bound owner-thread copying before allocating an independent project value."""
    from pydantic import BaseModel
    stack, nodes, size = [(project, 0)], 0, 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > SNAPSHOT_NODES or depth > 64:
            raise KbcStoreError('PT-KBC-LIMIT', 'project exceeds the desktop snapshot limit; use the CLI')
        if isinstance(value, str):
            size += len(value) * 4  # conservative UTF-8 bound, without allocating an encoding
        elif isinstance(value, bytes):
            size += len(value)
        else:
            if isinstance(value, BaseModel):
                children = value.__dict__.values()
            elif isinstance(value, dict):
                children = (*value.keys(), *value.values()) if len(value) <= SNAPSHOT_NODES // 2 else ()
                if len(value) > SNAPSHOT_NODES // 2:
                    raise KbcStoreError('PT-KBC-LIMIT', 'project exceeds the desktop snapshot limit; use the CLI')
            elif isinstance(value, (list, tuple)):
                children = value
            else:
                children = ()
            if len(children) + len(stack) + nodes > SNAPSHOT_NODES:
                raise KbcStoreError('PT-KBC-LIMIT', 'project exceeds the desktop snapshot limit; use the CLI')
            stack.extend((child, depth + 1) for child in children)
        if size > SNAPSHOT_BYTES:
            raise KbcStoreError('PT-KBC-LIMIT', 'project exceeds the desktop snapshot limit; use the CLI')


def read_snapshot(service) -> KbSnapshot:
    """Owner-thread bounded capture, including row integrity/JSON decoding and independent project copying.

    Refuse oversized stored inputs before loading their payloads. Large-project latency remains a qualification
    gate; the CLI can still read projects exceeding this desktop-only snapshot policy.
    """
    from ..enrichment.storage import EnrichmentStore
    store = EnrichmentStore(service.store)
    kinds = (CONTEXT_KIND, *ENGINE_KINDS)
    _bound_project(service.project)
    if 'enrichment_entries' in store._tables():
        # LIMIT bounds the metadata scan; length(BLOB) obtains byte counts without materializing Python payloads.
        sizes = store._db.execute(
            'SELECT length(CAST(body AS BLOB)) FROM enrichment_entries '
            'WHERE kind IN (?,?,?,?) LIMIT ?', (*kinds, SNAPSHOT_ROWS + 1)).fetchall()
        if len(sizes) > SNAPSHOT_ROWS or sum(row[0] for row in sizes) > SNAPSHOT_BYTES:
            raise KbcStoreError('PT-KBC-LIMIT', 'stored rows exceed the desktop snapshot limit; use the CLI')
    return KbSnapshot(service.project.model_copy(deep=True),
                      tuple((kind, tuple(store.entries(kind))) for kind in kinds))


class SnapshotRows:
    """The read side of ``EnrichmentStore`` that ``load_default`` uses, answered from a snapshot's rows. A row is
    stale against ``current`` exactly as in ``EnrichmentStore.entries``: flagged in the store, or of another guard."""

    def __init__(self, snapshot: KbSnapshot):
        self._snapshot = snapshot

    def entries(self, kind: str, current=None) -> list[Entry]:
        return [dataclasses.replace(e, stale=e.stale or (current is not None and e.guard != current))
                for e in self._snapshot.entries(kind)]


class SnapshotEngine(RealEngine):
    """``RealEngine`` over a snapshot instead of a directory: the same view, and it opens nothing."""

    def __init__(self, snapshot: KbSnapshot):
        self._snapshot = snapshot

    def read(self, project_dir: str) -> EngineView | None:
        return self.view(SnapshotRows(self._snapshot), self._snapshot.project)


def leads_from_snapshot(service: KbService, snapshot: KbSnapshot, **options) -> LeadsReport | None:
    """``leads_report`` for a project its owner holds open: ``service`` supplies the advisory workspace (a separate
    file that allows concurrent readers), the project is read through ``snapshot`` only. Any thread may call it;
    ``options`` are those of ``leads_report``. No directory is passed on: the snapshot ports need none."""
    from .wiring import SnapshotProjectPort
    port = SnapshotProjectPort(snapshot.project.id, {CONTEXT_KIND: snapshot.entries(CONTEXT_KIND)})
    held = KbService(service.root, dataclasses.replace(service.env, project=lambda _workspace, _name: port))
    return leads_report(held, SnapshotEngine(snapshot), '', **options)


def _elsewhere(service: KbService, bundle: ContextBundle) -> tuple[list[NotApplicable], list[str], list[str]]:
    """CVEs of the bundle's source documents that the context leaves out (other products only, or a mention only), and
    the bundle's source documents that a newer imported revision has replaced (``ReverseIndex.active_ids``). A source
    no longer in the workspace is not called replaced: that is unknown, not newer."""
    if not (service.root / DB_NAME).is_file():
        return [], [], []
    with service._open(create=False) as ws:
        index, _ = load_index(ws, service.ports)
        try:
            rev = ws.current_revision(bundle.investigation_id)
        except ValidationError:
            rev = None
    active = index.active_ids()
    replaced = sorted(s.doc_id for s in bundle.sources if index.get(s.doc_id) is not None and s.doc_id not in active)
    mine = {bundle.scope_id} if bundle.scope_id else set(rev.scope_ids if rev else ())
    if not mine:
        return [], [], replaced
    known = {c.cve for c in bundle.context.cards}
    edges: dict[str, list] = defaultdict(list)
    names: dict[str, str] = {}
    cwes: dict[str, str] = {}
    for source in bundle.sources:
        doc = index.get(source.doc_id)
        if doc is None:
            continue
        names.update({s.scope_id: s.display_name for s in doc.scopes})
        cwes.update({c.cve: c.stated_cwe for c in doc.cards if c.stated_cwe})
        for edge in doc.edges:
            edges[edge.cve].append(edge)
    elsewhere, mentions = [], []
    for cve in sorted(set(edges) - known):
        real = [e for e in edges[cve] if e.relation not in MINOR_RELATIONS]
        if any(e.scope_id in mine for e in real):
            continue
        if real:
            products = tuple(sorted({names.get(e.scope_id, 'another product') for e in real}))
            elsewhere.append(NotApplicable(cve, products, cwes.get(cve)))
        elif any(e.relation == 'mention-only' for e in edges[cve]):
            mentions.append(cve)
    return elsewhere, mentions, replaced


def leads_report(service: KbService, engine, project_dir: str, *, kev: ExploitationLookup | None = None,
                 cve: str | None = None, limit: int | None = None, alignment: Alignment | None = None
                 ) -> LeadsReport | None:
    """The report behind ``kb leads``, typed; None when the project has neither an advisory context nor a ranking."""
    bundles = service._project_bundles(project_dir)
    bundle = bundles[-1] if bundles else None
    view = engine.read(project_dir)
    if bundle is None and view is None:
        return None
    wanted = _cve(cve)
    elsewhere, mentions, replaced = _elsewhere(service, bundle) if bundle else ([], [], [])
    return build_leads(bundle, view, alignment=alignment or default_alignment(), kev=kev, elsewhere=elsewhere,
                       mention_only=mentions, only_cve=wanted, limit=limit, replaced_sources=replaced,
                       engine_note=getattr(engine, 'note', '') if view is None else '')


def leads_outcome(service: KbService, engine, project_dir: str, *, kev: ExploitationLookup | None = None,
                  cve: str | None = None, limit: int | None = None, alignment: Alignment | None = None) -> Outcome:
    report = leads_report(service, engine, project_dir, kev=kev, cve=cve, limit=limit, alignment=alignment)
    if report is None:
        return Outcome(4, 'unavailable', {'contract': 'kbcorrelation/1', 'state': 'no-advisory'}, TEXT_KB17)
    return _present(report, _cve(cve))


def _cve(raw: str | None) -> str | None:
    try:
        return normalise_cve(raw) if raw else None
    except KbSyntaxError as exc:
        raise KbcStoreError('PT-KBC-INPUT', str(exc)) from None


def _present(report: LeadsReport, wanted: str | None) -> Outcome:
    result = report.model_dump(mode='json')
    count = sum(len(g.leads) for g in report.groups) + len(report.unattributed)
    if wanted and not report.groups:
        return Outcome(4, 'unavailable', result, f'{wanted} is not part of this project\'s advisory context.')
    if report.state == 'no-comparison':
        return Outcome(4, 'unavailable', result, render_text(report))
    warnings = [report.text] if report.state == 'stale' else []
    if not count:
        return Outcome(4, 'unavailable', result, render_text(report), warnings)
    return Outcome(0, 'complete', result, render_text(report), warnings)


def register(sub) -> None:
    leads = add_common(sub.add_parser('leads', help='group the changed functions by CVE (run "rank" first)'))
    leads.add_argument('project', metavar='PROJECT')
    leads.add_argument('--cve', metavar='CVE', help='show one CVE group only')
    leads.add_argument('--limit', type=_positive, metavar='N', help='at most N leads per group')
    leads.add_argument('--kev-dir', type=Path, metavar='DIR', help='KEV catalog folder of "patchtrace kev" (read only; '
                       'default: its usual folder)')


def _positive(text: str) -> int:
    if not re.fullmatch(r'[0-9]{1,6}', text) or int(text) < 1:
        raise argparse.ArgumentTypeError('--limit must be a whole number from 1 to 999999')
    return int(text)


def cmd_leads(args, context, out) -> int:
    outcome = leads_outcome(context.service(args), context.engine or RealEngine(), args.project,
                            kev=context.exploitation(args.kev_dir), cve=args.cve, limit=args.limit)
    return present(out, 'kb leads', args, outcome)


HANDLERS = {'leads': cmd_leads}
