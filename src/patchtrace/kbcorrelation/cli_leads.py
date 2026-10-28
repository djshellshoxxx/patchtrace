"""`kb leads PROJECT [--cve CVE] [--limit N]` (KB-integration-plan 8.1; slice K4a). Qt-free; read-only.

Reads the project's stored advisory context and the engine's stored ranking and signals, then groups the changed
functions by CVE (:mod:`.leads`). It never fetches and never runs an engine: run ``patchtrace rank PROJECT`` first.
``RealEngine`` and ``default_alignment`` import ``enrichment`` lazily; slice K8 moves them to ``adapters/engine.py``.

Hook for ``kbcorrelation/cli.py`` (applied in this slice): ``from . import cli_leads`` plus ``cli_leads.register`` in
``REGISTRARS`` and ``**cli_leads.HANDLERS`` in ``HANDLERS``. ``patchtrace/cli.py`` needs nothing beyond the ``kb`` hook.
"""
from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path

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

SIGNAL_SUMMARY = 160


def default_alignment() -> Alignment:
    from ..enrichment.cve import ALIGNING_CONFIDENCE, CWE_DETECTORS
    return Alignment(dict(CWE_DETECTORS), frozenset(ALIGNING_CONFIDENCE))


def _change(match) -> str:
    return 'added' if not match.older else 'removed' if not match.newer else 'modified'


class RealEngine:
    """``EngineEvidence`` over the stored default-profile ranking and signals (``enrichment.pipeline.load_default``)."""

    def read(self, project_dir: str) -> EngineView | None:
        from ..enrichment.pipeline import load_default
        from ..enrichment.storage import EnrichmentStore
        from ..enrichment.views import build_views
        from ..service import ProjectService
        try:
            service = ProjectService.open(Path(project_dir), maintenance=False)
        except Exception:
            raise KbcStoreError('PT-KBC-STORAGE', 'the project cannot be opened') from None
        try:
            result, sets, _ = load_default(EnrichmentStore(service.store), service.project)
            if result is None:
                return None
            views = build_views(service.project)
        finally:
            service.close()
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


def _elsewhere(service: KbService, bundle: ContextBundle) -> tuple[list[NotApplicable], list[str]]:
    """CVEs of the bundle's source documents that the context leaves out: other products only, or a mention only."""
    if not (service.root / DB_NAME).is_file():
        return [], []
    with service._open(create=False) as ws:
        index, _ = load_index(ws, service.ports)
        try:
            rev = ws.current_revision(bundle.investigation_id)
        except ValidationError:
            rev = None
    mine = {bundle.scope_id} if bundle.scope_id else set(rev.scope_ids if rev else ())
    if not mine:
        return [], []
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
    return elsewhere, mentions


def leads_outcome(service: KbService, engine, project_dir: str, *, kev: ExploitationLookup | None = None,
                  cve: str | None = None, limit: int | None = None, alignment: Alignment | None = None) -> Outcome:
    bundles = service._project_bundles(project_dir)
    bundle = bundles[-1] if bundles else None
    view = engine.read(project_dir)
    if bundle is None and view is None:
        return Outcome(4, 'unavailable', {'contract': 'kbcorrelation/1', 'state': 'no-advisory'}, TEXT_KB17)
    wanted = _cve(cve)
    elsewhere, mentions = _elsewhere(service, bundle) if bundle else ([], [])
    report = build_leads(bundle, view, alignment=alignment or default_alignment(), kev=kev, elsewhere=elsewhere,
                         mention_only=mentions, only_cve=wanted, limit=limit)
    return _present(report, wanted)


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
