"""Facade of the KB-CVE correlator (KB-integration-plan section 9; slice K3). Qt-free, offline.

``KbService`` is what the CLI (and, later, the dock controller) calls. It owns no policy of its own: lookups come from
``index``, state from ``workflow`` through ``WorkspaceStore``, files and projects from the ports in :class:`Env`
(bound by ``wiring``), and every method returns an :class:`Outcome` (exit code, envelope status, JSON-ready result,
plain text) or raises ``KbcStoreError`` carrying a ``PT-KBC-*`` code. Nothing here fetches or executes anything.

Exit codes (plan 8.1): 0 ok; 2 invalid arguments, a blocked or contradicting pair, unsupported; 3 runtime failure or
partial coverage; 4 complete in scope with nothing to report, or nothing to compute yet; 5 cancelled.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from pydantic import ValidationError

from . import components as comp
from . import pairs as pr
from . import resolver
from .cli_index import IndexPorts, load_index
from .context import ContextBundle, RulesPort, build_bundle, vulnerability_pointer
from .contracts import (
    HARD_BLOCKS,
    AnalystDecision,
    Coverage,
    CveCard,
    InvestigationRevision,
    Lead,
    SearchScope,
    SourceRef,
    domain_id,
)
from .export import EXTENSIONS, to_json, to_markdown
from .ids import KbSyntaxError, normalise_cve, normalise_kb_edge
from .index import Lookup, ReverseIndex
from .limits import MAX_SEARCH_MONTHS
from .lineage import IndexRow
from .pairs import LocalFile
from .plan import index_plan, local_plan
from .ports import AdvisoryPort, ClockPort, ProjectPort
from .products import clean_text
from .recovery import repair
from .store import AttachRequest, Fault, KbcStoreError, ProjectAttachment, WorkspaceStore, atomic_write
from .workflow import Event

RELATION_LABEL = {
    'vendor-remediation': 'Vendor remediation (MSRC CVRF, product-specific)',
    'vendor-association': 'Vendor reference (CSAF text or URL)',
    'mention-only': 'Mentioned in advisory text only',
    'analyst-asserted': 'Entered by you',
    'disputed': 'Revisions disagree',
    'package-contains': 'Update package contains the file',
}
OUTCOME_BY_STATUS = {'found': 'METADATA_READY', 'partial': 'METADATA_PARTIAL', 'not_observed': 'NOT_OBSERVED',
                     'not_searched': 'SCOPE_REQUIRED'}
UNSELECTED_SCOPE = domain_id('kbc.scope', 1, {'unselected': True})
SCOPE_FILE_BYTES = 64 * 1024
TEXT_KB6 = 'This update applies to several products. Choose the product and architecture of the files you are analyzing.'
TEXT_KB7 = ('The advisory does not name the changed file. Enter a file name such as clfs.sys, or choose two files '
            'you already have.')
TEXT_KB8 = 'Microsoft lists this CVE for other products only. It is left out of the leads for {product}.'
TEXT_KB13 = ('Advisory context is attached. It records what the vendor states and which checks could not be made; '
             'it does not show that any changed function addresses a vulnerability.')
TEXT_KB17 = ('This project has no advisory context. Search a KB or CVE to attach one; applicability to these two '
             'files stays unverified until you confirm it.')
TEXT_PAIRS_E0 = ('Pair candidates need the Windows file index, which is not available offline. Supply two files you '
                 'already have with "kb import-pair".')


class FileIndex(Protocol):
    """The offline Windows file index: rows of one file name plus how many index entries could not become rows;
    bound by ``wiring.WorkspaceFileIndex``."""

    def available(self) -> bool: ...

    def rows(self, file_name: str, winbindex_key: str) -> tuple[Sequence[IndexRow], int]: ...


class ProjectAccess(ProjectPort, Protocol):
    """``ProjectPort`` plus the two reads and the lookup the service needs; bound by ``wiring.RealProjectPort``."""

    def open_project(self, directory: str) -> str: ...

    def list_rows(self, project_id: str, kind: str) -> Mapping[str, bytes]: ...


@dataclass(frozen=True)
class Env:
    advisory: AdvisoryPort
    clock: ClockPort
    rules: RulesPort
    inspect: Callable[[str], LocalFile]
    escape: Callable[[str], str]
    project: Callable[[WorkspaceStore | None, str], ProjectAccess]
    fault: Fault | None = None
    file_index: Callable[[Path], FileIndex] | None = None


@dataclass
class Outcome:
    exit: int
    status: str
    result: dict[str, Any]
    text: str
    warnings: list[str] = field(default_factory=list)
    error: str | None = None


def _fail(code: str, message: str) -> KbcStoreError:
    return KbcStoreError(code, message)


def parse_lead(raw: str) -> tuple[str, str]:
    text = raw.strip()
    try:
        return ('cve', normalise_cve(text)) if text[:3].upper() == 'CVE' else ('kb', normalise_kb_edge(text))
    except KbSyntaxError as exc:
        raise _fail('PT-KBC-INPUT', str(exc)) from None


def _scope_dict(scope) -> dict:
    return {'scope_id': scope.scope_id, 'display_name': clean_text(scope.display_name, 200), 'family': scope.family,
            'architecture': scope.architecture, 'release': scope.release, 'mapping': scope.mapping}


def _edge_dict(group, names: Mapping[str, str]) -> dict:
    return {'kb': group.kb, 'cve': group.cve, 'scope_id': group.scope_id, 'product': names.get(group.scope_id, ''),
            'relation': group.relation, 'label': RELATION_LABEL.get(group.relation, group.relation),
            'fixed_builds': list(group.fixed_builds), 'releases': list(group.release_ids), 'kev': 'not-loaded',
            'refs': [{'doc_id': r.doc_id, 'pointer': r.pointer} for r in group.refs]}


def _plain_edge(edge, names: Mapping[str, str]) -> dict:
    return {'kb': edge.kb, 'cve': edge.cve, 'scope_id': edge.scope_id, 'product': names.get(edge.scope_id, ''),
            'relation': edge.relation, 'label': RELATION_LABEL.get(edge.relation, edge.relation),
            'ref': {'doc_id': edge.ref.doc_id, 'pointer': edge.ref.pointer}}


def _card_dict(card: CveCard) -> dict:
    return {**card.model_dump(mode='json', exclude={'contract'}),
            'title': clean_text(card.title, 300) if card.title else None,
            'stated_by': f'stated by vendor ({card.source_kind.upper()})' if card.stated_cwe else None}


class KbService:
    def __init__(self, root: Path, env: Env):
        self.root = Path(root).expanduser()
        self.env = env
        self.ports = IndexPorts(advisory=env.advisory, clock=env.clock)

    # ------------------------------------------------------------------------------------------ plumbing

    def _open(self, *, create: bool = True) -> WorkspaceStore:
        return WorkspaceStore(self.root, create=create, fault=self.env.fault, clock=self.env.clock)

    def _now(self) -> str:
        return self.env.clock.now_utc()

    @staticmethod
    def _get(ws: WorkspaceStore, investigation_id: str) -> InvestigationRevision:
        try:
            found = ws.current_revision(investigation_id)
        except ValidationError:
            found = None
        if found is None:
            raise _fail('PT-KBC-INPUT', 'there is no investigation with that id in this workspace')
        return found

    def _decide(self, ws: WorkspaceStore, investigation_id: str, op: str, prior: str, next_: str, reason: str) -> None:
        ws.append_decision(investigation_id, AnalystDecision(op=op, prior=prior, next=next_, reason=reason[:500],
                                                             created_at=self._now()))

    def _step(self, ws: WorkspaceStore, rev: InvestigationRevision, kind: str, **fields: Any) -> InvestigationRevision:
        return ws.apply(rev, Event(kind, rev.revision, **fields))

    def _scope(self, index: ReverseIndex, months: str | None, scope_file: Path | None) -> SearchScope | None:
        """The finite scope coverage is computed against; None means the whole loaded corpus."""
        names: list[str] = []
        doc_ids: list[str] = []
        if months:
            names = [m.strip() for m in months.split(',') if m.strip()]
        if scope_file is not None:
            try:
                data = json.loads(self._read_small(scope_file))
                names += list(data.get('months', []))
                doc_ids += list(data.get('doc_ids', []))
            except (ValueError, AttributeError, TypeError):
                raise _fail('PT-KBC-SCOPE', 'the scope file is not JSON with "months" and "doc_ids" lists') from None
        if not names and not doc_ids:
            return None
        if len(set(names)) > MAX_SEARCH_MONTHS:
            raise _fail('PT-KBC-SCOPE', f'a search names at most {MAX_SEARCH_MONTHS} months')
        try:
            months_t, ids_t = tuple(sorted(set(names))), tuple(sorted(set(doc_ids)))
            if months_t and ids_t:
                return SearchScope(kind='mixed', months=months_t, doc_ids=ids_t, corpus_digest=index.corpus_digest())
            return SearchScope(kind='selected_months', months=months_t) if months_t else \
                SearchScope(kind='provided_files', doc_ids=ids_t)
        except (ValidationError, ValueError):
            raise _fail('PT-KBC-SCOPE', 'the scope names an invalid month (YYYY-Mon) or document id') from None

    @staticmethod
    def _read_small(path: Path) -> str:
        try:
            with open(path, 'rb') as handle:
                data = handle.read(SCOPE_FILE_BYTES + 1)
        except OSError:
            raise _fail('PT-KBC-INPUT', 'the scope file cannot be read') from None
        if len(data) > SCOPE_FILE_BYTES:
            raise _fail('PT-KBC-SCOPE', 'the scope file is too large')
        return data.decode('utf-8', errors='replace')

    @staticmethod
    def _lookup(index: ReverseIndex, kind: str, value: str, scope: SearchScope | None, scope_id: str | None,
                now: str) -> Lookup:
        look = index.lookup_kb if kind == 'kb' else index.lookup_cve
        return look(value, scope=scope, scope_id=scope_id, now=now)

    # ------------------------------------------------------------------------------------------ search

    def search(self, lead: str, *, months: str | None = None, scope_file: Path | None = None,
               product: str | None = None, investigation: str | None = None) -> Outcome:
        kind, value = parse_lead(lead)
        with self._open() as ws:
            index, unreadable = load_index(ws, self.ports)
            scope = self._scope(index, months, scope_file)
            now = self._now()
            full = self._lookup(index, kind, value, scope, None, now)
            names = {s.scope_id: s.display_name for s in full.scopes}
            if product is not None and product not in names:
                raise _fail('PT-KBC-INPUT', 'that product is not one of the products listed for the lead')
            shown = self._lookup(index, kind, value, scope, product, now) if product else full
            rev = self._get(ws, investigation) if investigation else None
            ws.put_coverage(full.coverage)
            rev = self._record_search(ws, rev, Lead(kind=kind, value=value, raw=lead.strip()[:200]), full, product)
            cves = sorted({e.cve for e in shown.edges}) if kind == 'kb' else [value]
            cards = [_card_dict(c) for cve in cves for c in self._lookup(index, 'cve', cve, scope, None, now).cards]
        return self._search_outcome(rev, kind, value, full, shown, product, cards, names, unreadable)

    def _record_search(self, ws: WorkspaceStore, rev: InvestigationRevision | None, lead: Lead, full: Lookup,
                       product: str | None) -> InvestigationRevision:
        if rev is None:
            rev = InvestigationRevision(investigation_id=str(uuid.uuid4()), revision=1, lead=lead, state='NEW')
            ws.create_investigation(rev)
        if rev.state == 'NEW':
            rev = self._step(ws, rev, 'lead_parsed')
        rev = self._step(ws, rev, 'search_done', outcome=OUTCOME_BY_STATUS[full.status],
                         scope_ids=tuple(sorted(s.scope_id for s in full.scopes)),
                         coverage_ids=(full.coverage.coverage_id,), warnings=tuple(w[:500] for w in full.warnings))
        if product:
            rev = self._step(ws, rev, 'product_selected', scope_id=product)
        return rev

    def _search_outcome(self, rev, kind, value, full, shown, product, cards, names, unreadable) -> Outcome:
        scopes = [_scope_dict(s) for s in full.scopes]
        kept = {(e.cve, e.kb, e.scope_id) for e in shown.edges}
        elsewhere = [_plain_edge(e, names) for e in full.edges if (e.cve, e.kb, e.scope_id) not in kept]
        warnings = list(full.warnings)
        if unreadable:
            warnings.append(f'{len(unreadable)} stored document(s) could not be read and were not searched')
        status = 'partial' if full.status in ('partial', 'not_searched') or (
            unreadable and full.status == 'not_observed') else full.status
        result = {'contract': 'kbcorrelation/1', 'investigation_id': rev.investigation_id, 'state': rev.state,
                  'lead': {'kind': kind, 'value': value}, 'coverage': {'state': full.coverage.state,
                                                                       'text': full.text, 'detail': full.coverage
                                                                       .model_dump(mode='json')},
                  'scopes': scopes, 'edges': [_edge_dict(g, names) for g in shown.groups], 'cards': cards,
                  'mention_only': [_plain_edge(e, names) for e in shown.mention_only],
                  'not_applicable': elsewhere, 'disputed': [_plain_edge(e, names) for e in shown.disputed],
                  'warnings': warnings, 'next': 'kb.next.choose_product' if len(scopes) > 1 and not product else None}
        lines = [full.text]
        lines += [f'{e["kb"]}  {e["cve"]}  {e["product"]}  {e["label"]}' for e in result['edges']]
        lines += [f'Mentioned only: {e["cve"]} (advisory text, not a remediation)' for e in result['mention_only']]
        if len(scopes) > 1 and not product:
            lines.append(TEXT_KB6)
        if elsewhere and product:
            lines.append(TEXT_KB8.format(product=names.get(product, product)))
        exit_code = {'found': 0, 'not_observed': 4}.get(status, 3)
        public = {'found': 'complete', 'not_observed': 'unavailable'}.get(status, 'partial')
        if status == 'not_observed':
            lines.append(f'{value} was not found in the documents checked. That does not mean it has no security '
                         'updates; these documents do not list it.')
        return Outcome(exit_code, public, result, '\n'.join(lines), warnings)

    # ------------------------------------------------------------------------------------------ products, components

    def products(self, investigation: str) -> Outcome:
        with self._open() as ws:
            rev = self._get(ws, investigation)
            index, _ = load_index(ws, self.ports)
        wanted = set(rev.scope_ids)
        scopes = [_scope_dict(s) for s in index.scopes() if s.scope_id in wanted]
        result = {'contract': 'kbcorrelation/1', 'investigation_id': rev.investigation_id,
                  'selected_scope_id': rev.selected_scope_id, 'products': scopes}
        if not scopes:
            return Outcome(4, 'unavailable', result, 'The search found no product for this lead.')
        lines = [f'{s["scope_id"][:12]}  {s["display_name"]}  {s["architecture"]}  ({s["mapping"]} mapping)'
                 for s in scopes]
        if len(scopes) > 1 and rev.selected_scope_id is None:
            lines.append(TEXT_KB6)
        return Outcome(0, 'complete', result, '\n'.join(lines))

    def components(self, investigation: str, *, product: str | None, files: Iterable[str]) -> Outcome:
        try:
            names = [comp.normalise_name(f) for f in files]
        except ValueError as exc:
            raise _fail('PT-KBC-INPUT', str(exc)) from None
        with self._open() as ws:
            rev = self._get(ws, investigation)
            scope_id = product or rev.selected_scope_id
            if scope_id is None:
                raise _fail('PT-KBC-INPUT', TEXT_KB6)
            if scope_id not in rev.scope_ids:
                raise _fail('PT-KBC-INPUT', 'that product is not one of the products listed for the lead')
            if rev.selected_scope_id != scope_id:
                rev = self._step(ws, rev, 'product_selected', scope_id=scope_id)
            for name in names:
                self._decide(ws, rev.investigation_id, 'component-name', rev.state, name,
                             'File name entered by the analyst; a user assertion, not evidence.')
            entered = sorted({*names, *(d.next for d in ws.decisions(rev.investigation_id)
                                        if d.op == 'component-name')})
            index, _ = load_index(ws, self.ports)
            cards, refs = self._lead_cards(index, rev, ws)
            hints, truncated = comp.hints_for(cards, refs, entered, scope_id)
            rev = self._step(ws, rev, 'components_ready' if comp.selectable(hints) else 'needs_filename')
        result = {'contract': 'kbcorrelation/1', 'investigation_id': rev.investigation_id, 'state': rev.state,
                  'scope_id': scope_id, 'truncated': truncated,
                  'hints': [h.model_dump(mode='json', exclude={'contract'}) for h in hints]}
        lines = [f'{h.tier}  {h.basename}  ({"; ".join(h.reasons)}); changed in this KB: {h.changed_in_kb}'
                 for h in hints]
        if rev.state == 'NEEDS_FILENAME':
            lines.append(TEXT_KB7)
        return Outcome(0 if comp.selectable(hints) else 4, 'complete' if comp.selectable(hints) else 'unavailable',
                       result, '\n'.join(lines))

    def _lead_cards(self, index: ReverseIndex, rev: InvestigationRevision,
                    ws: WorkspaceStore) -> tuple[list[CveCard], dict[str, SourceRef]]:
        cves, _, _ = self._lead_cves(index, rev, ws)
        cards: list[CveCard] = []
        refs: dict[str, SourceRef] = {}
        for cve in cves:
            look = index.lookup_cve(cve, scope_id=rev.selected_scope_id, now=self._now())
            cards += look.cards[:1]
            if look.edges:
                edge = look.edges[0]
                refs[cve] = SourceRef(doc_id=edge.ref.doc_id, pointer=vulnerability_pointer(edge.ref.pointer),
                                      assertion='advisory_fact')
        return cards, refs

    def _lead_cves(self, index: ReverseIndex, rev: InvestigationRevision,
                   ws: WorkspaceStore) -> tuple[tuple[str, ...], tuple[str, ...], tuple[Coverage, ...]]:
        """CVEs the lead names under the selected product, CVEs mentioned only, and the stored search coverage."""
        coverage = tuple(c for c in (ws.get_coverage(i) for i in rev.coverage_ids) if c is not None)
        now, scope_id, lead = self._now(), rev.selected_scope_id, rev.lead
        if lead.kind == 'kb':
            look = index.lookup_kb(lead.value, scope_id=scope_id, now=now)
            return (tuple(sorted({e.cve for e in look.edges})), tuple(sorted({e.cve for e in look.mention_only})),
                    coverage or (look.coverage,))
        if lead.kind == 'cve':
            return (lead.value,), (), coverage
        return (), (), coverage

    def _lead_kbs(self, index: ReverseIndex, rev: InvestigationRevision) -> dict[str, str | None]:
        """KB ids the lead leads to under the selected product, each with its one vendor-stated fixed build (or None
        when the documents state none or disagree)."""
        lead, scope_id, now = rev.lead, rev.selected_scope_id, self._now()
        if lead.kind == 'kb':
            look = index.lookup_kb(lead.value, scope_id=scope_id, now=now)
            kbs = {lead.value}
        elif lead.kind == 'cve':
            look = index.lookup_cve(lead.value, scope_id=scope_id, now=now)
            kbs = {e.kb for e in look.edges}
        else:
            raise _fail('PT-KBC-INPUT', 'this investigation started from two files and has no KB to look up')
        fixed = {kb: {e.fixed_build for e in look.edges if e.kb == kb and e.fixed_build} for kb in kbs}
        return {kb: next(iter(builds)) if len(builds) == 1 else None for kb, builds in sorted(fixed.items())}

    def _unanswered(self, rev: InvestigationRevision, reason: str, text: str) -> Outcome:
        result = {'contract': 'kbcorrelation/1', 'investigation_id': rev.investigation_id, 'pairs': [],
                  'reason': reason}
        return Outcome(4, 'unavailable', result, text)

    def _resolve_pairs(self, investigation: str, product: str | None, files: Iterable[str]):
        """``(revision, resolutions, skipped_rows, files_without_record)``, or ``(revision, Outcome)`` when the
        offline file index cannot answer. Read-only: the investigation is not advanced."""
        try:
            names = [comp.normalise_name(f) for f in files]
        except ValueError as exc:
            raise _fail('PT-KBC-INPUT', str(exc)) from None
        file_index = self.env.file_index(self.root) if self.env.file_index else None
        with self._open() as ws:
            rev = self._get(ws, investigation)
            if file_index is None or not file_index.available():
                return rev, self._unanswered(rev, 'file index not available offline', TEXT_PAIRS_E0)
            scope_id = product or rev.selected_scope_id
            if scope_id is None:
                raise _fail('PT-KBC-INPUT', TEXT_KB6)
            if scope_id not in rev.scope_ids:
                raise _fail('PT-KBC-INPUT', 'that product is not one of the products listed for the lead')
            rev = rev.model_copy(update={'selected_scope_id': scope_id})
            index, _ = load_index(ws, self.ports)
            scope = next(s for s in index.scopes() if s.scope_id == scope_id)
            entered = sorted({*names, *(d.next for d in ws.decisions(rev.investigation_id)
                                        if d.op == 'component-name')})
            cards, refs = self._lead_cards(index, rev, ws)
            hints, _ = comp.hints_for(cards, refs, entered, scope_id)
            chosen = sorted({h.basename for h in hints if h.tier in comp.SELECTING_TIERS})
            kbs = self._lead_kbs(index, rev)
        if not chosen:
            return rev, self._unanswered(rev, 'no file name', TEXT_KB7)
        covered = scope.family != 'windows-server' and scope.winbindex_key is not None
        found, skipped, missing = [], 0, []
        for name in chosen:  # the index is consulted only where it can answer; the resolver states why otherwise
            rows, gap = file_index.rows(name, scope.winbindex_key) if covered else ((), 0)
            if covered and not rows and not gap:
                missing.append(name)
                continue
            skipped = max(skipped, gap)
            found += [resolver.resolve(rows, kb=kb, scope=scope, file_name=name, fixed_build=fixed,
                                       skipped_rows=gap) for kb, fixed in kbs.items()]
        return rev, found, skipped, missing

    @staticmethod
    def _candidate_dict(res: resolver.Resolution, pair) -> dict:
        return {**KbService._pair_dict(pair), 'kb': res.kb, 'file_name': res.file_name,
                'changed_in_kb': res.changed_in_kb, 'window': list(pair.window),
                'older_availability': pair.older.availability, 'newer_availability': pair.newer.availability}

    @staticmethod
    def _resolution_dict(res: resolver.Resolution) -> dict:
        return {'kb': res.kb, 'file_name': res.file_name, 'version_key': res.version_key,
                'changed_in_kb': res.changed_in_kb, 'last_changed_in': res.last_changed_in,
                'blockers': list(res.blockers), 'note': res.note, 'skipped_rows': res.skipped_rows,
                'truncated': res.truncated}

    def pairs(self, investigation: str, *, product: str | None = None, files: Iterable[str] = ()) -> Outcome:
        got = self._resolve_pairs(investigation, product, files)
        if isinstance(got[1], Outcome):
            return got[1]
        rev, found, skipped, missing = got
        candidates = [self._candidate_dict(res, pair) for res in found for pair in res.pairs]
        result = {'contract': 'kbcorrelation/1', 'investigation_id': rev.investigation_id,
                  'scope_id': rev.selected_scope_id, 'pairs': candidates,
                  'resolutions': [self._resolution_dict(r) for r in found], 'files_without_record': missing,
                  'skipped_rows': skipped}
        lines = [f'{c["grade"]}/{c["tier"]}  {c["file_name"]}  {c["kb"]}  older {c["older_sha256"][:12]} -> newer '
                 f'{c["newer_sha256"][:12]}  [{", ".join(c["reason_codes"]) or "no flags"}]  {c["pair_id"][:12]}'
                 for c in candidates]
        lines += [f'{r.file_name}  {r.kb}: {r.note}' for r in found if not r.pairs and r.note]
        lines += [f'{name}: no Winbindex record is saved in this workspace.' for name in missing]
        text = '\n'.join(lines)
        if skipped:  # an index with unreadable entries cannot say the newest builds are absent
            return Outcome(3, 'partial', result, text,
                           [f'{skipped} file-index entries could not be read, so newer builds may be missing.'])
        return Outcome(0, 'complete', result, text) if candidates else Outcome(4, 'unavailable', result, text)

    @staticmethod
    def _block_text(pair) -> str:
        arch = next((f.machine for f in (pair.older, pair.newer) if f.machine != pr.SUPPORTED_ARCH), 'not AMD64')
        blocking = [c for c in pair.reason_codes if c in HARD_BLOCKS or c == 'ORDER_UNVERIFIED']
        return ' '.join(pr.reason_text(code, arch=arch, k=len(pair.window)) for code in blocking)

    def plan(self, investigation: str, *, pair_id: str | None = None, product: str | None = None,
             files: Iterable[str] = ()) -> Outcome:
        got = self._resolve_pairs(investigation, product, files)
        if isinstance(got[1], Outcome):
            return got[1]
        rev, found, _, _ = got
        every = [pair for res in found for pair in res.pairs]
        if pair_id is None:
            pair = next((p for p in every if p.grade != 'X'), None)
        else:
            pair = next((p for p in every if p.pair_id.startswith(pair_id)), None)
            if pair is None:
                raise _fail('PT-KBC-INPUT', 'that pair is not a candidate for this lead; list them with "kb pairs"')
        result = {'contract': 'kbcorrelation/1', 'investigation_id': rev.investigation_id, 'plan': None, 'pair': None}
        if pair is None:
            return Outcome(4, 'unavailable', result, 'There is no pair candidate to plan; see "kb pairs".')
        result['pair'] = self._pair_dict(pair)
        if pair.grade == 'X':
            text = self._block_text(pair)
            return Outcome(2, 'failed', result, text, error=f'{", ".join(pair.reason_codes)}: {text}')
        plan = index_plan(pair)
        result['plan'] = plan.as_dict()
        return Outcome(0, 'complete', result, plan.text)

    # ------------------------------------------------------------------------------------------ import-pair

    def import_pair(self, investigation: str, older: str, newer: str, directory: str, *, name: str | None = None,
                    confirm_same_component: bool = False, dry_run: bool = False) -> Outcome:
        older_f, newer_f = self.env.inspect(older), self.env.inspect(newer)
        with self._open() as ws:
            rev = None if investigation == 'new' else self._get(ws, investigation)
            scope_id = rev.selected_scope_id if rev and rev.selected_scope_id else UNSELECTED_SCOPE
            pair = pr.propose_manual(older_f, newer_f, scope_id=scope_id,
                                     confirm_same_component=confirm_same_component)
            plan = local_plan(pair)
            if pair.grade == 'X':
                return self._blocked(pair)
            if dry_run:
                return Outcome(0, 'complete', {'contract': 'kbcorrelation/1', 'plan': plan.as_dict(),
                                               'pair': self._pair_dict(pair)}, plan.text)
            rev = self._approve_pair(ws, rev, pair, older_f, newer_f, confirm_same_component)
            index, _ = load_index(ws, self.ports)
            bundle = self._bundle(index, ws, rev, base=rev.revision, pair_id=pair.pair_id, older=pair.older.sha256,
                                  newer=pair.newer.sha256)
            request = AttachRequest(revision=rev, pair_id=pair.pair_id, older_path=older, newer_path=newer,
                                    older_sha=pair.older.sha256, newer_sha=pair.newer.sha256, directory=directory,
                                    source_shas=tuple(d.sha256 for d in bundle.sources), plan_sha=plan.plan_sha)
            port = self.env.project(ws, clean_text(name or '', 200) or 'KB comparison')
            outcome = ProjectAttachment(ws, port).attach(request, ((bundle.context_key,
                                                                    bundle.model_dump_json().encode()),))
        return self._attach_outcome(outcome, rev.investigation_id, pair, plan.plan_sha, bundle.context_key)

    @staticmethod
    def _pair_dict(pair) -> dict:
        return {'pair_id': pair.pair_id, 'grade': pair.grade, 'tier': pair.tier, 'bytes_state': pair.bytes_state,
                'lineage_state': pair.lineage_state, 'fix_boundary': pair.fix_boundary,
                'reason_codes': list(pair.reason_codes), 'older_sha256': pair.older.sha256,
                'newer_sha256': pair.newer.sha256, 'older_name': pair.older.basename,
                'newer_name': pair.newer.basename}

    def _blocked(self, pair) -> Outcome:
        codes = pr.blocking_reasons(pair)
        result = {'contract': 'kbcorrelation/1', 'pair': self._pair_dict(pair), 'project': None}
        text = pr.blocking_text(pair)
        if codes == ('IDENTICAL_CONTENT',):  # complete answer, nothing to compare
            return Outcome(4, 'unavailable', result, text, error=None)
        return Outcome(2, 'failed', result, text, error=f'{", ".join(codes)}: {text}')

    def _approve_pair(self, ws: WorkspaceStore, rev: InvestigationRevision | None, pair, older_f: LocalFile,
                      newer_f: LocalFile, confirmed: bool) -> InvestigationRevision:
        """New or existing investigation to BYTES_VERIFIED for this pair, recording each analyst decision."""
        if rev is None:
            rev = InvestigationRevision(
                investigation_id=str(uuid.uuid4()), revision=1, state='NEW',
                lead=Lead(kind='pair', value=older_f.basename, raw=f'{older_f.basename} {newer_f.basename}'))
            ws.create_investigation(rev)
        if rev.state == 'BYTES_VERIFIED' and rev.selected_pair_id == pair.pair_id:
            return rev  # an earlier run stopped before the attach finished; the attach itself is idempotent
        if rev.state == 'NEW':
            rev = self._step(ws, rev, 'lead_parsed')
        inv = rev.investigation_id
        rev = self._step(ws, rev, 'pair_proposed', outcome='PAIR_PROPOSED', pair_id=pair.pair_id)
        self._decide(ws, inv, 'orientation', 'unverified',
                     f'older={pair.older.sha256[:12]} newer={pair.newer.sha256[:12]}',
                     'Older and newer were chosen by the analyst; the release order was not established.')
        if confirmed and older_f.basename != newer_f.basename:
            self._decide(ws, inv, 'name-mismatch-confirmation', 'NAME_MISMATCH', 'same component',
                         'The analyst confirmed that the two differently named files are the same component.')
        rev = self._step(ws, rev, 'pair_approved', pair_id=pair.pair_id)
        self._decide(ws, inv, 'pair-approval', 'PAIR_PROPOSED', 'PAIR_APPROVED',
                     f'Manual pair grade {pair.grade}, tier {pair.tier}; bytes {pair.bytes_state}, lineage '
                     f'{pair.lineage_state}, fix boundary {pair.fix_boundary}; reasons {", ".join(pair.reason_codes)}.')
        return self._step(ws, rev, 'bytes_verified', parsed=True, both_sides=True)

    def _bundle(self, index: ReverseIndex, ws: WorkspaceStore, rev: InvestigationRevision, *, base: int,
                pair_id: str | None, older: str | None, newer: str | None) -> ContextBundle:
        cves, mention, coverage = self._lead_cves(index, rev, ws)
        return build_bundle(investigation_id=rev.investigation_id, base_revision=base, lead=rev.lead, cves=cves,
                            index=index, rules=self.env.rules, now=self._now(), coverage=coverage,
                            scope_id=rev.selected_scope_id, pair_id=pair_id, older_sha=older, newer_sha=newer,
                            mention_only=mention)

    def _attach_outcome(self, outcome, investigation_id: str, pair, plan_sha: str, context_key: str) -> Outcome:
        link = outcome.value
        result = {'contract': 'kbcorrelation/1', 'investigation_id': investigation_id,
                  'pair': self._pair_dict(pair), 'plan_sha': plan_sha, 'context_key': context_key,
                  'project': link.model_dump(mode='json', exclude={'contract'}) if link else None}
        if outcome.status == 'ok':
            return Outcome(0, 'complete', result, TEXT_KB13, list(outcome.warnings))
        warnings = list(outcome.warnings)
        if link is not None:
            result['issues'] = [i.model_dump(mode='json') for i in outcome.issues]
            return Outcome(3, 'partial', result, 'The comparison project was created, but the advisory context could '
                           'not be attached. Run "kb attach --repair"; the project is unaffected.', warnings)
        issue = outcome.issues[0]
        raise KbcStoreError(issue.code, issue.message, recoverable=issue.recoverable, details=issue.details)

    # ------------------------------------------------------------------------------------------ attach

    def attach(self, project_dir: str, investigation: str, *, repair_it: bool) -> Outcome:
        directory = Path(project_dir).resolve().as_posix()
        with self._open(create=False) as ws:
            self._get(ws, investigation)
            ours = self._ops_for(ws, directory, investigation)
            if not ours:
                raise _fail('PT-KBC-UNSUPPORTED', 'this workspace did not create that project, and attaching '
                            'context to a foreign project arrives with a later slice')
            if not repair_it:
                return self._link_outcome(ours, None, 'Context is not attached yet. Run "kb attach --repair".')
            index, _ = load_index(ws, self.ports)
            port = self.env.project(ws, 'KB comparison')
            result = repair(ws, port, context_for=lambda op, body: self._rebuilt_rows(index, ws, body),
                            only=lambda body: body['directory'] == directory
                            and body['revision']['investigation_id'] == investigation)
            return self._link_outcome(self._ops_for(ws, directory, investigation), result,
                                      'The context is still pending; see the issues.')

    @staticmethod
    def _link_outcome(ops: list[tuple[str, str, dict]], result, pending_text: str) -> Outcome:
        links = [{'project_id': body['project_id'], 'project_revision': body['project_revision'],
                  'state': (body['link_state'] or 'context-pending') if state == 'done' else 'intent',
                  'pair_id': body['pair_id']} for _, state, body in ops]
        done = all(link['state'] == 'attached' for link in links)
        payload = {'contract': 'kbcorrelation/1', 'links': links,
                   'issues': [i.model_dump(mode='json') for i in result.issues] if result else []}
        warnings = list(result.warnings) if result else []
        return Outcome(0 if done else 3, 'complete' if done else 'partial', payload,
                       TEXT_KB13 if done else pending_text, warnings)

    @staticmethod
    def _ops_for(ws: WorkspaceStore, directory: str, investigation: str) -> list[tuple[str, str, dict]]:
        return [(op, state, body) for op, state, body in ws.journal_ops()
                if body['directory'] == directory and body['revision']['investigation_id'] == investigation]

    def _rebuilt_rows(self, index: ReverseIndex, ws: WorkspaceStore, body: dict) -> tuple[tuple[str, bytes], ...]:
        rev = InvestigationRevision.model_validate_json(json.dumps(body['revision']))
        bundle = self._bundle(index, ws, rev, base=body['base'], pair_id=body['pair_id'], older=body['older_sha'],
                              newer=body['newer_sha'])
        return ((bundle.context_key, bundle.model_dump_json().encode()),)

    # ------------------------------------------------------------------------------------------ explain, export

    def _project_bundles(self, project_dir: str) -> list[ContextBundle]:
        port = self.env.project(None, 'KB comparison')
        project_id = port.open_project(project_dir)
        try:
            rows = port.list_rows(project_id, 'kb-context')
            bundles = [ContextBundle.model_validate_json(body) for body in rows.values()]
        except ValidationError:
            raise _fail('PT-KBC-VERIFY', 'a stored advisory context failed validation') from None
        return sorted(bundles, key=lambda b: (b.base_revision, b.context_key))

    def explain(self, project_dir: str, cve: str | None) -> Outcome:
        bundles = self._project_bundles(project_dir)
        if not bundles:
            return Outcome(4, 'unavailable', {'contract': 'kbcorrelation/1', 'cves': []}, TEXT_KB17)
        bundle = bundles[-1]
        wanted = normalise_cve(cve) if cve else None
        rows = []
        for card, profile, hypothesis in zip(bundle.context.cards, bundle.cwe_profiles, bundle.hypotheses,
                                             strict=True):
            if wanted is None or card.cve == wanted:
                rows.append({'cve': card.cve, 'card': _card_dict(card),
                             'cwe_status': profile.status,
                             'hypotheses': [h.model_dump(mode='json') for h in hypothesis.hypotheses],
                             'hypothesis_unknowns': list(hypothesis.unknowns)})
        result = {'contract': 'kbcorrelation/1', 'context_key': bundle.context_key, 'cves': rows,
                  'coverage': [c.model_dump(mode='json') for c in bundle.context.coverage],
                  'unknowns': list(bundle.context.unknowns), 'limitations': list(bundle.context.limitations),
                  'hooks': list(bundle.context.hooks)}
        if not rows:
            return Outcome(4, 'unavailable', result, f'{wanted} is not part of this project\'s advisory context.')
        lines = []
        for row in rows:
            card = row['card']
            lines.append(f'{row["cve"]}: {card["title"] or "no title"}')
            if card['stated_cwe']:
                lines.append(f'  {card["stated_cwe"]} {card["stated_by"]}')
            lines += [f'  Hypothesis {h["rule_id"]}: {"; ".join(h["expected_operations"])}' for h in row['hypotheses']]
            lines.append(f'  Applicability: {card["applicability"]}; KEV: {card["kev"]}')
        lines += [f'Unknown: {u}' for u in bundle.context.unknowns] + [f'Limit: {x}' for x in bundle.context.limitations]
        return Outcome(0, 'complete', result, '\n'.join(lines))

    def export(self, project_dir: str, target: str, *, overwrite: bool) -> Outcome:
        path = Path(target)
        fmt = EXTENSIONS.get(path.suffix.lower())
        if fmt is None:
            raise _fail('PT-KBC-INPUT', 'the export file must end in .json or .md')
        if path.exists() and not overwrite:
            raise _fail('PT-KBC-INPUT', 'the export file already exists; pass --overwrite to replace it')
        bundles = self._project_bundles(project_dir)
        if not bundles:
            return Outcome(4, 'unavailable', {'contract': 'kbcorrelation/1', 'written': False}, TEXT_KB17)
        bundle = bundles[-1]
        data = to_json(bundle) if fmt == 'json' else to_markdown(bundle, self.env.escape).encode('utf-8')
        try:
            atomic_write(path, data)
        except OSError:
            raise _fail('PT-KBC-STORAGE', 'the export file cannot be written') from None
        result = {'contract': 'kbcorrelation/1', 'written': True, 'format': fmt, 'file': path.name,
                  'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'context_key': bundle.context_key}
        return Outcome(0, 'complete', result, f'Wrote {path.name} ({len(data)} bytes).')
