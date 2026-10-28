"""CVE-grouped leads: which changed functions an advisory context may explain (KB-integration-plan 4, 7.2 `LeadRow`;
slice K4a). Pure; reads the engine only through :class:`EngineEvidence`.

Rules that keep the claim small:

* a function joins CVE group G when a detector signal of G's stated CWE family fires on it at an aligning confidence
  (the map and the confidences arrive as :class:`Alignment`, bound by the caller); every other function goes to
  ``unattributed``, which is always listed. Several groups per function are allowed, one :class:`LeadRow` each.
* inside a group the engine's own order is kept; groups sort by (KEV listed, supporting channel set, CVE id). KEV is a
  group header chip only: it moves a group, never a function within it, and it never counts as supporting evidence.
* the only number shown is the engine's attention order, labelled as such; channels are listed in words, never counted.
  Missing or unavailable evidence is ``unknown`` or ``not-run``, never a negative vote. Contested engine verdicts keep
  the lead and say so.
* a CVE the context does not cover for the chosen product is listed apart (``not_applicable``) and contributes nothing;
  a mention in advisory text only is ``mention_only``.
* stale means the project's ordered SHA-256 pair differs from the pair the context was prepared for, or an advisory
  document the context was prepared from has been replaced by a newer imported revision; navigation is off and
  ``stale_reasons`` says which. A ranking from an earlier analysis run is never read (``load_default`` guards it), and the
  engine's reason is shown instead of "not ranked yet".
"""
from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

from .context import ContextBundle
from .contracts import (
    Channel,
    Chip,
    ChipState,
    ContextReport,
    Contract,
    Coverage,
    CveCard,
    CveId,
    Hook,
    LeadNav,
    LeadRow,
    Record,
    Sha256,
    Short,
    domain_id,
)
from .products import clean_text
from .sources.scope import coverage_text

LeadsState = Literal['ready', 'no-comparison', 'no-advisory', 'stale']
StaleReason = Literal['file-pair', 'advisory-revision']
KevState = Literal['listed', 'not-listed', 'no-snapshot']

TEXT_NO_COMPARISON = ('No comparison has been ranked for this project yet, so only the advisory context is shown. '
                      'Run the comparison and rank it to see leads.')
TEXT_NO_ADVISORY = ('No advisory context is attached to this project, so the engine\'s own order is shown alone. '
                    'Search a KB or CVE to attach one.')
TEXT_STALE_PAIR = 'This context was prepared for a different file pair.'
TEXT_STALE_ADVISORY = 'A newer revision of an advisory document this context was prepared from has been imported since.'
TEXT_STALE_TAIL = 'It is shown for reference; navigation is off.'
TEXT_NO_CURRENT_RANKING = ('The stored ranking does not match the current analysis, so only the advisory context is '
                           'shown. {note}')
TEXT_READY = ('Leads pair the advisory context with the comparison. The order inside a group is the engine\'s own '
              'attention order; it does not show that any changed function addresses a vulnerability.')
TEXT_GUARD = 'absence of a signal is not a negative finding'
BASIS_RANKED = 'attention order {rank} of {total} (the engine\'s own order, not a measure of risk)'
BASIS_UNRANKED = 'no attention order (the engine did not rank this change)'
KEV_TEXTS = {'no-snapshot': 'KEV: not loaded', 'not-listed': 'KEV: not in the loaded snapshot'}
KevSourceState = Literal['loaded', 'not-loaded', 'unreadable']
TEXT_KEV_NOT_LOADED = 'KEV: not loaded.'
UNATTRIBUTED = 'unattributed'
_LINE_SEPARATORS = str.maketrans({'\u2028': ' ', '\u2029': ' '})


def plain_text(value: object, limit: int = 1000) -> str:
    """Untrusted text for display: ``clean_text`` plus the Unicode line and paragraph separators it keeps."""
    return clean_text(value.translate(_LINE_SEPARATORS) if isinstance(value, str) else value, limit)


# ---------------------------------------------------------------------------------------------- ports

@dataclass(frozen=True)
class EngineSignal:
    detector: str
    confidence: str
    group_key: str
    summary: str = ''


@dataclass(frozen=True)
class EngineRow:
    match_id: str
    name: str
    change: Literal['modified', 'added', 'removed']
    attention_rank: int | None
    signals: tuple[EngineSignal, ...] = ()
    verdicts: tuple[tuple[str, str], ...] = ()  # (engine, 'changed' | 'unchanged' | 'unknown')


@dataclass(frozen=True)
class EngineView:
    project_revision: int
    run_id: str | None
    older_sha: str
    newer_sha: str
    rows: tuple[EngineRow, ...]


class EngineEvidence(Protocol):
    """Read-only view of a project's stored ranking and signals; never runs an engine. None: nothing ranked yet."""

    def read(self, project_dir: str) -> EngineView | None: ...


@dataclass(frozen=True)
class Alignment:
    """CWE -> detector families and the confidences that count as alignment (``enrichment.cve`` supplies both)."""
    detectors: Mapping[str, tuple[str, ...]]
    aligning: frozenset[str]

    def hits(self, cwe: str | None, row: EngineRow) -> tuple[EngineSignal, ...]:
        wanted = self.detectors.get(cwe or '', ())
        return tuple(s for s in row.signals if s.detector in wanted and s.confidence in self.aligning)


@dataclass(frozen=True)
class KevFact:
    """What the loaded KEV snapshot says about one CVE. ``snapshot_sha256`` is the snapshot id; the catalog version,
    freshness and age come from a real snapshot (``adapters.kev``) and stay None for a bare fact."""
    state: KevState
    date_added: str | None = None
    snapshot_sha256: str | None = None
    catalog_version: str | None = None
    freshness: str | None = None
    age_days: int | None = None


class ExploitationLookup(Protocol):
    """Answers one CVE. A lookup may also carry ``source`` (a :class:`KevSource`); one without it is reported as
    not loaded at report level (capability probe, plan 9 K8)."""

    def status(self, cve: str) -> KevFact: ...


class NullExploitation:
    """KEV is not loaded: every answer is 'not loaded'."""

    def status(self, cve: str) -> KevFact:
        return KevFact('no-snapshot')


@dataclass(frozen=True)
class NotApplicable:
    cve: str
    products: tuple[str, ...]
    stated_cwe: str | None = None


# ---------------------------------------------------------------------------------------------- report

class LeadGroup(Record):
    group: CveId
    kev: KevState
    kev_text: Short
    cwe: Short | None = None
    cwe_text: Short | None = None
    hypotheses: tuple[Short, ...] = ()
    leads: tuple[LeadRow, ...] = ()


class NotApplicableCve(Record):
    cve: CveId
    products: tuple[Short, ...]
    stated_cwe: Short | None = None
    text: Short


class KevSource(Record):
    """The KEV snapshot behind every group's KEV chip, for the whole report: identity, origin and age, or why there is
    none. ``unreadable`` means catalogs are stored but none could be read; it says nothing about any CVE."""
    state: KevSourceState = 'not-loaded'
    text: Short = TEXT_KEV_NOT_LOADED
    snapshot_id: Sha256 | None = None
    catalog_version: Short | None = None
    date_released: Short | None = None
    retrieved_at: Short | None = None
    source: Short | None = None
    authenticity: Short | None = None
    freshness: Short | None = None
    age_days: int | None = None
    banner: Short | None = None
    notes: tuple[Short, ...] = ()


class LeadsReport(Contract):
    state: LeadsState
    text: Short
    context_key: Sha256 | None = None
    project_revision: int | None = None
    run_id: Short | None = None
    stale: bool = False
    stale_reasons: tuple[StaleReason, ...] = ()
    coverage: tuple[Coverage, ...] = ()
    coverage_text: tuple[Short, ...] = ()
    groups: tuple[LeadGroup, ...] = ()
    unattributed: tuple[LeadRow, ...] = ()
    not_applicable: tuple[NotApplicableCve, ...] = ()
    mention_only: tuple[CveId, ...] = ()
    unknowns: tuple[Short, ...] = ()
    limitations: tuple[Short, ...] = ()
    truncated: int = 0
    hooks: tuple[Hook, ...] = ()
    kev_source: KevSource = KevSource()


# ---------------------------------------------------------------------------------------------- chips

def _chip(channel: Channel, state: ChipState, text: str) -> Chip:
    return Chip(channel=channel, state=state, text=plain_text(text, 500) or channel)


def _contested(row: EngineRow) -> str | None:
    seen = {verdict for _, verdict in row.verdicts}
    if {'changed', 'unchanged'} <= seen:
        pairs = ', '.join(f'{engine} {verdict}' for engine, verdict in sorted(row.verdicts))
        return f'engines disagree ({pairs})'
    return None


def _code_chip(row: EngineRow, hits: Sequence[EngineSignal], aligned: bool = True) -> Chip:
    contested = _contested(row)
    if contested:
        return _chip('code-change', 'contradicts', f'contradicts: {contested}')
    if hits:
        first = hits[0]
        note = f': {first.summary}' if first.summary else ''
        return _chip('code-change', 'supports', f'observed {first.detector} signal ({first.confidence}){note}')
    if row.change != 'modified':
        return _chip('code-change', 'unknown', f'{row.change} function: no older/newer pair to compare')
    if row.signals:
        names = ', '.join(sorted({s.detector for s in row.signals}))
        what = 'the stated CWE' if aligned else 'any applicable CVE'
        return _chip('code-change', 'neutral', f'detector signals ({names}) do not align with {what}')
    return _chip('code-change', 'unknown', f'no detector signal; {TEXT_GUARD}')


def _member_chips(card: CveCard, rules: Sequence[str], row: EngineRow, hits: Sequence[EngineSignal],
                  kev: KevFact, pair_stale: bool) -> tuple[Chip, ...]:
    detectors = ', '.join(sorted({s.detector for s in hits}))
    rule = rules[0] if rules else 'no curated hypothesis'
    doc = f'stated by vendor ({card.source_kind.upper()}), unverified local file; 1 source family'
    return (
        _chip('documentary', 'supports', f'{card.cve}: {doc}'),
        _chip('applicability', 'unknown', card.applicability or 'applicability unknown'),
        _kev_chip(kev),
        _chip('hypothesis', 'supports', f'hypothesis {rule} aligns with detector {detectors}'),
        _chip('binary-identity', 'unknown' if pair_stale else 'supports',
              'the file pair differs from the one the context was prepared for' if pair_stale
              else 'the two files are the pair the context was prepared for (SHA-256)'),
        _code_chip(row, hits),
        _chip('anchor', 'not-run', 'anchor facts are not loaded'),
    )


def _snapshot_clause(kev: KevFact) -> str:
    """`` (catalog V, N days old)`` for a fact from a real snapshot; empty for a bare fact. A stale or future-dated
    snapshot says so, because a CVE it does not list may have been added since."""
    if kev.catalog_version is None:
        return ''
    if kev.freshness == 'future':
        age = 'release time in the future; check this computer\'s clock'
    elif kev.age_days is None:
        age = 'age not known'
    else:
        age = 'today' if kev.age_days == 0 else '1 day old' if kev.age_days == 1 else f'{kev.age_days} days old'
        if kev.freshness == 'stale':
            age += '; it may lack newer entries'
    return f' (catalog {kev.catalog_version}, {age})'


def _kev_chip(kev: KevFact) -> Chip:
    clause = _snapshot_clause(kev)
    if kev.state == 'listed':
        return _chip('exploitation', 'supports', f'KEV listed {kev.date_added or "(date unknown)"}{clause}; '
                                                 'a CVE-level fact, not about this function')
    if kev.state == 'not-listed' and clause:
        return _chip('exploitation', 'neutral', f'{KEV_TEXTS["not-listed"]}{clause}; not listed does not mean not '
                                                'exploited')
    return _chip('exploitation', 'not-run' if kev.state == 'no-snapshot' else 'neutral', KEV_TEXTS[kev.state])


def _loose_chips(row: EngineRow, elsewhere: Sequence[NotApplicable], alignment: Alignment,
                 pair_stale: bool) -> tuple[Chip, ...]:
    other = next((n for n in elsewhere if alignment.hits(n.stated_cwe, row)), None)
    if other is not None:
        where = ', '.join(other.products) or 'other products'
        text = f'no applicable CVE: its aligned {other.stated_cwe} {other.cve} lists {where} only'
    else:
        text = 'no applicable CVE in the context aligns with this change'
    chips = [_chip('applicability', 'neutral', text), _code_chip(row, (), aligned=False)]
    if pair_stale:
        chips.append(_chip('binary-identity', 'unknown', 'the file pair differs from the one the context was prepared '
                                                         'for'))
    return tuple(sorted(chips, key=lambda c: c.channel))


# ---------------------------------------------------------------------------------------------- build

def _lead(row: EngineRow, group: str, chips: tuple[Chip, ...], total: int, view: EngineView, bundle_key: str | None,
          stale: bool, hooks: tuple[Hook, ...]) -> LeadRow:
    basis = (BASIS_RANKED.format(rank=row.attention_rank, total=total) if row.attention_rank is not None
             else BASIS_UNRANKED)
    lead_id = domain_id('kbc.lead', 1, {'context_key': bundle_key, 'run_id': view.run_id, 'group': group,
                                        'match_id': row.match_id})
    nav = LeadNav(match_id=None if stale else row.match_id, project_revision=view.project_revision,
                  run_id=view.run_id)
    return LeadRow(lead_id=lead_id, level='function', group=group, subject=plain_text(row.name, 200) or 'unnamed',
                   chips=tuple(sorted(chips, key=lambda c: c.channel)), rank_basis=basis, nav=nav, stale=stale,
                   hooks=hooks)


def _order(rows: Iterable[EngineRow]) -> list[EngineRow]:
    return sorted(rows, key=lambda r: (r.attention_rank is None, r.attention_rank or 0, r.match_id))


def _supporting(leads: Sequence[LeadRow]) -> frozenset[str]:
    """Channels that support a group's leads. ``exploitation`` is a CVE-level fact, never evidence about a function, so
    KEV moves a group only through its own sort key and never strengthens the evidence count."""
    return frozenset(c.channel for lead in leads for c in lead.chips
                     if c.state == 'supports' and c.channel != 'exploitation')


def _group(card: CveCard, rules: Sequence[str], leads: list[LeadRow], kev: KevFact) -> LeadGroup:
    kev_text = (_kev_chip(kev).text)
    return LeadGroup(group=card.cve, kev=kev.state, kev_text=kev_text, cwe=card.stated_cwe,
                     cwe_text=(f'{card.stated_cwe} stated by vendor ({card.source_kind.upper()})'
                               if card.stated_cwe else None),
                     hypotheses=tuple(rules), leads=tuple(leads))


def _not_applicable(items: Sequence[NotApplicable]) -> tuple[NotApplicableCve, ...]:
    rows = []
    for item in sorted(items, key=lambda n: n.cve):
        where = ', '.join(item.products) or 'other products'
        rows.append(NotApplicableCve(cve=item.cve, products=tuple(item.products), stated_cwe=item.stated_cwe,
                                     text=plain_text(f'{item.cve} ({where} only)', 500)))
    return tuple(rows)


def build_leads(bundle: ContextBundle | None, view: EngineView | None, *, alignment: Alignment,
                kev: ExploitationLookup | None = None, elsewhere: Sequence[NotApplicable] = (),
                mention_only: Sequence[str] = (), only_cve: str | None = None, limit: int | None = None,
                replaced_sources: Collection[str] = (), engine_note: str = '') -> LeadsReport:
    """Group the engine's changed functions by the CVEs of ``bundle``. ``bundle`` None means no advisory is attached.
    ``replaced_sources`` are document ids of ``bundle.sources`` that a newer imported revision has replaced;
    ``engine_note`` is the engine's reason when ``view`` is None (for example a ranking behind the analysis)."""
    kev = kev or NullExploitation()
    report: ContextReport | None = bundle.context if bundle else None
    cards = tuple(report.cards) if report else ()
    rules = [[h.rule_id for h in hs.hypotheses] for hs in bundle.hypotheses] if bundle else []
    pair_stale = bool(bundle and view and (bundle.older_sha, bundle.newer_sha) != (view.older_sha, view.newer_sha))
    replaced = bool(bundle and view and {s.doc_id for s in bundle.sources} & set(replaced_sources))
    reasons: tuple[StaleReason, ...] = (*(('file-pair',) if pair_stale else ()),
                                        *(('advisory-revision',) if replaced else ()))
    stale = bool(reasons)
    state: LeadsState = ('no-advisory' if bundle is None else 'no-comparison' if view is None
                         else 'stale' if stale else 'ready')
    text = _state_text(state, reasons, engine_note)
    key = bundle.context_key if bundle else None
    facts = {card.cve: kev.status(card.cve) for card in cards}
    grouped: dict[str, list[LeadRow]] = {card.cve: [] for card in cards}
    loose: list[LeadRow] = []
    rows = _order(view.rows) if view else []
    for row in rows:
        member = False
        for card, rule_ids in zip(cards, rules, strict=True):
            hits = alignment.hits(card.stated_cwe, row)
            if not hits:
                continue
            member = True
            hooks: tuple[Hook, ...] = ('kb.meaning.hypothesis', 'kb.next.review_lead')
            grouped[card.cve].append(_lead(row, card.cve, _member_chips(card, rule_ids, row, hits, facts[card.cve],
                                                                        pair_stale), len(rows), view, key, stale,
                                           hooks))
        if not member:
            loose.append(_lead(row, UNATTRIBUTED, _loose_chips(row, elsewhere, alignment, pair_stale), len(rows),
                               view, key, stale, ('kb.next.review_lead',)))
    groups = [_group(card, rule_ids, grouped[card.cve], facts[card.cve]) for card, rule_ids in zip(cards, rules,
                                                                                                    strict=True)]
    groups.sort(key=lambda g: (g.kev != 'listed', -len(_supporting(g.leads)), g.group))
    if only_cve:
        groups, loose = [g for g in groups if g.group == only_cve], []
    groups, loose, dropped = _limited(groups, loose, limit)
    return LeadsReport(
        state=state, text=text, context_key=key, project_revision=view.project_revision if view else None,
        run_id=view.run_id if view else None, stale=stale, stale_reasons=reasons, coverage=tuple(report.coverage) if report else (),
        coverage_text=tuple(coverage_text(c) for c in report.coverage) if report else (), groups=tuple(groups),
        unattributed=tuple(loose), not_applicable=_not_applicable(elsewhere),
        mention_only=tuple(sorted(set(mention_only))), unknowns=tuple(report.unknowns) if report else (),
        limitations=tuple(report.limitations) if report else (), truncated=dropped, hooks=_hooks(state),
        kev_source=_kev_source(kev))


def _kev_source(kev: ExploitationLookup) -> KevSource:
    source = getattr(kev, 'source', None)
    return source if isinstance(source, KevSource) else KevSource()


def _state_text(state: LeadsState, reasons: Sequence[StaleReason], engine_note: str) -> str:
    if state == 'stale':
        parts = {'file-pair': TEXT_STALE_PAIR, 'advisory-revision': TEXT_STALE_ADVISORY}
        return ' '.join([*(parts[r] for r in reasons), TEXT_STALE_TAIL])
    if state == 'no-comparison' and engine_note:
        return plain_text(TEXT_NO_CURRENT_RANKING.format(note=engine_note), 1000)
    return {'ready': TEXT_READY, 'no-comparison': TEXT_NO_COMPARISON, 'no-advisory': TEXT_NO_ADVISORY}[state]


def _hooks(state: LeadsState) -> tuple[Hook, ...]:
    return {'ready': ('kb.next.review_lead',), 'no-comparison': ('kb.next.run_comparison',),
            'no-advisory': ('kb.next.import_documents',), 'stale': ('kb.next.run_comparison',)}[state]


def _limited(groups: list[LeadGroup], loose: list[LeadRow], limit: int | None
             ) -> tuple[list[LeadGroup], list[LeadRow], int]:
    if limit is None:
        return groups, loose, 0
    dropped = sum(max(0, len(g.leads) - limit) for g in groups) + max(0, len(loose) - limit)
    return ([g.model_copy(update={'leads': g.leads[:limit]}) for g in groups], loose[:limit], dropped)


# ---------------------------------------------------------------------------------------------- text report

def lead_summary(lead: LeadRow) -> str:
    supports = [c.text for c in lead.chips if c.state == 'supports' and c.channel in ('hypothesis', 'code-change')]
    other = [f'{c.state}: {c.text}' for c in lead.chips
             if (c.channel == 'code-change' and c.state in ('contradicts', 'neutral', 'unknown'))
             or (c.channel == 'applicability' and c.state in ('contradicts', 'neutral'))]
    parts = [f'supports: {"; ".join(supports)}'] if supports else []
    return ' | '.join([*parts, *other, lead.rank_basis])


def render_text(report: LeadsReport) -> str:
    kev = report.kev_source
    lines = [*report.coverage_text, report.text, kev.text, *([kev.banner] if kev.banner else []),
             *(f'KEV note: {note}' for note in kev.notes)]
    ordinal = 0

    def emit(lead: LeadRow) -> None:
        nonlocal ordinal
        ordinal += 1
        go = '' if lead.stale or lead.nav.match_id is None else f' | go to match {lead.nav.match_id}'
        lines.append(f'  {ordinal} {lead.subject}   {lead_summary(lead)}{go}')

    for group in report.groups:
        cwe = f' | {group.cwe_text}' if group.cwe_text else ''
        rules = f' | hypothesis {", ".join(group.hypotheses)}' if group.hypotheses else ''
        lines.append(f'GROUP {group.group}  {group.kev_text}{cwe}{rules}')
        for lead in group.leads:
            emit(lead)
    lines.append('GROUP unattributed (always visible)')
    for lead in report.unattributed:
        emit(lead)
    tail = [f'NOT APPLICABLE  {n.text}' for n in report.not_applicable]
    tail += [f'MENTION ONLY  {cve}' for cve in report.mention_only]
    if tail:
        lines.append('   '.join(tail))
    if report.truncated:
        lines.append(f'{report.truncated} more lead(s) not shown (limit).')
    lines += [f'Unknown: {u}' for u in report.unknowns] + [f'Limit: {x}' for x in report.limitations]
    return '\n'.join(lines)
