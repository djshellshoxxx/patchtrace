"""`SearchService`: the facade over segments, ranking, live pair expansion and fuzzy name suggestions (WB1 section 7).

A search parses nothing itself: it takes a `SearchRequest` whose `QueryPlan` came from `parse_query`, builds the
segments it needs, reads candidates with the plan's `match_*` expressions only (bound parameters, no LIKE),
groups them into leads by the live pairing, orders them with `rank`, and expands the requested page from the
open project. Qt-free; the project is read through the `ProjectService`-shaped object it was given.
"""
from __future__ import annotations

import base64
import json
import re
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path

from patchtrace.enrichment.identity import domain_id
from patchtrace.models import ComparisonProject
from patchtrace.search import build as builds
from patchtrace.search import expand, fuzzy, paths, rank
from patchtrace.search.capability import SearchCapability, probe_capability, require_search
from patchtrace.search.contracts import (
    Attention,
    CounterpartHint,
    CoverageEntry,
    Evidence,
    Locator,
    NameSuggestion,
    Presence,
    QueryPlan,
    Reason,
    SearchHit,
    SearchRequest,
    SearchResult,
)
from patchtrace.search.errors import SearchError
from patchtrace.search.limits import DEFAULT_LIMITS, SearchLimits
from patchtrace.search.normalize import fold, sanitize_text
from patchtrace.search.query import match_substring, match_words
from patchtrace.search.rank import Candidate, Lead
from patchtrace.search.segment import Flag, Segment, try_open
from patchtrace.search.sources.base import SourceSpec

AttentionPort = Callable[[ComparisonProject], tuple[object, object, str]]  # `enrichment.pipeline.load_default` shape
ExtraSpecs = Callable[[builds.BuildRequest], tuple[SourceSpec, ...]]
PENDING = ('missing', 'building', 'failed', 'truncated')
FUNCTION_LINKED = ('fn', 'ir', 'tool')
NAME_KINDS = ('function', 'import', 'export')
MAX_EVIDENCE = 6
SNIPPET_CHARS = 300
BROAD_PAGE = 200
BROAD_WARNING = 'Too many documents match; showing the first {n} in index order, unranked. Narrow the query.'
DOC_COLUMNS = 'd.id, d.kind, d.side, d.subject, d.display, d.extra, d.ref, d.rva, d.flags, d.value_sha'
SCHEME = {'function': 'function', 'code': 'function', 'asm': 'function', 'string': 'string', 'import': 'import',
          'export': 'export', 'build': 'pe-field', 'capability': 'capability', 'rule': 'rule', 'advisory': 'advisory',
          'cve': 'cve', 'cwe': 'advisory', 'kb': 'advisory', 'note': 'note', 'finding': 'finding'}
_MARKS = re.compile('([\x02\x03])')


class _TooBroad(Exception):
    def __init__(self, first: list[Candidate]):
        self.first = first


# ---------------------------------------------------------------------------------------------- reading

def _in(column: str, values: tuple[str, ...]) -> tuple[str, list]:
    return (f' AND {column} IN ({",".join("?" * len(values))})', list(values)) if values else ('', [])


def _strict(plan: QueryPlan) -> QueryPlan:
    return plan.model_copy(update={'last_prefix': False,
                                   'terms': tuple(t.model_copy(update={'prefix': False}) for t in plan.terms)})


def _prefixed(plan: QueryPlan) -> QueryPlan:
    """`mode=prefix`: the last word is a prefix whatever its length."""
    if not plan.terms:
        return plan
    last = plan.terms[-1].model_copy(update={'prefix': True})
    return plan.model_copy(update={'terms': (*plan.terms[:-1], last)})


class _Reader:
    """Candidates of one open segment for one plan. Runs on the caller's thread; `interrupt()` enforces the timeout."""

    def __init__(self, segment: Segment, plan: QueryPlan, index: expand.PairIndex, limits: SearchLimits):
        self.segment, self.plan, self.index, self.limits = segment, plan, index, limits
        self.filters, self.params = (lambda k, s: (k[0] + s[0], k[1] + s[1]))(
            _in('d.kind', plan.kinds), _in('d.side', plan.sides))
        self.found: dict[int, Candidate] = {}

    def candidates(self) -> list[Candidate]:
        plan, tables = self.plan, set(self.segment.info.tables)
        wanted = set(plan.in_) or {'name', 'code', 'text'}
        timer = threading.Timer(self.limits.query_timeout_s, self.segment.interrupt)
        timer.start()
        try:
            if not (plan.terms or plan.phrases):
                self._browse()
            else:
                if 'name' in tables and 'name' in wanted:
                    self._names()
                if 'code' in tables and 'code' in wanted:
                    self._words('fts_code', 4, 'code-words', 'code')
                if 'text' in tables and 'text' in wanted:
                    self._words('fts_text', 3, 'text-words', 'text')
                if 'signature' in plan.in_:
                    self._signatures()
            self._identities()
        except sqlite3.OperationalError as exc:
            interrupted = 'interrupt' in str(exc).lower()
            raise SearchError('PT-SEARCH-TIMEOUT' if interrupted else 'PT-SEARCH-STORE',
                              'the search took too long and was stopped' if interrupted
                              else 'the search index could not be read', recoverable=True) from None
        finally:
            timer.cancel()
        return list(self.found.values())

    def _candidate(self, row: tuple, table: str, tier: int, reason: str, field_: str, detail: str = '',
                   snippet: str = '') -> Candidate:
        info = self.segment.info
        return Candidate(info.group, info.digest16, table, row[0], row[1], row[2], row[3], row[4], row[5], row[6],
                         row[7], row[8], row[9], tier, reason, field_, detail, float(row[10]) if len(row) > 10 else 0.0,
                         snippet)

    def _keep(self, candidate: Candidate) -> None:
        current = self.found.get(candidate.doc_id)
        if current is None or candidate.tier < current.tier:
            self.found[candidate.doc_id] = candidate

    def _fetch(self, table: str, expression: str, snippet: bool) -> list[tuple]:
        base = f'FROM {table} JOIN doc d ON d.id = {table}.rowid WHERE {table} MATCH ?{self.filters}'
        params = [expression, *self.params]
        conn, cap = self.segment.conn, self.limits.candidate_cap
        count = conn.execute(f'SELECT count(*) FROM (SELECT 1 {base} LIMIT ?)', (*params, cap + 1)).fetchone()[0]
        snip = f", snippet({table}, -1, char(2), char(3), '…', 16)" if snippet else ", ''"
        if count > cap:
            first = conn.execute(f'SELECT {DOC_COLUMNS}, 0.0{snip} {base} ORDER BY d.id LIMIT ?',
                                 (*params, BROAD_PAGE)).fetchall()
            raise _TooBroad([self._candidate(r[:10], table, 3, '', '', snippet=r[11]) for r in first])
        return conn.execute(f'SELECT {DOC_COLUMNS}, bm25({table}){snip} {base} ORDER BY bm25({table}), d.id',
                            params).fetchall()

    def _names(self) -> None:
        plan, mode = self.plan, self.plan.mode
        if mode in ('auto', 'words', 'exact', 'prefix'):
            strict = _strict(_prefixed(plan) if mode == 'prefix' else plan)
            explicit = any(t.prefix for t in plan.terms) or mode == 'prefix'
            expression = None if explicit else match_words(strict, 'fts_name')
            single = plan.terms[0].fold if len(plan.terms) == 1 and not plan.phrases else None
            for row in self._fetch('fts_name', expression, False) if expression else ():
                exact = single is not None and fold(row[4]) == single
                if mode == 'exact' and not exact:
                    continue
                self._keep(self._candidate(row, 'fts_name', 0 if exact else 1, 'exact-id' if exact else 'name-words',
                                           'name', 'full name' if exact else ''))
        if mode in ('auto', 'prefix') and (plan.last_prefix or mode == 'prefix' or any(t.prefix for t in plan.terms)):
            expression = match_words(_prefixed(plan) if mode == 'prefix' else plan, 'fts_name')
            for row in self._fetch('fts_name', expression, False) if expression else ():
                self._keep(self._candidate(row, 'fts_name', 2, 'name-prefix', 'name'))
        if mode in ('auto', 'substring'):
            expression = match_substring(plan)
            for row in self._fetch('tri_name', expression, False) if expression else ():
                self._keep(self._candidate(row, 'tri_name', 2, 'name-substring', 'name'))

    def _words(self, table: str, tier: int, reason: str, field_: str) -> None:
        if self.plan.mode in ('exact', 'substring'):
            return
        expression = match_words(_prefixed(self.plan) if self.plan.mode == 'prefix' else self.plan, table)
        for row in self._fetch(table, expression, True) if expression else ():
            self._keep(self._candidate(row[:11], table, tier, reason, field_, snippet=row[11]))

    def _signatures(self) -> None:
        needles = [t.fold for t in self.plan.terms]
        rows = self.segment.conn.execute(
            f"SELECT {DOC_COLUMNS}, 0.0 FROM doc d WHERE d.kind = 'function' AND d.extra != ''{self.filters} "
            'ORDER BY d.id LIMIT ?', (*self.params, self.limits.scan_rows_max))
        for row in rows:
            if all(n in fold(row[5]) for n in needles):
                self._keep(self._candidate(row, 'doc', 3, 'text-words', 'signature'))

    def _browse(self) -> None:
        plan = self.plan
        kinds = '' if plan.kinds else " AND d.kind = 'function'"
        rows = self.segment.conn.execute(f'SELECT {DOC_COLUMNS}, 0.0 FROM doc d WHERE 1 = 1{kinds}{self.filters} '
                                         'ORDER BY d.id LIMIT ?', (*self.params, self.limits.candidate_cap + 1))
        found = rows.fetchall()
        if len(found) > self.limits.candidate_cap:
            raise _TooBroad([self._candidate(r, 'doc', 3, '', '') for r in found[:BROAD_PAGE]])
        for row in found:
            self._keep(self._candidate(row, 'doc', 3, '', ''))

    def _identities(self) -> None:
        for term in self.plan.identity:
            if term.kind in ('sha256', 'address'):
                self._lookup(term)
            else:
                needle = fold(term.value)
                for key, candidate in list(self.found.items()):
                    if needle in fold(f'{candidate.display} {candidate.extra} {candidate.subject}'):
                        self.found[key] = replace(candidate, tier=0, reason='exact-id', field=term.kind)

    def _lookup(self, term) -> None:
        if term.kind == 'sha256':
            where, params, label = 'd.value_sha = ?', [term.value], 'sha256'
        else:
            value = int(term.value, 16)
            subjects = self.index.at_address(value)
            marks = ','.join('?' * len(subjects))
            where, params, label = f'(d.rva = ?{f" OR d.subject IN ({marks})" if subjects else ""})', [value, *subjects], 'address'
        rows = self.segment.conn.execute(f'SELECT {DOC_COLUMNS}, 0.0 FROM doc d WHERE {where}{self.filters} '
                                         'ORDER BY d.id LIMIT ?', (*params, *self.params, self.limits.candidate_cap))
        for row in rows:
            self._keep(self._candidate(row, 'doc', 0, 'exact-id', label))

    def names(self) -> list[Candidate]:
        """Unique display names of real (non-auto) function, import and export documents, in index order."""
        marks = ','.join('?' * len(NAME_KINDS))
        rows = self.segment.conn.execute(
            f'SELECT {DOC_COLUMNS}, 0.0 FROM doc d WHERE d.kind IN ({marks}) AND (d.flags & ?) = 0 '
            'ORDER BY d.id LIMIT ?', (*NAME_KINDS, int(Flag.AUTO), self.limits.fuzzy_candidates))
        return [self._candidate(row, 'doc', 2, 'typo', 'name') for row in rows]


# --------------------------------------------------------------------------------------------- evidence

def parse_snippet(raw: str) -> tuple[str, tuple[tuple[int, int], ...]]:
    """Plain text and integer highlight spans from an FTS5 snippet with STX/ETX markers."""
    text, spans, start, size = [], [], None, 0
    for part in _MARKS.split(raw):
        if part == '\x02':
            start = size
        elif part == '\x03':
            if start is not None and size > start:
                spans.append((start, size))
            start = None
        else:
            clean = sanitize_text(part, 1 << 20)
            text.append(clean)
            size += len(clean)
    joined = ''.join(text)
    if len(joined) > SNIPPET_CHARS:
        joined = joined[:SNIPPET_CHARS - 3] + '...'
        spans = [(a, min(b, SNIPPET_CHARS - 3)) for a, b in spans if a < SNIPPET_CHARS - 3]
    return joined, tuple(spans)


def name_spans(display: str, plan: QueryPlan) -> tuple[tuple[int, int], ...]:
    """Case-insensitive occurrences of the query words in a name; none when lowering changes the length."""
    lowered = display.lower()
    if len(lowered) != len(display):
        return ()
    found = sorted((at, at + len(n)) for term in plan.terms if (at := lowered.find(n := term.nfc.lower())) >= 0)
    merged: list[tuple[int, int]] = []
    for start, end in found:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return tuple(merged)


# ------------------------------------------------------------------------------------------------ run

@dataclass
class _Run:
    """State of one search call: the live project facts and the segments opened so far."""
    request: builds.BuildRequest
    directory: Path
    index: expand.PairIndex
    ranks: dict[str, int]
    ranked: int
    attention_known: bool
    attention_note: str
    comparable: Callable[[str], bool]
    segments: dict[str, Segment | None] = field(default_factory=dict)

    def segment(self, group: str) -> Segment | None:
        if group not in self.segments:
            spec = next((s for s in self.request.specs if s.group == group and s.buildable), None)
            self.segments[group] = spec and try_open(paths.segment_path(self.directory, group, spec.digest16))
        return self.segments[group]

    def close(self) -> None:
        for segment in self.segments.values():
            if segment is not None:
                segment.close()

    def pairing(self, c: Candidate):
        head = c.group.partition(':')[0]
        if head in FUNCTION_LINKED and c.kind in rank.FUNCTION_KINDS:
            return self.index.match_of(c.subject)
        if head in ('ann', 'fnd'):
            return self.index.matches.get(c.subject)
        if c.flags & int(Flag.SYMBOL) and c.side:
            return self.index.by_name.get((c.side, c.display))
        return None

    def presence(self, c: Candidate) -> Presence | None:
        if c.kind != 'string':
            return None
        if c.group == 'raw':
            added = c.side == 'newer'
            return Presence(older='unknown' if added else 'present', newer='present' if added else 'unknown',
                            basis=f'Ghidriff lists the string as {"added" if added else "deleted"}; the other side is not checked')
        head, engine, side = (c.group.split(':') + ['', ''])[:3]
        if head != 'tool' or c.value_sha is None:
            return None
        other = 'older' if side == 'newer' else 'newer'
        sibling = self.segment(f'tool:{engine}:{other}')
        if sibling is None or not self.comparable(engine):
            return Presence(basis=f'the {other} {engine} run is missing or not comparable')
        there = sibling.conn.execute("SELECT 1 FROM doc WHERE kind = 'string' AND value_sha = ? LIMIT 1",
                                     (c.value_sha,)).fetchone() is not None
        states = {side: 'present', other: 'present' if there else 'absent'}
        return Presence(older=states['older'], newer=states['newer'],
                        basis=f'compared with the comparable {other} {engine} run')


# ---------------------------------------------------------------------------------------------- service

class SearchService:
    def __init__(self, service, cache_root: Path, *, limits: SearchLimits = DEFAULT_LIMITS,
                 capability: SearchCapability | None = None, attention: AttentionPort | None = None,
                 comparable: Callable[[str], bool] = lambda engine: False, extra_specs: ExtraSpecs | None = None,
                 clock: Callable[[], float] = time.monotonic):
        """`service` has `.project` and `.root` (a `ProjectService`). `attention` is `lambda p: load_default(store, p)`;
        `comparable(engine)` says whether the older and newer runs of a tool are comparable; `extra_specs` adds
        source groups (tool, advisory, unified IR) to the build request."""
        self.service, self.cache_root, self.limits = service, Path(cache_root), limits
        self._capability, self._attention, self._comparable = capability, attention, comparable
        self._extra, self._clock = extra_specs, clock
        self._memo: tuple[tuple, builds.BuildRequest] | None = None

    # -- build and coverage
    def build_request(self, run_id: str | None = None) -> builds.BuildRequest:
        project = self.service.project
        stamp = (project.id, project.revision, run_id)
        if self._memo is None or self._memo[0] != stamp:
            request = builds.build_request(self.service, run_id=run_id)
            if self._extra:
                request = replace(request, specs=request.specs + self._extra(request))
            self._memo = (stamp, request)
        return self._memo[1]

    def coverage(self, run_id: str | None = None) -> tuple[CoverageEntry, ...]:
        return builds.coverage(self.build_request(run_id), self.cache_root)

    def build(self, *, run_id: str | None = None, **options) -> builds.BuildReport:
        """`build_index` for this project (`groups`, `rebuild`, `cancel`, `progress` pass through)."""
        return builds.build_index(self.build_request(run_id), self.cache_root, limits=self.limits, **options)

    def capability(self) -> SearchCapability:
        if self._capability is None:
            self._capability = probe_capability()
        return self._capability

    # -- locators and hints
    def check_locator(self, locator: Locator, run_id: str | None = None) -> None:
        """Raise `PT-SEARCH-LOCATOR` unless the locator still names the same function text in the live project."""
        expand.validate_locator(expand.PairIndex.build(self.service.project, run_id), locator)

    def counterpart_hints(self, run_id: str | None = None) -> tuple[CounterpartHint, ...]:
        if not fuzzy.available():
            return ()
        older, newer = expand.rename_candidates(expand.PairIndex.build(self.service.project, run_id))
        return fuzzy.counterpart_hints(older, newer, limits=self.limits)

    # -- search
    def search(self, request: SearchRequest, *, build: bool = True, cancel: Callable[[], bool] = lambda: False,
               run_id: str | None = None) -> SearchResult:
        require_search(self.capability())
        started = self._clock()
        plan, plan_request = request.plan, self.build_request(run_id)
        offset = self._offset(request, plan_request)
        needed = [s for s in plan_request.specs if s.buildable and _relevant(s, plan)]
        built_ms = 0
        if build:
            have = {e.group: e.status for e in builds.coverage(plan_request, self.cache_root)}
            missing = {s.group for s in needed if have.get(s.group) == 'missing'}
            if missing:
                builds.build_index(plan_request, self.cache_root, groups=missing, cancel=cancel, limits=self.limits)
                built_ms = int((self._clock() - started) * 1000)
        coverage = builds.coverage(plan_request, self.cache_root)
        wanted = {s.group for s in needed}
        state = {e.group: e.status for e in coverage}
        run = self._run(plan_request, run_id)
        warnings: list[str] = []
        try:
            leads, broad = self._leads(run, request, [g for g in wanted if state[g] in ('indexed', 'truncated')], cancel)
            suggestions = self._suggestions(run, request, leads, warnings)
            hints = self.counterpart_hints(run_id) if plan.mode == 'similar' and request.expand else ()
            ordered = leads if broad else rank.order(leads, request.sort)
            hits = tuple(self._hit(run, request, lead, broad) for lead in ordered[offset:offset + request.limit])
        finally:
            run.close()
        more = offset + request.limit < len(ordered)
        if broad:
            warnings.append(BROAD_WARNING.format(n=len(ordered)))
        status = self._status(plan, len(ordered), broad, [state[g] for g in wanted], suggestions or hints, warnings)
        return SearchResult(
            status=status, coverage=coverage, hits=hits,
            total=None if broad else len(ordered), total_capped=broad,
            cursor=self._cursor(plan_request, request, offset + request.limit) if more else None,
            interpreted_as=_interpreted(plan), suggestions=suggestions, counterpart_hints=tuple(hints[:200]),
            warnings=tuple(warnings[:16]), index_key=plan_request.index_key,
            timings_ms={'build': built_ms, 'search': int((self._clock() - started) * 1000) - built_ms})

    def _run(self, plan_request: builds.BuildRequest, run_id: str | None) -> _Run:
        project = self.service.project
        index = expand.PairIndex.build(project, run_id or plan_request.run_id)
        ranks, note = {}, ''
        result = None
        if self._attention is not None:
            result, _signals, note = self._attention(project)
            ranks = {e.match_id: e.rank for e in result.entries} if result is not None else {}
        return _Run(plan_request, builds.segment_directory(plan_request, self.cache_root), index, ranks,
                    len(ranks), result is not None, note, self._comparable)

    def _leads(self, run: _Run, request: SearchRequest, groups: list[str], cancel) -> tuple[list[Lead], bool]:
        found: list[Candidate] = []
        broad = False
        for group in sorted(groups):
            if cancel():
                raise SearchError('PT-SEARCH-CANCEL', 'the search was cancelled')
            segment = run.segment(group)
            if segment is None:
                continue
            try:
                found += _Reader(segment, request.plan, run.index, self.limits).candidates()
            except _TooBroad as exc:
                found, broad = exc.first, True
                break
        grouped: dict[str, list[Candidate]] = {}
        matches = {}
        for c in found:
            match = run.pairing(c) if request.group else None
            key = f'm:{match.id}' if match else f'd:{c.group}:{c.doc_id}'
            grouped.setdefault(key, []).append(c)
            matches[key] = match
        leads = [self._lead(run, key, cands, matches[key]) for key, cands in grouped.items()]
        return [lead for lead in leads if _admits(lead, request.plan)], broad

    def _lead(self, run: _Run, key: str, cands: list[Candidate], match) -> Lead:
        lead = Lead(key, cands, match, run.ranks.get(match.id) if match else None, run.ranked, run.attention_known)
        for c in cands:
            shown = run.presence(c)
            if shown is not None and (c.group == 'raw' or {shown.older, shown.newer} == {'present', 'absent'}):
                lead.delta = True
        return lead

    def _hit(self, run: _Run, request: SearchRequest, lead: Lead, broad: bool) -> SearchHit:
        shown = lead.candidates[:MAX_EVIDENCE]
        presence = next((p for c in lead.candidates if (p := run.presence(c)) is not None), None)
        rank_ = None
        if lead.attention_rank is not None:
            rank_ = Attention(rank=lead.attention_rank, of=max(lead.attention_of, lead.attention_rank))
        expansion = (expand.expansion(lead.match, rank_, run.attention_note)
                     if request.expand and lead.match is not None else None)
        reasons = ('unranked: too many documents match',) if broad else rank.rank_reasons(lead, run.attention_note)
        return SearchHit(hit_id='h-' + domain_id('search-hit', 1, lead.key)[:24], tier=lead.tier,
                         change_class=lead.change_class, components=len(lead.origins),
                         evidence=tuple(_evidence(run, c, request.plan, lead) for c in shown),
                         evidence_total=len(lead.candidates), presence=presence, expansion=expansion,
                         rank_reasons=reasons)

    def _suggestions(self, run: _Run, request: SearchRequest, leads: list[Lead], warnings: list[str]):
        plan = request.plan
        single = len(plan.terms) == 1 and not plan.phrases
        named = any(lead.tier <= 2 for lead in leads)
        if not single or (named and plan.mode != 'similar') or plan.mode in ('exact', 'substring', 'prefix', 'words'):
            return ()
        if not fuzzy.available():
            warnings.append(fuzzy.UNAVAILABLE)
            return ()
        unique: dict[str, Candidate] = {}
        for spec in run.request.specs:
            segment = run.segment(spec.group) if spec.buildable and 'name' in spec.table_sets else None
            if segment is not None:
                for c in _Reader(segment, plan, run.index, self.limits).names():
                    unique.setdefault(c.display, c)
        candidates = sorted(unique.values(), key=lambda c: c.display)
        picks = fuzzy.suggest(plan.terms[0].nfc, [c.display for c in candidates], limits=self.limits)
        return tuple(NameSuggestion(name=candidates[i].display, edits=edits, locator=_locator(run, candidates[i]))
                     for i, edits in picks)

    def _status(self, plan, total, broad, states, extras, warnings) -> str:
        if plan.mode == 'similar' and not fuzzy.available():
            return 'unsupported'
        if broad:
            return 'too-broad'
        incomplete = any(s in PENDING for s in states)
        if total or extras:
            return 'partial' if incomplete else 'ok'
        if incomplete:
            return 'indexing' if not any(s in ('indexed', 'truncated') for s in states) else 'partial'
        return 'no-results'

    def _cursor(self, plan_request, request: SearchRequest, offset: int) -> str:
        body = {'k': plan_request.index_key, 'q': request.plan.digest(), 's': request.sort, 'o': offset}
        return base64.urlsafe_b64encode(json.dumps(body, sort_keys=True).encode()).decode().rstrip('=')

    def _offset(self, request: SearchRequest, plan_request) -> int:
        if request.cursor is None:
            return 0
        try:
            body = json.loads(base64.urlsafe_b64decode(request.cursor + '=' * (-len(request.cursor) % 4)))
            offset = int(body['o'])
            same = (body['k'], body['q'], body['s']) == (plan_request.index_key, request.plan.digest(), request.sort)
        except (ValueError, KeyError, TypeError):
            raise SearchError('PT-SEARCH-INPUT', 'the page cursor is not valid') from None
        if not same or offset < 0:
            raise SearchError('PT-SEARCH-STALE', 'the index or the query changed since this page; search again',
                              recoverable=True)
        return offset


# ------------------------------------------------------------------------------------------- helpers

def _relevant(spec: SourceSpec, plan: QueryPlan) -> bool:
    return ((not plan.kinds or bool(set(spec.kinds) & set(plan.kinds)))
            and (spec.side is None or not plan.sides or spec.side in plan.sides))


def _admits(lead: Lead, plan: QueryPlan) -> bool:
    if plan.is_ and (lead.match is None or lead.match.category not in plan.is_):
        return False
    return not (plan.scope == 'changed' and lead.change_class > 1)


def _interpreted(plan: QueryPlan) -> str:
    parts = []
    words = [t.nfc + ('*' if t.prefix else '') for t in plan.terms]
    if words:
        last = f' (the last word "{plan.terms[-1].nfc}" also matches as a prefix)' if plan.last_prefix else ''
        parts.append('all of: ' + ', '.join(words) + last)
    parts += [f'phrase "{p}"' for p in plan.phrases]
    if plan.excludes:
        parts.append('without: ' + ', '.join(plan.excludes))
    for label, values in (('kind', plan.kinds), ('side', plan.sides), ('is', plan.is_), ('in', plan.in_)):
        if values:
            parts.append(f'{label}: {", ".join(values)}')
    parts.append(f'scope: {plan.scope}')
    return '; '.join(parts)[:300]


def _locator(run: _Run, c: Candidate) -> Locator:
    head = c.group.partition(':')[0]
    linked = expand.function_locator(run.index, c.subject) if head in FUNCTION_LINKED else None
    if linked is not None:
        return linked.model_copy(update={'scheme': SCHEME[c.kind] if c.kind in ('string', 'capability', 'rule') else 'function'})
    return Locator(scheme=SCHEME[c.kind], side=c.side, rva=c.rva, source_ref=f'{c.group}#{c.ref}')


def _evidence(run: _Run, c: Candidate, plan: QueryPlan, lead: Lead) -> Evidence:
    snippet, spans = parse_snippet(c.snippet) if c.snippet else (c.display, name_spans(c.display, plan))
    reasons = [Reason(code=c.reason, field=c.field, detail=c.detail)] if c.reason else []
    if c.group == 'raw' and c.kind == 'string':
        reasons.append(Reason(code='delta', field='string', detail='added' if c.side == 'newer' else 'deleted'))
    return Evidence(kind=c.kind, side=c.side, origin=c.origin, title=c.display, snippet=snippet, spans=spans,
                    reasons=tuple(reasons), locator=_locator(run, c), seen_by=(c.origin,), group=c.group,
                    digest16=c.digest16)
