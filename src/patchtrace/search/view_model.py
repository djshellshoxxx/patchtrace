"""Pure view model of the search panel (WB1 section 8; slice S6). Qt-free; the widgets live in `ui_search`.

Everything the panel shows is computed here from `SearchResult` objects: the state line (Q0-Q12), the table rows
(strings precomputed, so `data()` is O(1)), the detail sections, the copied lead and the suggestion rows. No
number is shown as a score: only counts, ordinal ranks and edit distances. Text is plain, ASCII glyphs only; all
model strings arrive sanitised from the contracts, and echoed query text is sanitised here.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from patchtrace.search.contracts import Evidence, Locator, NameSuggestion, Presence, SearchHit, SearchResult
from patchtrace.search.limits import DEFAULT_LIMITS
from patchtrace.search.normalize import sanitize_text

ROW_CAP = 5000
COPY_LIMIT = 16 * 1024
QUERY_ECHO = 80
HEADERS = ('Side', 'Kind', 'Match', 'Where', 'Change', 'Why')
ACCESSIBLE_NAMES = {'search.query': 'Search query', 'search.side': 'Search side', 'search.kinds': 'Search kinds',
                    'search.scope': 'Search scope', 'search.mode': 'Search mode', 'search.sort': 'Search sort order',
                    'search.table': 'Search results', 'search.detail': 'Selected result details',
                    'search.suggestions': 'Search suggestions'}
KIND_LABELS = {'function': 'Function', 'code': 'Code', 'asm': 'Assembly', 'string': 'String', 'import': 'Import',
               'export': 'Export', 'capability': 'Capability', 'rule': 'Rule', 'build': 'Build fact',
               'advisory': 'Advisory', 'cve': 'CVE', 'cwe': 'CWE', 'kb': 'KB', 'note': 'Note', 'finding': 'Finding'}
SCOPE_LABELS = {'indexed': 'everything indexed', 'changed': 'changed functions'}
CAP_NOTE = f'Showing the first {ROW_CAP:,}. Refine the search.'
NO_ATTENTION = 'attention/1 rank unavailable: run Rank changes'
ORDINAL_NOTE = 'Leads are ordered by categories and counts; no number here is a measure of correctness.'
Q11 = ("Instruction text is not searchable: Ghidriff keeps only a hash of each function's instructions. "
       'Run unified extraction to add it.')
PRESENCE_WORDS = {'present': 'present', 'absent': 'absent', 'unknown': 'unknown'}


@dataclass(frozen=True, slots=True)
class PanelState:
    id: str
    text: str
    actions: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Progress:
    group: str
    done: int
    total: int


@dataclass(frozen=True, slots=True)
class Failure:
    code: str
    message: str


def _echo(query: str) -> str:
    return sanitize_text(query, QUERY_ECHO)


def _count(result: SearchResult) -> str:
    if result.total is None:
        return f'{DEFAULT_LIMITS.candidate_cap:,}+'
    return f'{result.total:,}'


def coverage_text(result: SearchResult, limit: int = 8) -> str:
    """Compact `group status` list of the groups that were searched or are missing."""
    parts = [f'{e.group} {e.status}' for e in result.coverage if e.status != 'not-applicable']
    shown = ', '.join(parts[:limit]) or 'no groups'
    return shown + (f', and {len(parts) - limit} more' if len(parts) > limit else '')


def missing_text(result: SearchResult) -> str:
    parts = [f'{e.group} is {e.status}' for e in result.coverage if e.status in ('missing', 'building', 'failed')]
    return '; '.join(parts[:8]) or 'some groups are not indexed'


def coverage_notes(result: SearchResult) -> tuple[str, ...]:
    """Q11 when instruction text is unavailable; other coverage reasons are shown by the Coverage dialog."""
    return (Q11,) if any('asm' in e.kinds and e.status == 'unavailable' for e in result.coverage) else ()


def panel_state(*, has_project: bool, query: str = '', result: SearchResult | None = None,
                progress: Progress | None = None, failure: Failure | None = None, shown: int = 0,
                scope: str = 'indexed', stale_what: str = 'project data changed', indexed: bool = True) -> PanelState:
    """The one state line: Q0 no project ... Q12 cancelled. `shown` is how many rows the table holds."""
    if not has_project:
        return PanelState('Q0', 'Open a project to search it.')
    if failure is not None:
        return PanelState('Q10', f'Search failed: {sanitize_text(failure.code, 32)}: '
                          f'{sanitize_text(failure.message, 200)}. Your project was not changed.',
                          ('Retry', 'Copy details'))
    if progress is not None:
        return PanelState('Q2', f'Indexing {sanitize_text(progress.group, 32)} ({progress.done} of {progress.total} '
                          'groups). You can already search what is indexed.', ('Cancel',))
    if result is None:
        if not indexed:
            return PanelState('Q1', "Not indexed yet. Search reads only this project's saved data; "
                              'nothing is uploaded.', ('Build index',))
        return PanelState('Q3', 'Search names, strings, APIs, code, notes and advisories. Use quotes for an exact '
                          'phrase and -word to exclude.')
    return _result_state(result, _echo(query), shown, stale_what, SCOPE_LABELS.get(scope, SCOPE_LABELS['indexed']))


def _result_state(result: SearchResult, query: str, shown: int, stale_what: str, scope: str) -> PanelState:
    status = result.status
    if status == 'unsupported':
        return PanelState('Q9', 'Full-text search is unavailable in this build (SQLite FTS5 missing). '
                          'The navigator filter still works.')
    if status == 'cancelled':
        return PanelState('Q12', 'Search cancelled. Nothing was changed.')
    if status == 'error':
        return PanelState('Q10', 'Search failed: PT-SEARCH-STORE: the search could not finish. '
                          'Your project was not changed.', ('Retry', 'Copy details'))
    if status == 'indexing' and not result.hits:
        return PanelState('Q1', "Not indexed yet. Search reads only this project's saved data; "
                          'nothing is uploaded.', ('Build index',))
    if status == 'too-broad':
        return PanelState('Q7', f"More than {DEFAULT_LIMITS.candidate_cap:,} matches for '{query}'. Showing the "
                          'first 200 in index order, not ranked. Add a word, choose a kind or side, or use a phrase.')
    if status == 'stale':
        return PanelState('Q8', f'The project changed after this index was built ({sanitize_text(stale_what, 80)}). '
                          'Results are for reference; opening one is checked against the current project.',
                          ('Update index',))
    if result.hits:
        return PanelState('Q4', f"{_count(result)} leads for '{query}' in {scope}. Showing {shown or len(result.hits)}.")
    if status == 'partial':
        return PanelState('Q6', f'No results yet, but the index is partial: {missing_text(result)}.')
    return PanelState('Q5', f"No results for '{query}' in what is indexed ({coverage_text(result)}). "
                      'This does not show the text is absent from the binary.')


# --------------------------------------------------------------------------------------------- rows

def locator_text(loc: Locator) -> str:
    parts = [loc.scheme]
    if loc.rva is not None:
        parts.append(f'rva 0x{loc.rva:x}')
    elif loc.file_offset is not None:
        parts.append(f'offset 0x{loc.file_offset:x}')
    if loc.line_start is not None:
        parts.append(f'lines {loc.line_start}-{loc.line_end}')
    if loc.source_ref:
        parts.append(loc.source_ref)
    return ' '.join(parts)


def _where(hit: SearchHit) -> str:
    """The first locator; a function lead without an address borrows the newer (else older) counterpart's."""
    loc = hit.evidence[0].locator
    if loc.rva is None and loc.file_offset is None and hit.expansion and hit.expansion.counterparts:
        known = sorted((c for c in hit.expansion.counterparts if c.rva is not None), key=lambda c: c.side != 'newer')
        if known:
            return locator_text(loc.model_copy(update={'rva': known[0].rva}))
    return locator_text(loc)


def sides_of(hit: SearchHit) -> tuple[str, ...]:
    found = {e.side for e in hit.evidence if e.side}
    if hit.expansion:
        found |= {c.side for c in hit.expansion.counterparts}
    return tuple(s for s in ('older', 'newer') if s in found)


def _side_label(sides: tuple[str, ...]) -> str:
    return 'Both' if len(sides) == 2 else sides[0].capitalize() if sides else '-'


def _match(first: Evidence) -> tuple[str, tuple[tuple[int, int], ...]]:
    if not first.snippet:
        return first.title, ()
    if first.snippet == first.title:
        return first.title, first.spans
    offset = len(first.title) + 2
    return f'{first.title}: {first.snippet}', tuple((a + offset, b + offset) for a, b in first.spans)


def _presence(presence: Presence | None) -> str:
    if presence is None or not presence.basis:
        return ''
    state = (presence.older, presence.newer)
    if state == ('absent', 'present'):
        return 'Only in newer'
    if state == ('present', 'absent'):
        return 'Only in older'
    return f'Presence unknown (older {presence.older}, newer {presence.newer})' if 'unknown' in state else ''


def _change(hit: SearchHit) -> str:
    """Pairing category and, for strings, which build carries it; both are shown when both are known."""
    parts = [hit.expansion.category.capitalize()] if hit.expansion is not None else []
    if note := _presence(hit.presence):
        parts.append(note)
    if parts:
        return '; '.join(parts)
    return 'Not a function change' if hit.change_class == 3 else 'Unknown'


def _why(hit: SearchHit) -> str:
    if hit.rank_reasons:
        return '; '.join(hit.rank_reasons[:2])
    return ', '.join(r.code for e in hit.evidence[:1] for r in e.reasons) or 'matched'


@dataclass(frozen=True, slots=True)
class ResultRowView:
    """One table row for one generation. `cells` follow `HEADERS`; `spans` index into the Match cell."""
    hit_id: str
    cells: tuple[str, str, str, str, str, str]
    spans: tuple[tuple[int, int], ...]
    accessible: str
    locator: Locator
    function_linked: bool
    other_side: bool


def row_view(hit: SearchHit) -> ResultRowView:
    first = hit.evidence[0]
    sides = sides_of(hit)
    match, spans = _match(first)
    where, change, why = _where(hit), _change(hit), _why(hit)
    kind = KIND_LABELS[first.kind]
    cells = (_side_label(sides), kind, match, where, change, why)
    accessible = f'{kind} in {cells[0]}: {first.title}; {where}; {change}; {why}'
    return ResultRowView(hit.hit_id, cells, spans, accessible, first.locator, first.locator.scheme == 'function'
                         or hit.expansion is not None, len(sides) == 2 or bool(hit.expansion and hit.expansion.counterparts))


@dataclass(slots=True)
class ResultsBuffer:
    """Rows of one generation, appended page by page and capped; a page of another generation is dropped."""
    generation: int
    cap: int = ROW_CAP
    rows: list[ResultRowView] = field(default_factory=list)
    cursor: str | None = None
    total: int | None = None
    truncated: bool = False

    def accept(self, generation: int, result: SearchResult) -> int:
        """Append the page; the number of rows added, or -1 when the generation is not the current one."""
        if generation != self.generation:
            return -1
        room = self.cap - len(self.rows)
        page = [row_view(h) for h in result.hits[:max(room, 0)]]
        self.rows += page
        self.total, self.cursor = result.total, result.cursor
        if len(result.hits) > room or (result.cursor and len(self.rows) >= self.cap):
            self.truncated, self.cursor = True, None
        return len(page)

    @property
    def can_fetch_more(self) -> bool:
        return self.cursor is not None and len(self.rows) < self.cap

    @property
    def note(self) -> str:
        return CAP_NOTE if self.truncated else ''


# ------------------------------------------------------------------------------------------- detail

def _origins(hit: SearchHit) -> str:
    return ', '.join(sorted({o for e in hit.evidence for o in e.seen_by}))


def _pair_lines(hit: SearchHit) -> list[str]:
    pair = hit.expansion
    if pair is None:
        return ['No pairing: this lead is not a function.']
    lines = [f'Category: {pair.category}; quality {pair.quality}; review {pair.review}'
             + ('; manual pairing' if pair.manual else '')]
    lines += [f'{c.side.capitalize()}: {c.name}' + (f' at 0x{c.rva:x}' if c.rva is not None else '')
              for c in pair.counterparts]
    if pair.match_types:
        lines.append('Match types: ' + ', '.join(pair.match_types))
    attention = pair.attention
    lines.append(f'Attention: rank {attention.rank} of {attention.of} ({attention.formula}, ordinal)'
                 if attention else NO_ATTENTION)
    return lines


def _fact_lines(hit: SearchHit) -> list[str]:
    lines = []
    pair, presence = hit.expansion, hit.presence
    if presence is not None:
        lines.append(f'Presence: older {PRESENCE_WORDS[presence.older]}, newer {PRESENCE_WORDS[presence.newer]}'
                     + (f' ({presence.basis})' if presence.basis else ''))
    if pair is not None:
        lines += [f'Signal: {s}' for s in pair.signals]
        if pair.unified:
            lines.append(f'Unified: {pair.unified.decision}, {pair.unified.materiality}'
                         + (f', {", ".join(pair.unified.classes)}' if pair.unified.classes else ''))
        lines += [f'Tool delta: {d}' for d in pair.tool_delta]
        if pair.series:
            lines.append(f'Series: {pair.series}')
    return lines or ['None recorded for this lead.']


def _provenance_lines(hit: SearchHit) -> list[str]:
    lines = []
    for e in hit.evidence:
        lines.append(f'{KIND_LABELS[e.kind]} {e.side or "-"} from {e.origin} (group {e.group}, index {e.digest16}); '
                     f'seen by {", ".join(e.seen_by)}; {locator_text(e.locator)}')
    if hit.evidence_total > len(hit.evidence):
        lines.append(f'Showing {len(hit.evidence)} of {hit.evidence_total} matching documents.')
    return lines


def _limit_lines(hit: SearchHit) -> list[str]:
    lines = list(hit.expansion.limitations) if hit.expansion else []
    if hit.presence is not None and hit.presence.basis:
        lines.append(hit.presence.basis)
    return [*lines, ORDINAL_NOTE]


def detail_sections(hit: SearchHit) -> tuple[tuple[str, tuple[str, ...]], ...]:
    first = hit.evidence[0]
    result = [f'{KIND_LABELS[first.kind]}: {first.title}', first.snippet] if first.snippet != first.title \
        else [f'{KIND_LABELS[first.kind]}: {first.title}']
    return (('Result', tuple(result)),
            ('Why it ranks here', hit.rank_reasons or ('matched the query',)),
            ('Pair', tuple(_pair_lines(hit))),
            ('Change facts', tuple(_fact_lines(hit))),
            ('Provenance', tuple(_provenance_lines(hit))),
            ('Limitations', tuple(_limit_lines(hit))))


def detail_text(hit: SearchHit) -> str:
    return '\n\n'.join(f'{title}\n' + '\n'.join(f'  {line}' for line in lines if line)
                       for title, lines in detail_sections(hit))


def copy_text(hit: SearchHit) -> str:
    """Title, locator and provenance of a lead, for the clipboard (capped at 16 KiB)."""
    first = hit.evidence[0]
    lines = [first.title, locator_text(first.locator), f'Origins: {_origins(hit)}', *_provenance_lines(hit)]
    return '\n'.join(lines)[:COPY_LIMIT]


# ------------------------------------------------------------------------------------ suggestions

@dataclass(frozen=True, slots=True)
class SuggestionRow:
    """`name | rva | side | edits`; the bare name is the edit text and the locator opens the function."""
    text: str
    name: str
    locator: Locator


def suggestion_row(suggestion: NameSuggestion) -> SuggestionRow:
    loc = suggestion.locator
    rva = f'0x{loc.rva:x}' if loc.rva is not None else '-'
    edits = 'same name' if suggestion.edits == 0 else f'{suggestion.edits} edit' + ('s' if suggestion.edits > 1 else '')
    return SuggestionRow(f'{suggestion.name} | {rva} | {loc.side or "-"} | {edits}', suggestion.name, loc)


def suggestion_rows(result: SearchResult) -> tuple[SuggestionRow, ...]:
    return tuple(suggestion_row(s) for s in result.suggestions[:DEFAULT_LIMITS.suggestions])
