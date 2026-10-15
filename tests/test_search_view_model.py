"""WB1 S6: the pure search view model: states Q0-Q12, rows, detail, paging cap, hostile text, tooltip data."""
from __future__ import annotations

import re
import subprocess
import sys

import pytest
from search_synergy_builders import attention, extra_specs, make_project

from patchtrace.search import tooltip_data
from patchtrace.search import view_model as vm
from patchtrace.search.contracts import (
    CoverageEntry,
    Evidence,
    Locator,
    NameSuggestion,
    Presence,
    SearchHit,
    SearchRequest,
    SearchResult,
)
from patchtrace.search.query import parse_query
from patchtrace.search.service import SearchService
from patchtrace.tooltips import TooltipEntry

BANNED = re.compile(r'vulnerab|exploit|confiden|score|probab|likely|malicious|risk|danger|bug', re.IGNORECASE)
CONTROL = re.compile('[\\x00-\\x08\\x0b-\\x1f\\x7f-\\x9f\\u2028\\u2029\\u202a-\\u202e\\u2066-\\u2069]')
HOSTILE = '\x00\x1b[31m<script>alert(1)</script>\u202e\n'


@pytest.fixture(scope='module')
def real(tmp_path_factory) -> SearchResult:
    tmp = tmp_path_factory.mktemp('vm')
    service = SearchService(make_project(tmp / 'project'), tmp / 'cache', attention=attention,
                            comparable=lambda engine: True, extra_specs=extra_specs)
    return service.search(SearchRequest(plan=parse_query('container size')))


def locator(**extra) -> Locator:
    return Locator(scheme='function', function_id='f1', side='newer', rva=0x1000, **extra)


def hit(title='Name', *, snippet='', spans=(), kind='function', hit_id='h1', **extra) -> SearchHit:
    evidence = Evidence(kind=kind, side='newer', origin='ghidra', title=title, snippet=snippet, spans=spans,
                        locator=locator(), seen_by=('ghidra',), group='fn', digest16='a' * 16)
    return SearchHit(hit_id=hit_id, tier=1, change_class=2, components=1, evidence=(evidence,), evidence_total=1,
                     **extra)


def result(status='ok', hits=(), **extra) -> SearchResult:
    return SearchResult(status=status, hits=tuple(hits), **extra)


def cov(status, group='fn', kinds=('function',)) -> CoverageEntry:
    return CoverageEntry(group=group, kinds=kinds, status=status)


# ---------------------------------------------------------------------------------------- states

@pytest.mark.parametrize('kwargs, state_id, text', [
    ({'has_project': False}, 'Q0', 'Open a project to search it.'),
    ({'has_project': True, 'indexed': False}, 'Q1',
     "Not indexed yet. Search reads only this project's saved data; nothing is uploaded."),
    ({'has_project': True, 'progress': vm.Progress('fn', 2, 5)}, 'Q2',
     'Indexing fn (2 of 5 groups). You can already search what is indexed.'),
    ({'has_project': True}, 'Q3', 'Search names, strings, APIs, code, notes and advisories. Use quotes for an '
     'exact phrase and -word to exclude.'),
    ({'has_project': True, 'query': 'probe', 'result': result(hits=[hit()], total=7), 'shown': 1}, 'Q4',
     "7 leads for 'probe' in everything indexed. Showing 1."),
    ({'has_project': True, 'query': 'probe', 'scope': 'changed', 'result': result(hits=[hit()], total=1), 'shown': 1},
     'Q4', "1 leads for 'probe' in changed functions. Showing 1."),
    ({'has_project': True, 'query': 'zz', 'result': result('no-results', coverage=(cov('indexed'),))}, 'Q5',
     "No results for 'zz' in what is indexed (fn indexed). This does not show the text is absent from the binary."),
    ({'has_project': True, 'query': 'zz', 'result': result('partial', coverage=(cov('indexed'), cov('building', 'raw')))},
     'Q6', 'No results yet, but the index is partial: raw is building.'),
    ({'has_project': True, 'query': 'a', 'result': result('too-broad', hits=[hit()], total_capped=True)}, 'Q7',
     "More than 20,000 matches for 'a'. Showing the first 200 in index order, not ranked. Add a word, choose a "
     'kind or side, or use a phrase.'),
    ({'has_project': True, 'result': result('stale', hits=[hit()], total=1), 'stale_what': 'revision changed'}, 'Q8',
     'The project changed after this index was built (revision changed). Results are for reference; opening one is '
     'checked against the current project.'),
    ({'has_project': True, 'result': result('unsupported')}, 'Q9',
     'Full-text search is unavailable in this build (SQLite FTS5 missing). The navigator filter still works.'),
    ({'has_project': True, 'failure': vm.Failure('PT-SEARCH-STORE', 'the search index could not be read')}, 'Q10',
     'Search failed: PT-SEARCH-STORE: the search index could not be read. Your project was not changed.'),
    ({'has_project': True, 'result': result('cancelled')}, 'Q12', 'Search cancelled. Nothing was changed.'),
    ({'has_project': True, 'result': result('indexing')}, 'Q1',
     "Not indexed yet. Search reads only this project's saved data; nothing is uploaded."),
], ids=['Q0', 'Q1', 'Q2', 'Q3', 'Q4', 'Q4-changed', 'Q5', 'Q6', 'Q7', 'Q8', 'Q9', 'Q10', 'Q12', 'Q1-result'])
def test_state_copy_is_exact(kwargs, state_id, text):
    state = vm.panel_state(**kwargs)
    assert (state.id, state.text) == (state_id, text)


@pytest.mark.parametrize('state_id, actions', [('Q1', ('Build index',)), ('Q2', ('Cancel',)),
                                               ('Q8', ('Update index',)), ('Q10', ('Retry', 'Copy details')),
                                               ('Q3', ())], ids=['Q1', 'Q2', 'Q8', 'Q10', 'Q3'])
def test_state_actions(state_id, actions):
    samples = {'Q1': {'indexed': False}, 'Q2': {'progress': vm.Progress('fn', 1, 2)},
               'Q8': {'result': result('stale', hits=[hit()], total=1)},
               'Q10': {'failure': vm.Failure('PT-SEARCH-STORE', 'x')}, 'Q3': {}}
    assert vm.panel_state(has_project=True, **samples[state_id]).actions == actions


def test_failure_wins_over_progress_and_results():
    state = vm.panel_state(has_project=True, failure=vm.Failure('PT-SEARCH-TIMEOUT', 'slow'),
                           progress=vm.Progress('fn', 1, 2), result=result(hits=[hit()], total=1))
    assert state.id == 'Q10'


def test_q11_only_when_instruction_text_is_unavailable():
    unavailable = result('ok', coverage=(cov('unavailable', 'ir', ('asm',)),))
    assert vm.coverage_notes(unavailable) == (vm.Q11,) and vm.Q11.startswith('Instruction text is not searchable')
    assert vm.coverage_notes(result('ok', coverage=(cov('indexed'),))) == ()


# ---------------------------------------------------------------------------------------- rows

def test_real_result_rows_and_columns(real):
    rows = [vm.row_view(h) for h in real.hits]
    first = rows[0]
    assert vm.HEADERS == ('Side', 'Kind', 'Match', 'Where', 'Change', 'Why')
    assert first.cells[:2] == ('Both', 'Function') and first.cells[2] == 'ClfsValidateContainerSize'
    assert first.cells[3] == 'function' and first.cells[4] == 'Modified; Only in newer'
    assert first.cells[5].startswith('tier 1: every query word') and first.function_linked and first.other_side
    assert first.accessible == (f'Function in Both: ClfsValidateContainerSize; {first.cells[3]}; Modified; Only in newer; '
                                f'{first.cells[5]}')
    advisory = rows[1]
    assert advisory.cells[1] == 'Advisory' and advisory.cells[4] == 'Not a function change'
    assert not advisory.function_linked and not advisory.other_side


def test_presence_drives_the_change_cell():
    assert vm.row_view(hit(presence=Presence(older='absent', newer='present', basis='compared'))).cells[4] == 'Only in newer'
    assert vm.row_view(hit(presence=Presence(older='present', newer='absent', basis='compared'))).cells[4] == 'Only in older'
    unknown = vm.row_view(hit(presence=Presence(basis='run missing'))).cells[4]
    assert unknown == 'Presence unknown (older unknown, newer unknown)'


def test_code_hit_spans_are_shifted_into_the_match_cell():
    row = vm.row_view(hit('Func', snippet='call probe now', spans=((5, 10),), kind='code'))
    start, end = row.spans[0]
    assert row.cells[2] == 'Func: call probe now' and row.cells[2][start:end] == 'probe'


def test_name_hit_spans_stay_on_the_title():
    row = vm.row_view(hit('ProbeForRead', snippet='ProbeForRead', spans=((0, 5),)))
    assert row.cells[2] == 'ProbeForRead' and row.spans == ((0, 5),)


@pytest.mark.parametrize('text', [HOSTILE, '‮evil', '<b>x</b>'], ids=['mixed', 'bidi', 'markup'])
def test_hostile_text_never_reaches_a_cell(text):
    h = hit(text, snippet=text, spans=())
    row = vm.row_view(h)
    shown = ' '.join((*row.cells, row.accessible, vm.detail_text(h), vm.copy_text(h)))
    assert not CONTROL.search(shown.replace('\n', ' '))  # markup stays visible plain text: widgets use drawText


@pytest.mark.parametrize('query', [HOSTILE, 'a' * 500], ids=['hostile', 'long'])
def test_query_echo_is_sanitised_and_bounded(query):
    state = vm.panel_state(has_project=True, query=query, result=result('no-results', coverage=(cov('indexed'),)))
    assert not re.search(r'[\x00-\x1f\x7f-\x9f‮]', state.text)
    assert len(state.text) < 400


# ---------------------------------------------------------------------------------------- paging

def page(n, cursor=None, total=None):
    return result(hits=[hit(f'N{i}', hit_id=f'h{i}') for i in range(n)], cursor=cursor, total=total)


def test_buffer_appends_pages_and_drops_other_generations():
    buffer = vm.ResultsBuffer(generation=3)
    assert buffer.accept(3, page(50, 'c1', 120)) == 50 and buffer.can_fetch_more and buffer.cursor == 'c1'
    assert buffer.accept(2, page(50, 'zz')) == -1 and len(buffer.rows) == 50 and buffer.cursor == 'c1'
    assert buffer.accept(3, page(70, None, 120)) == 70 and not buffer.can_fetch_more and buffer.note == ''


def test_buffer_never_holds_more_than_the_cap_for_a_huge_service():
    buffer = vm.ResultsBuffer(generation=1, cap=500)
    pages = 0
    while buffer.can_fetch_more or pages == 0:  # a million-hit service always has another cursor
        buffer.accept(1, page(200, 'next', 1_000_000))
        pages += 1
    assert len(buffer.rows) == 500 and buffer.truncated and pages == 3 and buffer.cursor is None
    assert buffer.note == 'Showing the first 5,000. Refine the search.'


def test_default_cap_is_5000():
    assert vm.ROW_CAP == 5000 and vm.CAP_NOTE == 'Showing the first 5,000. Refine the search.'


# ---------------------------------------------------------------------------------------- detail

def test_detail_sections_of_a_real_lead(real):
    sections = dict(vm.detail_sections(real.hits[0]))
    assert list(sections) == ['Result', 'Why it ranks here', 'Pair', 'Change facts', 'Provenance', 'Limitations']
    assert 'Attention: rank 1 of 3 (attention/1, ordinal)' in sections['Pair']
    assert any(line.startswith('Presence: older absent, newer present') for line in sections['Change facts'])
    assert any('from floss' in line for line in sections['Provenance'])
    assert vm.ORDINAL_NOTE in sections['Limitations']


def test_missing_attention_is_unknown_not_zero(real):
    bare = real.hits[0].model_copy(update={'expansion': real.hits[0].expansion.model_copy(update={'attention': None})})
    assert vm.NO_ATTENTION in dict(vm.detail_sections(bare))['Pair']


def test_non_function_lead_has_no_pair(real):
    assert dict(vm.detail_sections(real.hits[1]))['Pair'] == ('No pairing: this lead is not a function.',)


def test_copy_text_has_title_locator_and_provenance(real):
    text = vm.copy_text(real.hits[0])
    assert text.splitlines()[0] == 'ClfsValidateContainerSize' and 'from ghidra' in text
    assert len(vm.copy_text(hit('x' * 200))) <= vm.COPY_LIMIT


def test_evidence_total_note():
    h = hit().model_copy(update={'evidence_total': 9})
    assert 'Showing 1 of 9 matching documents.' in vm.detail_text(h)


def test_no_banned_word_in_any_shown_text(real):
    texts = [vm.detail_text(h) + vm.copy_text(h) + ' '.join(vm.row_view(h).cells) for h in real.hits]
    for state in (vm.panel_state(has_project=True, query='q', result=real, shown=3), vm.panel_state(has_project=False),
                  vm.panel_state(has_project=True), vm.panel_state(has_project=True, indexed=False),
                  vm.panel_state(has_project=True, result=result('too-broad'), query='q'),
                  vm.panel_state(has_project=True, result=result('stale', hits=[hit()]))):
        texts.append(state.text)
    texts += [vm.Q11, vm.CAP_NOTE, vm.NO_ATTENTION, vm.ORDINAL_NOTE, *vm.ACCESSIBLE_NAMES.values()]
    assert [t for t in texts if BANNED.search(t)] == []


# ---------------------------------------------------------------------------------------- suggestions

def test_suggestion_rows_carry_name_and_locator():
    suggestion = NameSuggestion(name='FormatLine', edits=1, locator=locator())
    row = vm.suggestion_row(suggestion)
    assert row.text == 'FormatLine | 0x1000 | newer | 1 edit' and row.name == 'FormatLine' and row.locator.function_id == 'f1'
    assert vm.suggestion_row(suggestion.model_copy(update={'edits': 2})).text.endswith('2 edits')


def test_duplicate_names_keep_distinct_locators():
    a = NameSuggestion(name='Same', edits=0, locator=locator())
    b = NameSuggestion(name='Same', edits=0, locator=Locator(scheme='function', function_id='f2', side='older', rva=0x20))
    rows = vm.suggestion_rows(result(suggestions=(a, b)))
    assert [r.name for r in rows] == ['Same', 'Same'] and rows[0].locator != rows[1].locator


# ---------------------------------------------------------------------------------------- tooltips

REQUIRED = ('search.dock search.action search.query search.side search.kinds search.scope search.mode search.sort '
            'search.save search.saved search.rebuild search.coverage search.table search.detail search.goto '
            'search.other_side search.copy').split()


def test_tooltip_ids_are_complete():
    assert sorted(tooltip_data.ENTRIES) == sorted(REQUIRED)
    assert sorted(tooltip_data.TEMPLATES) == ['search.coverage_row', 'search.row', 'search.suggestion']
    assert set(vm.ACCESSIBLE_NAMES) >= {'search.query', 'search.table', 'search.detail', 'search.suggestions'}


@pytest.mark.parametrize('table', ['ENTRIES', 'TEMPLATES'])
def test_tooltip_fields_are_plain_text_and_render(table):
    for key, fields in getattr(tooltip_data, table).items():
        assert len(fields) == 5 and all(isinstance(f, str) for f in fields), key
        assert all(fields[:3]), key
        rendered = TooltipEntry(*fields).render()
        assert not re.search(r'[<>]', rendered) and not BANNED.search(rendered), key


def test_template_fields_are_known():
    allowed = {'title', 'where', 'name', 'edits', 'group', 'status'}
    used = {f for fields in tooltip_data.TEMPLATES.values() for text in fields for f in re.findall(r'\{(\w+)\}', text)}
    assert used <= allowed
    assert not any('{' in text for fields in tooltip_data.ENTRIES.values() for text in fields)


def test_view_model_never_imports_qt():
    code = ("import sys; import patchtrace.search.view_model, patchtrace.search.tooltip_data; "
            "sys.exit(any(m.startswith(('PySide', 'PyQt')) for m in sys.modules))")
    done = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
