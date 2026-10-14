from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from patchtrace.search.contracts import QueryPlan
from patchtrace.search.errors import SearchError
from patchtrace.search.query import TABLE_COLUMNS, match_substring, match_words, parse_query
from patchtrace.search.tokenize import code_idents, name_words

FIXTURES = Path(__file__).parent / 'fixtures' / 'search'
QUERIES = json.loads((FIXTURES / 'queries.json').read_text(encoding='utf-8'))
HOSTILE = json.loads((FIXTURES / 'hostile.json').read_text(encoding='utf-8'))
ANY_TEXT = st.text(alphabet=st.characters(exclude_categories=()), max_size=300)
FRAGMENTS = ['a', 'ab', 'copy', 'mem*', '-x', '-', '*', '"', '"p q"', 'kind:string', 'kind:', 'side:newer', 'is:added',
             'in:code', 'scope:changed', 'CVE-2024-1234', '0x140001a40', '1400', 'NEAR(', 'OR', 'AND', 'NOT', '(', ')',
             '^', '{', '}', ':', 'raw:x', "'", '%', '\\', 'std::v', 'é', '中', '\ud800', '\x00', 'é']
GRAMMAR_TEXT = st.lists(st.sampled_from(FRAGMENTS), max_size=12).map(' '.join)
_DB: dict[str, sqlite3.Connection] = {}


def _tables() -> sqlite3.Connection:
    """One real database holding every table shape the builders target; shared by all tests of this module."""
    if 'db' not in _DB:
        db = sqlite3.connect(':memory:')
        tok = "tokenize='unicode61 remove_diacritics 2'"
        db.execute(f'CREATE VIRTUAL TABLE fts_name USING fts5(raw, words, {tok})')
        db.execute("CREATE VIRTUAL TABLE tri_name USING fts5(name, tokenize='trigram')")
        db.execute(f'CREATE VIRTUAL TABLE fts_code USING fts5(body, idents, {tok})')
        db.execute(f'CREATE VIRTUAL TABLE fts_text USING fts5(title, body, {tok})')
        for i, name in enumerate(['RtlCopyMemory', 'ProbeForRead', 'FUN_140001a40', 'École', 'std::vector<int>']):
            db.execute('INSERT INTO fts_name(rowid, raw, words) VALUES (?, ?, ?)', (i, name.casefold(), name_words(name)))
            db.execute('INSERT INTO tri_name(rowid, name) VALUES (?, ?)', (i, name.casefold()))
        body = 'if (ProbeForRead(p, n)) RtlCopyMemory(d, p, n);'
        db.execute('INSERT INTO fts_code(rowid, body, idents) VALUES (1, ?, ?)', (body, code_idents(body)))
        db.execute('INSERT INTO fts_text(rowid, title, body) VALUES (1, ?, ?)', ('CVE-2024-1234', 'copy memory flaw'))
        _DB['db'] = db
    return _DB['db']


def _run_all_builders(plan: QueryPlan) -> None:
    db = _tables()
    for table in ('fts_name', 'fts_code', 'fts_text'):
        for columns in (None, TABLE_COLUMNS[table], TABLE_COLUMNS[table][:1]):
            expression = match_words(plan, table, columns)
            if expression is not None:
                db.execute(f'SELECT rowid FROM {table} WHERE {table} MATCH ? LIMIT 5', (expression,)).fetchall()
    expression = match_substring(plan)
    if expression is not None:
        db.execute('SELECT rowid FROM tri_name WHERE tri_name MATCH ? LIMIT 5', (expression,)).fetchall()


def _parse_or_refuse(text: str) -> QueryPlan | None:
    try:
        return parse_query(text)
    except SearchError as err:
        assert err.code == 'PT-SEARCH-QUERY' and err.exit_code == 2
        return None


@pytest.mark.parametrize('index', range(len(QUERIES['ok'])), ids=lambda i: f'ok{i}')
def test_golden_plans(index):
    case = QUERIES['ok'][index]
    plan = parse_query(case['query'])
    assert plan.text == case.get('text', case['query'].strip())
    assert [t.fold for t in plan.terms] == case.get('terms', [])
    assert [list(t.alt) for t in plan.terms if t.alt] == case.get('alt', [])
    assert list(plan.phrases) == case.get('phrases', [])
    assert list(plan.excludes) == case.get('excludes', [])
    assert plan.last_prefix is case.get('last_prefix', False)
    assert list(plan.kinds) == case.get('kinds', [])
    assert list(plan.sides) == case.get('sides', [])
    assert plan.scope == case.get('scope', 'indexed')
    assert list(plan.is_) == case.get('is', [])
    assert list(plan.in_) == case.get('in', [])
    assert [[i.kind, i.value] for i in plan.identity] == case.get('identity', [])
    assert match_words(plan, 'fts_name') == case['name']
    assert match_substring(plan) == case['substring']
    _run_all_builders(plan)


@pytest.mark.parametrize('index', range(len(QUERIES['errors'])), ids=lambda i: f'err{i}')
def test_golden_errors(index):
    case = QUERIES['errors'][index]
    with pytest.raises(SearchError) as err:
        parse_query(case['query'])
    assert err.value.code == 'PT-SEARCH-QUERY' and err.value.recoverable
    assert case['hint'] is None or case['hint'] in err.value.message


@pytest.mark.parametrize('index', range(len(HOSTILE)), ids=lambda i: f'h{i}')
def test_hostile_inputs_never_break_sql(index):
    plan = _parse_or_refuse(HOSTILE[index])
    if plan is not None:
        _run_all_builders(plan)


@given(ANY_TEXT)
@settings(max_examples=500, deadline=None)
def test_no_unicode_input_raises_operational_error(text):
    plan = _parse_or_refuse(text)
    if plan is not None:
        _run_all_builders(plan)


@given(GRAMMAR_TEXT)
@settings(max_examples=500, deadline=None)
def test_grammar_soup_never_raises_operational_error(text):
    plan = _parse_or_refuse(text)
    if plan is not None:
        _run_all_builders(plan)
        assert QueryPlan.model_validate_json(plan.model_dump_json()) == plan


def test_matches_against_real_tables():
    db = _tables()

    def rows(table, expression):
        return [r[0] for r in db.execute(f'SELECT rowid FROM {table} WHERE {table} MATCH ? ORDER BY rowid', (expression,))]

    assert rows('fts_name', match_words(parse_query('copy'), 'fts_name')) == [0]  # CamelCase blind spot [F8]
    assert rows('fts_name', match_words(parse_query('copy mem'), 'fts_name')) == [0]  # implicit prefix
    assert rows('fts_name', match_words(parse_query('copy mem', mode='words'), 'fts_name')) == []
    assert rows('fts_name', match_words(parse_query('re'), 'fts_name')) == [1]  # prefix of `read`
    assert rows('fts_name', match_words(parse_query('re -probe'), 'fts_name')) == []  # exclusion wins
    assert rows('fts_name', match_words(parse_query('co -probe'), 'fts_name')) == [0]
    assert rows('fts_name', match_words(parse_query('école'), 'fts_name')) == [3]
    assert rows('fts_name', match_words(parse_query('ECOLE'), 'fts_name')) == [3]  # remove_diacritics 2
    assert rows('tri_name', match_substring(parse_query('opymem'))) == [0]
    assert rows('tri_name', match_substring(parse_query('opy_mem'))) == []  # literal, `_` is no wildcard
    assert rows('fts_name', match_words(parse_query('0x140001a40'), 'fts_name')) == []  # raw column holds the name
    assert rows('fts_name', match_words(parse_query('140001a40'), 'fts_name')) == [2]
    assert rows('fts_code', match_words(parse_query('probe'), 'fts_code', ('idents',))) == [1]
    assert rows('fts_code', match_words(parse_query('probe', mode='words'), 'fts_code', ('body',))) == []  # body holds ProbeForRead
    assert rows('fts_code', match_words(parse_query('"for read"'), 'fts_code', ('idents',))) == [1]
    assert rows('fts_text', match_words(parse_query('"copy memory"'), 'fts_text')) == [1]
    assert rows('fts_text', match_words(parse_query('cve-2024-1234'), 'fts_text', ('title',))) == [1]
    assert rows('fts_text', match_words(parse_query('"memory copy"'), 'fts_text')) == []  # adjacency, order


def test_column_filter_comes_from_an_allow_list():
    plan = parse_query('copy')
    with pytest.raises(ValueError):
        match_words(plan, 'fts_name', ('body',))
    with pytest.raises(ValueError):
        match_words(plan, 'fts_name', ())
    with pytest.raises(ValueError):
        match_words(plan, 'tri_name')
    with pytest.raises(ValueError):
        match_words(plan, 'doc; DROP TABLE doc')


def test_user_text_never_becomes_fts_syntax():
    plan = parse_query('OR NEAR(a b) raw:x ^y')
    expression = match_words(plan, 'fts_name')
    assert expression == '"or" AND "near(a" AND "b)" AND "raw:x" AND "^y" *'


def test_digest_is_whitespace_and_order_stable():
    first, second = parse_query('kind:string  copy'), parse_query('copy kind:string')
    assert first.digest() == second.digest()
    assert first.canonical() == parse_query('kind:string copy').canonical() != second.canonical()  # text is display
    assert first.digest() != parse_query('copy kind:import').digest()
    assert first.digest() != parse_query('copy kind:string', mode='words').digest()
    assert len(first.digest()) == 64


def test_mode_words_has_no_implicit_prefix():
    assert parse_query('copy', mode='auto').last_prefix and not parse_query('copy', mode='words').last_prefix


def test_nfc_text_is_canonical():
    assert parse_query('école').text == 'école'
    assert parse_query('école').digest() == parse_query('école').digest()
