"""Saved searches and recent queries (WB1 S7, pure part): contract, bounds, dedupe, ordering, both stores, and the
old-reader gate for the `search-saved` enrichment kind. Synthetic data only."""
from __future__ import annotations

import itertools
import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from patchtrace.enrichment import storage
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.sample import create_sample
from patchtrace.search import saved
from patchtrace.search.errors import SearchError
from patchtrace.search.limits import DEFAULT_LIMITS
from patchtrace.search.query import parse_query
from patchtrace.search.saved import (
    EnrichmentSavedStore,
    MemoryRecentStore,
    MemorySavedStore,
    RecentQueries,
    RecentStore,
    SavedSearch,
    SavedSearchStore,
    dump_recent,
    load_recent,
    remember,
    rerun_plan,
)

FUTURE = '9999-01-01T00:00:00+00:00'
UUIDS = (f'00000000-0000-4000-8000-{n:012x}' for n in itertools.count(1))


def ticker():
    ticks = itertools.count()
    return lambda: datetime(2099, 1, 1, tzinfo=UTC).replace(microsecond=next(ticks))


def memory():
    return MemorySavedStore(clock=ticker(), new_id=lambda: next(UUIDS))


def raised(call, *args) -> SearchError:
    with pytest.raises(SearchError) as info:
        call(*args)
    return info.value


@pytest.fixture
def enrichment_store(tmp_path):
    svc = create_sample(tmp_path / 'real')
    try:
        yield svc, EnrichmentSavedStore(EnrichmentStore(svc.store), svc.project.id, clock=ticker(),
                                        new_id=lambda: next(UUIDS))
    finally:
        svc.close()


@pytest.fixture(params=['memory', 'enrichment'])
def store(request, enrichment_store):
    return memory() if request.param == 'memory' else enrichment_store[1]


# --- contract ---------------------------------------------------------------------------------------------------

def event(**fields) -> dict:
    base = {'saved_id': 'search-saved:00000000-0000-4000-8000-000000000001', 'op': 'create', 'name': 'n',
            'plan': parse_query('foo').model_dump(mode='json'), 'created': '2099-01-01T00:00:00+00:00'}
    return {**base, **fields}


def test_a_valid_create_and_delete_round_trip():
    create = SavedSearch.model_validate_json(json.dumps(event()))
    assert SavedSearch.model_validate_json(create.model_dump_json()) == create
    other = 'search-saved:00000000-0000-4000-8000-000000000002'
    SavedSearch.model_validate_json(json.dumps(event(saved_id=other, op='delete', name=None, plan=None,
                                                      of=create.saved_id)))


@pytest.mark.parametrize('fields', [
    {'unknown': 1}, {'contract': 'search-saved/2'}, {'name': ''}, {'name': 'x' * 65}, {'plan': None}, {'name': None},
    {'of': 'search-saved:00000000-0000-4000-8000-000000000009'}, {'saved_id': 'nope'}, {'created': 'yesterday'},
    {'op': 'delete', 'name': None, 'plan': None, 'of': None},
    {'op': 'delete', 'name': None, 'plan': None, 'of': 'search-saved:00000000-0000-4000-8000-000000000001'},
], ids=['extra', 'contract', 'empty-name', 'long-name', 'no-plan', 'no-name', 'create-target', 'bad-id',
        'bad-time', 'delete-no-target', 'delete-self'])
def test_invalid_rows_are_refused(fields):
    with pytest.raises(ValidationError):
        SavedSearch.model_validate_json(json.dumps(event(**fields)))


def test_the_model_is_frozen():
    with pytest.raises(ValidationError):
        SavedSearch.model_validate_json(json.dumps(event())).name = 'x'


# --- both stores: behaviour -------------------------------------------------------------------------------------

def test_both_stores_are_saved_search_stores(store):
    assert isinstance(store, SavedSearchStore)


def test_save_list_and_delete(store):
    first = store.save('Zeta', parse_query('foo'))
    second = store.save('alpha', parse_query('bar kind:string'))
    assert [i.name for i in store.list().items] == ['alpha', 'Zeta']  # folded name order, not insertion order
    assert (first.text, second.text) == ('foo', 'bar kind:string')
    assert store.delete(first.saved_id) is True
    assert store.delete(first.saved_id) is False
    assert store.delete('search-saved:unknown') is False
    assert [i.name for i in store.list().items] == ['alpha']
    assert store.list().skipped == 0


def test_same_name_and_plan_returns_the_existing_one_and_writes_nothing(store):
    one = store.save('Mine', parse_query('foo'))
    assert store.save('  mine ', parse_query('foo')) == one
    assert len(store.list().items) == 1


def test_same_name_with_another_plan_is_refused(store):
    store.save('Mine', parse_query('foo'))
    assert raised(store.save, 'MINE', parse_query('bar')).code == 'PT-SEARCH-INPUT'
    assert [i.text for i in store.list().items] == ['foo']


def test_a_deleted_name_can_be_used_again(store):
    old = store.save('Mine', parse_query('foo'))
    store.delete(old.saved_id)
    assert store.save('Mine', parse_query('bar')).text == 'bar'


@pytest.mark.parametrize('name', ['', '   ', 'x' * 65, 'a\x00b', 'a‮b', None, 3],
                         ids=['empty', 'blank', 'long', 'nul', 'bidi', 'none', 'int'])
def test_bad_names_are_refused(store, name):
    assert raised(store.save, name, parse_query('foo')).code == 'PT-SEARCH-INPUT'
    assert store.list().items == ()


def test_a_name_is_normalised_and_bounded(store):
    assert store.save('  a  b  ', parse_query('foo')).name == 'a b'
    assert store.save('é' + 'x' * 62, parse_query('bar')).name.startswith('é')  # NFC, then 64 counted


def test_only_a_parsed_plan_can_be_saved(store):
    assert raised(store.save, 'n', 'foo').code == 'PT-SEARCH-INPUT'


def test_the_count_is_bounded(store):
    for number in range(DEFAULT_LIMITS.saved_searches):
        store.save(f'n{number}', parse_query('foo'))
    assert raised(store.save, 'one more', parse_query('foo')).code == 'PT-SEARCH-LIMIT'
    assert len(store.list().items) == DEFAULT_LIMITS.saved_searches


def test_delete_frees_a_slot(store):
    items = [store.save(f'n{n}', parse_query('foo')) for n in range(DEFAULT_LIMITS.saved_searches)]
    store.delete(items[0].saved_id)
    assert store.save('fits', parse_query('foo')).name == 'fits'


# --- untrusted text: re-parsed, never executed ------------------------------------------------------------------

def test_running_a_saved_search_reparses_its_text():
    plan = parse_query('foo kind:string')
    item = memory().save('s', plan)
    assert rerun_plan(item) == plan


def test_a_tampered_text_is_refused_by_the_grammar_not_run(enrichment_store):
    svc, target = enrichment_store
    item = target.save('s', parse_query('foo'))
    bad = saved.SavedQuery(item.saved_id, 's', 'kind:nonsense "', item.created)
    assert raised(rerun_plan, bad).code == 'PT-SEARCH-QUERY'


def test_a_plan_that_its_text_does_not_give_is_refused(store):
    forged = parse_query('foo').model_copy(update={'text': 'bar'})
    assert raised(store.save, 's', forged).code == 'PT-SEARCH-INPUT'
    assert store.list().items == ()


# --- enrichment adapter -----------------------------------------------------------------------------------------

def test_rows_are_append_only_and_guarded(enrichment_store):
    svc, target = enrichment_store
    item = target.save('Mine', parse_query('foo'))
    target.delete(item.saved_id)
    rows = svc.store.connection.execute(
        'SELECT id, kind, run_id, raw_sha256, input_digest, stale, status FROM enrichment_entries '
        'WHERE kind=?', ('search-saved',)).fetchall()
    assert len(rows) == 2  # the create is kept; the delete is a tombstone row
    create = next(r for r in rows if r[0] == item.saved_id)
    assert create[1:3] == ('search-saved', 'search')
    assert create[3] == create[4] == parse_query('foo').digest()
    assert all(r[5] == 0 and r[6] == 'complete' for r in rows)
    assert target.list().items == ()


def test_unreadable_rows_are_counted_not_hidden(enrichment_store):
    svc, target = enrichment_store
    target.save('Mine', parse_query('foo'))
    store = EnrichmentStore(svc.store)
    guard = Guard(svc.project.id, 'search', 'a' * 64, 'a' * 64)
    newer = event(saved_id='search-saved:00000000-0000-4000-8000-0000000000aa', contract='search-saved/2')
    store.publish('search-saved', guard, guard, 0, 'complete', newer, newer['saved_id'])
    alien = event(saved_id='search-saved:00000000-0000-4000-8000-0000000000bb')
    foreign = Guard('another-project', 'search', 'a' * 64, 'a' * 64)
    store.publish('search-saved', foreign, foreign, 0, 'complete', alien, alien['saved_id'])
    mismatch = event(saved_id='search-saved:00000000-0000-4000-8000-0000000000cc')
    store.publish('search-saved', guard, guard, 0, 'complete', mismatch, 'search-saved:other')
    listed = target.list()
    assert [i.name for i in listed.items] == ['Mine'] and listed.skipped == 3


def test_saved_searches_survive_retention_and_a_reopen(enrichment_store):
    svc, target = enrichment_store
    target.save('Mine', parse_query('foo'))
    EnrichmentStore(svc.store).apply_retention(Guard(svc.project.id, 'r', 'a' * 64, 'b' * 64), started=FUTURE)
    reopened = EnrichmentSavedStore(EnrichmentStore(svc.store), svc.project.id)
    assert [i.name for i in reopened.list().items] == ['Mine']
    assert 'search-saved' not in storage.DERIVED_KINDS


def test_an_old_reader_ignores_the_kind(enrichment_store, monkeypatch):
    svc, target = enrichment_store
    target.save('Mine', parse_query('foo'))
    meta = svc.store.connection.execute("SELECT value FROM enrichment_meta WHERE key='extension_version'")
    assert meta.fetchone()[0] == '1'  # no extension_version bump: v1 clients keep full access
    old_kinds = frozenset(storage.KINDS) - {'search-saved'}
    monkeypatch.setattr(storage, 'KINDS', old_kinds)  # a reader from before saved searches
    old = EnrichmentStore(svc.store)
    for kind in sorted(old_kinds):
        assert all(e.kind == kind for e in old.entries(kind))
    old.apply_retention(Guard(svc.project.id, 'r', 'a' * 64, 'b' * 64), started=FUTURE)
    count = svc.store.connection.execute("SELECT COUNT(*) FROM enrichment_entries WHERE kind='search-saved'")
    assert count.fetchone()[0] == 1
    svc.store.save(svc.store.load())  # the project contract still opens and saves with the row present
    monkeypatch.undo()
    assert [i.name for i in EnrichmentSavedStore(EnrichmentStore(svc.store), svc.project.id).list().items] == ['Mine']


def test_a_storage_failure_is_a_typed_store_error(enrichment_store, monkeypatch):
    _, target = enrichment_store
    monkeypatch.setattr(storage, 'KINDS', frozenset(storage.KINDS) - {'search-saved'})
    assert raised(target.save, 'Mine', parse_query('foo')).code == 'PT-SEARCH-STORE'


# --- recent queries ---------------------------------------------------------------------------------------------

def test_remember_orders_newest_first_and_dedupes_by_folded_text():
    recent = ()
    for query in ('alpha', 'beta', '  Gamma  ', 'ALPHA'):
        recent = remember(recent, query)
    assert recent == ('ALPHA', 'Gamma', 'beta')


def test_remember_is_bounded_in_count_and_length():
    recent = ()
    for number in range(saved.RECENT_MAX + 5):
        recent = remember(recent, f'q{number}')
    assert len(recent) == saved.RECENT_MAX and recent[0] == f'q{saved.RECENT_MAX + 4}'
    assert remember(recent, 'x' * (DEFAULT_LIMITS.query_chars + 1)) == recent


@pytest.mark.parametrize('query', ['', '   ', 'a\x00b', 'a‮b', None, 7], ids=['empty', 'blank', 'nul', 'bidi',
                                                                                    'none', 'int'])
def test_remember_ignores_unusable_queries(query):
    assert remember(('keep',), query) == ('keep',)


def test_recent_round_trips_through_text():
    recent = ('b', 'a')
    assert load_recent(dump_recent(recent)) == recent
    assert json.loads(dump_recent(recent))['contract'] == 'search-recent/1'


@pytest.mark.parametrize('text', [None, '', 'not json', '[]', '{}', '{"contract": "search-recent/2", "queries": ["a"]}',
                                  '{"contract": "search-recent/1", "queries": "a"}'],
                         ids=['none', 'empty', 'garbage', 'list', 'no-contract', 'newer', 'bad-queries'])
def test_load_recent_reads_garbage_as_empty(text):
    assert load_recent(text) == ()


def test_load_recent_ignores_unknown_fields_and_drops_bad_entries():
    text = json.dumps({'contract': 'search-recent/1', 'extra': 1, 'queries': ['b', 5, '', 'a\x00', 'a', 'B']})
    assert load_recent(text) == ('b', 'a')


def test_load_recent_bounds_a_hostile_list():
    text = json.dumps({'contract': 'search-recent/1', 'queries': [f'q{n}' for n in range(5000)]})
    assert len(load_recent(text)) == saved.RECENT_MAX


def test_recent_queries_over_a_store():
    backing = MemoryRecentStore()
    assert isinstance(backing, RecentStore)
    recent = RecentQueries(backing)
    assert recent.items() == ()
    recent.add('one')
    assert recent.add('two') == ('two', 'one')
    assert RecentQueries(backing).items() == ('two', 'one')
    recent.clear()
    assert recent.items() == ()


def test_recent_queries_survive_a_corrupt_backing_value():
    recent = RecentQueries(MemoryRecentStore('{{{'))
    assert recent.add('fresh') == ('fresh',)
