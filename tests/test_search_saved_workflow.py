"""Saved workflow: real project persistence, compatible plans, bounded settings and headless ownership."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from PySide6.QtCore import QSettings

from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.gui.qt.settings import PanelSettings
from patchtrace.search import cli
from patchtrace.search.errors import SearchError
from patchtrace.search.query import parse_query
from patchtrace.search.saved import EnrichmentSavedStore, MemorySavedStore, SavedQuery, rerun_plan
from patchtrace.service import ProjectService


@pytest.mark.parametrize('mode', ['auto', 'words', 'exact', 'prefix', 'substring', 'similar'])
def test_saved_query_round_trips_every_validated_mode(mode):
    store = MemorySavedStore()
    plan = parse_query('ReadItem side:older scope:changed', mode=mode)
    item = store.save('Useful query', plan)
    assert rerun_plan(store.list().items[0]).digest() == plan.digest()
    assert store.save('Useful query', plan) == item


def test_effective_filters_preserve_phrases_and_replace_only_explicit_filters():
    from patchtrace.search.saved_actions import effective_plan

    plan = effective_plan('"side:newer" read side:newer scope:changed kind:function',
                          mode='exact', side='older', scope='indexed')
    assert plan.phrases == ('side:newer',)
    assert plan.sides == ('older',) and plan.scope == 'indexed' and plan.mode == 'exact'
    assert parse_query(plan.text, mode=plan.mode).digest() == plan.digest()
    assert effective_plan('read side:newer scope:changed').sides == ('newer',)
    assert effective_plan('read side:newer', side='both').sides == ()
    with pytest.raises(SearchError):
        effective_plan('x' * 256, side='older')


def test_canonical_filter_overrides_never_remove_ordinary_side_or_scope_words():
    from patchtrace.search.saved_actions import effective_plan

    plan = effective_plan('side scope read', side='older', scope='changed')
    assert [term.nfc for term in plan.terms] == ['side', 'scope', 'read']


def test_legacy_read_dto_defaults_to_auto_and_invalid_mode_is_typed():
    legacy = SavedQuery('id', 'name', 'read', '2099-01-01T00:00:00+00:00')
    assert rerun_plan(legacy).mode == 'auto'
    invalid = SavedQuery('id', 'name', 'read', legacy.created, mode='not-a-mode')
    with pytest.raises(SearchError, match='PT-SEARCH-QUERY'):
        rerun_plan(invalid)


def test_recent_adapter_keeps_long_queries_with_both_budgets_and_clear(tmp_path):
    from patchtrace.search.qt_saved import SettingsRecentStore
    from patchtrace.search.saved import RecentQueries, dump_recent
    from patchtrace.search.saved_actions import RECENT_BYTES

    settings = PanelSettings(QSettings(str(tmp_path / 'settings.ini'), QSettings.Format.IniFormat), 'search')
    recent = RecentQueries(SettingsRecentStore(settings))
    for index in range(30):
        recent.add(chr(0x1f600 + index) * 256)
    items = recent.items()
    assert 1 < len(items) <= 20
    assert all(len(item) == 256 for item in items)
    assert len(dump_recent(items).encode('utf-8')) <= RECENT_BYTES
    assert len(dump_recent((chr(0x1f600 + 29) * 256,) * 20).encode('utf-8')) > RECENT_BYTES
    assert items == RecentQueries(SettingsRecentStore(settings)).items()
    recent.clear()
    assert recent.items() == () and settings.get_list('recent') == ()


@pytest.fixture
def project_path(tmp_path):
    service = ProjectService.sample(tmp_path / 'project')
    path = service.root
    service.close()
    return path


def call(path, *args, **kwargs):
    out, err = io.StringIO(), io.StringIO()
    code = cli.main([str(path), *args, '--json'], stdout=out, stderr=err, **kwargs)
    assert out.getvalue().count('\n') == 1
    return code, json.loads(out.getvalue()), err.getvalue()


def test_cli_save_list_reopen_delete_never_constructs_search(project_path, monkeypatch):
    from patchtrace.search.service import SearchService

    def forbidden(*_args, **_kwargs):
        raise AssertionError('storage-only action constructed the search service')

    monkeypatch.setattr(SearchService, '__init__', forbidden)
    code, doc, err = call(project_path, '--save', 'Exact older', '--query', 'read_item',
                          '--mode', 'exact', '--side', 'older', '--scope', 'changed')
    assert code == 0, err
    item = doc['result']['item']
    assert item['mode'] == 'exact' and 'side:older' in item['text']
    code, listed, _ = call(project_path, '--saved-list')
    assert code == 0 and listed['result']['items'] == [item]
    assert call(project_path, '--saved-delete', item['saved_id'])[1]['result']['deleted'] is True
    assert call(project_path, '--saved-delete', item['saved_id'])[1]['result']['deleted'] is False
    assert call(project_path, '--saved-list')[1]['result']['items'] == []
    service = ProjectService.open(project_path)
    try:
        assert len(EnrichmentStore(service.store).entries('search-saved')) == 2
    finally:
        service.close()


@pytest.mark.parametrize('arguments', [
    ['--saved-list', '--query', 'read'], ['--saved-delete', 'id', '--mode', 'exact'],
    ['--saved-run', 'id', '--side', 'older'], ['--save', 'name', '--query', 'read', '--rebuild'],
    ['--saved-list', '--probe'], ['--saved-list', '--status'],
])
def test_invalid_saved_combinations_do_not_open_project(arguments):
    def forbidden(_path):
        raise AssertionError('invalid arguments opened the project')

    code, doc, _ = call('unused', *arguments, opener=forbidden)
    assert code == 2 and doc['status'] == 'failed'


def test_cli_one_open_and_close_including_store_failure(project_path, monkeypatch):
    opened, closed = [], []

    def opener(path):
        service = ProjectService.open(path)
        real_close = service.close
        opened.append(service)

        def close():
            closed.append(service)
            real_close()

        service.close = close
        return service, None

    assert call(project_path, '--saved-list', opener=opener)[0] == 0
    assert opened == closed and len(opened) == 1
    monkeypatch.setattr(EnrichmentSavedStore, 'list', lambda _s: (_ for _ in ()).throw(
        SearchError('PT-SEARCH-STORE', 'controlled store failure')))
    assert call(project_path, '--saved-list', opener=opener)[0] == 3
    assert opened == closed and len(opened) == 2


def test_persisted_legacy_and_tampered_clauses_reparse_while_corrupt_mode_is_skipped(project_path):
    service = ProjectService.open(project_path)
    try:
        store = EnrichmentStore(service.store)
        guard = Guard(service.project.id, 'search', 'a' * 64, 'a' * 64)
        for number, label in enumerate(('legacy', 'tampered', 'corrupt'), 1):
            plan = parse_query('read_item', mode='exact' if label != 'legacy' else 'auto').model_dump(mode='json')
            if label == 'legacy':
                del plan['mode']
            elif label == 'tampered':
                plan['terms'] = parse_query('smuggled').model_dump(mode='json')['terms']
            else:
                plan['mode'] = 'execute-sql'
            ident = f'search-saved:00000000-0000-4000-8000-{number:012x}'
            event = {'contract': 'search-saved/1', 'saved_id': ident, 'op': 'create', 'name': label,
                     'plan': plan, 'created': '2099-01-01T00:00:00+00:00'}
            store.publish('search-saved', guard, guard, service.project.revision, 'complete', event, ident)
    finally:
        service.close()
    code, doc, _ = call(project_path, '--saved-list')
    assert code == 0 and doc['result']['skipped'] == 1 and doc['warnings']
    items = {item['name']: item for item in doc['result']['items']}
    assert set(items) == {'legacy', 'tampered'} and items['legacy']['mode'] == 'auto'
    plan = rerun_plan(SavedQuery(**items['tampered']))
    assert plan.mode == 'exact' and [term.nfc for term in plan.terms] == ['read_item']


def test_saved_cli_real_headless_journey_and_deleted_run(project_path, tmp_path):
    script = r'''
import io, json, sys
from patchtrace.search.cli import main
def run(*args):
    out = io.StringIO()
    code = main([sys.argv[1], *args, '--json'], stdout=out)
    return code, json.loads(out.getvalue())
code, saved = run('--save', 'Exact', '--query', 'read_item', '--mode', 'exact', '--side', 'newer')
assert code == 0, saved
ident = saved['result']['item']['saved_id']
code, result = run('--saved-run', ident, '--cache-dir', sys.argv[2])
assert code == 0 and result['result']['hits'], result
assert all(e['side'] == 'newer' for h in result['result']['hits'] for e in h['evidence'])
assert run('--saved-delete', ident)[0] == 0
assert run('--saved-run', ident, '--cache-dir', sys.argv[2])[0] == 2
assert not [m for m in sys.modules if m.startswith(('PySide6', 'patchtrace.ui', 'patchtrace.search.qt_'))]
print('real saved-search CLI journey passed without Qt')
'''
    result = subprocess.run([sys.executable, '-c', script, str(project_path), str(tmp_path / 'cache')],
                            capture_output=True, text=True, timeout=30,
                            env={**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')})
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'journey passed without Qt' in result.stdout
