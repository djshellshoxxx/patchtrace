"""Offline retained-page service/CLI journeys over authored CSV bytes."""
from __future__ import annotations

import threading

import kbc_helpers as h
import pytest
from kbc_k1_support import import_fixture, no_sockets  # noqa: F401
from kbc_k3_support import FixedClock, Kb

from patchtrace.kbcorrelation import cli, wiring
from patchtrace.kbcorrelation.inventory_contracts import InventoryLimits
from patchtrace.kbcorrelation.inventory_service import context_for
from patchtrace.kbcorrelation.inventory_store import add_inventory
from patchtrace.kbcorrelation.sources.cvrf import SourceError
from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore

pytestmark = pytest.mark.usefixtures('no_sockets')
HEADER = b'File name,File version,File size,Architecture\n'


def late_native_csv():
    return HEADER + b''.join(f'arm{i}.sys,1.2.3.4,128,arm64\n'.encode() for i in range(5001)) + (
        b'exampledrv.sys,1.2.3.4,256,x64\n')


def imported(service, tmp_path, raw):
    path = tmp_path / 'source.csv'
    path.write_bytes(raw)
    return service.import_inventory(path, context_for('KB5099001')).result['import_id']


@pytest.mark.parametrize('parent_budget', [5_000, 50_000])
def test_retention_reaches_later_native_section_without_changing_v1_or_investigation(tmp_path, parent_budget):
    service = wiring.build_service(tmp_path / 'ws', clock=FixedClock())
    with WorkspaceStore(service.root) as ws:
        ws.add_document(import_fixture('cvrf-2099-Feb.json'), h.read_fixture_bytes('cvrf-2099-Feb.json'))
    investigation = service.search('KB5099001').result['investigation_id']
    if parent_budget == 50_000:
        source_id = imported(service, tmp_path, late_native_csv())
    else:
        with WorkspaceStore(service.root) as ws:
            original, _ = add_inventory(ws, late_native_csv(), context_for('KB5099001'),
                                        now='2099-01-01T00:00:00Z',
                                        limits=InventoryLimits(max_entries=parent_budget))
            source_id = original.import_id
    before = service.inventory_details(source_id).result
    assert before['inventory']['accepted_count'] == min(parent_budget, 5002)
    assert before['inventory']['truncated'] is (parent_budget < 5002)
    with WorkspaceStore(service.root) as ws:
        revision, decisions = ws.current_revision(investigation), ws.decisions(investigation)

    retained = service.retain_inventory(source_id)
    result, summary = retained.result, retained.result['inventory']
    assert retained.exit == 3 and retained.status == 'partial'
    assert result['source_import_id'] == source_id and result['import_id'] != source_id
    assert summary['contract'] == 'kb-file-inventory/2'
    assert summary['retention'] == {'architecture': 'amd64', 'page': 1}
    assert summary['scan_complete'] is True and summary['page_capacity'] == 5000
    assert (summary['matching_count'], summary['excluded_count'], summary['omitted_count']) == (1, 5001, 0)
    assert summary['conflict_witness_count'] == 0
    assert summary['context']['architecture'] == 'unknown'  # the filter is not a context assertion
    assert summary['source'] == before['inventory']['source']
    assert 'Source scan: complete' in retained.text and 'excluded 5001' in retained.text
    detail = service.inventory_details(result['import_id']).result
    assert [entry['basename'] for entry in detail['entries']] == ['exampledrv.sys']
    assert detail['entries'][0]['reference']['logical_record'] == 5003
    assert service.inventory_details(source_id).result == before
    again = service.retain_inventory(result['import_id'])
    assert again.result['import_id'] == result['import_id'] and again.result['already_present']
    assert service.inventories().result['total'] == 2
    listed = next(item for item in service.inventories().result['inventories']
                  if item['import_id'] == result['import_id'])
    assert listed['retention'] == summary['retention'] and listed['scan_complete'] is True
    with WorkspaceStore(service.root) as ws:
        assert ws.current_revision(investigation) == revision and ws.decisions(investigation) == decisions


@pytest.mark.parametrize('arguments', [
    {'page': 0}, {'page': 100001}, {'page': True}, {'page': '1'}, {'architecture': 'x64'},
])
def test_retention_policy_is_validated_before_opening_or_creating_workspace(tmp_path, arguments):
    service = wiring.build_service(tmp_path / 'absent', clock=FixedClock())
    with pytest.raises(SourceError) as caught:
        service.retain_inventory('a' * 64, **arguments)
    assert caught.value.code == 'PT-KBC-INPUT' and not service.root.exists()


def test_cancelled_retention_never_opens_a_workspace(tmp_path):
    service = wiring.build_service(tmp_path / 'absent', clock=FixedClock())
    cancelled = threading.Event()
    cancelled.set()
    with pytest.raises(SourceError) as caught:
        service.retain_inventory('a' * 64, cancel=cancelled)
    assert caught.value.code == 'PT-KBC-CANCEL' and not service.root.exists()


def test_unknown_retention_source_is_not_a_new_import(tmp_path):
    service = wiring.build_service(tmp_path / 'absent', clock=FixedClock())
    with pytest.raises((SourceError, KbcStoreError)):
        service.retain_inventory('a' * 64)
    assert not service.root.exists()


@pytest.mark.parametrize('flag', ['--help', '-h'])
def test_retain_help_is_offline_and_does_not_initialize_service(monkeypatch, capsys, flag):
    def forbidden(*_args):
        pytest.fail('retain help initialized service')

    monkeypatch.setattr(cli.Context, '_env', forbidden)
    assert cli.main(['inventory', 'retain', flag]) == 0
    output = capsys.readouterr()
    assert not output.err and all(word in output.out for word in ('IMPORT_ID', '--architecture', '--page'))


@pytest.mark.parametrize('arguments', [[], ['a' * 64, '--page', '0'], ['a' * 64, '--page', '100001'],
                                      ['a' * 64, '--page', 'first'], ['a' * 64, '--architecture', 'x64']])
def test_invalid_retain_cli_has_one_input_error_and_no_workspace(tmp_path, capsys, arguments):
    kb = Kb(tmp_path, capsys)
    code, document, error = kb('inventory', 'retain', *arguments)
    assert code == 2 and document['status'] == 'failed' and error.startswith('error:')
    assert not kb.workspace.exists()


def test_cli_retention_and_show_keep_distinct_source_and_display_pagination(tmp_path, capsys):
    kb = Kb(tmp_path, capsys)
    path = tmp_path / 'source.csv'
    path.write_bytes(late_native_csv())
    code, original, _ = kb('inventory', 'import', str(path), '--kb', 'KB5099001')
    assert code == 0 and original['result']['inventory']['accepted_count'] == 5002
    assert not original['result']['inventory']['truncated']
    source = original['result']['import_id']
    code, retained, error = kb('inventory', 'retain', source, '--architecture', 'amd64', '--page', '1')
    assert code == 3 and not error and retained['command'] == 'kb inventory retain'
    page_id = retained['result']['import_id']
    summary = retained['result']['inventory']
    assert summary['matching_count'] == 1 and summary['excluded_count'] == 5001
    _, shown, _ = kb('inventory', 'show', page_id, '--limit', '1', '--offset', '0')
    assert shown['result']['entries'][0]['basename'] == 'exampledrv.sys'
    assert shown['result']['inventory']['retention']['page'] == 1
    _, empty, _ = kb('inventory', 'show', page_id, '--limit', '1', '--offset', '1')
    assert empty['result']['entries'] == [] and empty['result']['inventory']['retention']['page'] == 1
    code, repeated, _ = kb('inventory', 'retain', source)
    assert code == 3 and repeated['result']['import_id'] == page_id and repeated['result']['already_present']


def test_cli_second_source_page_respects_the_captured_lower_capacity(tmp_path, capsys):
    kb = Kb(tmp_path, capsys)
    raw = HEADER + b'first.sys,1.2.3.4,128,x64\nsecond.sys,1.2.3.4,128,x64\n'
    with WorkspaceStore(kb.workspace) as ws:
        original, _ = add_inventory(ws, raw, context_for('KB5099001'), now=FixedClock().now_utc(),
                                    limits=InventoryLimits(max_entries=1))
    code, retained, _ = kb('inventory', 'retain', original.import_id, '--page', '2')
    assert code == 3
    summary = retained['result']['inventory']
    assert summary['retention'] == {'architecture': 'amd64', 'page': 2}
    assert summary['page_capacity'] == 1 and summary['matching_count'] == 2 and summary['omitted_count'] == 1
    _, shown, _ = kb('inventory', 'show', retained['result']['import_id'])
    assert [entry['basename'] for entry in shown['result']['entries']] == ['second.sys']


def test_retained_summary_and_details_expose_conflicts_beyond_the_page(tmp_path):
    service = wiring.build_service(tmp_path / 'ws', clock=FixedClock())
    raw = HEADER + b'example.sys,1.2.3.4,128,x64\nexample.sys,1.2.3.4,256,x64\n'
    with WorkspaceStore(service.root) as ws:
        original, _ = add_inventory(ws, raw, context_for('KB5099001'), now=service._now(),
                                    limits=InventoryLimits(max_entries=1))
    retained = service.retain_inventory(original.import_id)
    summary = retained.result['inventory']
    assert retained.exit == 3 and summary['scan_complete'] is True
    assert summary['conflict_count'] == summary['conflict_witness_count'] == 1
    details = service.inventory_details(retained.result['import_id']).result
    assert details['entries'][0]['state'] == 'conflicted'
    assert len(details['inventory']['conflict_witnesses']) == 1


def test_incomplete_source_scan_summary_never_suggests_filename_selection(tmp_path):
    service = wiring.build_service(tmp_path / 'ws', clock=FixedClock())
    raw = HEADER + b'first.sys,1.2.3.4,128,x64\nsecond.sys,1.2.3.4,128,x64\n'
    with WorkspaceStore(service.root) as ws:
        original, _ = add_inventory(ws, raw, context_for('KB5099001'), now=service._now(),
                                    limits=InventoryLimits(max_records=2))
    retained = service.retain_inventory(original.import_id)
    assert retained.exit == 3 and retained.result['inventory']['scan_complete'] is False
    assert 'counts cover only the observed source prefix' in retained.text
    assert 'Filename selection is unavailable' in retained.text
