"""Published v1 capacity and bounded v2 pages preserve captured evidence."""
from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from pydantic import ValidationError
from test_kbc_inventory_store import fetched

from patchtrace.kbcorrelation import inventory_contracts as contracts
from patchtrace.kbcorrelation import inventory_csv as csv
from patchtrace.kbcorrelation import inventory_store as store
from patchtrace.kbcorrelation.sources.cvrf import SourceError
from patchtrace.kbcorrelation.store import WorkspaceStore

pytestmark = pytest.mark.usefixtures('no_sockets')
CONTEXT = contracts.InventoryContext(kb='KB5099001')
NOW = '2099-03-02T00:00:00Z'
HEADER = 'File name,File version,File size,Architecture\r\n'
RAW = (HEADER + 'example.dll,1.2.3.4,128,x64\r\n').encode()
FIXTURE = Path(__file__).parent / 'fixtures/kbcorrelation/inventory-capacity-compat.json'
GOLDENS = json.loads(FIXTURE.read_text())['records']


def retention(page=1):
    return contracts.InventoryRetention(architecture='amd64', page=page)


@pytest.mark.parametrize('golden', GOLDENS, ids=lambda value: value['name'])
def test_captured_v1_and_v2_records_replay_without_rebinding_bytes_or_identities(tmp_path, golden):
    raw, body = golden['raw_utf8'].encode(), golden['record_json']
    value = json.loads(body)
    assert hashlib.sha256(body.encode()).hexdigest() == golden['record_sha256']
    with WorkspaceStore(tmp_path / 'ws') as ws:
        store._create_table(ws, store.INVENTORY_TABLE)
        ws.db.execute(f'INSERT INTO {store.INVENTORY_TABLE} VALUES (?,?,?,?,?,?)',
                      (1, value['import_id'], value['source']['sha256'], len(raw), body,
                       golden['record_sha256']))
        path = ws.object_path(value['source']['sha256'])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(gzip.compress(raw, mtime=0))
        original_raw = path.read_bytes()
        for verify in (False, True):
            replayed = store.get_inventory(ws, value['import_id'], verify=verify)
            assert replayed.model_dump_json() == body
        listed, = store.list_inventories(ws)
        assert listed.model_dump_json() == body
        if replayed.parsed.parser_version == 1:
            repeated, added = store.add_inventory(ws, raw, replayed.parsed.context, now=NOW,
                                                  limits=replayed.parsed.limits)
        else:
            repeated, added = store.retain_inventory(ws, replayed.import_id, replayed.parsed.retention)
        assert not added and repeated.model_dump_json() == body
        assert path.read_bytes() == original_raw
        assert ws.db.execute(f'SELECT body FROM {store.INVENTORY_TABLE}').fetchone() == (body,)
        assert store.inventory_count(ws) == 1
        assert ws.db.execute('SELECT COUNT(*) FROM revisions').fetchone()[0] == 0


def test_published_v1_default_and_v2_default_have_separate_budget_identities():
    ordinary = csv.parse_inventory(RAW, CONTEXT)
    page = csv.parse_inventory_page(RAW, CONTEXT, retention())
    assert ordinary.limits.max_entries == 50_000
    assert page.limits.max_entries == 5_000
    captured = contracts.InventoryLimits(max_entries=5_000)
    assert page.inventory_id == contracts.inventory_page_identity(page.raw_sha256, CONTEXT, retention(), captured)
    assert page.inventory_id == contracts.inventory_page_identity(page.raw_sha256, CONTEXT, retention())
    assert page.inventory_id != ordinary.inventory_id


@pytest.mark.parametrize('budget', [5_001, 50_000])
def test_v2_parser_rejects_wider_v1_budget_even_for_one_retained_entry(budget):
    limits = contracts.InventoryLimits(max_entries=budget)
    with pytest.raises(SourceError) as caught:
        csv.parse_inventory_page(RAW, CONTEXT, retention(), limits=limits)
    assert caught.value.code == 'PT-KBC-INPUT'


@pytest.mark.parametrize('budget', [5_001, 50_000])
def test_saved_v2_rejects_wider_budget_with_consistent_one_row_identity(budget):
    parsed = csv.parse_inventory_page(RAW, CONTEXT, retention())
    body = parsed.model_dump(mode='json')
    wider = contracts.InventoryLimits(max_entries=budget)
    body['limits'] = wider.model_dump(mode='json')
    body['inventory_id'] = contracts.inventory_page_identity(parsed.raw_sha256, CONTEXT, retention(), wider)
    body['entries'][0]['entry_id'] = contracts.entry_identity(body['inventory_id'], 2)
    with pytest.raises(ValidationError) as caught:
        contracts.CsvInventoryPage.model_validate_json(json.dumps(body))
    assert any(error['loc'] == ('limits', 'max_entries') for error in caught.value.errors())


@pytest.mark.parametrize('budget', [5_001, True, '1', 1.5])
def test_page_budget_model_is_strict_and_does_not_inherit_the_wider_v1_ceiling(budget):
    with pytest.raises(ValidationError):
        contracts.InventoryPageLimits(max_entries=budget)


def test_page_schema_keeps_retained_counts_and_arrays_bounded_independently_of_v1():
    fields = contracts.CsvInventoryPage.model_json_schema()['properties']
    for name in ('entries', 'conflict_witnesses'):
        assert fields[name]['maxItems'] == 5_000
    for name in ('accepted_count', 'duplicate_count', 'conflict_count'):
        assert fields[name]['maximum'] == 5_000
    for name in ('records_scanned', 'matching_count', 'excluded_count', 'omitted_count'):
        assert fields[name]['maximum'] == 100_000
    assert contracts.InventoryLimits.model_json_schema()['properties']['max_entries']['maximum'] == 50_000
    assert contracts.InventoryPageLimits.model_json_schema()['properties']['max_entries']['maximum'] == 5_000


@pytest.mark.parametrize('parent_budget', [1, 2, 5_000, 50_000])
def test_page_two_derives_only_entry_budget_and_keeps_parent_source_and_revisions(tmp_path, parent_budget):
    capacity = min(parent_budget, 5_000)
    count = min(2 * capacity + 1, 5_001)
    raw = (HEADER + ''.join(f'file{index}.dll,1.2.3.4,128,x64\r\n' for index in range(count))).encode()
    limits = contracts.InventoryLimits(max_entries=parent_budget, max_bytes=2_000_000,
                                        max_text_chars=2_000_000, max_field_chars=512,
                                        max_record_chars=1_024, max_columns=8, max_records=6_000,
                                        max_diagnostics=7, max_sections=6, max_seconds=9.0)
    with WorkspaceStore(tmp_path / 'ws') as ws:
        parent, _ = store.add_inventory(ws, raw, CONTEXT, now=NOW, limits=limits, retrieval=fetched(raw))
        parent_body = parent.model_dump_json()
        raw_path = ws.object_path(parent.source.sha256)
        raw_before = raw_path.read_bytes()
        first, first_added = store.retain_inventory(ws, parent.import_id, retention())
        second, second_added = store.retain_inventory(ws, parent.import_id, retention(page=2))
        expected_limits = limits.model_dump(mode='json') | {'max_entries': capacity}
        assert first_added and second_added
        assert first.parsed.limits.model_dump(mode='json') == expected_limits
        assert second.parsed.limits.model_dump(mode='json') == expected_limits
        assert first.parsed.accepted_count == capacity
        assert second.parsed.accepted_count == min(capacity, count - capacity)
        assert second.parsed.entries[0].reference.logical_record == capacity + 2
        assert second.parsed.entries[0].basename == f'file{capacity}.dll'
        assert first.parsed.scan_complete and second.parsed.scan_complete
        assert first.source == second.source == parent.source
        assert first.retrieval == second.retrieval == parent.retrieval
        repeated, added = store.retain_inventory(ws, second.import_id, retention())
        assert not added and repeated.model_dump_json() == first.model_dump_json()
        assert store.get_inventory(ws, second.import_id) == second
        assert store.get_inventory(ws, parent.import_id).model_dump_json() == parent_body
        assert raw_path.read_bytes() == raw_before
        assert store.inventory_count(ws) == 3
        assert ws.db.execute('SELECT COUNT(*) FROM revisions').fetchone()[0] == 0
