"""Explicit source pages preserve immutable v1 evidence and source-wide conflicts."""
from __future__ import annotations

import gzip
import hashlib
import json
import threading
from pathlib import Path

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from pydantic import ValidationError
from test_kbc_inventory_selection import select, service, snapshot, start
from test_kbc_inventory_store import damage_body, fetched

from patchtrace.kbcorrelation import inventory_contracts as contracts
from patchtrace.kbcorrelation import inventory_csv as csv
from patchtrace.kbcorrelation import inventory_store as store
from patchtrace.kbcorrelation.sources.cvrf import SourceError
from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore

pytestmark = pytest.mark.usefixtures('no_sockets')
CONTEXT = contracts.InventoryContext(kb='KB5099001')
NOW = '2099-01-01T00:00:00Z'
HEADER = 'File name,File version,File size,Architecture\r\n'
RAW = (HEADER + 'arm.sys,1.2.3.4,10,arm64\r\n' * 3 +
       'first.sys,1.2.3.4,20,x64\r\nsecond.sys,1.2.3.4,30,x64\r\n'
       'third.sys,1.2.3.4,40,x64\r\nfirst.sys,1.2.3.5,20,x64\r\n').encode()
LIMITS = contracts.InventoryLimits(max_entries=2)


def retention(architecture='amd64', page=1):
    return contracts.InventoryRetention(architecture=architecture, page=page)


def parse(raw=RAW, *, architecture='amd64', page=1, limits=LIMITS, **kwargs):
    return csv.parse_inventory_page(raw, CONTEXT, retention(architecture, page), limits=limits, **kwargs)


def frozen_v1():
    return json.loads((Path(__file__).parent / 'fixtures/kbcorrelation/inventory-legacy-tsp.json').read_text())


def test_published_v1_tsp_classification_and_serialization_are_frozen():
    fixture = frozen_v1()
    expected = json.loads(fixture['record_json'])['parsed']
    parsed = csv.parse_inventory(fixture['raw_utf8'].encode(), contracts.InventoryContext(kb='KB5036893'),
                                 limits=contracts.InventoryLimits.model_validate(expected['limits']))
    assert parsed.model_dump(mode='json') == expected
    assert parsed.inventory_id == 'f5418e5b760c38e3788eb27213fd792faa909c023413891c31cabac2c48f5c6d'
    assert parsed.entries[0].entry_id == 'abf4283d53148c82b03dd99e0a44a55588a1876d3cdb892bc7067c796373eeda'


def test_frozen_published_v1_import_replays_from_unchanged_sqlite_and_raw_bytes(tmp_path):
    fixture = frozen_v1()
    body, raw = fixture['record_json'], fixture['raw_utf8'].encode()
    value = json.loads(body)
    with WorkspaceStore(tmp_path / 'ws') as ws:
        store._create_table(ws, store.INVENTORY_TABLE)
        ws.db.execute(f'INSERT INTO {store.INVENTORY_TABLE} VALUES (?,?,?,?,?,?)',
                      (1, value['import_id'], value['source']['sha256'], len(raw), body,
                       hashlib.sha256(body.encode()).hexdigest()))
        path = ws.object_path(value['source']['sha256'])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(gzip.compress(raw, mtime=0))
        before = path.read_bytes()
        replayed = store.get_inventory(ws, value['import_id'])
        assert replayed.model_dump_json() == body and path.read_bytes() == before
        assert replayed.parsed.entries[0].state == 'descriptive-only'


def test_explicit_page_reaches_later_architecture_without_changing_legacy_result():
    legacy = csv.parse_inventory(RAW, CONTEXT, limits=LIMITS)
    assert {entry.architecture for entry in legacy.entries} == {'arm64'}
    first, second = parse(), parse(page=2)
    assert first.contract == 'kb-file-inventory/2' and first.parser_version == 2
    assert first.scan_complete and not first.truncated
    assert (first.matching_count, first.excluded_count, first.omitted_count) == (4, 3, 2)
    assert [entry.reference.logical_record for entry in first.entries] == [5, 6]
    assert [entry.reference.logical_record for entry in second.entries] == [7, 8]
    assert first.inventory_id != second.inventory_id != legacy.inventory_id
    assert first.accepted_count == second.accepted_count == 2
    assert first.records_scanned == second.records_scanned == 8


@pytest.mark.parametrize('page', [1, 2])
def test_cross_page_conflicts_keep_exact_witnesses_even_when_diagnostics_are_full(page):
    result = parse(page=page, limits=contracts.InventoryLimits(max_entries=2, max_diagnostics=1))
    entry = next(entry for entry in result.entries if entry.basename == 'first.sys')
    assert entry.state == 'conflicted' and 'CONFLICTING_METADATA' in entry.diagnostics
    witness, = result.conflict_witnesses
    assert witness.conflict_group == entry.conflict_group and witness.field == 'version_components'
    assert (witness.first.logical_record, witness.second.logical_record) == (5, 8)
    assert witness.first.raw_sha256 == witness.second.raw_sha256 == result.raw_sha256
    assert contracts.CsvInventoryPage.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize('architecture', ['amd64', 'arm64', 'unknown'])
def test_architecture_filter_keeps_unknown_and_conflicted_claims_visible(architecture):
    raw = (b'Windows x64-based\r\n' + HEADER.encode() +
           b'one.sys,1.2.3.4,20,x64\r\nunknown.sys,1.2.3.4,20,mystery\r\n'
           b'conflict.sys,1.2.3.4,20,arm64\r\n')
    result = parse(raw, architecture=architecture, limits=contracts.DEFAULT_PAGE_LIMITS)
    assert {'unknown.sys', 'conflict.sys'} <= {entry.basename for entry in result.entries}
    assert next(entry for entry in result.entries if entry.basename == 'conflict.sys').state == 'conflicted'
    assert ('one.sys' in {entry.basename for entry in result.entries}) == (architecture == 'amd64')


def test_explicit_v2_tsp_classification_has_a_distinct_identity():
    fixture = frozen_v1()
    raw, context = fixture['raw_utf8'].encode(), contracts.InventoryContext(kb='KB5036893')
    old = csv.parse_inventory(raw, context)
    page = csv.parse_inventory_page(raw, context, retention())
    assert old.entries[0].state == 'descriptive-only' and page.entries[0].state == 'metadata-only'
    assert page.entries[0].entry_id != old.entries[0].entry_id
    assert page.entries[0].reference == old.entries[0].reference


@pytest.mark.parametrize('values', [{'page': True}, {'page': 0}, {'page': -1}, {'page': 100001},
                                   {'page': '1'}, {'architecture': 'x64'}, {'architecture': False}])
def test_retention_policy_is_strict_and_bounded(values):
    with pytest.raises(ValidationError):
        contracts.InventoryRetention(**values)


def test_full_scan_keeps_structural_checks_beyond_the_requested_page():
    raw = (HEADER + 'valid.sys,1.2.3.4,20,x64\r\n"unfinished').encode()
    assert csv.parse_inventory(raw, CONTEXT, limits=contracts.InventoryLimits(max_entries=1)).accepted_count == 1
    with pytest.raises(SourceError) as raised:
        parse(raw, limits=contracts.InventoryLimits(max_entries=1))
    assert raised.value.code == 'PT-KBC-SOURCE'


def test_complete_out_of_range_page_is_an_input_error():
    with pytest.raises(SourceError) as raised:
        parse(page=3)
    assert raised.value.code == 'PT-KBC-INPUT'


def test_record_limit_yields_an_explicit_incomplete_source_scan():
    result = parse(limits=contracts.InventoryLimits(max_entries=2, max_records=6))
    assert not result.scan_complete and result.truncated and result.status == 'partial'
    assert result.records_scanned == 6 and result.matching_count == 2


def test_page_retention_is_idempotent_and_preserves_source_receipt_and_raw_object(tmp_path):
    with WorkspaceStore(tmp_path / 'ws') as ws:
        original, _ = store.add_inventory(ws, RAW, CONTEXT, now=NOW, limits=LIMITS, retrieval=fetched(RAW))
        before = original.model_dump_json(), ws.object_path(original.source.sha256).read_bytes()
        first, added = store.retain_inventory(ws, original.import_id, retention())
        second, _ = store.retain_inventory(ws, original.import_id, retention(page=2))
        repeated, added_again = store.retain_inventory(ws, second.import_id, retention())
        assert added and not added_again and repeated == first
        assert first.source == original.source and first.retrieval == original.retrieval
        assert store.get_inventory(ws, first.import_id) == first
        assert store.get_inventory(ws, original.import_id).model_dump_json() == before[0]
        assert ws.object_path(original.source.sha256).read_bytes() == before[1]
        assert store.inventory_count(ws) == 3
        assert ws.db.execute('SELECT COUNT(*) FROM revisions').fetchone()[0] == 0


def test_cancelled_full_scan_appends_nothing_and_preserves_the_original(tmp_path, monkeypatch):
    cancel = threading.Event()
    with WorkspaceStore(tmp_path / 'ws') as ws:
        original, _ = store.add_inventory(ws, RAW, CONTEXT, now=NOW, limits=LIMITS)
        real_consume = csv._Parser.consume

        def stop(parser, row, delimiter):
            real_consume(parser, row, delimiter)
            if row.number == 6:
                cancel.set()

        with monkeypatch.context() as patch:
            patch.setattr(csv._Parser, 'consume', stop)
            with pytest.raises((SourceError, KbcStoreError)) as raised:
                store.retain_inventory(ws, original.import_id, retention(), cancel=cancel)
        assert raised.value.code == 'PT-KBC-CANCEL'
        assert store.inventory_count(ws) == 1 and store.get_inventory(ws, original.import_id) == original


def test_new_page_never_changes_a_revision_and_incomplete_page_selection_is_refused(tmp_path):
    svc = service(tmp_path)
    state = start(svc)
    raw = (HEADER + 'review.sys,1.2.3.4,128,x64\r\nother.sys,1.2.3.4,128,x64\r\n').encode()
    limits = contracts.InventoryLimits(max_entries=1, max_records=2)
    with WorkspaceStore(svc.root) as ws:
        original, _ = store.add_inventory(ws, raw, CONTEXT, now=NOW, limits=limits)
    selected = select(svc, state, (original.import_id, original.parsed.entries[0].entry_id))
    before = snapshot(svc, state[0])
    with WorkspaceStore(svc.root) as ws:
        page, _ = store.retain_inventory(ws, original.import_id, retention())
    assert snapshot(svc, state[0]) == before
    with pytest.raises(KbcStoreError) as raised:
        svc.select_inventory(state[0], page.import_id, page.parsed.entries[0].entry_id,
                             product=state[1], expected_revision=selected.result['revision'], assert_scope=True)
    assert raised.value.code == 'PT-KBC-LIMIT' and snapshot(svc, state[0]) == before


def test_page_tampering_cannot_bypass_raw_replay(tmp_path):
    with WorkspaceStore(tmp_path / 'ws') as ws:
        original, _ = store.add_inventory(ws, RAW, CONTEXT, now=NOW, limits=LIMITS)
        page, _ = store.retain_inventory(ws, original.import_id, retention())
        damage_body(ws, page, lambda value: value['parsed']['conflict_witnesses'][0].update(field='size_bytes'))
        with pytest.raises(KbcStoreError) as raised:
            store.get_inventory(ws, page.import_id)
        assert raised.value.code == 'PT-KBC-VERIFY'
        assert store.get_inventory(ws, original.import_id) == original


def test_missing_conflict_group_is_a_validation_error_in_a_saved_page(tmp_path):
    raw = (HEADER + 'one.sys,1.2.3.4,20,x64\r\ntwo.sys,1.2.3.4,20,x64\r\n'
           'one.sys,1.2.3.5,20,x64\r\ntwo.sys,1.2.3.5,20,x64\r\n').encode()
    with WorkspaceStore(tmp_path / 'ws') as ws:
        original, _ = store.add_inventory(ws, raw, CONTEXT, now=NOW)
        page, _ = store.retain_inventory(ws, original.import_id, retention())
        invalid = page.parsed.model_dump(mode='json')
        invalid['entries'][0]['conflict_group'] = None
        with pytest.raises(ValidationError):
            contracts.CsvInventoryPage.model_validate_json(json.dumps(invalid))
        damage_body(ws, page, lambda value: value['parsed']['entries'][0].update(conflict_group=None))
        with pytest.raises(KbcStoreError) as raised:
            store.get_inventory(ws, page.import_id)
        assert raised.value.code == 'PT-KBC-VERIFY'
