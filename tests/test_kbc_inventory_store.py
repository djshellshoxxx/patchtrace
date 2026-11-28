"""PW-01 real SQLite/raw-object persistence; synthetic sources and no network."""
from __future__ import annotations

import gzip
import hashlib
import json
import sqlite3
import threading
from dataclasses import replace

import pytest
from kbc_k1_support import NOW, import_fixture, no_sockets  # noqa: F401
from pydantic import ValidationError

from patchtrace.kbcorrelation import inventory_store as store
from patchtrace.kbcorrelation.inventory_contracts import InventoryContext, InventoryLimits
from patchtrace.kbcorrelation.limits import KbcLimits
from patchtrace.kbcorrelation.sources.cvrf import SourceError
from patchtrace.kbcorrelation.sources.inventory_fetch import FetchedSource, build_plan
from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore

pytestmark = pytest.mark.usefixtures('no_sockets')

CSV = b'File name,File version,File size,Architecture\r\nexample.dll,1.2.3.4,128,x64\r\n'
HTML = b'<html><p>File information</p><a href="/files.csv">File information CSV</a></html>'
CONTEXT = InventoryContext(kb='KB5099001')
CSV_URL = 'https://download.microsoft.com/download/a/b/c/files.csv'
PAGE_URL = 'https://support.microsoft.com/help/5099001'
LATER = '2099-03-02T00:00:00Z'


@pytest.fixture
def ws(tmp_path):
    with WorkspaceStore(tmp_path / 'kb') as workspace:
        yield workspace


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fetched(raw=CSV, *, kind='file-inventory', now=NOW, url=CSV_URL, redirects=()):
    """A synthetic transport result; no request is performed by this fixture."""
    plan = build_plan(url, kind=kind, redirects=redirects)
    return FetchedSource(kind=kind, original_url=url, final_url=plan.urls[-1], redirect_chain=plan.urls,
                         raw=raw, sha256=sha(raw), retrieved_at=now, plan_sha=plan.plan_sha)


def add(ws, raw=CSV, context=CONTEXT, **kwargs):
    return store.add_inventory(ws, raw, context, now=kwargs.pop('now', NOW), **kwargs)


def table_names(ws):
    return {name for (name,) in ws.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def damage_body(ws, record, change, table=store.INVENTORY_TABLE):
    """Model an untrusted on-disk cache, deliberately bypassing append-only protection."""
    ws.db.execute(f'DROP TRIGGER {table}_update')
    body = record.model_dump(mode='json')
    change(body)
    encoded = json.dumps(body, separators=(',', ':'))
    ws.db.execute(f'UPDATE {table} SET body=?,body_sha256=? WHERE import_id=?',
                  (encoded, sha(encoded.encode()), record.import_id))


def test_empty_old_workspace_reads_do_not_migrate_or_change_advisories(ws):
    before = table_names(ws)
    assert store.list_inventories(ws) == store.list_support(ws) == ()
    assert store.inventory_count(ws) == store.support_count(ws) == 0
    assert store.get_inventory(ws, 'a' * 64) is store.get_support(ws, 'a' * 64) is None
    assert store.referenced_raw_hashes(ws) == ()
    assert table_names(ws) == before
    assert ws.db.execute('PRAGMA user_version').fetchone()[0] == 1


def test_original_bytes_are_retained_with_separate_unverified_assertion(ws):
    raw = b'\xef\xbb\xbf' + CSV
    record, added = add(ws, raw, asserted_source=CSV_URL)
    assert added
    assert record.source.kind == 'kb-file-csv'
    assert record.source.sha256 == sha(raw) == record.parsed.raw_sha256
    assert record.source.size == len(raw)
    assert record.source.origin == 'local-import'
    assert record.source.uri is None and record.source.lineage == 'analyst'
    assert record.source.authenticity == 'unverified-local-file'
    assert record.asserted_source == CSV_URL and record.retrieval is None
    assert ws.read_object(record.source.sha256) == raw
    assert store.get_inventory(ws, record.import_id) == record
    assert store.InventoryImport.model_validate_json(record.model_dump_json()) == record
    assert store.referenced_raw_hashes(ws) == (sha(raw),)
    assert store.inventory_count(ws) == 1
    assert ws.db.execute('SELECT COUNT(*) FROM docs').fetchone()[0] == 0
    assert ws.db.execute('SELECT COUNT(*) FROM edges').fetchone()[0] == 0
    assert ws.db.execute('PRAGMA user_version').fetchone()[0] == 1
    with pytest.raises(ValidationError):
        record.asserted_source = None
    with pytest.raises(ValidationError):
        store.InventoryImport.model_validate_json(record.model_dump_json()[:-1] + ',"extra":true}')


def test_same_import_is_idempotent_and_keeps_first_timestamp(ws):
    first, added = add(ws)
    before = ws.object_path(first.source.sha256).stat().st_mtime_ns
    second, repeated = add(ws, now=LATER)
    assert added and not repeated
    assert second == first and second.source.retrieved_at == NOW
    assert ws.object_path(first.source.sha256).stat().st_mtime_ns == before
    assert store.inventory_count(ws) == 1
    assert len(tuple((ws.root / 'objects').glob('*/*.gz'))) == 1


@pytest.mark.parametrize('context', [
    InventoryContext(kb='KB5099002'),
    InventoryContext(kb='KB5099001', product_scope_id='a' * 64),
    InventoryContext(kb='KB5099001', product='Windows Server'),
    InventoryContext(kb='KB5099001', release='2099'),
    InventoryContext(kb='KB5099001', build='29999.1'),
    InventoryContext(kb='KB5099001', architecture='amd64'),
    InventoryContext(kb='KB5099001', locale='invariant'),
])
def test_same_raw_with_different_context_preserves_both_claims(ws, context):
    original, _ = add(ws)
    changed, added = add(ws, context=context)
    assert added and changed.import_id != original.import_id
    assert changed.source.doc_id == original.source.doc_id
    assert store.get_inventory(ws, original.import_id) == original
    assert store.get_inventory(ws, changed.import_id) == changed
    assert store.inventory_count(ws) == 2
    assert store.referenced_raw_hashes(ws) == (sha(CSV),)


def test_asserted_urls_are_distinct_inert_claims_even_when_not_fetchable(ws):
    first, _ = add(ws)
    second, _ = add(ws, asserted_source=CSV_URL)
    third, _ = add(ws, asserted_source='https://example.invalid/unverified.csv')
    assert len({record.import_id for record in (first, second, third)}) == 3
    assert len({record.source.doc_id for record in (first, second, third)}) == 1
    assert all(record.source.uri is None for record in (first, second, third))


@pytest.mark.parametrize('url', ['http://example.com/a', 'https://u:p@example.com/a',
                                'https://example.com/a#frag', 'https://example.com/\\x',
                                'https://example.com/a\n', 'https://example.com/\u202ea'])
def test_unsafe_assertions_fail_before_mutating_workspace(ws, url):
    with pytest.raises(KbcStoreError) as caught:
        add(ws, asserted_source=url)
    assert caught.value.code == 'PT-KBC-INPUT'
    assert store.inventory_count(ws) == 0 and not (ws.root / 'objects').exists()


def test_captured_custom_limits_replay_exact_partial_inventory(ws):
    raw = CSV + b'other.dll,1.2.3.5,256,x64\r\n'
    limited, _ = add(ws, raw, limits=InventoryLimits(max_entries=1))
    complete, _ = add(ws, raw)
    assert limited.parsed.truncated and limited.parsed.accepted_count == 1
    assert complete.parsed.accepted_count == 2
    assert limited.import_id != complete.import_id
    assert store.get_inventory(ws, limited.import_id) == limited
    assert store.get_inventory(ws, complete.import_id) == complete


def test_local_and_two_fetched_events_never_upgrade_or_overwrite_each_other(ws):
    local, _ = add(ws, asserted_source=CSV_URL)
    remote, added = add(ws, retrieval=fetched())
    repeated, duplicate = add(ws, retrieval=fetched(), now=LATER)
    later, later_added = add(ws, retrieval=fetched(now=LATER))
    assert added and later_added and not duplicate and repeated == remote
    assert len({record.import_id for record in (local, remote, later)}) == 3
    assert len({record.source.doc_id for record in (local, remote, later)}) == 1
    assert remote.source.origin == 'https-fetch' and remote.source.uri == CSV_URL
    assert remote.source.authenticity == 'tls-allowlisted-host'
    assert remote.source.lineage == 'microsoft-support'
    assert remote.retrieval.redirect_chain == (CSV_URL,)
    assert store.get_inventory(ws, local.import_id).source.origin == 'local-import'
    assert store.get_inventory(ws, remote.import_id) == remote
    assert store.inventory_count(ws) == 3


def test_redirect_provenance_is_exact_and_distinct_from_a_direct_fetch(ws):
    first, _ = add(ws, retrieval=fetched())
    original = 'https://go.microsoft.com/fwlink/?LinkId=123456'
    redirected, _ = add(ws, retrieval=fetched(url=original, redirects=(CSV_URL,)))
    assert first.import_id != redirected.import_id
    assert redirected.source.uri == original
    assert redirected.retrieval.original_url == original
    assert redirected.retrieval.final_url == CSV_URL
    assert redirected.retrieval.redirect_chain == (original, CSV_URL)
    assert store.get_inventory(ws, redirected.import_id) == redirected


@pytest.mark.parametrize('change', [
    {'sha256': 'f' * 64}, {'raw': b'different'}, {'plan_sha': 'f' * 64},
    {'final_url': 'https://download.microsoft.com/download/elsewhere.csv'},
    {'redirect_chain': ('https://example.invalid/files.csv',)},
    {'kind': 'support-page'},
])
def test_forged_or_inconsistent_fetch_result_is_rejected(ws, change):
    with pytest.raises(KbcStoreError) as caught:
        add(ws, retrieval=replace(fetched(), **change))
    assert caught.value.code == 'PT-KBC-VERIFY'
    assert store.inventory_count(ws) == 0 and not (ws.root / 'objects').exists()


def test_arbitrary_receipt_dict_cannot_upgrade_a_local_import(ws):
    with pytest.raises(KbcStoreError) as caught:
        add(ws, retrieval=fetched().receipt())
    assert caught.value.code == 'PT-KBC-INPUT'
    assert store.inventory_count(ws) == 0


def test_support_html_raw_page_context_and_fetch_provenance_are_retained(ws):
    local, added = store.add_support(ws, HTML, PAGE_URL, now=NOW)
    repeated, duplicate = store.add_support(ws, HTML, PAGE_URL, now=LATER)
    other, _ = store.add_support(ws, HTML, PAGE_URL + '?other=1', now=NOW)
    remote, _ = store.add_support(ws, HTML, PAGE_URL, now=NOW,
                                  retrieval=fetched(HTML, kind='support-page', url=PAGE_URL))
    assert added and not duplicate and local == repeated
    assert local.source.kind == 'kb-support-html'
    assert local.source.origin == 'local-import' and local.source.uri is None
    assert local.page_url == PAGE_URL and local.source.sha256 == sha(HTML)
    assert ws.read_object(local.source.sha256) == HTML
    assert len({record.import_id for record in (local, other, remote)}) == 3
    assert store.get_support(ws, local.import_id) == local
    assert store.get_support(ws, remote.import_id) == remote
    assert store.support_count(ws) == 3 and store.inventory_count(ws) == 0
    assert store.referenced_raw_hashes(ws) == (sha(HTML),)
    assert ws.db.execute('SELECT COUNT(*) FROM edges').fetchone()[0] == 0


def test_support_fetch_uses_final_page_url_for_relative_links(ws):
    final = PAGE_URL + '?redirected=1'
    receipt = fetched(HTML, kind='support-page', url=PAGE_URL, redirects=(final,))
    with pytest.raises(KbcStoreError) as caught:
        store.add_support(ws, HTML, PAGE_URL, now=NOW, retrieval=receipt)
    assert caught.value.code == 'PT-KBC-INPUT'
    record, _ = store.add_support(ws, HTML, final, now=NOW, retrieval=receipt)
    assert record.source.uri == PAGE_URL and record.page_url == final
    assert store.get_support(ws, record.import_id) == record


@pytest.mark.parametrize('operation', ['inventory', 'support'])
@pytest.mark.parametrize('point', ['after_object', 'before_commit'])
def test_faults_rollback_rows_and_migration_leave_only_raw_orphan(ws, operation, point):
    class Crash(BaseException):
        pass

    def fault(name):
        if name == f'{operation}_{point}':
            raise Crash()

    ws.fault = fault
    before = table_names(ws)
    raw = CSV if operation == 'inventory' else HTML
    with pytest.raises(Crash):
        if operation == 'inventory':
            add(ws)
        else:
            store.add_support(ws, HTML, PAGE_URL, now=NOW)
    assert table_names(ws) == before and not ws.db.in_transaction
    assert store.inventory_count(ws) == store.support_count(ws) == 0
    assert ws.unreferenced_objects() == (sha(raw),)
    assert ws.read_object(sha(raw)) == raw
    ws.fault = lambda _point: None
    if operation == 'inventory':
        assert add(ws)[1]
    else:
        assert store.add_support(ws, HTML, PAGE_URL, now=NOW)[1]


@pytest.mark.parametrize('point', ['start', 'inventory_after_object', 'inventory_before_commit'])
def test_cancellation_preserves_existing_rows_and_rolls_back_new_claim(ws, point):
    original, _ = add(ws)
    token = threading.Event()
    if point == 'start':
        token.set()
    ws.fault = lambda name: token.set() if name == point else None
    with pytest.raises((KbcStoreError, SourceError)) as caught:
        add(ws, context=InventoryContext(kb='KB5099002'), cancel=token)
    assert caught.value.code == 'PT-KBC-CANCEL'
    assert store.inventory_count(ws) == 1 and not ws.db.in_transaction
    assert store.get_inventory(ws, original.import_id) == original


def test_cancelled_read_and_malformed_token_do_not_mutate_state(ws):
    record, _ = add(ws)
    token = threading.Event()
    token.set()
    for action in (lambda: store.get_inventory(ws, record.import_id, cancel=token),
                   lambda: store.list_inventories(ws, cancel=token), lambda: add(ws, cancel=object())):
        with pytest.raises(KbcStoreError) as caught:
            action()
        assert caught.value.code in {'PT-KBC-CANCEL', 'PT-KBC-INPUT'}
    assert store.inventory_count(ws) == 1


@pytest.mark.parametrize('raw_damage', [b'not gzip', gzip.compress(b'wrong bytes'), gzip.compress(CSV) + b'tail'])
def test_raw_corruption_is_detected_and_never_repaired_by_reimport(ws, raw_damage):
    record, _ = add(ws)
    path = ws.object_path(record.source.sha256)
    path.write_bytes(raw_damage)
    for action in (lambda: store.get_inventory(ws, record.import_id), lambda: add(ws),
                   lambda: add(ws, context=InventoryContext(kb='KB5099002'))):
        with pytest.raises(KbcStoreError) as caught:
            action()
        assert caught.value.code == 'PT-KBC-VERIFY'
        assert path.read_bytes() == raw_damage
    assert store.inventory_count(ws) == 1


def test_missing_raw_cannot_be_recreated_over_an_existing_import(ws):
    record, _ = add(ws)
    ws.object_path(record.source.sha256).unlink()
    for context in (CONTEXT, InventoryContext(kb='KB5099002')):
        with pytest.raises(KbcStoreError) as caught:
            add(ws, context=context)
        assert caught.value.code == 'PT-KBC-STORAGE'
    assert not ws.object_path(record.source.sha256).exists()


def test_changed_parsed_value_with_fresh_body_checksum_still_fails_replay(ws):
    record, _ = add(ws)
    damage_body(ws, record, lambda body: body['parsed']['entries'][0].update(size_bytes=129))
    cached = store.get_inventory(ws, record.import_id, verify=False)
    assert cached.parsed.entries[0].size_bytes == 129
    for action in (lambda: store.get_inventory(ws, record.import_id), lambda: add(ws)):
        with pytest.raises(KbcStoreError) as caught:
            action()
        assert caught.value.code == 'PT-KBC-VERIFY'
    assert store.inventory_count(ws) == 1


@pytest.mark.parametrize('change', [
    lambda body: body.update(import_id='a' * 64),
    lambda body: body['source'].update(size=1),
    lambda body: body['source'].update(kind='csaf'),
    lambda body: body['source'].update(object_path='objects/elsewhere.gz'),
    lambda body: body['source'].update(origin='https-fetch', uri=CSV_URL,
                                     authenticity='tls-allowlisted-host', lineage='microsoft-support'),
    lambda body: body['parsed'].update(parser_version=2),
    lambda body: body.update(unknown=True),
])
def test_corrupt_record_cannot_pass_even_when_raw_replay_is_disabled(ws, change):
    record, _ = add(ws)
    damage_body(ws, record, change)
    with pytest.raises(KbcStoreError) as caught:
        store.get_inventory(ws, record.import_id, verify=False)
    assert caught.value.code == 'PT-KBC-VERIFY'


@pytest.mark.parametrize('suffix', [',"contract":"kb-inventory-import/1"}', ',"unknown":NaN}',
                                   ',"unknown":1e999}', ',"unknown":"\\ud800"}'])
def test_cached_json_uses_strict_reader_before_model_validation(ws, suffix):
    record, _ = add(ws)
    ws.db.execute(f'DROP TRIGGER {store.INVENTORY_TABLE}_update')
    body = record.model_dump_json()[:-1] + suffix
    ws.db.execute(f'UPDATE {store.INVENTORY_TABLE} SET body=?,body_sha256=?', (body, sha(body.encode())))
    with pytest.raises(KbcStoreError) as caught:
        store.get_inventory(ws, record.import_id, verify=False)
    assert caught.value.code == 'PT-KBC-VERIFY'


def test_record_checksum_and_index_columns_are_verified(ws):
    record, _ = add(ws)
    ws.db.execute(f'DROP TRIGGER {store.INVENTORY_TABLE}_update')
    ws.db.execute(f'UPDATE {store.INVENTORY_TABLE} SET body_sha256=?', ('f' * 64,))
    with pytest.raises(KbcStoreError) as caught:
        store.get_inventory(ws, record.import_id, verify=False)
    assert caught.value.code == 'PT-KBC-VERIFY'
    ws.db.execute(f'UPDATE {store.INVENTORY_TABLE} SET body_sha256=?,size=size+1',
                  (sha(record.model_dump_json().encode()),))
    with pytest.raises(KbcStoreError) as caught:
        store.get_inventory(ws, record.import_id, verify=False)
    assert caught.value.code == 'PT-KBC-VERIFY'


def test_invalid_utf8_database_text_is_a_verification_failure(ws):
    record, _ = add(ws)
    ws.db.execute(f'DROP TRIGGER {store.INVENTORY_TABLE}_update')
    ws.db.execute(f'UPDATE {store.INVENTORY_TABLE} SET body=CAST(? AS TEXT),body_sha256=?',
                  (b'\x80', sha(b'\x80')))
    with pytest.raises(KbcStoreError) as caught:
        store.get_inventory(ws, record.import_id, verify=False)
    assert caught.value.code == 'PT-KBC-VERIFY'


def test_support_replay_detects_wrong_extraction_digest_even_with_rebound_identity(ws):
    record, _ = store.add_support(ws, HTML, PAGE_URL, now=NOW)
    wrong = 'e' * 64
    new_id = store._support_id(record.source, record.page_url, wrong, None)
    damage_body(ws, record, lambda body: body.update(extraction_sha256=wrong, import_id=new_id),
                table=store.SUPPORT_TABLE)
    ws.db.execute(f'UPDATE {store.SUPPORT_TABLE} SET import_id=?', (new_id,))
    assert store.get_support(ws, new_id, verify=False).extraction_sha256 == wrong
    with pytest.raises(KbcStoreError) as caught:
        store.get_support(ws, new_id)
    assert caught.value.code == 'PT-KBC-VERIFY'


def test_support_parser_version_rejects_boolean_alias(ws):
    record, _ = store.add_support(ws, HTML, PAGE_URL, now=NOW)
    damage_body(ws, record, lambda body: body.update(parser_version=True), table=store.SUPPORT_TABLE)
    with pytest.raises(KbcStoreError) as caught:
        store.get_support(ws, record.import_id, verify=False)
    assert caught.value.code == 'PT-KBC-VERIFY'


@pytest.mark.parametrize('table', [store.INVENTORY_TABLE, store.SUPPORT_TABLE])
def test_import_tables_are_append_only(table, ws):
    add(ws)
    store.add_support(ws, HTML, PAGE_URL, now=NOW)
    for sql in (f'UPDATE {table} SET size=1', f'DELETE FROM {table}'):
        with pytest.raises(sqlite3.IntegrityError, match='append-only'):
            ws.db.execute(sql)
    assert store.inventory_count(ws) == store.support_count(ws) == 1


def test_readonly_legacy_store_returns_empty_and_refuses_add_without_objects(tmp_path):
    root = tmp_path / 'readonly'
    with WorkspaceStore(root) as ws:
        ws.db.execute('PRAGMA user_version=99')
    with WorkspaceStore(root) as ws:
        assert ws.read_only and store.list_inventories(ws) == store.list_support(ws) == ()
        assert store.inventory_count(ws) == store.support_count(ws) == 0
        before = table_names(ws)
        for action in (lambda: add(ws), lambda: store.add_support(ws, HTML, PAGE_URL, now=NOW)):
            with pytest.raises(KbcStoreError) as caught:
                action()
            assert caught.value.code == 'PT-KBC-STORAGE'
        assert table_names(ws) == before and not (root / 'objects').exists()


def test_existing_inventory_replays_in_a_readonly_newer_workspace(tmp_path):
    root = tmp_path / 'readonly'
    with WorkspaceStore(root) as ws:
        record, _ = add(ws)
        ws.db.execute('PRAGMA user_version=99')
    with WorkspaceStore(root) as ws:
        assert ws.read_only
        assert store.get_inventory(ws, record.import_id) == record
        assert store.list_inventories(ws, verify=True) == (record,)
        with pytest.raises(KbcStoreError):
            add(ws)


def test_pages_are_stable_disjoint_and_have_counts_without_loading_records(ws):
    records = [add(ws, context=InventoryContext(kb=f'KB509900{index}'))[0] for index in range(1, 5)]
    expected = tuple(sorted(records, key=lambda record: record.import_id))
    assert store.list_inventories(ws, limit=2) + store.list_inventories(ws, limit=2, offset=2) == expected
    assert store.list_inventories(ws, offset=4) == ()
    assert store.inventory_count(ws) == 4


@pytest.mark.parametrize('kwargs', [{'limit': 0}, {'limit': 101}, {'limit': True}, {'offset': -1},
                                   {'offset': True}, {'verify': 'false'}])
def test_invalid_pagination_fails_even_for_empty_store(ws, kwargs):
    with pytest.raises(KbcStoreError) as caught:
        store.list_inventories(ws, **kwargs)
    assert caught.value.code == 'PT-KBC-INPUT'


def test_bounded_json_row_is_rejected_before_retrieval_and_page_budget_is_enforced(ws, monkeypatch):
    record, _ = add(ws)
    monkeypatch.setattr(store, 'MAX_RECORD_BYTES', 20)
    with pytest.raises(KbcStoreError) as caught:
        store.get_inventory(ws, record.import_id, verify=False)
    assert caught.value.code == 'PT-KBC-VERIFY'
    monkeypatch.setattr(store, 'MAX_RECORD_BYTES', 64 * 1024 * 1024)
    monkeypatch.setattr(store, 'MAX_PAGE_BYTES', 20)
    with pytest.raises(KbcStoreError) as caught:
        store.list_inventories(ws)
    assert caught.value.code == 'PT-KBC-LIMIT'


def test_workspace_budget_includes_metadata_and_rechecks_inside_transaction(ws):
    first, _ = add(ws)
    body_size = len(first.model_dump_json().encode())
    ws.limits = KbcLimits(workspace_objects_bytes=len(CSV) + body_size)
    assert add(ws)[1] is False  # idempotency does not charge the budget twice
    with pytest.raises(KbcStoreError) as caught:
        add(ws, context=InventoryContext(kb='KB5099002'))
    assert caught.value.code == 'PT-KBC-LIMIT'
    assert store.inventory_count(ws) == 1


def test_budget_failure_before_raw_write_leaves_old_store_unchanged(tmp_path):
    with WorkspaceStore(tmp_path / 'tiny', limits=KbcLimits(workspace_objects_bytes=1)) as ws:
        before = table_names(ws)
        with pytest.raises(KbcStoreError) as caught:
            add(ws)
        assert caught.value.code == 'PT-KBC-LIMIT'
        assert table_names(ws) == before and not (ws.root / 'objects').exists()


def test_inventory_keeps_existing_advisory_rows_and_schema_intact(ws):
    document = import_fixture('cvrf-2099-Feb.json')
    from kbc_helpers import read_fixture_bytes
    assert ws.add_document(document, read_fixture_bytes('cvrf-2099-Feb.json'))
    before = tuple(ws.db.execute('SELECT * FROM edges'))
    add(ws)
    store.add_support(ws, HTML, PAGE_URL, now=NOW)
    assert tuple(ws.db.execute('SELECT * FROM edges')) == before
    assert ws.sources() == (document.source,)
    assert ws.db.execute('PRAGMA user_version').fetchone()[0] == 1


def test_symlinked_raw_object_is_rejected_without_reading_or_replacing_target(ws, tmp_path):
    record, _ = add(ws)
    outside = tmp_path / 'outside.gz'
    expected = gzip.compress(CSV)
    outside.write_bytes(expected)
    path = ws.object_path(record.source.sha256)
    path.unlink()
    path.symlink_to(outside)
    for action in (lambda: store.get_inventory(ws, record.import_id), lambda: add(ws)):
        with pytest.raises(KbcStoreError) as caught:
            action()
        assert caught.value.code == 'PT-KBC-VERIFY'
    assert path.is_symlink() and outside.read_bytes() == expected


def test_symlinked_object_parent_is_rejected_before_write(ws, tmp_path):
    outside = tmp_path / 'elsewhere'
    outside.mkdir()
    (ws.root / 'objects').symlink_to(outside, target_is_directory=True)
    with pytest.raises(KbcStoreError) as caught:
        add(ws)
    assert caught.value.code == 'PT-KBC-VERIFY'
    assert tuple(outside.iterdir()) == () and store.inventory_count(ws) == 0


def test_compressed_object_size_is_bounded_before_loading(ws):
    record, _ = add(ws)
    path = ws.object_path(record.source.sha256)
    with path.open('wb') as handle:
        handle.truncate(store.MAX_BYTES + 65_537)
    with pytest.raises(KbcStoreError) as caught:
        store.get_inventory(ws, record.import_id)
    assert caught.value.code == 'PT-KBC-VERIFY'


@pytest.mark.parametrize('table', [store.INVENTORY_TABLE, store.INVENTORY_TABLE.upper()])
def test_database_views_cannot_impersonate_inventory_tables(ws, table):
    ws.db.execute(f'CREATE VIEW {table} AS SELECT 1')
    with pytest.raises(KbcStoreError) as caught:
        store.list_inventories(ws)
    assert caught.value.code == 'PT-KBC-VERIFY'


def test_corrupt_large_index_fields_are_rejected_without_exposing_their_text(ws):
    record, _ = add(ws)
    ws.db.execute(f'DROP TRIGGER {store.INVENTORY_TABLE}_update')
    ws.db.execute(f'UPDATE {store.INVENTORY_TABLE} SET import_id=?', ('x' * 1_000_000,))
    with pytest.raises(KbcStoreError) as caught:
        store.list_inventories(ws)
    assert caught.value.code == 'PT-KBC-VERIFY' and len(str(caught.value)) < 200
    ws.db.execute(f'UPDATE {store.INVENTORY_TABLE} SET import_id=?,sha256=?', (record.import_id, 'x' * 1_000_000))
    for action in (lambda: store.get_inventory(ws, record.import_id),
                   lambda: store.referenced_raw_hashes(ws),
                   lambda: add(ws, context=InventoryContext(kb='KB5099002'))):
        with pytest.raises(KbcStoreError) as caught:
            action()
        assert caught.value.code == 'PT-KBC-VERIFY' and len(str(caught.value)) < 200


def test_duplicate_race_returns_the_committed_record_without_replacing_timestamp(ws):
    concurrent = []

    def fault(point):
        if point == 'inventory_after_object':
            with WorkspaceStore(ws.root) as other:
                concurrent.append(add(other, now=LATER)[0])

    ws.fault = fault
    record, added = add(ws)
    assert not added and record == concurrent[0]
    assert record.source.retrieved_at == LATER and store.inventory_count(ws) == 1


def test_budget_is_rechecked_after_raw_write_before_row_commit(ws):
    ws.fault = lambda point: setattr(ws, 'limits', KbcLimits(workspace_objects_bytes=1)) \
        if point == 'inventory_after_object' else None
    before = table_names(ws)
    with pytest.raises(KbcStoreError) as caught:
        add(ws)
    assert caught.value.code == 'PT-KBC-LIMIT'
    assert table_names(ws) == before and store.inventory_count(ws) == 0
    assert ws.unreferenced_objects() == (sha(CSV),)
