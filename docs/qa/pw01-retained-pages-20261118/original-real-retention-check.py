"""One-off offline qualification of immutable captured CSV; no network or external writes."""
import hashlib
import json
import socket
import tempfile
import time
from pathlib import Path

from patchtrace.kbcorrelation.inventory_contracts import InventoryContext, InventoryRetention
from patchtrace.kbcorrelation.inventory_store import add_inventory, get_inventory, inventory_count, retain_inventory
from patchtrace.kbcorrelation.store import WorkspaceStore


def forbidden(*args, **kwargs):
    raise AssertionError('offline qualification must not request network access')


socket.socket = socket.create_connection = socket.getaddrinfo = forbidden
capture = Path('/workspace/scratch/e83fbf4505c3/pw01-live-evidence/20261118T074241Z-e077563/proxy-csv-raw.csv')
raw = capture.read_bytes()
sha = hashlib.sha256(raw).hexdigest()
assert sha == 'b327eb5d0f8d7a0d6a9c8c2d1a7af1df134bc2a54c3e0da2eff0fb335547a627'
report = {'source_sha256': sha, 'source_size': len(raw), 'input_kind': 'saved proxy capture, local unverified import',
          'pages': []}
with tempfile.TemporaryDirectory(prefix='pw01-retention-real-', dir='/workspace/scratch/e83fbf4505c3') as temp:
    with WorkspaceStore(Path(temp) / 'workspace') as ws:
        original, added = add_inventory(ws, raw, InventoryContext(kb='KB5036893'), now='2026-11-18T07:42:41Z')
        assert added
        assert original.parsed.inventory_id == '5e54590efc97daf62a7e92d4d169ecf9a5506f1909344f737c110823599587e9'
        assert original.parsed.accepted_count == 5000 and original.parsed.records_scanned == 5261
        assert {entry.architecture for entry in original.parsed.entries} == {'arm64'}
        frozen, gzip_raw = original.model_dump_json(), ws.object_path(sha).read_bytes()
        all_records, ids = set(), set()
        for number, expected in enumerate((5000, 5000, 5000, 3761), 1):
            before = time.monotonic()
            page, added = retain_inventory(ws, original.import_id, InventoryRetention(architecture='amd64', page=number))
            parsed = page.parsed
            assert added and parsed.scan_complete and not parsed.truncated
            assert parsed.accepted_count == expected and parsed.limits.max_entries == 5000
            assert (parsed.matching_count, parsed.excluded_count, parsed.records_scanned) == (18761, 18834, 42845)
            assert parsed.omitted_count == 18761 - expected
            assert page.source == original.source and page.retrieval == original.retrieval
            assert page.asserted_source == original.asserted_source
            assert get_inventory(ws, page.import_id) == page
            assert get_inventory(ws, original.import_id).model_dump_json() == frozen
            assert ws.object_path(sha).read_bytes() == gzip_raw
            assert ws.db.execute('SELECT COUNT(*) FROM revisions').fetchone()[0] == 0
            refs = {entry.reference.logical_record for entry in parsed.entries}
            assert not refs & all_records
            all_records.update(refs)
            ids.add(parsed.inventory_id)
            witness = next((w for w in parsed.conflict_witnesses
                            if w.first.logical_record == 24355 and w.second.logical_record == 41380), None)
            if number in (1, 4):
                aarsvc = next(entry for entry in parsed.entries if entry.basename == 'aarsvc.dll')
                assert aarsvc.state == 'conflicted' and witness is not None
                assert witness.conflict_group == aarsvc.conflict_group
            row = {'page': number, 'inventory_id': parsed.inventory_id, 'import_id': page.import_id,
                   'retained': expected, 'matching': parsed.matching_count, 'excluded': parsed.excluded_count,
                   'omitted': parsed.omitted_count, 'rejected': parsed.rejected_count,
                   'records_scanned': parsed.records_scanned, 'logical_record_range': [min(refs), max(refs)],
                   'conflict_count': parsed.conflict_count, 'witness_count': len(parsed.conflict_witnesses),
                   'aarsvc_witness': witness.model_dump(mode='json') if witness else None,
                   'retention_and_verified_replay_seconds': round(time.monotonic() - before, 3)}
            report['pages'].append(row)
            print(json.dumps(row), flush=True)
        repeated, added = retain_inventory(ws, page.import_id, InventoryRetention(architecture='amd64', page=1))
        assert not added and repeated.import_id == report['pages'][0]['import_id']
        assert len(all_records) == 18761 and len(ids) == 4 and inventory_count(ws) == 5
        report.update(amd64_rows_reachable=len(all_records), original_v1_replayed=True,
                      source_provenance_unchanged=True, raw_object_unchanged=True, investigation_revisions=0,
                      cross_page_witness_replayed=True, repeated_retention_idempotent=True)
assert capture.read_bytes() == raw
report['capture_unchanged'] = True
Path('/workspace/scratch/e83fbf4505c3/pw01-retention-real-result.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'qualification': 'passed', 'amd64_rows_reachable': len(all_records)}), flush=True)
