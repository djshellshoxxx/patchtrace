"""Saved-plan execution against authored PE/PDB responses; no network or target execution."""
from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
from dataclasses import replace

import pytest
from test_tier_w_fetch import BLOB, Opener, Resp
from test_tier_w_fetch_plan import binary_plan, place
from tier_w_builders import TIER_W_FIXTURES

from tools.calibration.common import canonical_json
from tools.calibration.tier_w import fetch_plan as F
from tools.calibration.tier_w.paths import Layout, TierWError
from tools.calibration.tier_w.transport import SymbolTransport


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        pytest.fail('saved-plan execution tests must not open sockets')
    monkeypatch.setattr(socket, 'create_connection', refuse)
    monkeypatch.setattr(socket.socket, 'connect', refuse)


def setup(tmp_path, kind='binary', *, max_files=100000, redirect=False):
    root = tmp_path / 'corpus'
    root.mkdir()
    if kind == 'pdb':
        binaries = binary_plan()
        place(root, binaries)

    def recompute():
        return (binary_plan(max_files=max_files) if kind == 'binary' else
                F.build_pdb_plan(root, binary_plan(), max_files=max_files, pdb_cap_mib=1))
    plan = recompute()
    path = tmp_path / 'plan.json'
    digest = F.save_plan(plan, path)
    fixtures = {hashlib.sha256(path.read_bytes()).hexdigest(): path.read_bytes()
                for path in TIER_W_FIXTURES.glob('tiny_v*.pe')}
    bodies = [fixtures[item.sha256] if item.kind == 'binary' else (TIER_W_FIXTURES / item.file_name).read_bytes()
              for item in plan.entries]
    responses = []
    for body in bodies:
        if redirect:
            responses.append(Resp(302, headers={'Location': BLOB}))
        responses.append(Resp(200, body, {'Content-Length': str(len(body))}))
    subject = SymbolTransport(opener=Opener(*responses), min_interval=0, sleep=lambda *_: None)
    options = dict(root=root, recompute=recompute, consent_hosts=['msdl.microsoft.com'], transport=subject,
                   disk_free=lambda _: 10**15)
    return plan, path, digest, options, bodies


def events(directory):
    previous, records = '0' * 64, []
    for index, path in enumerate(sorted(directory.glob('*.jsonl')), 1):
        record = json.loads(path.read_bytes())
        digest = record.pop('sha256')
        assert record['seq'] == index and record['prev_sha256'] == previous
        assert hashlib.sha256(canonical_json(record)).hexdigest() == digest
        previous = digest
        records.append(dict(record, sha256=digest))
    return records


@pytest.mark.parametrize('kind', ['binary', 'pdb'])
def test_exact_plan_executes_then_reuses_verified_artifacts_without_requests(tmp_path, kind):
    plan, path, digest, options, bodies = setup(tmp_path, kind, redirect=True)
    result = F.fetch_saved_plan(path, digest, **options)
    assert result.status == 'completed' and result.plan_sha256 == digest and result.remaining == 0
    assert [row['status'] for row in result.results] == ['fetched', 'fetched']
    assert all(row['redirect_host'] == 'acct.blob.core.windows.net' for row in result.results)
    for item, body in zip(plan.entries, bodies, strict=True):
        assert F._destination(options['root'], item).read_bytes() == body
    records = events(result.attempt_ledger)
    assert len(records) == 4 and records[-1]['sha256'] == result.ledger_head_sha256
    assert all(event['plan_sha256'] == digest and event['tier'] == 'W' for event in records)
    assert 'SECRET' not in str(records) and BLOB not in str(records)
    prior = {file: file.read_bytes() for file in result.attempt_ledger.iterdir()}
    options['transport'].opener = Opener()
    repeated = F.fetch_saved_plan(path, digest, **options)
    assert repeated.status == 'completed' and not options['transport'].opener.calls
    assert [row['status'] for row in repeated.results] == ['reused', 'reused']
    assert all(row['origin'] == 'local-verified' and not row['requested'] and 'retrieved_at' not in row
               for row in repeated.results)
    assert repeated.attempt_ledger != result.attempt_ledger
    assert all(file.read_bytes() == data for file, data in prior.items())


def test_pdb_symbol_bytes_changed_without_guid_or_age_change_cannot_be_reused(tmp_path):
    plan, path, digest, options, _ = setup(tmp_path, 'pdb', max_files=1)
    F.fetch_saved_plan(path, digest, **options)
    target = F._destination(options['root'], plan.entries[0])
    identity = F.msf.read_identity(target)
    original = target.read_bytes()
    assert b'checksum' in original
    changed = original.replace(b'checksum', b'xhecksum', 1)
    target.write_bytes(changed)
    assert F.msf.read_identity(target) == identity
    options['transport'].opener = Opener()
    with pytest.raises(TierWError) as caught:
        F.fetch_saved_plan(path, digest, **options)
    assert caught.value.code == 'PT-TIERW-VERIFY'
    assert not options['transport'].opener.calls and target.read_bytes() == changed


def test_existing_pdb_cannot_backfill_a_missing_trusted_receipt(tmp_path):
    plan, path, digest, options, bodies = setup(tmp_path, 'pdb', max_files=1)
    target = F._destination(options['root'], plan.entries[0])
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(bodies[0])
    with pytest.raises(TierWError, match='no verified download receipt'):
        F.fetch_saved_plan(path, digest, **options)
    assert not options['transport'].opener.calls and target.read_bytes() == bodies[0]
    assert not F._receipt_path(target).exists()


@pytest.mark.parametrize('damage', ['missing', 'sha256', 'size', 'target', 'url', 'unknown', 'bool-size',
                                   'oversize', 'link', 'hardlink', 'canonical'])
def test_pdb_receipt_admission_refuses_before_any_request_and_preserves_evidence(tmp_path, damage):
    plan, path, digest, options, bodies = setup(tmp_path, 'pdb', max_files=1)
    F.fetch_saved_plan(path, digest, **options)
    target = F._destination(options['root'], plan.entries[0])
    receipt_path = F._receipt_path(target)
    if damage == 'missing':
        receipt_path.unlink()
    elif damage == 'link':
        original = tmp_path / 'original-receipt.json'
        receipt_path.rename(original)
        try:
            receipt_path.symlink_to(original)
        except OSError:
            pytest.skip('symlink unavailable')
    elif damage == 'hardlink':
        try:
            os.link(receipt_path, tmp_path / 'aliased-receipt.json')
        except OSError:
            pytest.skip('hardlink unavailable')
    elif damage == 'oversize':
        receipt_path.write_bytes(b'x' * (F.PDB_RECEIPT_LIMIT + 1))
    else:
        document = json.loads(receipt_path.read_bytes())
        if damage == 'sha256':
            document['file_sha256'] = '0' * 64
        elif damage == 'size':
            document['size'] += 1
        elif damage == 'target':
            document['destination'] = 'tier-w/pdbs/foreign'
        elif damage == 'url':
            document['source_url'] += '?secret=REFUSED'
        elif damage == 'unknown':
            document['approval'] = True
        elif damage == 'bool-size':
            document['size'] = True
        if damage == 'canonical':
            receipt_path.write_bytes(json.dumps(document).encode())
        else:
            receipt_path.write_bytes((json.dumps(document, sort_keys=True, indent=1) + '\n').encode())
    before = receipt_path.read_bytes() if receipt_path.exists() else None
    options['transport'].opener = Opener()
    with pytest.raises(TierWError):
        F.fetch_saved_plan(path, digest, **options)
    assert not options['transport'].opener.calls and target.read_bytes() == bodies[0]
    assert (receipt_path.read_bytes() if receipt_path.exists() else None) == before


@pytest.mark.parametrize('changed_download', [False, True])
def test_receipt_without_artifact_recovers_only_the_previously_verified_bytes(tmp_path, monkeypatch, changed_download):
    plan, path, digest, options, bodies = setup(tmp_path, 'pdb', max_files=1)
    target = F._destination(options['root'], plan.entries[0])
    publish = F.owned.publish_stream

    def fail_artifact(destination, *args, **kwargs):
        if destination == target:
            raise OSError('authored interruption between receipt and artifact publication')
        return publish(destination, *args, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(F.owned, 'publish_stream', fail_artifact)
        first = F.fetch_saved_plan(path, digest, **options)
    assert first.results[0]['status'] == 'failed' and not target.exists()
    receipt_path = F._receipt_path(target)
    retained = receipt_path.read_bytes()
    body = bodies[0].replace(b'checksum', b'xhecksum', 1) if changed_download else bodies[0]
    options['transport'].opener = Opener(Resp(200, body))
    recovered = F.fetch_saved_plan(path, digest, **options)
    assert receipt_path.read_bytes() == retained
    if changed_download:
        assert recovered.results[0]['status'] == 'failed' and not target.exists()
    else:
        assert recovered.results[0]['status'] == 'fetched' and target.read_bytes() == bodies[0]


def test_receipt_publication_failure_cannot_publish_a_pdb(tmp_path, monkeypatch):
    plan, path, digest, options, _ = setup(tmp_path, 'pdb', max_files=1)
    target = F._destination(options['root'], plan.entries[0])
    receipt_path = F._receipt_path(target)
    publish = F._publish_small

    def fail_receipt(path, *args, **kwargs):
        if path == receipt_path:
            raise OSError('authored receipt publication failure')
        return publish(path, *args, **kwargs)

    monkeypatch.setattr(F, '_publish_small', fail_receipt)
    result = F.fetch_saved_plan(path, digest, **options)
    assert result.results[0]['status'] == 'failed' and not target.exists() and not receipt_path.exists()


@pytest.mark.skipif(os.name == 'nt', reason='in-place receipt mutation is denied by the native held Windows handle')
def test_receipt_remains_bound_through_pdb_artifact_publication(tmp_path, monkeypatch):
    plan, path, digest, options, bodies = setup(tmp_path, 'pdb', max_files=1)
    target = F._destination(options['root'], plan.entries[0])
    receipt_path = F._receipt_path(target)
    publish = F.owned.publish_stream

    def change_receipt(destination, *args, **kwargs):
        published = publish(destination, *args, **kwargs)
        if destination == target:
            receipt_path.write_bytes(b'foreign receipt after body publication')
        return published

    monkeypatch.setattr(F.owned, 'publish_stream', change_receipt)
    result = F.fetch_saved_plan(path, digest, **options)
    assert result.results[0]['status'] == 'failed' and target.read_bytes() == bodies[0]
    assert receipt_path.read_bytes() == b'foreign receipt after body publication'


@pytest.mark.parametrize('damage', ['digest', 'source', 'hosts', 'extra-host', 'canonical', 'interval', 'disk'])
def test_admission_refuses_changed_or_unfunded_plan_before_request(tmp_path, damage):
    plan, path, digest, options, _ = setup(tmp_path)
    if damage == 'digest':
        digest = '0' * 64
    elif damage == 'source':
        options['recompute'] = lambda: binary_plan(max_files=1)
    elif damage == 'hosts':
        options['consent_hosts'] = []
    elif damage == 'extra-host':
        options['consent_hosts'].append('winbindex.m417z.com')
    elif damage == 'canonical':
        path.write_bytes(json.dumps(plan.model_dump(mode='json')).encode())
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    elif damage == 'interval':
        options['transport'].min_interval = float('nan')
    else:
        options['disk_free'] = lambda _: 0
    with pytest.raises(TierWError):
        F.fetch_saved_plan(path, digest, **options)
    assert not options['transport'].opener.calls
    assert not (options['root'] / 'tier-w' / 'ledger').exists()


@pytest.mark.parametrize('kind', ['binary', 'pdb'])
@pytest.mark.parametrize('damage', ['bytes', 'directory', 'link'])
def test_every_selected_destination_is_admitted_before_first_request(tmp_path, kind, damage):
    plan, path, digest, options, _ = setup(tmp_path, kind)
    target = F._destination(options['root'], plan.entries[-1])
    target.parent.mkdir(parents=True, exist_ok=True)
    foreign = tmp_path / 'foreign'
    foreign.write_bytes(b'prior evidence')
    if damage == 'bytes':
        target.write_bytes(b'prior evidence')
    elif damage == 'directory':
        target.mkdir()
    else:
        try:
            target.symlink_to(foreign)
        except OSError:
            pytest.skip('symlink unavailable')
    with pytest.raises(TierWError):
        F.fetch_saved_plan(path, digest, **options)
    assert not options['transport'].opener.calls and foreign.read_bytes() == b'prior evidence'
    if damage == 'bytes':
        assert target.read_bytes() == b'prior evidence'
    elif damage == 'directory':
        assert target.is_dir()
    else:
        assert target.is_symlink()


@pytest.mark.parametrize('failure', ['404', 'bad-body', 'wrong-pdb'])
def test_remote_refusals_do_not_publish_an_artifact_or_claim_fetch_success(tmp_path, failure):
    kind = 'pdb' if failure == 'wrong-pdb' else 'binary'
    plan, path, digest, options, bodies = setup(tmp_path, kind, max_files=1)
    response = Resp(404) if failure == '404' else Resp(200, b'invalid bytes')
    if failure == 'wrong-pdb':
        other = 'tiny_v2.pdb' if plan.entries[0].file_name == 'tiny_v1.pdb' else 'tiny_v1.pdb'
        response = Resp(200, (TIER_W_FIXTURES / other).read_bytes())
    options['transport'].opener = Opener(response)
    result = F.fetch_saved_plan(path, digest, **options)
    assert result.status == 'partial'
    assert result.results[0]['status'] == ('not-found' if failure == '404' else 'rejected')
    assert not F._destination(options['root'], plan.entries[0]).exists()
    assert events(result.attempt_ledger)[1]['status'] == result.results[0]['status']


@pytest.mark.parametrize('damage', ['bytes', 'link', 'foreign-path', 'metadata'])
def test_transport_result_is_reverified_inside_its_owned_stage(tmp_path, monkeypatch, damage):
    plan, path, digest, options, bodies = setup(tmp_path, max_files=1)
    subject = options['transport']
    download = subject.download
    foreign = tmp_path / 'foreign'
    foreign.write_bytes(bodies[0])
    staged = []

    def substituted(*args, **kwargs):
        result = download(*args, **kwargs)
        staged.append(result.path)
        if damage == 'bytes':
            result.path.write_bytes(b'X' * result.size)
        elif damage == 'link':
            result.path.rename(result.path.with_name('displaced'))
            try:
                result.path.symlink_to(foreign)
            except OSError:
                pytest.skip('symlink unavailable')
        elif damage == 'foreign-path':
            result = replace(result, path=foreign)
        else:
            result = replace(result, redirect_host='acct.blob.core.windows.net/?sig=SECRET')
        return result

    monkeypatch.setattr(subject, 'download', substituted)
    result = F.fetch_saved_plan(path, digest, **options)
    assert result.results[0]['status'] == 'failed' and not F._destination(options['root'], plan.entries[0]).exists()
    assert foreign.read_bytes() == bodies[0] and staged[0].exists()
    assert 'SECRET' not in str(events(result.attempt_ledger))


@pytest.mark.parametrize('kind', ['binary', 'pdb'])
@pytest.mark.parametrize('same', [False, True])
def test_racing_final_creator_is_preserved_and_only_exact_bytes_may_be_reused(tmp_path, monkeypatch, same, kind):
    plan, path, digest, options, bodies = setup(tmp_path, kind, max_files=1)
    target = F._destination(options['root'], plan.entries[0])
    publish = F.owned.publish_stream

    def competing(destination, source, **kwargs):
        if destination == target and not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bodies[0] if same else b'foreign creator')
        return publish(destination, source, **kwargs)

    monkeypatch.setattr(F.owned, 'publish_stream', competing)
    result = F.fetch_saved_plan(path, digest, **options)
    assert result.results[0]['status'] == ('reused' if same else 'failed')
    assert target.read_bytes() == (bodies[0] if same else b'foreign creator')
    if same:
        assert result.results[0]['requested'] is True
        if kind == 'pdb':
            receipt = F.load_pdb_fetch_receipt(F._receipt_path(target).read_bytes())
            assert receipt.file_sha256 == hashlib.sha256(bodies[0]).hexdigest()


@pytest.mark.parametrize('switch', ['file', 'caller-event', 'transport-event'])
def test_cancel_during_body_retains_attempt_prefix_and_restores_transport_event(tmp_path, switch):
    plan, path, digest, options, _ = setup(tmp_path)
    caller, existing = threading.Event(), threading.Event()
    options.update(cancel=caller)
    options['transport'].cancel = existing

    def progress(item, size, total):
        if size:
            if switch == 'file':
                Layout(options['root']).cancel_file.write_bytes(b'')
            else:
                (caller if switch == 'caller-event' else existing).set()

    result = F.fetch_saved_plan(path, digest, progress=progress, **options)
    assert result.status == 'cancelled' and result.remaining == 1
    assert options['transport'].cancel is existing
    assert not any(F._destination(options['root'], item).exists() for item in plan.entries)
    assert [record['event'] for record in events(result.attempt_ledger)] == [
        'fetch-started', 'binary-cancelled', 'fetch-finished']
    assert not list(Layout(options['root']).staging.rglob('.download-*'))


def test_later_cancel_preserves_first_completed_output_and_ledger_event(tmp_path):
    plan, path, digest, options, bodies = setup(tmp_path)
    cancel = threading.Event()

    def progress(item, size, total):
        if item == plan.entries[1] and size:
            cancel.set()

    result = F.fetch_saved_plan(path, digest, cancel=cancel, progress=progress, **options)
    assert [row['status'] for row in result.results] == ['fetched', 'cancelled']
    assert F._destination(options['root'], plan.entries[0]).read_bytes() == bodies[0]
    assert not F._destination(options['root'], plan.entries[1]).exists()
    assert events(result.attempt_ledger)[1]['event'] == 'binary-fetched'


def test_cancel_after_download_retains_verified_stage_without_promotion(tmp_path, monkeypatch):
    plan, path, digest, options, bodies = setup(tmp_path, max_files=1)
    event, stages = threading.Event(), []
    download = options['transport'].download

    def stopped(*args, **kwargs):
        got = download(*args, **kwargs)
        stages.append(got.path)
        event.set()
        return got

    monkeypatch.setattr(options['transport'], 'download', stopped)
    result = F.fetch_saved_plan(path, digest, cancel=event, **options)
    assert result.status == 'cancelled' and not F._destination(options['root'], plan.entries[0]).exists()
    assert stages[0].read_bytes() == bodies[0]


def test_unbounded_host_iterable_is_refused_after_three_values(tmp_path):
    _plan, path, digest, options, _ = setup(tmp_path)
    yielded = []

    def hosts():
        while True:
            yielded.append(True)
            yield 'msdl.microsoft.com'

    options['consent_hosts'] = hosts()
    with pytest.raises(TierWError):
        F.fetch_saved_plan(path, digest, **options)
    assert len(yielded) == 3 and not options['transport'].opener.calls


def test_attempt_budget_failure_keeps_completed_artifact_and_existing_event(tmp_path, monkeypatch):
    plan, path, digest, options, bodies = setup(tmp_path)
    publish, first = F._publish_small, []

    def bound(path, data, *args, **kwargs):
        result = publish(path, data, *args, **kwargs)
        if path.name == '000001.jsonl':
            first.append(path)
            monkeypatch.setattr(F, 'LEDGER_LIMIT', len(data))
        return result

    monkeypatch.setattr(F, '_publish_small', bound)
    with pytest.raises(TierWError) as caught:
        F.fetch_saved_plan(path, digest, **options)
    assert caught.value.code == 'PT-TIERW-LIMIT' and caught.value.__notes__
    assert len(options['transport'].opener.calls) == 1
    assert F._destination(options['root'], plan.entries[0]).read_bytes() == bodies[0]
    assert [record['event'] for record in events(first[0].parent)] == ['fetch-started']


def test_disk_preflight_is_repeated_before_each_download(tmp_path):
    plan, path, digest, options, bodies = setup(tmp_path)
    checks = []

    def free(root):
        checks.append(root)
        return 10**15 if len(checks) <= 2 else 0

    options['disk_free'] = free
    result = F.fetch_saved_plan(path, digest, **options)
    assert len(checks) == 3 and len(options['transport'].opener.calls) == 1
    assert [row['status'] for row in result.results] == ['fetched', 'failed']
    assert result.results[-1]['error_code'] == 'PT-TIERW-CONFIG'
    assert F._destination(options['root'], plan.entries[0]).read_bytes() == bodies[0]


def test_receipt_conflict_after_publication_keeps_artifact_and_prior_event_without_claiming_success(tmp_path, monkeypatch):
    plan, path, digest, options, bodies = setup(tmp_path)
    publish, records = F._publish_small, []

    def collide(target, data, anchor):
        if target.suffix == '.jsonl':
            records.append(target)
            if target.name == '000002.jsonl' and not target.exists():
                target.write_bytes(b'foreign receipt')
        return publish(target, data, anchor)

    monkeypatch.setattr(F, '_publish_small', collide)
    with pytest.raises(TierWError) as caught:
        F.fetch_saved_plan(path, digest, **options)
    assert caught.value.code == 'PT-TIERW-VERIFY' and caught.value.__notes__
    assert len(options['transport'].opener.calls) == 1
    assert F._destination(options['root'], plan.entries[0]).read_bytes() == bodies[0]
    assert not F._destination(options['root'], plan.entries[1]).exists()
    assert json.loads(records[0].read_bytes())['event'] == 'fetch-started'
    assert records[1].read_bytes() == b'foreign receipt'


@pytest.mark.parametrize('receipt_failure', [False, True])
def test_hard_interruption_preserves_primary_and_completed_prefix(tmp_path, monkeypatch, receipt_failure):
    plan, path, digest, options, bodies = setup(tmp_path)
    primary = KeyboardInterrupt('authored interruption')
    record = F._AttemptLedger.record

    def record_or_fail(ledger, event, **fields):
        if event == 'fetch-interrupted' and receipt_failure:
            raise OSError('secondary receipt failure')
        return record(ledger, event, **fields)

    def progress(item, size, total):
        if item == plan.entries[1] and size:
            raise primary

    monkeypatch.setattr(F._AttemptLedger, 'record', record_or_fail)
    with pytest.raises(KeyboardInterrupt) as caught:
        F.fetch_saved_plan(path, digest, progress=progress, **options)
    assert caught.value is primary and options['transport'].cancel is None
    assert F._destination(options['root'], plan.entries[0]).read_bytes() == bodies[0]
    assert not F._destination(options['root'], plan.entries[1]).exists()
    directory = next((options['root'] / 'tier-w' / 'ledger').glob('*/*/*'))
    records = events(directory)
    assert records[1]['event'] == 'binary-fetched'
    if receipt_failure:
        assert primary.__notes__ == ['Fetch interruption receipt also failed: OSError']
    else:
        assert records[-1]['event'] == 'fetch-interrupted'


@pytest.mark.parametrize('operation', ['save', 'read', 'execute'])
def test_linked_parent_followed_by_traversal_is_refused_before_normalization(tmp_path, operation):
    plan, path, digest, options, _ = setup(tmp_path)
    link = tmp_path / 'alias'
    try:
        link.symlink_to(options['root'], target_is_directory=True)
    except OSError:
        pytest.skip('symlink unavailable')
    spelling = link / '..' / ('new.json' if operation == 'save' else 'plan.json')
    with pytest.raises(TierWError):
        if operation == 'save':
            F.save_plan(plan, spelling)
        elif operation == 'read':
            F.read_plan(spelling)
        else:
            options['root'] = link / '..' / 'corpus'
            F.fetch_saved_plan(path, digest, **options)
    assert not (tmp_path / 'new.json').exists() and not options['transport'].opener.calls
