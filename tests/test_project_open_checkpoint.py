"""Committed-copy reads preserve operation checks without startup recovery writes."""
from __future__ import annotations

import gc
import hashlib
import weakref

import pytest

from patchtrace import ingestion
from patchtrace import service as core
from patchtrace.input_readers import InputReadError
from patchtrace.models import AnalysisRun
from patchtrace.persistence import ProjectStore
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService


class Ledger:
    def __init__(self, reason='cancelled'):
        self.counts = []
        self.stop = lambda count: False
        self.failure = InputReadError(reason)
        self.output_reservation = 123456

    def __call__(self, count):
        assert type(count) is int and 0 <= count <= 1 << 20
        self.counts.append(count)
        if self.stop(count):
            raise self.failure


def project_case(tmp_path, status='completed'):
    sources = [tmp_path / f'{side}.sys' for side in ('older', 'newer')]
    for variant, path in enumerate(sources):
        path.write_bytes(synthetic_pe(variant))
    root = tmp_path / 'project'
    with ProjectService.create(*sources, 'authored project', root) as service:
        (root / 'runs').mkdir()
        raw = b'{"authored":true,"scope":"metadata only"}\n'
        (root / 'runs' / 'authored.json').write_bytes(raw)
        candidate = service.project.model_copy(deep=True)
        candidate.runs.append(AnalysisRun(status=status, backend='authored', backend_version='none',
            raw_path='runs/authored.json', raw_sha256=hashlib.sha256(raw).hexdigest()))
        service.store.save(candidate)
        identity = candidate.id
        copies = [root / item.relative_path for item in candidate.artifacts]
    return root, sources, copies, identity


def committed_bytes(root):
    paths = [root / 'project.sqlite3', *sorted((root / 'artifacts').glob('*.bin')),
             *sorted((root / 'runs').glob('*.json'))]
    return {path: path.read_bytes() for path in paths}


@pytest.mark.parametrize('status', ['queued', 'running'])
def test_explicit_no_recovery_open_keeps_committed_state_and_raw_bytes(tmp_path, status):
    root, sources, _copies, identity = project_case(tmp_path, status)
    before = committed_bytes(root)
    for path in sources:
        path.unlink()
    ledger = Ledger()
    with ProjectService.open(root, maintenance=False, recover_interrupted=False, checkpoint=ledger) as service:
        assert service.project.id == service.store.project_id == identity
        assert service.project.runs[-1].status == status
    assert committed_bytes(root) == before
    assert any(ledger.counts) and ledger.output_reservation == 123456


def test_same_checkpoint_accounts_actual_copy_pe_raw_reads_and_cache_hits(tmp_path, monkeypatch):
    root, sources, _copies, _identity = project_case(tmp_path)
    for path in sources:
        path.unlink()
    ledger, reads = Ledger(), []
    actual_read = ingestion._read

    def read(stream, size, checkpoint=None):
        assert checkpoint is ledger
        data = actual_read(stream, size, checkpoint)
        reads.append(len(data))
        return data

    monkeypatch.setattr(ingestion, '_read', read)
    with ProjectService.open(root, maintenance=False, recover_interrupted=False, checkpoint=ledger) as service:
        assert sum(ledger.counts) == sum(reads) > 0
        first_reads, first_counts = len(reads), len(ledger.counts)
        service.store.load(recover_interrupted=False, checkpoint=ledger)
        assert len(reads) == first_reads
        assert len(ledger.counts) > first_counts and set(ledger.counts[first_counts:]) == {0}
    assert ledger.output_reservation == 123456


def test_cancel_before_open_has_no_store_or_lock_side_effect(tmp_path, monkeypatch):
    root, _sources, _copies, _identity = project_case(tmp_path)
    before = committed_bytes(root)
    lock_before = (root / '.patchtrace.lock').read_bytes()
    ledger = Ledger()
    ledger.stop = lambda count: True

    def unexpected(*args, **kwargs):
        raise AssertionError('already-cancelled open acquired a store')

    monkeypatch.setattr(core, 'ProjectStore', unexpected)
    with pytest.raises(InputReadError) as caught:
        ProjectService.open(root, maintenance=False, recover_interrupted=False, checkpoint=ledger)
    assert caught.value is ledger.failure
    assert committed_bytes(root) == before and (root / '.patchtrace.lock').read_bytes() == lock_before


@pytest.mark.parametrize('phase', ['older', 'newer', 'raw'])
@pytest.mark.parametrize('reason', ['cancelled', 'limited'])
def test_neutral_stop_during_committed_copy_reads_closes_without_rollback(tmp_path, monkeypatch, phase, reason):
    root, _sources, copies, _identity = project_case(tmp_path, 'queued')
    selected = {'older': copies[0], 'newer': copies[1], 'raw': root / 'runs' / 'authored.json'}[phase]
    before = committed_bytes(root)
    ledger, current, stores = Ledger(reason), [], []
    real_read, real_init = ingestion._read, ProjectStore.__init__

    def initialize(store, *args, **kwargs):
        real_init(store, *args, **kwargs)
        stores.append(store)

    def read(stream, size, checkpoint=None):
        current.append(stream.name)
        try:
            return real_read(stream, size, checkpoint)
        finally:
            current.pop()

    def rollback(*args, **kwargs):
        raise AssertionError('a committed-project read entered creation rollback')

    monkeypatch.setattr(ProjectStore, '__init__', initialize)
    monkeypatch.setattr(ingestion, '_read', read)
    monkeypatch.setattr(core, '_rollback_creation', rollback)
    ledger.stop = lambda count: count > 0 and bool(current) and str(current[-1]) == str(selected)
    with pytest.raises(InputReadError) as caught:
        ProjectService.open(root, maintenance=False, recover_interrupted=False, checkpoint=ledger)
    assert caught.value is ledger.failure
    assert stores and all(store.closed and store.connection is None and store.lock is None for store in stores)
    assert committed_bytes(root) == before and ledger.output_reservation == 123456
    with ProjectService.open(root, maintenance=False, recover_interrupted=False) as service:
        assert service.project.runs[-1].status == 'queued'


def test_cache_hit_can_stop_without_rehashing_or_mutating_the_snapshot(tmp_path, monkeypatch):
    root, _sources, _copies, _identity = project_case(tmp_path)
    with ProjectService.open(root, maintenance=False) as service:
        before = committed_bytes(root)
        ledger = Ledger('limited')

        def unexpected(*args, **kwargs):
            raise AssertionError('valid cached identity unexpectedly rehashed')

        monkeypatch.setattr(ingestion, '_read', unexpected)
        service.store.load(recover_interrupted=False, checkpoint=ledger)
        assert ledger.counts and set(ledger.counts) == {0}
        ledger.stop = lambda count: True
        with pytest.raises(InputReadError) as caught:
            service.store.load(recover_interrupted=False, checkpoint=ledger)
        assert caught.value is ledger.failure
        assert committed_bytes(root) == before


def test_checkpoint_is_not_retained_by_a_successfully_opened_service(tmp_path):
    root, _sources, _copies, _identity = project_case(tmp_path)
    ledger = Ledger()
    reference = weakref.ref(ledger)
    service = ProjectService.open(root, maintenance=False, recover_interrupted=False, checkpoint=ledger)
    try:
        del ledger
        gc.collect()
        assert reference() is None
        assert service.store.load(recover_interrupted=False).id == service.project.id
    finally:
        service.close()


@pytest.mark.parametrize('target', ['artifact', 'raw'])
def test_checkpoint_never_bypasses_complete_copy_verification(tmp_path, target):
    root, _sources, copies, _identity = project_case(tmp_path)
    database = (root / 'project.sqlite3').read_bytes()
    damaged = copies[0] if target == 'artifact' else root / 'runs' / 'authored.json'
    damaged.chmod(0o600)
    damaged.write_bytes(b'X' * damaged.stat().st_size)
    with pytest.raises(ValueError, match='immutable input|preserved raw output'):
        ProjectService.open(root, maintenance=False, recover_interrupted=False, checkpoint=Ledger())
    assert (root / 'project.sqlite3').read_bytes() == database


def test_recovery_carries_same_checkpoint_to_precommit_and_preserves_old_snapshot_on_stop(tmp_path, monkeypatch):
    root, _sources, _copies, _identity = project_case(tmp_path, 'queued')
    before = committed_bytes(root)
    ledger, stores, statements = Ledger('limited'), [], []
    real_init = ProjectStore.__init__

    def initialize(store, *args, **kwargs):
        real_init(store, *args, **kwargs)
        stores.append(store)
        store.connection.set_trace_callback(statements.append)

    monkeypatch.setattr(ProjectStore, '__init__', initialize)
    ledger.stop = lambda count: bool(stores) and stores[0].connection.in_transaction and any(
        sql.startswith('INSERT INTO current_snapshot') for sql in statements)
    with pytest.raises(InputReadError) as caught:
        ProjectService.open(root, maintenance=False, checkpoint=ledger)
    assert caught.value is ledger.failure and 'ROLLBACK' in statements and 'COMMIT' not in statements
    assert committed_bytes(root) == before and stores[0].closed


def test_no_checkpoint_runs_after_a_successful_recovery_commit(tmp_path, monkeypatch):
    root, _sources, _copies, _identity = project_case(tmp_path, 'running')
    ledger, committed = Ledger(), []
    real_save = ProjectStore.save

    def save(store, project, **kwargs):
        assert kwargs['checkpoint'] is ledger
        result = real_save(store, project, **kwargs)
        assert not store.connection.in_transaction
        committed.append(True)
        return result

    monkeypatch.setattr(ProjectStore, 'save', save)
    ledger.stop = lambda count: bool(committed)
    with ProjectService.open(root, maintenance=False, checkpoint=ledger) as service:
        assert service.project.runs[-1].status == 'failed'
    assert committed == [True]
    with ProjectStore(root) as store:
        assert store.load(recover_interrupted=False).runs[-1].status == 'failed'


@pytest.mark.parametrize('options', [{}, {'maintenance': False}])
def test_default_open_preserves_existing_load_and_verify_injection_shapes(tmp_path, monkeypatch, options):
    root, _sources, _copies, _identity = project_case(tmp_path)
    real_load, real_files = ProjectStore.load, ProjectStore._verify_files
    calls = []

    def load(store):
        calls.append('load')
        return real_load(store)

    def files(store, project):
        calls.append('verify')
        return real_files(store, project)

    monkeypatch.setattr(ProjectStore, 'load', load)
    monkeypatch.setattr(ProjectStore, '_verify_files', files)
    with ProjectService.open(root, **options):
        pass
    assert calls == ['load', 'verify']


@pytest.mark.parametrize('kind', ['neutral', 'keyboard', 'exit'])
def test_failed_owned_open_closes_for_all_primary_failures(tmp_path, monkeypatch, kind):
    root, _sources, _copies, _identity = project_case(tmp_path)
    before = committed_bytes(root)
    primary = {'neutral': InputReadError('cancelled'), 'keyboard': KeyboardInterrupt(), 'exit': SystemExit(7)}[kind]
    stores = []
    real_init = ProjectStore.__init__

    def initialize(store, *args, **kwargs):
        real_init(store, *args, **kwargs)
        stores.append(store)

    def refuse(*args, **kwargs):
        raise primary

    monkeypatch.setattr(ProjectStore, '__init__', initialize)
    monkeypatch.setattr(ProjectStore, '_verify_files', refuse)
    try:
        with pytest.raises(BaseException) as caught:
            ProjectService.open(root, maintenance=False)
        assert caught.value is primary and not getattr(primary, '__notes__', [])
        assert stores[0].closed and stores[0].connection is None and stores[0].lock is None
    finally:
        for store in stores:
            store.close()
    assert committed_bytes(root) == before


@pytest.mark.parametrize('secondary', [PermissionError('private secondary text'), KeyboardInterrupt('secondary')],
                         ids=['os-error', 'base-exception'])
def test_secondary_failed_open_close_preserves_original_and_bounded_retention_note(tmp_path, monkeypatch, secondary):
    root, _sources, _copies, _identity = project_case(tmp_path)
    before = committed_bytes(root)
    primary = InputReadError('limited')
    primary.add_note('existing bounded note')
    real_close = ProjectStore.close

    def refuse(*args, **kwargs):
        raise primary

    def close(store):
        real_close(store)
        raise secondary

    monkeypatch.setattr(ProjectStore, '_verify_files', refuse)
    monkeypatch.setattr(ProjectStore, 'close', close)
    with pytest.raises(BaseException) as caught:
        ProjectService.open(root, maintenance=False)
    assert caught.value is primary
    assert primary.__notes__[0] == 'existing bounded note'
    assert len(primary.__notes__) == 2 and 'resources may remain open' in primary.__notes__[1]
    assert 'private secondary' not in primary.__notes__[1] and 'secondary' not in primary.__notes__[1]
    assert committed_bytes(root) == before


def test_close_failure_after_success_is_still_observable(tmp_path, monkeypatch):
    root, _sources, _copies, _identity = project_case(tmp_path)
    real_close = ProjectStore.close
    secondary = PermissionError('authored successful-path close failure')

    def close(store):
        real_close(store)
        raise secondary

    service = ProjectService.open(root, maintenance=False)
    monkeypatch.setattr(ProjectStore, 'close', close)
    with pytest.raises(PermissionError) as caught:
        service.close()
    assert caught.value is secondary
