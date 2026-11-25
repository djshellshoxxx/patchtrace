"""A backup must reopen even if the source changes during the copy."""
import hashlib
import json
import sqlite3
import stat
from contextlib import closing
from pathlib import Path

import pytest

from patchtrace import cli, persistence
from patchtrace.service import ProjectService


def change_bytes(path, data):
    mode = stat.S_IMODE(path.stat().st_mode)
    path.chmod(mode | stat.S_IWUSR)
    try:
        path.write_bytes(data)
    finally:
        path.chmod(mode)


@pytest.mark.parametrize('kind', ['artifact', 'raw'])
@pytest.mark.parametrize('where', ['source', 'staged'])
def test_backup_refuses_changed_copy_and_keeps_previous_backup(tmp_path, monkeypatch, kind, where):
    with ProjectService.sample(tmp_path / 'source') as service:
        saved = service.project
        previous = service.backup(tmp_path / 'previous')
        relative = Path(saved.artifacts[0].relative_path if kind == 'artifact'
                        else next(run.raw_path for run in saved.runs if run.raw_path))
        source_file = service.root / relative
        original = source_file.read_bytes()
        changed = original[:-1] + bytes([original[-1] ^ 1])
        copytree = persistence.shutil.copytree

        def copy_directory(src, dst, *args, **kwargs):
            if Path(src) != service.root / relative.parts[0]:
                return copytree(src, dst, *args, **kwargs)
            if where == 'source':
                change_bytes(source_file, changed)
                try:
                    return copytree(src, dst, *args, **kwargs)
                finally:
                    change_bytes(source_file, original)
            completed = copytree(src, dst, *args, **kwargs)
            change_bytes(Path(dst).parent / relative, changed)
            return completed

        failed = tmp_path / 'attempt'
        with monkeypatch.context() as patch:
            patch.setattr(persistence.shutil, 'copytree', copy_directory)
            with pytest.raises(ValueError, match='PT-STORAGE'):
                service.backup(failed)
        assert not failed.exists()
        assert not list(tmp_path.glob('.patchtrace-backup-*'))
        assert service.store.load(recover_interrupted=False) == saved
        retried = service.backup(failed)
    for root in (previous, retried):
        with ProjectService.open(root) as restored:
            assert restored.project == saved
            assert (root / relative).read_bytes() == original


def test_backup_refuses_different_valid_staged_snapshot(tmp_path, monkeypatch):
    with ProjectService.sample(tmp_path / 'source') as service:
        copytree = persistence.shutil.copytree

        def swap_snapshot(src, dst, *args, **kwargs):
            result = copytree(src, dst, *args, **kwargs)
            if Path(src) == service.root / 'artifacts':
                with closing(sqlite3.connect(Path(dst).parent / 'project.sqlite3')) as database, database:
                    data = json.loads(database.execute('SELECT payload FROM current_snapshot').fetchone()[0])
                    data['name'] = 'Other valid snapshot'
                    payload = json.dumps(data)
                    database.execute('UPDATE current_snapshot SET payload=?, sha256=?',
                                     (payload, hashlib.sha256(payload.encode()).hexdigest()))
            return result

        monkeypatch.setattr(persistence.shutil, 'copytree', swap_snapshot)
        destination = tmp_path / 'backup'
        with pytest.raises(ValueError, match='PT-STORAGE'):
            service.backup(destination)
        assert not destination.exists()
        assert not list(tmp_path.glob('.patchtrace-backup-*'))


def test_interrupted_stage_verification_is_read_only_and_retryable(tmp_path, monkeypatch):
    destination = tmp_path / 'backup'
    with ProjectService.sample(tmp_path / 'source') as service:
        load = persistence.ProjectStore.load

        def interrupt_stage(store, *, recover_interrupted=True):
            if store.root.parent == tmp_path and store.root.name.startswith('.patchtrace-backup-'):
                assert not recover_interrupted
                assert not (store.root / '.patchtrace.lock').exists()
                with pytest.raises(sqlite3.OperationalError, match='readonly'):
                    store.connection.execute('DELETE FROM current_snapshot')
                raise KeyboardInterrupt()
            return load(store, recover_interrupted=recover_interrupted)

        with monkeypatch.context() as patch:
            patch.setattr(persistence.ProjectStore, 'load', interrupt_stage)
            with pytest.raises(KeyboardInterrupt):
                service.backup(destination)
        assert not destination.exists() and not list(tmp_path.glob('.patchtrace-backup-*'))
        saved = service.project
        service.backup(destination)
    assert not (destination / '.patchtrace.lock').exists()
    with ProjectService.open(destination) as reopened:
        assert reopened.project == saved


def rewrite_run(root, change):
    with closing(sqlite3.connect(root / 'project.sqlite3')) as db, db:
        old, old_hash = db.execute('SELECT payload, sha256 FROM current_snapshot').fetchone()
        data = json.loads(old)
        change(data['runs'][0])
        payload = json.dumps(data, ensure_ascii=False)
        digest = hashlib.sha256(payload.encode()).hexdigest()
        db.execute('UPDATE current_snapshot SET payload=?, sha256=?', (payload, digest))
        db.execute('UPDATE history SET payload=?, sha256=? WHERE sha256=?', (payload, digest, old_hash))
        return payload, digest


@pytest.mark.parametrize('when', ['staged', 'published'])
def test_backup_refuses_nested_boolean_replaced_with_equal_integer(tmp_path, monkeypatch, capsys, when):
    root, destination = tmp_path / 'source', tmp_path / 'backup'
    with ProjectService.sample(root):
        pass

    def change_type(run):
        assert run['settings']['synthetic'] is True
        run['settings']['synthetic'] = 1

    if when == 'staged':
        copytree = persistence.shutil.copytree

        def changed_stage(src, dst, *args, **kwargs):
            result = copytree(src, dst, *args, **kwargs)
            if Path(src) == root / 'artifacts':
                rewrite_run(Path(dst).parent, change_type)
            return result

        monkeypatch.setattr(persistence.shutil, 'copytree', changed_stage)
    else:
        backup = persistence.ProjectStore.backup

        def changed_publication(store, out):
            result = backup(store, out)
            rewrite_run(result, change_type)
            return result

        monkeypatch.setattr(persistence.ProjectStore, 'backup', changed_publication)

    code = cli.main(['project', 'backup', str(root), '--out', str(destination), '--json'])
    doc = json.loads(capsys.readouterr().out)
    assert code == 3 and 'snapshot differs' in doc['error']
    assert destination.exists() == (when == 'published')


def test_cli_backup_verifies_original_v1_snapshot_with_omitted_default(tmp_path, capsys):
    root, destination = tmp_path / 'source', tmp_path / 'backup'
    with ProjectService.sample(root):
        pass

    def omit_default(run):
        assert run.pop('error') is None

    original = rewrite_run(root, omit_default)
    code = cli.main(['project', 'backup', str(root), '--out', str(destination), '--json'])
    assert code == 0 and json.loads(capsys.readouterr().out)['result']['verified']
    with ProjectService.open(destination) as copied:
        assert copied.project.runs[0].error is None
        assert copied.store.connection.execute('SELECT payload,sha256 FROM current_snapshot').fetchone() == original


@pytest.mark.parametrize('phase', ['source-before', 'stage-digest', 'stage-transaction',
                                   'source-after', 'published-digest', 'published-transaction'])
def test_sqlite_verification_error_reports_publication_state(tmp_path, capsys, monkeypatch, phase):
    root, destination = tmp_path / 'source', tmp_path / 'backup'
    with ProjectService.sample(root) as service:
        expected = service.project
    digest = persistence.ProjectStore.snapshot_sha256
    enter = persistence.ProjectStore.__enter__
    causes = []

    def needs_failure(store):
        if phase.startswith('source'):
            return store.root == root and destination.exists() == (phase == 'source-after')
        if phase.startswith('stage'):
            return store.root.name.startswith('.patchtrace-backup-')
        return store.root == destination

    def query(store):
        if not needs_failure(store) or phase.endswith('transaction'):
            return digest(store)
        # Interrupt the real digest SELECT, then release the injection for reconciliation.
        store.connection.set_progress_handler(lambda: 1, 1)
        try:
            return digest(store)
        except ValueError as exc:
            causes.append(exc.__cause__)
            raise
        finally:
            store.connection.set_progress_handler(None, 0)

    def entering(store):
        result = enter(store)
        if phase.endswith('transaction') and needs_failure(store):
            # The first statement after entry is the verifier's real BEGIN.
            store.connection.set_progress_handler(lambda: 1, 1)
        return result

    with monkeypatch.context() as patch:
        patch.setattr(persistence.ProjectStore, 'snapshot_sha256', query)
        patch.setattr(persistence.ProjectStore, '__enter__', entering)
        code = cli.main(['project', 'backup', str(root), '--out', str(destination), '--json'])
    doc = json.loads(capsys.readouterr().out)
    assert code == 3 and doc['result'] is None and 'PT-STORAGE' in doc['error']
    if not phase.endswith('transaction'):
        assert len(causes) == 1 and causes[0].sqlite_errorcode == sqlite3.SQLITE_INTERRUPT
    published = phase in {'source-after', 'published-digest', 'published-transaction'}
    assert destination.exists() == published
    assert not list(tmp_path.glob('.patchtrace-backup-*'))
    if published:
        assert 'backup did not verify' in doc['error'] and str(destination) in doc['error']
        with ProjectService.open(destination) as restored:
            assert restored.project == expected
    else:
        assert 'left at' not in doc['error']
    with ProjectService.open(root) as reopened:
        assert reopened.project == expected


def test_missing_snapshot_digest_preserves_storage_diagnostic(tmp_path):
    with ProjectService.sample(tmp_path / 'source') as service:
        with pytest.raises(ValueError, match='PT-STORAGE: project snapshot is missing'):
            with service.store.connection:
                service.store.connection.execute('DELETE FROM current_snapshot')
                service.store.snapshot_sha256()
        assert service.store.load(recover_interrupted=False) == service.project
