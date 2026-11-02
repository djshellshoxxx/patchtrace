"""PR #151: a failed publication must not authorize a later prune, including after restart."""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

import pytest
from test_prune_backup import CURRENT, FUTURE, _generations

from patchtrace import persistence
from patchtrace import verified_backup as V
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.service import ProjectService


@pytest.fixture
def service(tmp_path):
    V.forget_all()
    with ProjectService.sample(tmp_path / 'project') as result:
        yield result
    V.forget_all()


def _rows(db, table='enrichment_entries'):
    key = 'id' if table == 'enrichment_entries' else 'sequence'
    return {row[0] for row in db.execute(f'SELECT {key} FROM {table}')}


def _save(service, name):
    candidate = service.project.model_copy(deep=True)
    candidate.name = name
    service.project = service.store.save(candidate)


def _mutate_after_link(monkeypatch, table='enrichment_entries', observe=None):
    original = os.link
    published = []

    def link_then_change(source, target, **kwargs):
        result = original(source, target, **kwargs)
        if observe is not None:
            observe(Path(source), Path(target))
        with sqlite3.connect(target) as db:
            db.execute(f'DELETE FROM {table}')
            assert db.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
        published.append((Path(source), Path(target), Path(target).read_bytes()))
        return result

    monkeypatch.setattr(os, 'link', link_then_change)
    return published


def test_valid_but_changed_publication_never_adopts_after_restart_or_deletes_rows(service, monkeypatch):
    store = EnrichmentStore(service.store)
    _generations(store, 10)
    before = _rows(service.store.connection)
    snapshot_sha = service.store.connection.execute(V.SNAPSHOT_SHA).fetchone()[0]
    with monkeypatch.context() as changes:
        published = _mutate_after_link(changes)
        assert store.apply_retention(CURRENT, started=FUTURE) == 0
        assert _rows(service.store.connection) == before
        V.forget_all()
        assert V.find_verified_backup(service.root, 'retention', project_id=service.project.id,
                                      snapshot_sha=snapshot_sha, require_tables=('enrichment_entries',)) is None
        assert store.apply_retention(CURRENT, started=FUTURE) == 0
        assert _rows(service.store.connection) == before
    assert len(published) == 2
    for stage, final, data in published:
        assert stage.read_bytes() == final.read_bytes() == data
        assert final not in V._candidates(service.root, 'retention')
    # Once a fresh complete copy can be made, the real public retention operation works.
    assert store.apply_retention(CURRENT, started=FUTURE) == 8
    accepted = V.find_verified_backup(service.root, 'retention', project_id=service.project.id,
                                      require_tables=('enrichment_entries',))
    assert accepted not in {final for _, final, _ in published}
    with sqlite3.connect(accepted) as db:
        assert _rows(db) == before


def test_history_after_reopen_keeps_every_row_when_new_publication_still_fails(service, monkeypatch):
    monkeypatch.setattr(persistence, 'HISTORY_KEEP', 2)
    published = _mutate_after_link(monkeypatch, table='history')
    _save(service, 'first failed prune')
    _save(service, 'same session remains blocked')
    before = _rows(service.store.connection, 'history')
    assert service.store._prune_blocked
    root = service.root
    service.close()
    V.forget_all()
    with ProjectService.open(root) as reopened:
        _save(reopened, 'after restart')
        assert before < _rows(reopened.store.connection, 'history')
        assert reopened.store.load().name == 'after restart'
    assert len(published) == 2
    assert all(stage.read_bytes() == final.read_bytes() == data for stage, final, data in published)


def test_newer_failed_publication_does_not_hide_an_earlier_valid_backup(service, monkeypatch):
    store = EnrichmentStore(service.store)
    _generations(store, 10)
    earlier = V.write_verified_backup(service.root, service.store.connection, 'retention')
    earlier_bytes = earlier.read_bytes()
    published = _mutate_after_link(monkeypatch)
    with pytest.raises(V.BackupError, match='changed during publication'):
        V.write_verified_backup(service.root, service.store.connection, 'retention')
    V.forget_all()
    assert V.find_verified_backup(service.root, 'retention', project_id=service.project.id,
                                  require_tables=('enrichment_entries',)) == earlier
    assert store.apply_retention(CURRENT, started=FUTURE) == 8
    assert earlier.read_bytes() == earlier_bytes
    stage, final, data = published[0]
    assert stage.read_bytes() == final.read_bytes() == data


def test_reader_does_not_admit_a_publication_before_its_final_validation(service, monkeypatch):
    store = EnrichmentStore(service.store)
    _generations(store, 10)
    observations = []

    def observe(stage, final):
        observations.append(V.find_verified_backup(service.root, 'retention', project_id=service.project.id,
                                                    require_tables=('enrichment_entries',)))

    _mutate_after_link(monkeypatch, observe=observe)
    assert store.apply_retention(CURRENT, started=FUTURE) == 0
    assert observations == [None]


@pytest.mark.parametrize('replace_stage', [False, True])
def test_foreign_final_and_stage_replacements_are_preserved_and_not_adopted(service, monkeypatch, replace_stage):
    original = os.link
    replacements = []

    def link_then_replace(stage, final, **kwargs):
        result = original(stage, final, **kwargs)
        final = Path(final)
        before = final.read_bytes()
        final.unlink()
        final.write_bytes(before)
        with sqlite3.connect(final) as db:
            db.execute('DELETE FROM history')
            assert db.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
        if replace_stage:
            Path(stage).unlink()
            Path(stage).write_bytes(b'foreign staging evidence')
        replacements.append((Path(stage), final, final.read_bytes()))
        return result

    monkeypatch.setattr(os, 'link', link_then_replace)
    with pytest.raises(V.BackupError, match='changed during publication'):
        V.write_verified_backup(service.root, service.store.connection, 'history-prune')
    stage, final, replaced_bytes = replacements[0]
    assert final.read_bytes() == replaced_bytes
    assert stage.exists()
    if replace_stage:
        assert stage.read_bytes() == b'foreign staging evidence'
    V.forget_all()
    assert final not in V._candidates(service.root, 'history-prune')
    assert V.find_verified_backup(service.root, 'history-prune', project_id=service.project.id) is None


def test_staging_cleanup_failure_cannot_return_success_or_make_pending_name_eligible(service, monkeypatch):
    original = Path.unlink

    def cannot_remove_stage(path, *args, **kwargs):
        if path.name.endswith('.sqlite3.part'):
            raise PermissionError('retained staging name')
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'unlink', cannot_remove_stage)
    with pytest.raises(V.BackupError):
        V.write_verified_backup(service.root, service.store.connection, 'history-prune')
    final, = (service.root / 'backups').glob('*.sqlite3')
    assert final.is_file()
    V.forget_all()
    assert V.find_verified_backup(service.root, 'history-prune', project_id=service.project.id) is None


def _refuse_stage_cleanup(monkeypatch):
    original = Path.unlink
    refused = []

    def cannot_remove_stage(path, *args, **kwargs):
        if path.name.endswith('.sqlite3.part'):
            refused.append((path, path.read_bytes()))
            raise PermissionError('retained staging name')
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'unlink', cannot_remove_stage)
    return refused


def test_retention_keeps_every_row_until_new_backup_cleanup_completes(service, monkeypatch):
    store = EnrichmentStore(service.store)
    _generations(store, 10)
    before = _rows(service.store.connection)
    with monkeypatch.context() as failure:
        refused = _refuse_stage_cleanup(failure)
        for _ in range(2):
            V.forget_all()
            assert store.apply_retention(CURRENT, started=FUTURE) == 0
            assert _rows(service.store.connection) == before
            assert V.find_verified_backup(service.root, 'retention', project_id=service.project.id) is None
    assert len(refused) == 2
    for stage, data in refused:
        assert stage.read_bytes() == data
    finals = list((service.root / 'backups').glob('project-pre-retention-*.sqlite3'))
    assert len(finals) == 2
    for final in finals:
        with sqlite3.connect(final) as copy:
            assert copy.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
            assert _rows(copy) == before
    assert store.apply_retention(CURRENT, started=FUTURE) == 8
    accepted = V.find_verified_backup(service.root, 'retention', project_id=service.project.id)
    assert accepted not in finals
    assert all(stage.read_bytes() == data for stage, data in refused)


def test_history_cleanup_failure_commits_save_keeps_rows_and_blocks_session(service, monkeypatch):
    monkeypatch.setattr(persistence, 'HISTORY_KEEP', 2)
    refused = _refuse_stage_cleanup(monkeypatch)
    before = _rows(service.store.connection, 'history')
    _save(service, 'cleanup failed')
    assert before < _rows(service.store.connection, 'history')
    assert service.store.load().name == 'cleanup failed'
    assert service.store._prune_blocked
    _save(service, 'same session skips copy')
    assert len(refused) == 1
    root = service.root
    before = _rows(service.store.connection, 'history')
    service.close()
    V.forget_all()
    with ProjectService.open(root) as reopened:
        _save(reopened, 'reopened cleanup failed')
        assert before < _rows(reopened.store.connection, 'history')
        assert reopened.store.load().name == 'reopened cleanup failed'
        assert reopened.store._prune_blocked
    assert len(refused) == 2
    assert all(stage.read_bytes() == data for stage, data in refused)


@pytest.mark.parametrize('replacement_at', ['after_verify', 'after_unlink'])
def test_foreign_stage_replacement_cannot_complete_or_be_removed(service, monkeypatch, replacement_at):
    original_remember = V._remember
    original_unlink = Path.unlink
    observed = []

    def replace(stage, final):
        # The published hard link keeps the original inode alive while replacing the stage.
        original_unlink(stage)
        stage.write_bytes(b'foreign staging evidence')
        observed.append((stage, final, final.read_bytes()))

    def remember_then_replace(path, facts, checked):
        result = original_remember(path, facts, checked)
        if result and replacement_at == 'after_verify':
            stage, = path.parent.glob(path.stem + '-*.sqlite3.part')
            replace(stage, path)
        return result

    def unlink_then_replace(path, *args, **kwargs):
        if path.name.endswith('.sqlite3.part') and replacement_at == 'after_unlink':
            final, = path.parent.glob('*.sqlite3')
            replace(path, final)
            return None
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(V, '_remember', remember_then_replace)
    monkeypatch.setattr(Path, 'unlink', unlink_then_replace)
    with pytest.raises(V.BackupError):
        V.write_verified_backup(service.root, service.store.connection, 'history-prune')
    stage, final, data = observed[0]
    assert stage.read_bytes() == b'foreign staging evidence'
    assert final.read_bytes() == data
    with sqlite3.connect(final) as db:
        assert db.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
        assert _rows(db, 'history') == _rows(service.store.connection, 'history')
    V.forget_all()
    assert V.find_verified_backup(service.root, 'history-prune', project_id=service.project.id) is None


@pytest.mark.parametrize('after_removal', [False, True])
def test_unreadable_stage_identity_cannot_return_success(service, monkeypatch, after_removal):
    original_remember = V._remember
    original_lstat = Path.lstat
    published = []
    stage_reads = 0

    def remember_then_observe(path, facts, checked):
        result = original_remember(path, facts, checked)
        if result:
            stage, = path.parent.glob(path.stem + '-*.sqlite3.part')
            published.append((stage, path, path.read_bytes()))
        return result

    def refuse_stage_identity(path, *args, **kwargs):
        nonlocal stage_reads
        if published and path == published[0][0]:
            stage_reads += 1
            if stage_reads == (2 if after_removal else 1):
                raise PermissionError('staging identity is unreadable')
        return original_lstat(path, *args, **kwargs)

    monkeypatch.setattr(V, '_remember', remember_then_observe)
    monkeypatch.setattr(Path, 'lstat', refuse_stage_identity)
    with pytest.raises(V.BackupError):
        V.write_verified_backup(service.root, service.store.connection, 'history-prune')
    stage, final, data = published[0]
    assert final.read_bytes() == data
    if not after_removal:
        assert stage.read_bytes() == data
        V.forget_all()
        assert V.find_verified_backup(service.root, 'history-prune', project_id=service.project.id) is None
    else:
        assert not stage.exists()


def test_successful_publication_removes_only_its_stage_and_keeps_normal_reuse(service):
    directory = service.root / 'backups'
    directory.mkdir(exist_ok=True)
    unrelated = directory / 'project-pre-history-prune-older-attempt.sqlite3.part'
    unrelated.write_bytes(b'prior interrupted evidence')
    final = V.write_verified_backup(service.root, service.store.connection, 'history-prune')
    assert list(directory.glob('*.part')) == [unrelated]
    assert unrelated.read_bytes() == b'prior interrupted evidence'
    V.forget_all()
    assert V.find_verified_backup(service.root, 'history-prune', project_id=service.project.id) == final
    assert V.trusted_backup(service.root, 'history-prune', project_id=service.project.id) == final


@pytest.mark.parametrize(('failing_scan', 'during_iteration'), [(1, False), (2, False), (2, True)])
def test_directory_read_failure_never_admits_a_failed_sqlite_publication(
    service, monkeypatch, failing_scan, during_iteration,
):
    with monkeypatch.context() as mutation:
        published = _mutate_after_link(mutation, table='history')
        with pytest.raises(V.BackupError, match='changed during publication'):
            V.write_verified_backup(service.root, service.store.connection, 'history-prune')
    stage, final, failed_bytes = published[0]
    assert V._candidates(service.root, 'history-prune') == []
    V.forget_all()
    directory = service.root / 'backups'
    original = os.scandir
    scans = 0

    @contextmanager
    def failed_scan(path):
        nonlocal scans
        if Path(path) == directory:
            scans += 1
        if Path(path) != directory or scans != failing_scan:
            with original(path) as entries:
                yield entries
            return
        if not during_iteration:
            raise PermissionError('directory read refused')
        with original(path) as entries:
            first = next(entry for entry in entries if entry.name == final.name)

        def interrupted():
            yield first
            raise OSError('directory read interrupted before pending stage')
        yield interrupted()

    monkeypatch.setattr(os, 'scandir', failed_scan)
    assert V.find_verified_backup(service.root, 'history-prune', project_id=service.project.id,
                                  require_tables=('history',)) is None
    assert stage.read_bytes() == final.read_bytes() == failed_bytes
