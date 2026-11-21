"""H2: an interrupted save must not leave later edits based on a stale snapshot.

Authored PE bytes are only project inputs; no target binary is executed. The
history limit is reduced to reach the real deferred maintenance boundary.
"""
from __future__ import annotations

import sqlite3

import pytest

from patchtrace import persistence, verified_backup
from patchtrace.models import AnalysisRun
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService


@pytest.fixture
def service(tmp_path):
    older, newer = tmp_path / 'older.bin', tmp_path / 'newer.bin'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    verified_backup.forget_all()
    try:
        with ProjectService.create(older, newer, 'Post-commit fixture', tmp_path / 'case') as svc:
            yield svc
    finally:
        verified_backup.forget_all()


def _notes(project):
    return [annotation.text for annotation in project.annotations]


def _interrupt_first_history_backup(service, monkeypatch, interruption):
    monkeypatch.setattr(persistence, 'HISTORY_KEEP', 1)

    def interrupted_backup(*_args, **_kwargs):
        raise interruption

    with monkeypatch.context() as patch:
        patch.setattr(verified_backup, 'ensure_verified_backup', interrupted_backup)
        with pytest.raises(type(interruption)) as caught:
            service.annotate(service.project.artifacts[0].id, 'first committed note')
    assert caught.value is interruption
    assert not service.store.connection.in_transaction
    committed = service.store.load(recover_interrupted=False)
    assert _notes(committed) == ['first committed note']
    return committed


@pytest.mark.parametrize('failure', [KeyboardInterrupt, SystemExit, RuntimeError])
def test_post_commit_history_failure_preserves_service_snapshot(service, monkeypatch, failure):
    committed = _interrupt_first_history_backup(service, monkeypatch, failure('authored post-commit failure'))
    assert service.project == committed


def test_followup_annotation_retains_prior_committed_note(service, monkeypatch):
    _interrupt_first_history_backup(service, monkeypatch, KeyboardInterrupt('authored cancellation'))
    service.annotate(service.project.artifacts[0].id, 'second note')
    assert _notes(service.project) == ['first committed note', 'second note']
    assert service.project == service.store.load(recover_interrupted=False)


def test_pre_commit_interruption_keeps_previous_memory_and_database(service, monkeypatch):
    before = service.project.model_copy(deep=True)
    history = service.store.history()
    interruption = KeyboardInterrupt('authored pre-commit interruption')

    def interrupted_save(_candidate):
        raise interruption

    with monkeypatch.context() as patch:
        patch.setattr(service.store, 'save', interrupted_save)
        with pytest.raises(KeyboardInterrupt) as caught:
            service.annotate(service.project.artifacts[0].id, 'uncommitted note')
    assert caught.value is interruption
    assert service.project == before == service.store.load(recover_interrupted=False)
    assert service.store.history() == history
    service.annotate(service.project.artifacts[0].id, 'later note')
    assert _notes(service.project) == ['later note']


def test_real_transaction_failure_keeps_prior_snapshot_and_allows_retry(service, monkeypatch):
    before = service.project.model_copy(deep=True)
    history = service.store.history()

    def failed_prune(*_args, **_kwargs):
        raise sqlite3.OperationalError('authored transaction failure')

    with monkeypatch.context() as patch:
        patch.setattr(service.store, '_prune_history', failed_prune)
        with pytest.raises(ValueError, match='prior snapshot retained'):
            service.annotate(service.project.artifacts[0].id, 'rolled back note')
    assert not service.store.connection.in_transaction
    assert service.project == before == service.store.load(recover_interrupted=False)
    assert service.store.history() == history
    service.annotate(service.project.artifacts[0].id, 'retry note')
    assert _notes(service.project) == ['retry note']


def test_reconciliation_does_not_recover_running_jobs_or_save_again(service, monkeypatch):
    running = AnalysisRun(status='running')
    candidate = service.project.model_copy(deep=True)
    candidate.runs.append(running)
    service._commit(candidate)
    history = service.store.history()
    _interrupt_first_history_backup(service, monkeypatch, KeyboardInterrupt('authored cancellation'))
    assert service.project.runs[0].id == running.id
    assert service.project.runs[0].status == 'running'
    assert len(service.store.history()) == len(history) + 1


@pytest.mark.parametrize('read_failure', [ValueError, KeyboardInterrupt])
def test_failed_reconciliation_preserves_original_error_and_refuses_later_edits(
        service, monkeypatch, read_failure):
    monkeypatch.setattr(persistence, 'HISTORY_KEEP', 1)
    interruption = KeyboardInterrupt('authored post-commit interruption')
    load_calls = []

    def interrupted_backup(*_args, **_kwargs):
        raise interruption

    def unreadable_snapshot(*, recover_interrupted=True):
        load_calls.append(recover_interrupted)
        raise read_failure('authored snapshot read failure')

    with monkeypatch.context() as patch:
        patch.setattr(verified_backup, 'ensure_verified_backup', interrupted_backup)
        patch.setattr(service.store, 'load', unreadable_snapshot)
        with pytest.raises(KeyboardInterrupt) as caught:
            service.annotate(service.project.artifacts[0].id, 'first committed note')
    assert caught.value is interruption
    assert load_calls == [False]
    assert any('reopen' in note.lower() for note in interruption.__notes__)
    committed = service.store.load(recover_interrupted=False)
    history = service.store.history()
    assert _notes(committed) == ['first committed note']
    assert not service.store.closed
    with pytest.raises(ValueError, match='PT-STORAGE:.*reopen'):
        service.annotate(service.project.artifacts[0].id, 'must not overwrite the committed note')
    assert service.store.load(recover_interrupted=False) == committed
    assert service.store.history() == history
    service.close()
    with ProjectService.open(service.root, maintenance=False) as reopened:
        reopened.annotate(reopened.project.artifacts[0].id, 'note after reopening')
        assert _notes(reopened.project) == ['first committed note', 'note after reopening']
