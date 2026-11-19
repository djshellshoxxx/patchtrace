"""Explicit retry reuses current store/ingestion invariants and preserves prior bytes."""
from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from patchtrace.ingestion import inspect_artifact
from patchtrace.input_readers import InputReadError
from patchtrace.persistence import (
    MAX_RETRY_DATABASE_BYTES,
    ProjectLock,
    ProjectStore,
    _clear_readonly_and_retry,
)
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService


def partial(tmp_path, database='current', artifacts=1):
    pair = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    for path, version in zip(pair, (0, 1), strict=True):
        path.write_bytes(synthetic_pe(version))
    root = tmp_path / 'project'
    with ProjectStore(root, create=True):
        pass
    if database == 'absent':
        (root / 'project.sqlite3').unlink()
    elif database == 'zero':
        (root / 'project.sqlite3').write_bytes(b'')
    for path, side in zip(pair[:artifacts], ('older', 'newer'), strict=False):
        inspect_artifact(path, side, root)
    return pair, root


def contents(root):
    if not root.exists():
        return None
    return {path.relative_to(root).as_posix(): ('link', str(path.readlink())) if path.is_symlink()
            else ('directory', path.stat().st_ino) if path.is_dir()
            else ('file', path.read_bytes(), path.stat().st_mode, path.stat().st_ino)
            for path in root.rglob('*')}


@pytest.mark.parametrize('database', ['absent', 'zero', 'current'])
@pytest.mark.parametrize('artifacts', [0, 1, 2])
def test_real_retry_reuses_present_inodes_and_reopens(tmp_path, database, artifacts):
    pair, root = partial(tmp_path, database, artifacts)
    before = contents(root)
    with ProjectService.retry_create(*pair, 'Recovered', root) as service:
        assert service.project.name == 'Recovered'
        assert [item.name for item in service.project.artifacts] == ['older.dll', 'newer.dll']
        identifier = service.project.id
    assert contents(root)['.patchtrace.lock'] == before['.patchtrace.lock']
    for name, old in before.items():
        if name.startswith('artifacts/'):
            assert contents(root)[name] == old
    if database != 'absent':
        assert (root / 'project.sqlite3').stat().st_ino == before['project.sqlite3'][3]
    with ProjectService.open(root) as reopened:
        assert reopened.project.id == identifier and reopened.project.name == 'Recovered'


@pytest.mark.parametrize('invalid', ['unknown', 'hidden', 'journal', 'foreign-table', 'foreign-view',
                                    'schema', 'snapshot', 'history', 'sequence', 'version', 'corrupt',
                                    'oversize', 'artifact-name', 'artifact-bytes', 'artifact-size'])
def test_refused_retry_preserves_all_destination_bytes_and_modes(tmp_path, invalid):
    pair, root = partial(tmp_path)
    database = root / 'project.sqlite3'
    if invalid in {'unknown', 'hidden', 'journal'}:
        names = {'unknown': 'notes.txt', 'hidden': '.operator', 'journal': 'project.sqlite3-journal'}
        (root / names[invalid]).write_bytes(b'preserved independent data')
    elif invalid in {'foreign-table', 'foreign-view', 'schema', 'snapshot', 'history', 'sequence', 'version'}:
        statement = {'foreign-table': 'CREATE TABLE notes(value TEXT)',
                     'foreign-view': 'CREATE VIEW note AS SELECT 1',
                     'schema': 'ALTER TABLE history ADD COLUMN note TEXT',
                     'snapshot': "INSERT INTO current_snapshot VALUES(1,'retained','retained')",
                     'history': "INSERT INTO history(revision,created,payload,sha256) VALUES(0,'x','x','x')",
                     'sequence': "INSERT INTO sqlite_sequence VALUES('history',1)",
                     'version': 'PRAGMA user_version=99'}[invalid]
        with sqlite3.connect(database) as connection:
            connection.execute(statement)
    elif invalid in {'corrupt', 'oversize'}:
        database.write_bytes(b'not sqlite' if invalid == 'corrupt' else b'x' * (MAX_RETRY_DATABASE_BYTES + 1))
    else:
        path = next((root / 'artifacts').iterdir())
        path.chmod(0o600)
        if invalid == 'artifact-name':
            path.rename(path.with_name('foreign.bin'))
        elif invalid == 'artifact-bytes':
            path.write_bytes(b'x' * path.stat().st_size)
        else:
            path.write_bytes(b'short')
    before = contents(root)
    with pytest.raises((ValueError, OSError)):
        ProjectService.retry_create(*pair, 'refused', root)
    assert contents(root) == before
    acquired = ProjectLock(root, _preserve_existing=True)
    acquired.close()
    assert contents(root) == before


@pytest.mark.parametrize('kind', ['absent', 'empty', 'missing-lock', 'short-lock'])
def test_retry_does_not_create_an_unrecognized_destination(tmp_path, kind):
    pair, valid = partial(tmp_path)
    root = tmp_path / 'unrecognized'
    if kind != 'absent':
        root.mkdir()
    if kind == 'missing-lock':
        (root / 'project.sqlite3').write_bytes((valid / 'project.sqlite3').read_bytes())
    elif kind == 'short-lock':
        (root / '.patchtrace.lock').write_bytes(b'retained short lock')
    before = contents(root)
    with pytest.raises((ValueError, OSError)):
        ProjectService.retry_create(*pair, 'refused', root)
    assert contents(root) == before


@pytest.mark.parametrize('kind', ['ancestor-link', 'link-dotdot', 'artifact-link', 'artifact-hardlink',
                                 'database-hardlink', 'lock-hardlink', 'reparse-dotdot'])
def test_retry_refuses_linked_lexical_paths_without_changes(tmp_path, monkeypatch, kind):
    pair, root = partial(tmp_path)
    requested = root
    try:
        if kind in {'ancestor-link', 'link-dotdot', 'reparse-dotdot'}:
            component = tmp_path / 'linked'
            if kind == 'reparse-dotdot':
                component.mkdir()
                real_lstat = Path.lstat

                def reparse(path, *args, **kwargs):
                    info = real_lstat(path, *args, **kwargs)
                    if path == component:
                        return SimpleNamespace(st_mode=info.st_mode, st_dev=info.st_dev, st_ino=info.st_ino,
                                               st_file_attributes=0x400)
                    return info

                monkeypatch.setattr(Path, 'lstat', reparse)
            else:
                component.symlink_to(tmp_path, target_is_directory=True)
            requested = component / root.name if kind == 'ancestor-link' else component / '..' / root.name
        else:
            paths = {'database-hardlink': root / 'project.sqlite3', 'lock-hardlink': root / '.patchtrace.lock'}
            path = paths.get(kind) or next((root / 'artifacts').iterdir())
            alias = tmp_path / 'alias'
            if kind == 'artifact-link':
                path.rename(alias)
                path.symlink_to(alias)
            else:
                os.link(path, alias)
    except (OSError, NotImplementedError):
        pytest.skip('filesystem does not provide the requested link operation')
    before = contents(root)
    with pytest.raises((ValueError, OSError)):
        ProjectService.retry_create(*pair, 'refused', requested)
    assert contents(root) == before


def test_identical_inputs_share_one_exact_retained_artifact(tmp_path):
    pair, root = partial(tmp_path)
    with ProjectService.retry_create(pair[0], pair[0], 'identical', root) as service:
        assert service.project.runs[0].status == 'identical'
        assert len(list((root / 'artifacts').iterdir())) == 1


def test_ordinary_dotdot_components_are_allowed_after_lexical_checks(tmp_path):
    pair, root = partial(tmp_path)
    ordinary = tmp_path / 'ordinary'
    ordinary.mkdir()
    with ProjectService.retry_create(*pair, 'ordinary parent', ordinary / '..' / root.name) as service:
        assert service.root == root


def test_cancel_before_preparation_preserves_exact_primary_and_destination(tmp_path):
    pair, root = partial(tmp_path)
    before, primary = contents(root), InputReadError('cancelled')

    def stop(_count):
        raise primary

    with pytest.raises(InputReadError) as caught:
        ProjectService.retry_create(*pair, 'cancelled', root, checkpoint=stop)
    assert caught.value is primary and contents(root) == before


@pytest.mark.parametrize('phase', ['retained-validation', 'new-publication', 'precommit'])
def test_cancel_during_real_destination_work_restores_prior_layout(tmp_path, monkeypatch, phase):
    from patchtrace import project_retry as module

    pair, root = partial(tmp_path, database='zero')
    before, primary = contents(root), InputReadError('cancelled')
    verify, inspect, initialize = module.verify_artifact, module.inspect_artifact, ProjectStore.__init__
    target_statements = []

    def verified(artifact, folder, **kwargs):
        result = verify(artifact, folder, **kwargs)
        if Path(folder) == root and phase == 'retained-validation':
            raise primary
        return result

    def inspected(path, side, folder, **kwargs):
        result = inspect(path, side, folder, **kwargs)
        if Path(folder) == root and phase == 'new-publication' and side == 'newer':
            raise primary
        return result

    def initialized(store, *args, **kwargs):
        initialize(store, *args, **kwargs)
        if store.root == root:
            store.connection.set_trace_callback(target_statements.append)

    def checkpoint(_count):
        if phase == 'precommit' and any(sql.startswith('INSERT INTO current_snapshot') for sql in target_statements):
            raise primary

    monkeypatch.setattr(module, 'verify_artifact', verified)
    monkeypatch.setattr(module, 'inspect_artifact', inspected)
    monkeypatch.setattr(ProjectStore, '__init__', initialized)
    with pytest.raises(InputReadError) as caught:
        ProjectService.retry_create(*pair, 'cancelled', root, checkpoint=checkpoint)
    assert caught.value is primary and contents(root) == before
    acquired = ProjectLock(root, _preserve_existing=True)
    acquired.close()


def test_live_destination_writer_refuses_retry_without_rewriting_lock(tmp_path):
    pair, root = partial(tmp_path)
    held = ProjectLock(root)
    before = contents(root)
    try:
        with pytest.raises(ValueError, match='locked'):
            ProjectService.retry_create(*pair, 'busy', root)
        assert contents(root) == before
    finally:
        held.close()


def test_retry_rechecks_layout_under_the_same_lock_before_database_admission(tmp_path, monkeypatch):
    from patchtrace import project_retry as module

    pair, root = partial(tmp_path)
    before = contents(root)
    validate = module.validate_retry
    observations = []

    def changed(*args, **kwargs):
        with pytest.raises(ValueError, match='locked'):
            ProjectLock(root, _preserve_existing=True)
        recheck = validate(*args, **kwargs)
        (root / 'contributor.txt').write_bytes(b'concurrent contributor data')

        def check():
            with pytest.raises(ValueError, match='locked'):
                ProjectLock(root, _preserve_existing=True)
            observations.append(True)
            return recheck()

        return check

    monkeypatch.setattr(module, 'validate_retry', changed)
    with pytest.raises(ValueError, match='entries'):
        ProjectService.retry_create(*pair, 'changed layout', root)
    after = contents(root)
    assert after.pop('contributor.txt')[1] == b'concurrent contributor data'
    assert after == before and observations == [True]


def test_retry_rejects_first_unknown_entry_without_consuming_an_unbounded_iterator(tmp_path, monkeypatch):
    from patchtrace import project_retry as module

    pair, root = partial(tmp_path)
    before, real_scandir = contents(root), os.scandir

    class Entries:
        def __enter__(self):
            yield SimpleNamespace(name='foreign')
            raise AssertionError('retry consumed entries after its first unknown file')

        def __exit__(self, *_):
            return False

    def scandir(path):
        return Entries() if Path(path) == root else real_scandir(path)

    with monkeypatch.context() as scoped:
        scoped.setattr(module.os, 'scandir', scandir)
        with pytest.raises(ValueError, match='entries'):
            ProjectService.retry_create(*pair, 'bounded refusal', root)
    assert contents(root) == before


def test_different_selected_input_does_not_adopt_retained_artifact(tmp_path):
    pair, root = partial(tmp_path)
    pair[0].write_bytes(synthetic_pe(2))
    before = contents(root)
    with pytest.raises(ValueError, match='selected inputs'):
        ProjectService.retry_create(*pair, 'different selection', root)
    assert contents(root) == before


def test_no_checkpoint_after_successful_destination_commit(tmp_path, monkeypatch):
    pair, root = partial(tmp_path)
    save, completed, counts = ProjectStore.save, [], []

    def committed(store, project, **kwargs):
        result = save(store, project, **kwargs)
        if store.root == root:
            completed.append(result.id)
        return result

    def checkpoint(count):
        assert not completed, 'retry checkpoint ran after successful destination save'
        counts.append(count)

    monkeypatch.setattr(ProjectStore, 'save', committed)
    with ProjectService.retry_create(*pair, 'completed', root, checkpoint=checkpoint) as service:
        assert completed == [service.project.id]
    assert any(count > 0 for count in counts)
    expected = hashlib.sha256(pair[0].read_bytes()).hexdigest()
    assert (root / 'artifacts' / f'{expected}.bin').is_file()


@pytest.mark.parametrize('ambient', [False, True])
def test_private_cleanup_failure_precedes_destination_commit_and_is_observable(tmp_path, monkeypatch, ambient):
    pair, root = partial(tmp_path)
    before, cleaned = contents(root), []
    cleanup = tempfile.TemporaryDirectory.cleanup
    secondary = OSError('private cleanup failed after removing the owned stage')

    def failed(temporary):
        cleanup(temporary)
        if Path(temporary.name).name.startswith('patchtrace-retry-'):
            cleaned.append(Path(temporary.name))
            raise secondary

    monkeypatch.setattr(tempfile.TemporaryDirectory, 'cleanup', failed)

    def attempt():
        with pytest.raises(OSError) as caught:
            ProjectService.retry_create(*pair, 'cleanup refused', root)
        assert caught.value is secondary

    if ambient:
        try:
            raise RuntimeError('unrelated handled caller exception')
        except RuntimeError:
            attempt()
    else:
        attempt()
    assert contents(root) == before and cleaned and not any(path.exists() for path in cleaned)


def test_secondary_private_cleanup_interruption_does_not_replace_active_cancellation(tmp_path, monkeypatch):
    from patchtrace import project_retry as module

    pair, root = partial(tmp_path)
    before, primary = contents(root), InputReadError('cancelled')
    cleanup, inspect = tempfile.TemporaryDirectory.cleanup, module.inspect_artifact

    def interrupted(temporary):
        cleanup(temporary)
        if Path(temporary.name).name.startswith('patchtrace-retry-'):
            raise KeyboardInterrupt('secondary private cleanup interruption')

    def inspected(path, side, folder, **kwargs):
        result = inspect(path, side, folder, **kwargs)
        if Path(folder) == root and side == 'newer':
            raise primary
        return result

    monkeypatch.setattr(tempfile.TemporaryDirectory, 'cleanup', interrupted)
    monkeypatch.setattr(module, 'inspect_artifact', inspected)
    with pytest.raises(InputReadError) as caught:
        ProjectService.retry_create(*pair, 'cancelled', root)
    assert caught.value is primary and contents(root) == before
    assert any('private staging cleanup failed' in note for note in primary.__notes__)


def test_changed_private_input_is_refused_and_only_new_publications_are_removed(tmp_path, monkeypatch):
    from patchtrace import project_retry as module

    pair, root = partial(tmp_path)
    before, inspect = contents(root), module.inspect_artifact

    def changed(path, side, folder, **kwargs):
        if Path(folder) == root and side == 'newer':
            Path(path).chmod(0o600)
            Path(path).write_bytes(synthetic_pe(3))
        return inspect(path, side, folder, **kwargs)

    monkeypatch.setattr(module, 'inspect_artifact', changed)
    with pytest.raises(ValueError, match='staged input changed'):
        ProjectService.retry_create(*pair, 'staged change', root)
    assert contents(root) == before


def test_failed_receipt_after_destination_commit_retains_a_reopenable_project(tmp_path, monkeypatch):
    pair, root = partial(tmp_path)
    save, primary = ProjectStore.save, RuntimeError('failure after actual destination COMMIT')

    def committed(store, project, **kwargs):
        result = save(store, project, **kwargs)
        if store.root == root:
            raise primary
        return result

    monkeypatch.setattr(ProjectStore, 'save', committed)
    with pytest.raises(RuntimeError) as caught:
        ProjectService.retry_create(*pair, 'committed retry', root)
    assert caught.value is primary
    with ProjectService.open(root) as reopened:
        assert reopened.project.name == 'committed retry'


def test_invalid_checkpoint_is_refused_before_destination_work(tmp_path):
    pair, root = partial(tmp_path)
    before = contents(root)
    with pytest.raises(InputReadError) as caught:
        ProjectService.retry_create(*pair, 'invalid policy', root, checkpoint=False)
    assert caught.value.reason == 'invalid' and contents(root) == before


def test_growing_retained_file_cannot_drive_unbounded_default_verification(tmp_path, monkeypatch):
    pair, root = partial(tmp_path)
    retained = next((root / 'artifacts').iterdir())
    retained.chmod(0o600)
    real_open, reads = Path.open, []
    original_database = (root / 'project.sqlite3').read_bytes()
    original_lock = (root / '.patchtrace.lock').read_bytes()

    class Growing:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def fileno(self):
            return self.stream.fileno()

        def read(self, size):
            reads.append(size)
            if len(reads) > 3:
                raise AssertionError('retry kept consuming a growing file past its selected-input bound')
            with real_open(retained, 'ab') as writer:
                writer.write(b'x' * (1024 * 1024))
            return self.stream.read(size)

    def opened(path, *args, **kwargs):
        stream = real_open(path, *args, **kwargs)
        return Growing(stream) if path == retained and args and args[0] == 'rb' else stream

    monkeypatch.setattr(Path, 'open', opened)
    with pytest.raises(InputReadError) as caught:
        ProjectService.retry_create(*pair, 'growing artifact', root)
    assert caught.value.reason == 'limited' and len(reads) == 1
    assert (root / 'project.sqlite3').read_bytes() == original_database
    assert (root / '.patchtrace.lock').read_bytes() == original_lock


@pytest.mark.parametrize('cancelled', [False, True])
def test_private_stage_replaced_before_cleanup_is_retained_and_never_finalized(tmp_path, monkeypatch, cancelled):
    import gc

    from patchtrace import project_retry as module

    pair, root = partial(tmp_path)
    before, inspect, stages = contents(root), module.inspect_artifact, []
    primary = InputReadError('cancelled')
    foreign = b'authored replacement owned by another writer'

    def substitute(path, side, folder, **kwargs):
        result = inspect(path, side, folder, **kwargs)
        if Path(folder) == root and side == 'newer':
            temporary = Path(path).parents[2]
            displaced = temporary.with_name(temporary.name + '-displaced')
            temporary.rename(displaced)
            temporary.mkdir()
            (temporary / 'foreign-proof.txt').write_bytes(foreign)
            stages.extend((temporary, displaced))
            if cancelled:
                raise primary
        return result

    monkeypatch.setattr(module, 'inspect_artifact', substitute)
    try:
        with pytest.raises(InputReadError if cancelled else ValueError) as caught:
            with ProjectService.retry_create(*pair, 'substituted private stage', root):
                pass
        if cancelled:
            assert caught.value is primary and primary.__notes__
        else:
            assert 'private staging ownership changed' in str(caught.value)
        gc.collect()  # No delayed TemporaryDirectory finalizer may delete the replacement either.
        assert (stages[0] / 'foreign-proof.txt').read_bytes() == foreign
        assert (stages[1] / 'project' / 'project.sqlite3').is_file()
        assert contents(root) == before
        acquired = ProjectLock(root, _preserve_existing=True)
        acquired.close()
    finally:
        for owned_test_path in stages:
            if owned_test_path.exists():
                shutil.rmtree(owned_test_path, onexc=_clear_readonly_and_retry)
