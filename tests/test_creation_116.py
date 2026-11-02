"""Creation staging and identity-owned failed-publication controls for #116."""
from __future__ import annotations

import pytest
from PySide6.QtWidgets import QDialog

from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService
from patchtrace.ui import NewProjectDialog


@pytest.mark.parametrize('invalid_side', ['older', 'newer'])
def test_failed_creation_allows_corrected_gui_retry(qtbot, tmp_path, invalid_side):
    older, newer = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    {'older': older, 'newer': newer}[invalid_side].write_bytes(b'malformed PE input')
    root = tmp_path / 'project'
    with pytest.raises(ValueError, match='PT-INPUT'):
        ProjectService.create(older, newer, 'Failed attempt', root)
    leftovers = sorted(str(path.relative_to(root)) for path in root.rglob('*')) if root.exists() else []
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    dialog = NewProjectDialog()
    qtbot.addWidget(dialog)
    dialog.name.setText('Retry')
    dialog.older.setText(str(older))
    dialog.newer.setText(str(newer))
    dialog.root.setText(str(root))
    dialog.accept()
    print({'invalid_side': invalid_side, 'leftovers': leftovers, 'wizard_error': dialog.error.text()})
    assert dialog.result() == QDialog.DialogCode.Accepted




def valid_pair(tmp_path):
    older, newer = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    return older, newer


@pytest.mark.parametrize('existing', [False, True])
@pytest.mark.parametrize('failure', ['older-copy', 'newer-copy', 'snapshot'])
def test_private_failure_never_mutates_destination(tmp_path, monkeypatch, existing, failure):
    from patchtrace import service
    from patchtrace.persistence import ProjectStore

    pair = valid_pair(tmp_path)
    root = tmp_path / 'project'
    if existing:
        root.mkdir()
    before = root.stat() if existing else None
    stages = []
    inspect = service.inspect_artifact
    save = ProjectStore.save

    def fail_copy(path, side, stage):
        stages.append(stage)
        artifact = inspect(path, side, stage)
        if failure == f'{side}-copy':
            raise OSError('constructed staging copy failure')
        return artifact

    def fail_snapshot(store, project):
        if failure == 'snapshot':
            stages.append(store.root)
            raise ValueError('constructed initial snapshot failure')
        return save(store, project)

    monkeypatch.setattr(service, 'inspect_artifact', fail_copy)
    monkeypatch.setattr(ProjectStore, 'save', fail_snapshot)
    with pytest.raises((OSError, ValueError), match='constructed'):
        ProjectService.create(*pair, 'Failed attempt', root)
    assert all(not path.exists() for path in stages)
    assert root.exists() == existing
    if existing:
        assert (root.stat().st_dev, root.stat().st_ino) == (before.st_dev, before.st_ino)
        assert list(root.iterdir()) == []
    assert pair[0].read_bytes() == synthetic_pe(0)
    assert pair[1].read_bytes() == synthetic_pe(1)


def fail_newer_publication(monkeypatch, callback=None):
    from patchtrace import project_creation

    original = project_creation.CreationPublication._publish_artifact
    def publish(publication, stage, artifact):
        if artifact.side == 'newer':
            if callback:
                callback(publication.root)
            raise OSError('constructed publication failure')
        return original(publication, stage, artifact)
    monkeypatch.setattr(project_creation.CreationPublication, '_publish_artifact', publish)


def test_publication_cleanup_holds_lock_and_preserves_foreign_entries(tmp_path, monkeypatch):
    import hashlib
    from pathlib import Path

    from patchtrace.persistence import ProjectLock

    pair = valid_pair(tmp_path)
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'user-note.txt').write_text('preserve user data')
    artifact = root / 'artifacts' / (hashlib.sha256(pair[0].read_bytes()).hexdigest() + '.bin')
    fail_newer_publication(monkeypatch)
    unlink = Path.unlink
    checked = []
    def observe_unlink(path, *args, **kwargs):
        if path == artifact:
            with pytest.raises(ValueError, match='locked'):
                ProjectLock(root)
            checked.append(path)
        return unlink(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'unlink', observe_unlink)
    with pytest.raises(OSError, match='publication failure'):
        ProjectService.create(*pair, 'Failed attempt', root)
    assert checked == [artifact]
    assert sorted(path.name for path in root.iterdir()) == ['.patchtrace.lock', 'user-note.txt']
    assert (root / 'user-note.txt').read_text() == 'preserve user data'
    released = ProjectLock(root)
    released.close()


def test_preexisting_artifact_is_not_removed_on_later_failure(tmp_path, monkeypatch):
    import hashlib

    pair = valid_pair(tmp_path)
    root = tmp_path / 'project'
    (root / 'artifacts').mkdir(parents=True)
    artifact = root / 'artifacts' / (hashlib.sha256(pair[0].read_bytes()).hexdigest() + '.bin')
    artifact.write_bytes(pair[0].read_bytes())
    before = artifact.stat()
    fail_newer_publication(monkeypatch)
    with pytest.raises(OSError, match='publication failure'):
        ProjectService.create(*pair, 'Failed attempt', root)
    assert artifact.read_bytes() == pair[0].read_bytes()
    assert (artifact.stat().st_dev, artifact.stat().st_ino) == (before.st_dev, before.st_ino)


def test_replaced_root_is_never_cleaned(tmp_path, monkeypatch):
    pair = valid_pair(tmp_path)
    root = tmp_path / 'project'
    displaced = tmp_path / 'original-attempt'
    def replace_root(folder):
        try:
            folder.rename(displaced)
        except PermissionError:
            pytest.skip('platform refuses renaming open project roots; injected identity control remains mandatory')
        folder.mkdir()
        (folder / 'user-data.txt').write_text('foreign replacement')
    fail_newer_publication(monkeypatch, replace_root)
    with pytest.raises(OSError, match='publication failure'):
        ProjectService.create(*pair, 'Failed attempt', root)
    assert [path.name for path in root.iterdir()] == ['user-data.txt']
    assert (root / 'user-data.txt').read_text() == 'foreign replacement'
    assert (displaced / 'project.sqlite3').exists()
    assert len(list((displaced / 'artifacts').glob('*.bin'))) == 1


def test_replaced_artifact_is_never_cleaned(tmp_path, monkeypatch):
    import hashlib
    import stat

    pair = valid_pair(tmp_path)
    root = tmp_path / 'project'
    artifact = root / 'artifacts' / (hashlib.sha256(pair[0].read_bytes()).hexdigest() + '.bin')
    def replace_artifact(folder):
        artifact.chmod(stat.S_IRUSR | stat.S_IWUSR)
        artifact.unlink()
        artifact.write_bytes(b'foreign replacement data')
    fail_newer_publication(monkeypatch, replace_artifact)
    with pytest.raises(OSError, match='publication failure'):
        ProjectService.create(*pair, 'Failed attempt', root)
    assert artifact.read_bytes() == b'foreign replacement data'


def test_failure_after_first_commit_retains_reopenable_project(tmp_path, monkeypatch):
    from patchtrace.persistence import ProjectStore

    pair = valid_pair(tmp_path)
    root = tmp_path / 'project'
    original = ProjectStore.save
    def late_failure(store, project):
        saved = original(store, project)
        if store.root == root:
            raise RuntimeError('constructed after-commit failure')
        return saved
    monkeypatch.setattr(ProjectStore, 'save', late_failure)
    with pytest.raises(RuntimeError, match='after-commit'):
        ProjectService.create(*pair, 'Committed project', root)
    with ProjectService.open(root) as reopened:
        assert reopened.project.name == 'Committed project'
        assert len(reopened.project.artifacts) == 2


@pytest.mark.parametrize('changed_path', ['root', 'lock'])
def test_changed_identity_preserves_attempt_without_native_rename(tmp_path, monkeypatch, changed_path):
    from patchtrace import project_creation

    pair = valid_pair(tmp_path)
    root = tmp_path / 'project'
    original = project_creation._identity
    changed = False
    def identity(path, *, directory=False):
        found = original(path, directory=directory)
        selected = root if changed_path == 'root' else root / '.patchtrace.lock'
        if changed and path == selected:
            return found[0], found[1] + 1
        return found
    def change_identity(folder):
        nonlocal changed
        changed = True
    monkeypatch.setattr(project_creation, '_identity', identity)
    fail_newer_publication(monkeypatch, change_identity)
    with pytest.raises(OSError, match='publication failure'):
        ProjectService.create(*pair, 'Failed attempt', root)
    assert (root / 'project.sqlite3').exists()
    assert len(list((root / 'artifacts').glob('*.bin'))) == 1


def test_private_cleanup_failure_releases_published_project_lock(tmp_path, monkeypatch):
    import tempfile

    pair = valid_pair(tmp_path)
    root = tmp_path / 'project'
    original = tempfile.TemporaryDirectory.cleanup
    def cleanup(stage):
        original(stage)
        raise OSError('constructed private cleanup failure')
    monkeypatch.setattr(tempfile.TemporaryDirectory, 'cleanup', cleanup)
    with pytest.raises(OSError, match='private cleanup'):
        ProjectService.create(*pair, 'Retained project', root)
    with ProjectService.open(root) as reopened:
        assert reopened.project.name == 'Retained project'


def test_publication_collision_never_overwrites_a_new_foreign_file(tmp_path, monkeypatch):
    import hashlib
    import os
    from pathlib import Path

    pair = valid_pair(tmp_path)
    root = tmp_path / 'project'
    target = root / 'artifacts' / (hashlib.sha256(pair[0].read_bytes()).hexdigest() + '.bin')
    foreign = b'foreign file appeared at publication'
    real_open, real_replace = os.open, os.replace
    def collided_open(path, flags, *args, **kwargs):
        if Path(path) == target and flags & os.O_EXCL:
            target.write_bytes(foreign)
        return real_open(path, flags, *args, **kwargs)
    def collided_replace(source, destination, *args, **kwargs):
        if Path(destination) == target:
            target.write_bytes(foreign)
        return real_replace(source, destination, *args, **kwargs)
    monkeypatch.setattr(os, 'open', collided_open)
    monkeypatch.setattr(os, 'replace', collided_replace)
    with pytest.raises((ValueError, OSError)):
        ProjectService.create(*pair, 'Collision', root)
    assert target.read_bytes() == foreign
    assert not (root / 'project.sqlite3').exists()


def test_cleanup_failure_releases_lock_and_allows_validated_service_retry(tmp_path, monkeypatch):
    import hashlib
    from pathlib import Path

    pair = valid_pair(tmp_path)
    root = tmp_path / 'project'
    target = root / 'artifacts' / (hashlib.sha256(pair[0].read_bytes()).hexdigest() + '.bin')
    real_unlink = Path.unlink
    with monkeypatch.context() as fault:
        fail_newer_publication(fault)
        def refuse_unlink(path, *args, **kwargs):
            if path == target:
                raise PermissionError('constructed cleanup failure')
            return real_unlink(path, *args, **kwargs)
        fault.setattr(Path, 'unlink', refuse_unlink)
        with pytest.raises(OSError, match='publication failure'):
            ProjectService.create(*pair, 'Failed attempt', root)
    assert target.read_bytes() == pair[0].read_bytes()
    with ProjectService.create(*pair, 'Retried project', root) as retried:
        assert retried.project.name == 'Retried project'


def test_private_interruption_never_opens_destination(tmp_path, monkeypatch):
    from patchtrace import service

    pair = valid_pair(tmp_path)
    root = tmp_path / 'project'
    stages = []
    real_inspect = service.inspect_artifact
    def interrupt(path, side, stage):
        stages.append(stage)
        real_inspect(path, side, stage)
        raise KeyboardInterrupt('constructed interruption')
    monkeypatch.setattr(service, 'inspect_artifact', interrupt)
    with pytest.raises(KeyboardInterrupt, match='constructed'):
        ProjectService.create(*pair, 'Interrupted', root)
    assert not root.exists()
    assert all(not stage.exists() for stage in stages)


def test_incomplete_unverified_publication_is_preserved_and_unlocked(tmp_path, monkeypatch):
    import stat

    from patchtrace.project_creation import CreationPublication

    pair = valid_pair(tmp_path)
    root = tmp_path / 'project'
    original = CreationPublication._publish_artifact
    def changed_stage(publication, stage, artifact):
        source = stage / artifact.relative_path
        source.chmod(stat.S_IRUSR | stat.S_IWUSR)
        source.write_bytes(b'changed stage')
        return original(publication, stage, artifact)
    monkeypatch.setattr(CreationPublication, '_publish_artifact', changed_stage)
    with pytest.raises(OSError, match='staged artifact changed'):
        ProjectService.create(*pair, 'Changed stage', root)
    files = list((root / 'artifacts').iterdir())
    assert len(files) == 1 and files[0].read_bytes() == b'changed stage'
    assert not (root / 'project.sqlite3').exists()
    from patchtrace.persistence import ProjectLock
    lock = ProjectLock(root)
    lock.close()


def fail_destination_initialization(monkeypatch, root, *, after_close=None, interrupted=False):
    import sqlite3
    from pathlib import Path

    real_connect = sqlite3.connect
    class FailingInitialization(sqlite3.Connection):
        failed = False
        def execute(self, sql, *args, **kwargs):
            if sql.startswith('CREATE TABLE history'):
                self.failed = True
                if interrupted:
                    raise KeyboardInterrupt('constructed initialization interruption')
                raise sqlite3.OperationalError('constructed initialization failure')
            return super().execute(sql, *args, **kwargs)
        def close(self):
            super().close()
            if self.failed and after_close:
                self.failed = False
                after_close()
    def connect(database, *args, **kwargs):
        if Path(database) == root / 'project.sqlite3':
            kwargs['factory'] = FailingInitialization
        return real_connect(database, *args, **kwargs)
    monkeypatch.setattr(sqlite3, 'connect', connect)


@pytest.mark.parametrize('interrupted', [False, True])
def test_destination_initialization_cleanup_holds_lock(tmp_path, monkeypatch, interrupted):
    from pathlib import Path

    from patchtrace.persistence import ProjectLock

    pair, root = valid_pair(tmp_path), tmp_path / 'project'
    fail_destination_initialization(monkeypatch, root, interrupted=interrupted)
    original, locked = Path.unlink, []
    def observe(path, *args, **kwargs):
        if path == root / 'project.sqlite3':
            try:
                competing = ProjectLock(root)
            except ValueError:
                locked.append(True)
            else:
                competing.close()
                locked.append(False)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'unlink', observe)
    with pytest.raises(KeyboardInterrupt if interrupted else ValueError):
        ProjectService.create(*pair, 'Initialization failure', root)
    assert locked == [True]
    assert not (root / 'project.sqlite3').exists()
    available = ProjectLock(root)
    available.close()


@pytest.mark.parametrize('replaced', ['database', 'root'])
def test_destination_initialization_preserves_replaced_paths(tmp_path, monkeypatch, replaced):
    pair, root = valid_pair(tmp_path), tmp_path / 'project'
    database = root / 'project.sqlite3'
    def replace_after_close():
        if replaced == 'database':
            database.rename(root / 'original.sqlite3')
        else:
            try:
                root.rename(tmp_path / 'displaced')
            except PermissionError:
                pytest.skip('platform refuses renaming open project root; identity controls remain mandatory')
            root.mkdir()
        database.write_bytes(b'foreign replacement')
    fail_destination_initialization(monkeypatch, root, after_close=replace_after_close)
    with pytest.raises(ValueError, match='PT-STORAGE'):
        ProjectService.create(*pair, 'Initialization failure', root)
    assert database.read_bytes() == b'foreign replacement'


def test_destination_initialization_cleanup_failure_releases_lock(tmp_path, monkeypatch):
    from pathlib import Path

    from patchtrace.persistence import ProjectLock

    pair, root = valid_pair(tmp_path), tmp_path / 'project'
    fail_destination_initialization(monkeypatch, root)
    original = Path.unlink
    def refuse(path, *args, **kwargs):
        if path == root / 'project.sqlite3':
            raise PermissionError('constructed constructor cleanup failure')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'unlink', refuse)
    with pytest.raises(ValueError, match='PT-STORAGE'):
        ProjectService.create(*pair, 'Initialization failure', root)
    available = ProjectLock(root)
    available.close()
    assert (root / 'project.sqlite3').exists()


@pytest.mark.parametrize('content', ['snapshot', 'history', 'foreign'])
def test_destination_initialization_keeps_new_database_content(tmp_path, monkeypatch, content):
    import sqlite3

    pair, root = valid_pair(tmp_path), tmp_path / 'project'
    real_connect = sqlite3.connect
    def populate_after_close():
        with real_connect(root / 'project.sqlite3') as connection:
            connection.executescript('CREATE TABLE current_snapshot (payload TEXT); CREATE TABLE history (payload TEXT);')
            if content == 'foreign':
                connection.execute('CREATE TABLE user_data (value TEXT)')
            else:
                table = 'current_snapshot' if content == 'snapshot' else 'history'
                connection.execute(f'INSERT INTO {table} VALUES (?)', ('preserve this content',))
    fail_destination_initialization(monkeypatch, root, after_close=populate_after_close)
    with pytest.raises(ValueError, match='PT-STORAGE'):
        ProjectService.create(*pair, 'Initialization failure', root)
    with real_connect(root / 'project.sqlite3') as connection:
        if content == 'foreign':
            assert connection.execute("SELECT name FROM sqlite_master WHERE name='user_data'").fetchone()
        else:
            table = 'current_snapshot' if content == 'snapshot' else 'history'
            assert connection.execute(f'SELECT payload FROM {table}').fetchone() == ('preserve this content',)


def test_publication_requires_path_lock_to_match_held_descriptor(tmp_path, monkeypatch):
    from patchtrace import project_creation
    from patchtrace.persistence import ProjectLock

    pair, root = valid_pair(tmp_path), tmp_path / 'project'
    original = project_creation._identity
    def replaced_lock(path, *, directory=False):
        found = original(path, directory=directory)
        if path == root / '.patchtrace.lock':
            return found[0], found[1] + 1
        return found
    monkeypatch.setattr(project_creation, '_identity', replaced_lock)
    with pytest.raises(OSError, match='lock identity'):
        ProjectService.create(*pair, 'Replaced lock', root)
    assert not (root / 'artifacts').exists()
    available = ProjectLock(root)
    available.close()
