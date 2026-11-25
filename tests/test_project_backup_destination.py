"""Service and CLI must agree on which project backup directory the user selected."""
import pytest

from patchtrace import cli
from patchtrace.service import ProjectService


@pytest.fixture
def source(tmp_path):
    root = tmp_path / 'project'
    ProjectService.sample(root).close()
    return root


def directory_link(path, target):
    try:
        path.symlink_to(target, target_is_directory=True)
    except OSError as error:
        if getattr(error, 'winerror', None) == 1314:
            pytest.skip('The Windows account cannot create a directory symbolic link.')
        raise


def assert_refused(entry, source, destination, capsys):
    message = 'PT-STORAGE: backup destination must be new and outside project'
    if entry == 'service':
        service = ProjectService.open(source)
        try:
            with pytest.raises(ValueError, match=message):
                service.backup(destination)
        finally:
            service.close()
    else:
        assert cli.main(['project', 'backup', str(source), '--out', str(destination)]) == 2
        assert message in capsys.readouterr().err


@pytest.mark.parametrize('entry', ['service', 'cli'])
def test_dangling_backup_leaf_is_refused(entry, source, tmp_path, capsys):
    target = tmp_path / 'absent'
    destination = tmp_path / 'backup'
    directory_link(destination, target)
    original_target = destination.readlink()
    assert_refused(entry, source, destination, capsys)
    assert destination.is_symlink() and destination.readlink() == original_target
    assert not target.exists()
    assert not list(tmp_path.glob('.patchtrace-backup-*'))


@pytest.mark.parametrize('entry', ['service', 'cli'])
def test_parent_alias_cannot_put_backup_inside_project(entry, source, tmp_path, capsys):
    alias = tmp_path / 'inside'
    directory_link(alias, source)
    assert_refused(entry, source, alias / 'backup', capsys)
    assert not (source / 'backup').exists()


@pytest.mark.parametrize('entry', ['service', 'cli'])
def test_new_backup_in_valid_parent_alias_can_be_reopened(entry, source, tmp_path):
    actual = tmp_path / 'backups'
    actual.mkdir()
    alias = tmp_path / 'outside'
    directory_link(alias, actual)
    destination = alias / 'new'
    if entry == 'service':
        service = ProjectService.open(source)
        try:
            assert service.backup(destination) == actual / 'new'
        finally:
            service.close()
    else:
        assert cli.main(['project', 'backup', str(source), '--out', str(destination)]) == 0
    reopened = ProjectService.open(actual / 'new')
    try:
        assert reopened.root == actual / 'new'
    finally:
        reopened.close()
