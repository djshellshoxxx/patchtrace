"""Recovery must retain exact damaged evidence before replacing series.json."""
import hashlib

import pytest
from test_nway_series import builds, create  # noqa: F401

from patchtrace.nway import series as store


@pytest.mark.parametrize('existing', ['different', 'directory', 'symlink'])
def test_recovery_collision_preserves_damaged_series(builds, tmp_path, capsys, existing):  # noqa: F811
    root = tmp_path / 'series'
    assert create(capsys, builds[:3], root)[0] == 0
    path = root / 'series.json'
    series = store.load(path)
    damaged = b'{ damaged evidence'
    path.write_bytes(damaged)
    backup = path.with_name(path.name + '.corrupt-' + hashlib.sha256(damaged).hexdigest()[:8])
    if existing == 'directory':
        backup.mkdir()
    elif existing == 'symlink':
        target = tmp_path / 'target'
        target.write_bytes(damaged)
        try:
            backup.symlink_to(target)
        except OSError:
            pytest.skip('symlinks unavailable')
    else:
        backup.write_bytes(b'x' * len(damaged))
    with pytest.raises(store.NwayError, match='PT-NWAY-STORAGE'):
        store.save(series, path, replace_corrupt=True)
    assert path.read_bytes() == damaged
    if existing == 'different':
        assert backup.read_bytes() == b'x' * len(damaged)
    elif existing == 'directory':
        assert backup.is_dir()
    else:
        assert backup.is_symlink() and target.read_bytes() == damaged
    assert not list(root.glob('.series-*'))


def test_exact_recovery_copy_is_reused_without_replacement(builds, tmp_path, capsys):  # noqa: F811
    root = tmp_path / 'series'
    assert create(capsys, builds[:3], root)[0] == 0
    path = root / 'series.json'
    series, good = store.load(path), path.read_bytes()
    damaged = b'{ damaged evidence'
    path.write_bytes(damaged)
    backup = path.with_name(path.name + '.corrupt-' + hashlib.sha256(damaged).hexdigest()[:8])
    backup.write_bytes(damaged)
    before = backup.stat()
    store.save(series, path, replace_corrupt=True)
    assert path.read_bytes() == good
    assert backup.read_bytes() == damaged
    assert backup.stat().st_ino == before.st_ino
    assert backup.stat().st_mtime_ns == before.st_mtime_ns
    assert store.load(path) == series
