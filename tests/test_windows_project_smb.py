"""Windows loopback SMB acceptance. Set PATCHTRACE_REQUIRE_WINDOWS_SMB=1 to require a pass."""
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from uuid import uuid4

import pytest

from patchtrace import verified_backup
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService


def unavailable(reason):
    if os.environ.get('PATCHTRACE_REQUIRE_WINDOWS_SMB') == '1':
        pytest.fail(reason)
    pytest.skip(reason)


def test_project_create_reopen_and_backup_on_loopback_share(tmp_path):
    if os.name != 'nt':
        unavailable('Native Windows is required for the loopback SMB acceptance test.')
    drive = tmp_path.drive
    if len(drive) != 2 or drive[1] != ':' or not drive[0].isascii() or not drive[0].isalpha():
        unavailable('The pytest temporary directory must be on a local drive.')
    # The sole share and server are derived from the local drive and fixed loopback IP.
    share = Path(f'//127.0.0.1/{drive[0]}$') / tmp_path.relative_to(tmp_path.anchor)
    marker = tmp_path / 'loopback-probe'
    token = uuid4().bytes
    marker.write_bytes(token)
    try:
        with (share / marker.name).open('r+b') as remote:
            assert remote.read() == token
            remote.write(b'!')
    except OSError as exc:
        unavailable(f'The existing loopback {drive[0]}$ share did not grant read/write '
                    f'access to the pytest directory (winerror={exc.winerror}).')
    assert marker.read_bytes() == token + b'!'

    older, newer = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    for variant, path in enumerate((older, newer)):
        path.write_bytes(synthetic_pe(variant))
    root = share / 'project #100%'
    with ProjectService.create(older, newer, 'SMB acceptance', root) as current:
        snapshot = current.project.model_dump()
    with ProjectService.open(root) as reopened:
        assert reopened.project.model_dump() == snapshot
        filename = reopened.store.connection.execute('PRAGMA database_list').fetchone()[2]
        normalized = filename.replace(chr(92), '/').casefold().replace('//?/unc/', '//')
        assert normalized.startswith('//127.0.0.1/'), filename
        backup = reopened.backup(share / 'backup #100%')
        expected_hash = reopened.store.connection.execute(verified_backup.SNAPSHOT_SHA).fetchone()
    with closing(verified_backup._open_read_only(backup / 'project.sqlite3')) as read_only:
        assert read_only.execute(verified_backup.SNAPSHOT_SHA).fetchone() == expected_hash
        with pytest.raises(sqlite3.OperationalError, match='readonly'):
            read_only.execute('DELETE FROM current_snapshot')
    with ProjectService.open(tmp_path / backup.name) as local_copy:
        assert local_copy.project.model_dump() == snapshot
