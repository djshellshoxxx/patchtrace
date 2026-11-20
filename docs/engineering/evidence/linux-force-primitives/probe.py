"""Bounded, authored Linux namespace experiments; no target binaries are executed.

Run from the repository root with PYTHONPATH=src and pass a new JSON output path.
These controls establish observed primitive behavior, not a production repair.
"""
from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
import tempfile
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from patchtrace.strings import export
from patchtrace.strings.contracts import StringsError

AT_FDCWD = -100
AT_EMPTY_PATH = 0x1000
AT_SYMLINK_FOLLOW = 0x400
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2
EXPECTED = b'authored intended export'
PRIOR = b'authored prior destination'
FOREIGN = b'authored substituted source'
LATER = b'authored later destination'
FIXTURE_FILESYSTEMS = []

libc = ctypes.CDLL(None, use_errno=True)
libc.linkat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
libc.linkat.restype = ctypes.c_int
libc.renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
libc.renameat2.restype = ctypes.c_int


def identity(fd: int) -> list[int]:
    s = os.fstat(fd)
    return [s.st_dev, s.st_ino]


def invoke(function, *arguments) -> dict:
    ctypes.set_errno(0)
    result = function(*arguments)
    error = ctypes.get_errno() if result == -1 else 0
    return {'return_value': result, 'errno': error, 'errno_name': errno.errorcode.get(error)}


def record_fixture(root: Path) -> None:
    FIXTURE_FILESYSTEMS.append(subprocess.check_output(
        ['stat', '-f', '-c', '%T', str(root)], text=True).strip())


@contextmanager
def anonymous_fixture():
    with tempfile.TemporaryDirectory(prefix='pt-force-primitives-') as raw:
        root = Path(raw)
        record_fixture(root)
        with ExitStack() as cleanup:
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            cleanup.callback(os.close, directory)
            fd = os.open('.', os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=directory)
            cleanup.callback(os.close, fd)
            os.write(fd, EXPECTED)
            os.fsync(fd)
            (root / 'target').write_bytes(PRIOR)
            yield root, directory, fd


def native_link(use_empty: bool, existing: bool) -> dict:
    with anonymous_fixture() as (root, directory, fd):
        name = b'target' if existing else b'new'
        source_fd = fd if use_empty else AT_FDCWD
        source = b'' if use_empty else os.fsencode(f'/proc/self/fd/{fd}')
        flags = AT_EMPTY_PATH if use_empty else AT_SYMLINK_FOLLOW
        call = invoke(libc.linkat, source_fd, source, directory, name, flags)
        target = root / os.fsdecode(name)
        if existing:
            assert call['errno'] == errno.EEXIST and target.read_bytes() == PRIOR
        elif call['return_value'] == 0:
            assert target.read_bytes() == EXPECTED
            assert [target.stat().st_dev, target.stat().st_ino] == identity(fd)
        return {'operation': 'linkat', 'source': 'empty_path_fd' if use_empty else 'proc_fd_follow',
                'destination_exists': existing, **call, 'held_identity': identity(fd),
                'destination_identity': [target.stat().st_dev, target.stat().st_ino] if target.exists() else None,
                'observed': 'collision_preserved' if existing else (
                    'held_inode_published' if call['return_value'] == 0 else 'capability_unavailable')}


def fd_rename(mode: str) -> dict:
    with anonymous_fixture() as (root, directory, fd):
        source_fd = AT_FDCWD if mode == 'proc_fd' else fd
        source = os.fsencode(f'/proc/self/fd/{fd}') if mode == 'proc_fd' else b''
        flags = AT_EMPTY_PATH if mode == 'empty_path_flag' else 0
        call = invoke(libc.renameat2, source_fd, source, directory, b'target', flags)
        expected_error = {'empty_path': errno.ENOENT, 'empty_path_flag': errno.EINVAL, 'proc_fd': errno.EXDEV}
        assert call['errno'] == expected_error[mode]
        assert (root / 'target').read_bytes() == PRIOR and os.pread(fd, len(EXPECTED), 0) == EXPECTED
        return {'operation': 'renameat2', 'source': mode, 'flags': flags, **call,
                'observed': 'no_fd_bound_replacement'}


CHILD = """
import json, os, pathlib, sys
root = pathlib.Path(sys.argv[1])
name = sys.argv[2]
(root / name).rename(root / 'held-original')
(root / name).write_bytes(bytes.fromhex(sys.argv[3]))
print(json.dumps({'euid': os.geteuid()}))
"""


def child_swap(root: Path, name: str) -> dict:
    result = subprocess.run([sys.executable, '-c', CHILD, str(root), name, FOREIGN.hex()],
                            capture_output=True, text=True, timeout=3, check=True)
    child = json.loads(result.stdout)
    assert child['euid'] == os.geteuid()
    return {'same_euid': True, 'child_exit_code': result.returncode}


def named_exchange() -> dict:
    with anonymous_fixture() as (root, directory, fd):
        os.link(f'/proc/self/fd/{fd}', 'stage', dst_dir_fd=directory, follow_symlinks=True)
        child = child_swap(root, 'stage')
        call = invoke(libc.renameat2, directory, b'stage', directory, b'target', RENAME_EXCHANGE)
        assert call['return_value'] == 0
        assert (root / 'target').read_bytes() == FOREIGN and (root / 'stage').read_bytes() == PRIOR
        # The parent authors an intervening publication after exchange, before rollback.
        (root / 'later').write_bytes(LATER)
        os.replace(root / 'later', root / 'target')
        rollback = invoke(libc.renameat2, directory, b'stage', directory, b'target', RENAME_EXCHANGE)
        assert rollback['return_value'] == 0
        assert (root / 'target').read_bytes() == PRIOR and (root / 'stage').read_bytes() == LATER
        assert os.pread(fd, len(EXPECTED), 0) == EXPECTED
        return {'operation': 'renameat2_exchange', **child, **call,
                'observed': 'substitute_published_despite_atomic_exchange',
                'blind_rollback': 'displaced_later_writer_from_destination',
                'later_publication_actor': 'probe_parent', 'rollback_call': rollback}


def no_replace() -> dict:
    with anonymous_fixture() as (root, directory, fd):
        os.link(f'/proc/self/fd/{fd}', 'stage', dst_dir_fd=directory, follow_symlinks=True)
        call = invoke(libc.renameat2, directory, b'stage', directory, b'target', RENAME_NOREPLACE)
        assert call['errno'] == errno.EEXIST
        assert (root / 'target').read_bytes() == PRIOR and (root / 'stage').read_bytes() == EXPECTED
        return {'operation': 'renameat2_noreplace', **call, 'observed': 'collision_preserved_not_replaced'}


def locking(kind: str) -> dict:
    with anonymous_fixture() as (root, directory, fd):
        os.link(f'/proc/self/fd/{fd}', 'stage', dst_dir_fd=directory, follow_symlinks=True)
        # TemporaryDirectory is private to this principal; no shared permissions change.
        mode = root.stat().st_mode & 0o777
        assert mode == 0o700
        held = directory if kind == 'directory_flock' else fd
        signals = []
        lease = {}
        with ExitStack() as cleanup:
            if kind == 'write_lease':
                previous_signal = signal.signal(signal.SIGIO, lambda number, _frame: signals.append(number))
                cleanup.callback(signal.signal, signal.SIGIO, previous_signal)
                try:
                    fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_WRLCK)
                except OSError as exc:
                    return {'operation': kind, 'observed': 'capability_unavailable',
                            'errno': exc.errno, 'errno_name': errno.errorcode.get(exc.errno)}
                cleanup.callback(fcntl.fcntl, fd, fcntl.F_SETLEASE, fcntl.F_UNLCK)
                lease['lease_before'] = fcntl.fcntl(fd, fcntl.F_GETLEASE)
                assert lease['lease_before'] == fcntl.F_WRLCK
            elif kind != 'private_directory':
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                cleanup.callback(fcntl.flock, held, fcntl.LOCK_UN)
            child = child_swap(root, 'stage')
            os.replace('stage', 'target', src_dir_fd=directory, dst_dir_fd=directory)
            assert (root / 'target').read_bytes() == FOREIGN
            assert os.pread(fd, len(EXPECTED), 0) == EXPECTED
            if kind == 'write_lease':
                lease['lease_after'] = fcntl.fcntl(fd, fcntl.F_GETLEASE)
                assert lease['lease_after'] == fcntl.F_WRLCK
            return {'operation': kind, **child, **lease, 'private_directory_mode': oct(mode),
                    'observed': 'source_name_substituted_and_published', 'sigio_received': signals}


def production_schedule() -> dict:
    with tempfile.TemporaryDirectory(prefix='pt-force-production-') as raw:
        root = Path(raw)
        record_fixture(root)
        target = root / 'target'
        target.write_bytes(PRIOR)
        replace = os.replace
        schedule = []

        def scheduled(source, destination, **kwargs):
            schedule.append(child_swap(root, source))
            return replace(source, destination, **kwargs)

        try:
            with patch.object(os, 'replace', scheduled):
                export.write_atomic(target, EXPECTED, force=True)
        except StringsError as exc:
            assert exc.code == 'PT-STR-EXPORT' and 'destination identity changed' in exc.message
            assert target.read_bytes() == FOREIGN
            assert (root / 'held-original').read_bytes() == EXPECTED
            return {'operation': 'current_production_final_boundary', 'schedule': schedule,
                    'error_code': exc.code, 'error_message': exc.message,
                    'observed': 'refused_receipt_after_foreign_bytes_visible'}
        raise AssertionError('Expected a postpublication refusal')


def main() -> None:
    expected_module = Path.cwd() / 'src/patchtrace/strings/export.py'
    assert Path(export.__file__).resolve() == expected_module.resolve()
    rows = [native_link(empty, exists) for empty in (True, False) for exists in (False, True)]
    rows.extend(fd_rename(mode) for mode in ('empty_path', 'empty_path_flag', 'proc_fd'))
    rows.extend((no_replace(), named_exchange()))
    rows.extend(locking(kind) for kind in ('file_flock', 'directory_flock', 'write_lease', 'private_directory'))
    rows.append(production_schedule())
    for row, filesystem in zip(rows, FIXTURE_FILESYSTEMS, strict=True):
        row['fixture_filesystem'] = filesystem
    report = {
        'schema': 'patchtrace-linux-force-primitive-probe/1',
        'observed_at': datetime.now(UTC).isoformat(),
        'source_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        'source_export_sha256': hashlib.sha256(expected_module.read_bytes()).hexdigest(),
        'python': sys.version, 'platform': platform.platform(), 'libc': platform.libc_ver(),
        'euid': os.geteuid(),
        'checkout_filesystem': subprocess.check_output(['stat', '-f', '-c', '%T', '.'], text=True).strip(),
        'scope': 'Authored bytes, real Linux syscalls, deterministic same-principal child schedules; no target execution.',
        'controls': rows,
        'conclusion': 'No tested primitive provides source-descriptor-bound atomic replacement of an existing name.',
        'production_changed': False,
    }
    destination = Path(sys.argv[1])
    with destination.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'controls': len(rows), 'capability_unavailable': sum(
        row['observed'] == 'capability_unavailable' for row in rows), 'report': str(destination)}, indent=2))


if __name__ == '__main__':
    main()
