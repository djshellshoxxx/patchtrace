"""Content-addressed placement of a built IR below the project (02 s3, deferred by S0a, 03 s12.2 item 6).

Layout: `runs/<ghidriff_run_id>/unified/ir/<ir_key[:16]>/{ir.sqlite3, manifest.json}`. The 16-hex directory name keeps
Windows paths short; the manifest holds the full key and a mismatch is `PT-UNIFIED-STORE`. Placement is one atomic
directory rename of an already complete private directory, so a reader never sees a half-written IR, and it is
idempotent: placing the same key twice keeps the first verified directory. No SQLite row is involved (the IR is
found by its key), therefore any thread may call these functions.
"""
from __future__ import annotations

import os
import re
import secrets
import shutil
import stat
import time
from pathlib import Path

from ...ingestion import safe_path
from ..contracts import ProgramIrManifest
from ..limits import UnifiedError
from . import schema
from .reader import _sha256_file, read_manifest

_RUN_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')
_KEY = re.compile(r'^[0-9a-f]{64}$')


def _error(message: str, reason: str, code: str = 'PT-UNIFIED-STORE') -> UnifiedError:
    return UnifiedError(code, message, reason=reason)


def ir_relative_dir(run_id: str, ir_key: str) -> str:
    if not _RUN_ID.match(run_id or '') or not _KEY.match(ir_key or ''):
        raise _error('Invalid run or IR identity for a sidecar path', 'bad-identity', 'PT-UNIFIED-INPUT')
    return f'runs/{run_id}/unified/ir/{ir_key[:16]}'


def ir_dir(root: Path, run_id: str, ir_key: str) -> Path:
    return safe_path(Path(root), ir_relative_dir(run_id, ir_key))


def _replace(source: Path, target: Path) -> None:
    for attempt in range(5):   # antivirus/indexer locks on Windows: bounded retry (5 x 200 ms), then STORE
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt == 4:
                raise _error('An IR directory could not be moved into place', 'replace-failed') from None
            time.sleep(0.2)


def _rmtree(path: Path) -> None:
    def retry(function, target, _exc):
        os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
        function(target)
    shutil.rmtree(path, onexc=retry)


def verify_ir_dir(directory: Path, *, expected_key: str | None = None) -> ProgramIrManifest:
    """Manifest valid, file hash equal; raises UnifiedError(STORE) otherwise. Does not open the database."""
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise _error('The IR directory is missing', 'dir-missing')
    manifest = read_manifest(directory)
    if expected_key is not None and manifest.ir_key != expected_key:
        raise _error('The IR belongs to another key', 'ir-key-mismatch')
    if {p.name for p in directory.iterdir()} != {schema.DB_NAME, schema.MANIFEST_NAME}:
        raise _error('The IR directory holds unexpected files', 'unexpected-files')
    database = directory / schema.DB_NAME
    if database.is_symlink() or not database.is_file() or _sha256_file(database) != manifest.file_sha256:
        raise _error('The IR database does not match its manifest', 'ir-file-hash')
    return manifest


def place_ir(root: Path, run_id: str, built: Path) -> Path:
    """Move a complete private IR directory to its content-addressed place and return the final directory."""
    built = Path(built)
    manifest = verify_ir_dir(built)
    final = ir_dir(root, run_id, manifest.ir_key)
    if final.exists():
        try:
            existing = verify_ir_dir(final, expected_key=manifest.ir_key)
        except UnifiedError:
            existing = None
        if existing is not None and existing.content_digest == manifest.content_digest:
            _rmtree(built)          # idempotent: the verified directory is already in place
            return final
        trash = final.with_name(f'tmp-{secrets.token_hex(8)}')   # corrupt or foreign leftover: move aside, replace
        _replace(final, trash)
        _rmtree(trash)
    final.parent.mkdir(parents=True, exist_ok=True)
    _replace(built, final)
    return final


def find_ir(root: Path, run_id: str, ir_key: str) -> Path | None:
    """The verified directory for `ir_key`, or None (a missing or corrupt IR is a cache miss, never a crash)."""
    try:
        directory = ir_dir(root, run_id, ir_key)
        if not directory.is_dir():
            return None
        verify_ir_dir(directory, expected_key=ir_key)
    except (UnifiedError, ValueError, OSError):
        return None
    return directory
