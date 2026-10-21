"""Identity-gated PDB staging for `local` symbol mode (SPEC-53 GHR-1). No network.

A PDB found by CodeView name in an analyst-chosen folder is copied (never moved) into
`<dest>/<name>/<GUID><age>/<name>` only if the copy's own GUID and age equal the PE CodeView record.
Directories are searched one level deep, by exact (case-insensitive) file name; symlinks are refused.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..pe_overview.models import CodeViewInfo
from .modes import CHUNK, MAX_PDB_BYTES, MAX_PDB_DIRS, MAX_STAGED, SymbolError
from .pdbid import PdbIdentity, read_pdb_identity

_NAME = re.compile(r'[^\x00-\x1f\x7f/\\:*?"<>|]{1,255}')
REASONS = ('guid_mismatch', 'age_mismatch', 'too_large', 'unreadable', 'not_found', 'limit')


@dataclass(frozen=True)
class Want:
    side: str          # 'older' | 'newer'
    pdb_name: str
    guid: str          # lowercase hyphenated
    age: int

    @property
    def guid_age(self) -> str:
        return uuid.UUID(self.guid).hex.upper() + f'{self.age:X}'


@dataclass(frozen=True)
class StagedSymbol:
    pdb_name: str
    guid_age: str
    sha256: str
    size: int
    side: str          # 'older' | 'newer' | 'both'


@dataclass(frozen=True)
class SkippedSymbol:
    pdb_name: str
    side: str
    reason: str


@dataclass(frozen=True)
class StagingResult:
    staged: tuple[StagedSymbol, ...]
    skipped: tuple[SkippedSymbol, ...]
    digest: str


def want_from_codeview(side: str, codeview: CodeViewInfo | None) -> Want | None:
    """The PDB a PE asks for, or None when it has no usable CodeView record (name is the basename only)."""
    if codeview is None or side not in ('older', 'newer'):
        return None
    name = codeview.pdb_path.replace('\\', '/').rsplit('/', 1)[-1].strip()
    if (not _NAME.fullmatch(name) or name in ('.', '..') or not name.lower().endswith('.pdb')
            or not isinstance(codeview.age, int) or not 0 <= codeview.age <= 0xFFFFFFFF):
        return None
    try:
        uuid.UUID(codeview.guid)
    except ValueError:
        return None
    return Want(side, name, codeview.guid.lower(), codeview.age)


def input_digest(staged: Sequence[StagedSymbol]) -> str:
    """SHA-256 over sorted (pdb_name, guid_age, pdb_sha256); stable, side-independent."""
    rows = sorted([s.pdb_name, s.guid_age, s.sha256] for s in staged)
    return hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode('utf-8')).hexdigest()


def validate_dirs(dirs: Sequence[str]) -> list[Path]:
    if len(dirs) > MAX_PDB_DIRS:
        raise SymbolError('PT-SYMBOL-MODE', f'at most {MAX_PDB_DIRS} PDB folders are allowed')
    out = []
    for text in dirs:
        path = Path(text)
        if not isinstance(text, str) or not path.is_absolute() or not path.is_dir():
            raise SymbolError('PT-SYMBOL-MODE', 'PDB folders must be absolute paths of existing directories')
        out.append(path)
    return out


def _candidates(directory: Path, name: str):
    lowered = name.lower()
    try:
        with os.scandir(directory) as it:
            for entry in it:
                if entry.name.lower() == lowered:
                    yield Path(entry.path)
    except OSError:
        return


def _copy(source: Path, target: Path, cancel: Callable[[], bool] | None) -> tuple[str, int]:
    """Copy through a no-follow handle, hashing the bytes written; raises OSError/SymbolError."""
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(source, flags)
    digest, total = hashlib.sha256(), 0
    with os.fdopen(fd, 'rb') as src:
        if not stat.S_ISREG(os.fstat(src.fileno()).st_mode):
            raise SymbolError('PT-SYMBOL-PDB-INVALID', 'PDB is not a regular file')
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, 'xb') as dst:
            while True:
                if cancel is not None and cancel():
                    raise SymbolError('PT-SYMBOL-PDB-INVALID', 'staging cancelled')
                chunk = src.read(CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_PDB_BYTES:
                    raise SymbolError('PT-SYMBOL-PDB-INVALID', 'too_large')
                digest.update(chunk)
                dst.write(chunk)
    return digest.hexdigest(), total


def _discard(target: Path) -> None:
    target.unlink(missing_ok=True)
    for parent in (target.parent, target.parent.parent):   # <name>/<GUIDage>; leave `dest` itself
        try:
            parent.rmdir()
        except OSError:
            break


def stage_symbols(wants: Sequence[Want], dirs: Sequence[str | Path], dest: Path, *,
                  read_identity: Callable[[Path], PdbIdentity] = read_pdb_identity,
                  cancel: Callable[[], bool] | None = None) -> StagingResult:
    """Stage every wanted PDB whose own identity matches; skip the rest with a reason. Never raises on a bad PDB."""
    folders = validate_dirs([str(d) for d in dirs])
    staged: dict[tuple[str, str], StagedSymbol] = {}
    skipped: list[SkippedSymbol] = []
    for want in wants:
        key = (want.pdb_name, want.guid_age)
        if key in staged:
            prior = staged[key]
            if prior.side != want.side:
                staged[key] = StagedSymbol(prior.pdb_name, prior.guid_age, prior.sha256, prior.size, 'both')
            continue
        if len(staged) >= MAX_STAGED:
            skipped.append(SkippedSymbol(want.pdb_name, want.side, 'limit'))
            continue
        reason = 'not_found'
        done = False
        for folder in folders:
            for cand in _candidates(folder, want.pdb_name):
                target = Path(dest) / want.pdb_name / want.guid_age / want.pdb_name
                try:
                    if cand.is_symlink() or cand.stat().st_size > MAX_PDB_BYTES:
                        reason = 'unreadable' if cand.is_symlink() else 'too_large'
                        continue
                    sha, size = _copy(cand, target, cancel)
                    identity = read_identity(target)
                except (OSError, SymbolError) as exc:
                    _discard(target)
                    if cancel is not None and cancel():
                        raise SymbolError('PT-CANCEL', 'PDB staging cancelled') from None
                    reason = 'too_large' if 'too_large' in str(exc) else 'unreadable'
                    continue
                if identity.guid.lower() != want.guid:
                    _discard(target)
                    reason = 'guid_mismatch'
                elif identity.age != want.age:
                    _discard(target)
                    reason = 'age_mismatch'
                else:
                    staged[key] = StagedSymbol(want.pdb_name, want.guid_age, sha, size, want.side)
                    done = True
                    break
            if done:
                break
        if not done:
            skipped.append(SkippedSymbol(want.pdb_name, want.side, reason))
    result = tuple(sorted(staged.values(), key=lambda s: (s.pdb_name, s.guid_age)))
    return StagingResult(result, tuple(skipped), input_digest(result))
