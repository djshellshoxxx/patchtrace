"""Local layout, atomic writes, identifiers and typed errors for Tier W (SPEC-33 s2).

Every document written under the root carries `"tier": "W"`; that marker (plus the `tw.` pair-id prefix) is what
the repository guard looks for, so a misplaced copy is caught even if someone renames it.
"""
from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from pathlib import Path

from .. import corpus

TIER = 'W'
REPO_ROOT = Path(__file__).resolve().parents[3]
CORPUS_ID = re.compile(r'tier-w-[A-Za-z0-9._-]{1,57}')
STEM = re.compile(r'[^A-Za-z0-9._-]')
WINDOWS_PATH_LIMIT = 240

# Exit codes shared by every subcommand (spec s11).
OK, PARTIAL, CONFIG, BLOCKED, CANCELLED = 0, 1, 2, 3, 5
ERROR_EXIT = {'PT-TIERW-INPUT': CONFIG, 'PT-TIERW-CONFIG': CONFIG, 'PT-TIERW-LIMIT': CONFIG,
              'PT-TIERW-VERIFY': PARTIAL, 'PT-TIERW-NETWORK': PARTIAL, 'PT-TIERW-BLOCKED': BLOCKED,
              'PT-TIERW-CANCEL': CANCELLED}


class TierWError(Exception):
    """Typed, user-safe failure. `code` maps to an exit code through ERROR_EXIT."""

    def __init__(self, code: str, message: str):
        super().__init__(f'{code}: {message}')
        self.code = code
        self.message = message


def calib_root(environ=None) -> Path:
    return corpus.calib_root(environ)


def inside(path: Path, tree: Path) -> bool:
    return corpus._inside(path, tree)


def check_root(root: Path, worktree: Path = REPO_ROOT) -> Path:
    """The corpus root must never be inside a git work tree (spec s2)."""
    root = Path(root).expanduser().resolve()
    if inside(root, worktree):
        raise TierWError('PT-TIERW-CONFIG', f'{corpus.ROOT_ENV} ({root}) is inside the work tree {worktree}; '
                                            'choose a directory outside the repository')
    return root


def check_corpus_id(value: str) -> str:
    if not isinstance(value, str) or not CORPUS_ID.fullmatch(value):
        raise TierWError('PT-TIERW-INPUT', 'corpus id must look like tier-w-<letters, digits, . _ -> (<= 64)')
    return value


def stem(file_name: str, limit: int = 24) -> str:
    """Identifier-safe short form of a file name for ids (`afd.sys` -> `afd.sys`)."""
    return STEM.sub('-', file_name)[:limit] or 'x'


def tool_safe_path(path: Path) -> list[str]:
    """Problems that stop Ghidra from using `path` as a project/output location (backend rule)."""
    resolved = Path(path).resolve()
    problems = []
    dotted = [p for p in resolved.parts if p.startswith('.')]
    if dotted:
        problems.append(f'path component {dotted[0]!r} starts with a dot, which Ghidra rejects; '
                        'use a short root such as D:\\ptcal or /srv/ptcal')
    if os.name == 'nt' and len(str(resolved)) >= WINDOWS_PATH_LIMIT - 60:
        problems.append('path is too long for reliable Ghidra runs on Windows; use a short root such as D:\\ptcal')
    return problems


class Layout:
    """Paths under `<root>/tier-w/` (binaries stay at the corpus tool's `<root>/binaries/<sha256>/<name>`)."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.base = self.root / 'tier-w'

    def catalogue(self, file_name: str) -> Path:
        return self.base / 'catalogue' / f'{file_name}.json'

    def manifest(self, corpus_id: str) -> Path:
        return self.base / 'manifests' / f'{check_corpus_id(corpus_id)}.json'

    def pairs(self, corpus_id: str) -> Path:
        return self.base / 'manifests' / f'{check_corpus_id(corpus_id)}.pairs.json'

    def ledger(self, corpus_id: str) -> Path:
        return self.base / 'ledger' / f'{check_corpus_id(corpus_id)}.jsonl'

    def pdb(self, name: str, guid_age: str) -> Path:
        lower = name.lower()
        return self.base / 'pdbs' / lower / guid_age.upper() / lower

    def symbols(self, sha256: str, producer: str) -> Path:
        return self.base / 'symbols' / f'{sha256}.{producer}.json'

    def labels_dir(self, corpus_id: str) -> Path:
        return self.base / 'labels' / check_corpus_id(corpus_id)

    def review_dir(self, corpus_id: str) -> Path:
        return self.base / 'review' / check_corpus_id(corpus_id)

    def run_dir(self, corpus_id: str, pair_id: str, condition: str) -> Path:
        return self.base / 'runs' / check_corpus_id(corpus_id) / pair_id / {'symbols-hidden': 'h',
                                                                           'symbols-visible': 'v'}[condition]

    def report(self, corpus_id: str) -> Path:
        return self.base / 'reports' / f'{check_corpus_id(corpus_id)}.evaluation.json'

    @property
    def cancel_file(self) -> Path:
        return self.base / 'CANCEL'

    @property
    def staging(self) -> Path:
        return self.base / 'staging'


def atomic_write(path: Path, data: bytes, *, read_only: bool = False) -> Path:
    """Write via a temporary file in the same directory, fsync, then os.replace (Windows-safe)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not os.access(path, os.W_OK):
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
    fd, name = tempfile.mkstemp(prefix='.tmp-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise
    if read_only:
        os.chmod(path, stat.S_IREAD)
    return path


def dumps(document) -> bytes:
    """Stable, readable JSON (sorted keys, UTF-8, no NaN) with a trailing newline."""
    return (json.dumps(document, sort_keys=True, indent=1, ensure_ascii=False, allow_nan=False) + '\n').encode()


def write_json(path: Path, document) -> Path:
    if not isinstance(document, dict) or document.get('tier') not in (TIER, 'R', 'test'):
        raise TierWError('PT-TIERW-INPUT', 'every Tier-W document must carry a tier marker')
    return atomic_write(path, dumps(document))


def write_jsonl(path: Path, records) -> Path:
    lines = [json.dumps(r, sort_keys=True, ensure_ascii=False, allow_nan=False) for r in records]
    return atomic_write(path, ('\n'.join(lines) + ('\n' if lines else '')).encode())


def read_bytes(path: Path, limit: int) -> bytes:
    """Bounded read: refuse files larger than `limit` before reading them."""
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise TierWError('PT-TIERW-INPUT', f'cannot read {path.name}: {exc.strerror or exc}') from None
    if size > limit:
        raise TierWError('PT-TIERW-LIMIT', f'{path.name} is {size} bytes, over the {limit}-byte cap')
    return path.read_bytes()
