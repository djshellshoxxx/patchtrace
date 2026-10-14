"""GZF retention seam for Ghidriff's analysed programs (A-01c, D-05, 03 s8, s12.7).

Called lazily from `backend.run_comparison` right after a successful Ghidriff process and BEFORE its scratch
directory is removed: Ghidriff saves one analysed program per input as `<artifact file name>-<sha1[:6] of the
artifact>.gzf` [src ghidriff 4f5d895 l.1411, 997]. Exactly two regular files within L-36 whose names match the two
artifacts are moved into the quarantine run directory as `older.gzf` / `newer.gzf`; the SHA-256 of each is recorded.
Anything else retains nothing (the extractor then analyses itself, B-01) and never fails the run. Stdlib only.
"""
from __future__ import annotations

import hashlib
import os
from collections.abc import Callable, Mapping
from pathlib import Path

from ..limits import DEFAULT_LIMITS

SIDES = ('older', 'newer')
CHUNK = 1 << 22


def _sha1_prefix(path: Path) -> str:
    digest = hashlib.sha1(usedforsecurity=False)   # Ghidriff's own naming scheme, not a security use
    with open(path, 'rb') as stream:
        while chunk := stream.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()[:6]


def expected_name(artifact: Path) -> str:
    return f'{Path(artifact).name}-{_sha1_prefix(Path(artifact))}.gzf'


def _move_and_hash(source: Path, target: Path) -> tuple[str, int]:
    """Copy with hashing to `<target>.part`, replace, then remove the source (works across volumes)."""
    digest, size = hashlib.sha256(), 0
    part = target.with_name(target.name + '.part')
    with open(source, 'rb') as reader, open(part, 'wb') as writer:
        while chunk := reader.read(CHUNK):
            digest.update(chunk)
            size += len(chunk)
            writer.write(chunk)
    os.replace(part, target)
    source.unlink()
    return digest.hexdigest(), size


def retain_gzfs(engine_gzfs: Path, target: Path, sources: Mapping[str, Path],
                limit: int = DEFAULT_LIMITS.l36_retained_gzf_bytes) -> dict | None:
    """Move the two analysed programs; returns `{"older": {"name","sha256","bytes"}, "newer": {...}}` or None."""
    placed: list[Path] = []
    try:
        engine_gzfs, target = Path(engine_gzfs), Path(target)
        if set(sources) != set(SIDES) or not engine_gzfs.is_dir():
            return None
        files = sorted(engine_gzfs.glob('*.gzf'))
        if len(files) != 2 or any(f.is_symlink() or not f.is_file() for f in files):
            return None
        if sum(f.stat().st_size for f in files) > limit:
            return None
        by_name = {f.name: f for f in files}
        wanted = {side: expected_name(sources[side]) for side in SIDES}
        if len(set(wanted.values())) != 2 or set(wanted.values()) != set(by_name):
            return None
        target.mkdir(parents=True, exist_ok=True)
        record: dict[str, dict] = {}
        for side in SIDES:
            destination = target / f'{side}.gzf'
            placed.append(destination)
            sha256, size = _move_and_hash(by_name[wanted[side]], destination)
            record[side] = {'name': wanted[side], 'sha256': sha256, 'bytes': size}
        return record
    except (OSError, ValueError):
        for path in placed:
            for leftover in (path, path.with_name(path.name + '.part')):
                try:
                    leftover.unlink(missing_ok=True)
                except OSError:
                    pass
        return None


def retain_run_gzfs(engine_gzfs: Path, quarantine: Path, sources: Mapping[str, Path], settings: dict,
                    event: Callable[[str, str], None]) -> None:
    """The `backend.run_comparison` seam: retain into `<quarantine>/unified/gzf/` (renamed with the run directory by
    `publish()`) and record `settings['gzf']`, or warn. Never raises: retention is an optimisation (B-01)."""
    try:
        record = retain_gzfs(Path(engine_gzfs), Path(quarantine) / 'unified' / 'gzf', sources)
    except Exception:  # noqa: BLE001 - nothing here may fail a completed comparison
        record = None
    if record is None:
        event('warning', 'The analysed Ghidra programs were not retained; the unified engine will analyse again')
    else:
        settings['gzf'] = record
