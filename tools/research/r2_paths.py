"""Confined, atomic research reports; explicit tool/archive inputs remain caller-selected.

Reports are confined to this checkout's fixed results subtree. Existing reports require
an explicit update; arbitrary filesystem destinations and all report-path symlinks fail.
Caller-selected input symlinks may resolve to regular bounded files: their contents still
need the probe's archive pin/member/binary verification before native execution.
This research helper assumes the checkout directory tree and selected input files stay
stable during an operation; it is not a sandbox against concurrent filesystem mutation.
"""
from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path

RESULTS = Path('docs/research/unified-matching-r2/results')
REPORT_MAX_BYTES = 32 * 1024 * 1024


def report_destination(value: str | Path, *, checkout_root: Path) -> Path:
    requested = Path(value)
    if '..' in requested.parts:
        raise ValueError('report path must not contain parent traversal')
    root = Path(checkout_root).resolve()
    boundary = root / RESULTS
    target = requested if requested.is_absolute() else root / requested
    try:
        relative = target.relative_to(root)
        target.relative_to(boundary)
    except ValueError:
        raise ValueError('report must be inside this checkout results directory') from None
    current = root
    for index, part in enumerate(relative.parts):
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise ValueError('report path must not contain symlinks')
        if index + 1 == len(relative.parts):
            if not stat.S_ISREG(mode):
                raise ValueError('existing report target must be a regular file')
        elif not stat.S_ISDIR(mode):
            raise ValueError('report parent must be a directory')
    if target == boundary:
        raise ValueError('report must name a file inside the results directory')
    return target


def write_report_json(value: str | Path, data, *, checkout_root: Path, replace: bool = False) -> Path:
    target = report_destination(value, checkout_root=checkout_root)
    encoded = (json.dumps(data, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('utf-8')
    if len(encoded) > REPORT_MAX_BYTES:
        raise ValueError('research report exceeds size limit')
    if target.exists() and not replace:
        raise FileExistsError('report already exists; only explicit report updates may replace it')
    target.parent.mkdir(parents=True, exist_ok=True)
    report_destination(target, checkout_root=checkout_root)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix='.r2-report-', suffix='.tmp', delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        report_destination(target, checkout_root=checkout_root)
        if replace:
            os.replace(temporary, target)
        else:
            # Publishing the complete temporary inode via a hard link is atomic and
            # fails if another writer claimed the destination since the earlier check.
            os.link(temporary, target)
        return target
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def read_report_json(value: str | Path, *, checkout_root: Path):
    target = report_destination(value, checkout_root=checkout_root)
    if target.stat().st_size > REPORT_MAX_BYTES:
        raise ValueError('research report exceeds size limit')
    with target.open('rb') as stream:
        content = stream.read(REPORT_MAX_BYTES + 1)
    if len(content) > REPORT_MAX_BYTES:
        raise ValueError('research report exceeds size limit')
    return json.loads(content)


def regular_input(value: str | Path, *, max_bytes: int) -> Path:
    target = Path(value).resolve(strict=True)
    info = target.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('selected input must resolve to a regular file')
    if info.st_size > max_bytes:
        raise ValueError('selected input exceeds size limit')
    return target
