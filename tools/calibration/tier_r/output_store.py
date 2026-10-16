"""LBL-31: bounded, atomic persistence for one normalized Tier R engine response.

Stored JSON is canonical: its raw-byte SHA-256 must equal the evaluator's output_sha256.
The output directory must start empty, preventing stale responses from being mistaken for
a later run. No binary bytes, executable contents, or raw provider payloads are stored.
"""
from __future__ import annotations

import hashlib
import os
import re
import tempfile
from pathlib import Path

from ..common import canonical_json
from . import contracts as C
from . import report_schemas as RS

MAX_ENGINE_OUTPUT_BYTES = 64 * 1024 * 1024
_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z')
_SUPPORTED = frozenset(('rz-diff', 'bindiff', 'ghidriff'))


class OutputError(ValueError):
    """Persistence or contract failure that must not be reported as an engine success."""


def output_file_name(pair_id: str, engine: str) -> str:
    if not isinstance(pair_id, str) or not _NAME.fullmatch(pair_id):
        raise OutputError('invalid pair identifier for output filename')
    if engine not in _SUPPORTED:
        raise OutputError(f'engine {engine!r} lacks a validated engine-output/1 storage contract')
    return f'{pair_id}.{engine}.json'


def prepare_output_dir(folder: Path) -> Path:
    """Reserve a fresh directory. Never mix two runs or silently reuse old output files."""
    folder = Path(folder)
    if folder.is_symlink():
        raise OutputError('output directory must not be a symlink')
    if folder.exists():
        if not folder.is_dir():
            raise OutputError('output path is not a directory')
        if any(folder.iterdir()):
            raise OutputError('output directory is nonempty; use a fresh directory for each evaluation')
    else:
        folder.mkdir(parents=True, exist_ok=False)
    return folder


def write_engine_output(folder: Path, pair_id: str, doc: dict) -> str:
    """Persist validated canonical JSON atomically; return the digest of the actual bytes."""
    filename = output_file_name(pair_id, doc.get('engine'))
    try:
        raw = canonical_json(doc)
    except (TypeError, ValueError) as exc:
        raise OutputError(f'engine output is not canonical JSON: {type(exc).__name__}') from None
    if len(raw) > MAX_ENGINE_OUTPUT_BYTES:
        raise OutputError(f'engine output exceeds the {MAX_ENGINE_OUTPUT_BYTES} byte cap')
    try:
        RS.load_engine_output(raw)
    except (C.ContractError, ValueError) as exc:
        raise OutputError(f'engine output contract invalid: {str(exc)[:250]}') from None
    path = Path(folder) / filename
    if path.exists() or path.is_symlink():
        raise OutputError(f'engine output {filename} already exists')
    pending = None
    try:
        fd, name = tempfile.mkstemp(prefix='.pending-', suffix='.json', dir=str(folder))
        pending = Path(name)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists() or path.is_symlink():
            raise OutputError(f'engine output {filename} already exists')
        os.replace(pending, path)
        pending = None
    except OSError as exc:
        raise OutputError(f'failed to persist engine output: {type(exc).__name__}') from None
    finally:
        if pending is not None:
            pending.unlink(missing_ok=True)
    return hashlib.sha256(raw).hexdigest()
