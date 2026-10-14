"""Compatibility facade for `.BinExport` validation (SPEC-10 §2, SPEC-10b §3).

The implementation lives in `binexport_*` modules: limits/budget, wire pre-scan, upb-only runtime loading from
the checked-in descriptor set, structural checker, identity, snapshot, pipeline and the capped worker.
Production acceptance is `binexport_run.accept_binexport` (worker-isolated, snapshot-based). The functions
here keep the SPEC-10 in-process API for existing callers and tests.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from .binexport_check import check_message as _check
from .binexport_limits import BinExportLimits, Budget, err
from .binexport_pipeline import inspect_bytes
from .binexport_proto import ProtoUnavailable, load_binexport2_class
from .contracts import SecondaryError, check_pair

__all__ = ['MAX_SIZE', 'BinExportResult', 'check_executable', 'check_message', 'check_pair_exports',
           'unmatched_addresses', 'validate_binexport']

MAX_SIZE = BinExportLimits().max_file_bytes  # 256 MiB (SPEC-10b §5; was 512 MiB in SPEC-10)


@dataclass(frozen=True)
class BinExportResult:
    status: str  # 'valid' or 'unsupported'
    reason: str | None
    executable_id: str | None = None
    executable_name: str | None = None
    architecture_name: str | None = None
    function_addresses: tuple[int, ...] = ()


def check_message(msg, limits: BinExportLimits | None = None, budget: Budget | None = None) -> BinExportResult:
    """Structural validation of a parsed BinExport2 message; raises SecondaryError.

    Unlike `binexport_check.check_message`, an empty executable_id is rejected here (legacy SPEC-10 rule);
    the unbound-id override exists only through `accept_binexport(accept_unbound=True)`."""
    report = _check(msg, limits, budget)
    meta = msg.meta_information
    if not (getattr(meta, 'executable_id', '') or '').strip():
        raise err('PT-SECONDARY-INPUT', 'executable_id_empty', 'meta_information.executable_id is empty')
    return BinExportResult('valid', None, meta.executable_id, meta.executable_name, meta.architecture_name,
                           report.vertex_addresses)


def check_executable(result: BinExportResult, artifact_sha256: str) -> None:
    """The Ghidra exporter writes the program SHA-256 as executable_id; anything else is a wrong pair."""
    if (result.executable_id or '').strip().lower() != artifact_sha256:
        raise SecondaryError('PT-SECONDARY-PAIR', 'BinExport executable_id does not match the artifact SHA-256',
                             reason='executable_id_mismatch')


def check_pair_exports(older: BinExportResult, newer: BinExportResult, older_sha256: str,
                       newer_sha256: str) -> None:
    check_pair(older.executable_id or '', newer.executable_id or '', older_sha256, newer_sha256)


def _bindings():
    try:
        return SimpleNamespace(BinExport2=load_binexport2_class())
    except ProtoUnavailable:
        return None


def _read_bounded(path: Path, limit: int) -> bytes:
    try:
        with open(path, 'rb') as handle:
            data = handle.read(limit + 1)
    except OSError as exc:
        raise err('PT-SECONDARY-INPUT', 'unreadable', f'cannot read BinExport file: {exc.strerror}') from None
    if len(data) > limit:
        raise err('PT-SECONDARY-LIMIT', 'too_large', f'BinExport file exceeds {limit} bytes')
    return data


def validate_binexport(path: Path, artifact_sha256: str, bindings=None) -> BinExportResult:
    """In-process validation (no worker, no snapshot). Prefer `binexport_run.accept_binexport`."""
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise err('PT-SECONDARY-INPUT', 'unreadable', f'cannot read BinExport file: {exc.strerror}') from None
    if size > MAX_SIZE:
        raise err('PT-SECONDARY-LIMIT', 'too_large', f'BinExport file exceeds {MAX_SIZE} bytes')
    limits = BinExportLimits(max_file_bytes=MAX_SIZE)
    if bindings is None:
        if _bindings() is None:
            return BinExportResult('unsupported', 'protobuf bindings not installed')
        data = _read_bounded(path, MAX_SIZE)
        if not data:
            raise err('PT-SECONDARY-INPUT', 'empty_file', 'BinExport file is empty')
        message = inspect_bytes(data, limits, Budget())[0]
    else:  # injected (test) bindings: duck-typed objects, no wire pre-scan possible
        data = _read_bounded(path, MAX_SIZE)
        message = bindings.BinExport2()
        try:
            message.ParseFromString(data)
        except Exception:
            raise err('PT-SECONDARY-INPUT', 'parse_failed', 'not a parseable BinExport2 message') from None
    result = check_message(message, limits)
    check_executable(result, artifact_sha256)
    return result


def unmatched_addresses(function_addresses: Iterable[int], matched: Iterable[int | None]) -> tuple[int, ...]:
    """BinDiff stores only matches; unmatched functions are call-graph vertices it never mentions."""
    seen = {a for a in matched if a is not None}
    return tuple(sorted({a for a in function_addresses} - seen))
