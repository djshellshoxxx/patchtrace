"""BinDiff input pairing (SPEC-29 §3). Pure apart from `copy_and_hash`; no Qt, no process I/O.

C4 depends on the accepted `.BinExport` only through the local `AcceptedBinExportLike` Protocol
(frozen seam, phase-c-build-coordination.md §1): `snapshot_path`, `summary.file_sha256`,
`summary.executable_id`, `summary.id_binding` (and `summary.architecture_name` when present). The C3
`AcceptedBinExport` satisfies it unchanged; nothing here imports C3 modules.

Binding rule (spec-decisions-20261014.md, BinDiff C4): a 64-hex `executable_id` must equal the project
artifact SHA-256 of its role. Any other id (empty, MD5, other) is refused unless the user explicitly
asserts the binding; the assertion is recorded in provenance and never hides a SHA-256 mismatch.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from .contracts import SecondaryError

Role = Literal['older', 'newer']
MAX_BINEXPORT_BYTES = 256 * 1024 * 1024  # spec-decisions: cap lowered from 512 MiB until live data exists
_SHA256 = re.compile(r'[0-9a-f]{64}')
_MD5 = re.compile(r'[0-9a-f]{32}')


@runtime_checkable
class BinExportSummaryLike(Protocol):
    @property
    def file_sha256(self) -> str: ...

    @property
    def executable_id(self) -> str: ...

    @property
    def id_binding(self) -> str: ...


@runtime_checkable
class AcceptedBinExportLike(Protocol):
    @property
    def snapshot_path(self) -> Path: ...

    @property
    def summary(self) -> BinExportSummaryLike: ...


@dataclass(frozen=True)
class BoundInput:
    role: Role
    path: Path                # the accepted read-only snapshot (never the user's original)
    file_sha256: str          # SHA-256 of the snapshot bytes, re-checked after copying
    executable_id: str        # normalised (stripped, lower-case)
    id_kind: str              # sha256 | md5 | empty | other
    asserted: bool            # True when bound only by the user's explicit confirmation


@dataclass(frozen=True)
class BoundPair:
    older: BoundInput
    newer: BoundInput

    @property
    def asserted(self) -> bool:
        return self.older.asserted or self.newer.asserted

    def expected_file_hashes(self) -> tuple[str, str]:
        """BinDiff copies each BinExport `executable_id` into `file.hash`; the importer checks this pair."""
        return self.older.executable_id, self.newer.executable_id

    def provenance(self) -> dict[str, str]:
        binding = 'sha256' if not self.asserted else (
            f'asserted:older={self.older.id_kind},newer={self.newer.id_kind}')
        return {'binexport_binding': binding, 'older_binexport_sha256': self.older.file_sha256,
                'newer_binexport_sha256': self.newer.file_sha256}


def _id_kind(identifier: str) -> str:
    if _SHA256.fullmatch(identifier):
        return 'sha256'
    if _MD5.fullmatch(identifier):
        return 'md5'
    return 'empty' if not identifier else 'other'


def _bind(item: AcceptedBinExportLike, role: Role, expected: str, other: str, accept_unbound: bool) -> BoundInput:
    summary = item.summary
    identifier = str(summary.executable_id or '').strip().lower()
    kind = _id_kind(identifier)
    if kind == 'sha256':
        if identifier != expected:
            if identifier == other:
                raise SecondaryError('PT-SECONDARY-ORIENTATION',
                                     'The .BinExport files are swapped: older and newer are reversed.',
                                     kind='binexport-orientation')
            raise SecondaryError('PT-SECONDARY-PAIR', f'The {role} .BinExport was exported from a different '
                                 f"file than this project's {role} artifact.", kind='binexport-wrong-artifact')
        asserted = False
    elif accept_unbound:
        asserted = True
    else:
        raise SecondaryError(
            'PT-SECONDARY-INPUT',
            f'The {role} .BinExport does not record a SHA-256 of its source executable, so it cannot be tied '
            "to this project's file. Re-export it with a BinExport that writes the executable hash, or "
            'confirm explicitly that it belongs to this artifact.', kind='binexport-unbound')
    file_sha256 = str(summary.file_sha256 or '').lower()
    if not _SHA256.fullmatch(file_sha256):
        raise SecondaryError('PT-SECONDARY-INPUT', f'The {role} .BinExport snapshot has no valid SHA-256.',
                             kind='binexport-invalid')
    return BoundInput(role, Path(item.snapshot_path), file_sha256, identifier, kind, asserted)


def bind_pair(older: AcceptedBinExportLike, newer: AcceptedBinExportLike, older_sha256: str, newer_sha256: str,
              *, accept_unbound: bool = False) -> BoundPair:
    """Tie both accepted inputs to the project artifact pair; raises SecondaryError with a §6 `kind`."""
    if older_sha256 == newer_sha256:
        raise SecondaryError('PT-SECONDARY-PAIR', "The project's older and newer artifacts are identical.",
                             kind='identical-pair')
    if str(older.summary.file_sha256).lower() == str(newer.summary.file_sha256).lower():
        raise SecondaryError('PT-SECONDARY-PAIR', 'The same .BinExport file was supplied for both sides.',
                             kind='binexport-same-file')
    first = _bind(older, 'older', older_sha256, newer_sha256, accept_unbound)
    second = _bind(newer, 'newer', newer_sha256, older_sha256, accept_unbound)
    if first.asserted and second.asserted and first.executable_id and first.executable_id == second.executable_id:
        raise SecondaryError('PT-SECONDARY-PAIR', 'Both .BinExport files claim the same source executable.',
                             kind='binexport-same-file')
    arch_old = getattr(older.summary, 'architecture_name', None)
    arch_new = getattr(newer.summary, 'architecture_name', None)
    if arch_old is not None and arch_new is not None and arch_old != arch_new:
        raise SecondaryError('PT-SECONDARY-PAIR', 'The two .BinExport files describe different architectures.',
                             kind='binexport-arch-mismatch')
    return BoundPair(first, second)


def _workdir_error(exc: OSError | None = None) -> SecondaryError:
    name = type(exc).__name__ if exc is not None else 'changed input'
    return SecondaryError('PT-SECONDARY-RUN', f'Could not prepare a private working folder ({name}).',
                          kind='workdir-error')


def copy_and_hash(source: Path, destination: Path, *, max_bytes: int = MAX_BINEXPORT_BYTES) -> str:
    """Copy (never link) a regular file to a new destination while hashing it; returns the copy's SHA-256.

    The destination must not exist (exclusive create). The caller compares the digest with the
    validated snapshot hash, which closes the validate -> use window.
    """
    try:
        info = os.lstat(source)
    except OSError as exc:
        raise _workdir_error(exc) from None
    if not stat.S_ISREG(info.st_mode):
        raise _workdir_error()
    if info.st_size > max_bytes:
        raise SecondaryError('PT-SECONDARY-LIMIT', '.BinExport input exceeds the size limit.',
                             kind='binexport-too-large')
    digest, total = hashlib.sha256(), 0
    try:
        with open(source, 'rb') as src, open(destination, 'xb') as dst:
            while chunk := src.read(1 << 20):
                total += len(chunk)
                if total > max_bytes:
                    raise SecondaryError('PT-SECONDARY-LIMIT', '.BinExport input exceeds the size limit.',
                                         kind='binexport-too-large')
                digest.update(chunk)
                dst.write(chunk)
    except OSError as exc:
        raise _workdir_error(exc) from None
    return digest.hexdigest()
