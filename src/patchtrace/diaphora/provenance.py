"""Pair binding for an imported Diaphora result (SPEC-DA-01 "Provenance and anti-misattribution"). Pure.

A Diaphora result has no intrinsic SHA-256 pair; `config.main_db/diff_db` are paths and are never trusted or
exported. The pair is bound either by a sidecar manifest (`diaphora-diff/1`) whose hashes are checked against the
result file and the project artifacts, or by an explicit user attestation recorded with lower trust.
"""
from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from .contracts import DiaphoraDiffManifest, DiaphoraError, Trust

MANIFEST_LIMIT = 64 * 1024


def load_manifest(path: Path) -> DiaphoraDiffManifest:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MANIFEST_LIMIT:
            raise DiaphoraError('PT-DIAPHORA-PROVENANCE', 'the manifest must be a regular file under 64 KiB')
        return DiaphoraDiffManifest.model_validate(json.loads(path.read_text(encoding='utf-8')))
    except (OSError, ValueError, ValidationError):
        raise DiaphoraError('PT-DIAPHORA-PROVENANCE', 'the manifest is unreadable or not diaphora-diff/1') from None


def bind(manifest: DiaphoraDiffManifest | None, user_attest_pair: bool, result_sha256: str,
         older_sha256: str, newer_sha256: str) -> Trust:
    """The trust level of the association, or a PT-DIAPHORA-* error. Hashes are re-checked at use time."""
    if manifest is None:
        if not user_attest_pair:
            raise DiaphoraError('PT-DIAPHORA-PROVENANCE',
                                'the result is not bound to this pair: give a diaphora-diff/1 manifest or '
                                'attest the pair explicitly (--user-attest-pair)')
        return 'user-attested'
    if manifest.result_sha256 != result_sha256:
        raise DiaphoraError('PT-DIAPHORA-PROVENANCE', 'the manifest describes another result file')
    found = (manifest.older_binary_sha256, manifest.newer_binary_sha256)
    if found == (newer_sha256, older_sha256) and older_sha256 != newer_sha256:
        raise DiaphoraError('PT-DIAPHORA-ORIENTATION', 'manifest binaries are reversed relative to older/newer')
    if found != (older_sha256, newer_sha256):
        raise DiaphoraError('PT-DIAPHORA-PAIR', 'manifest binaries do not match the project artifact pair')
    return 'manifest-bound'
