"""Engine run records and the content-addressed cache key (SPEC-28 §4.1, §5.1). Pure: no I/O, no Qt."""
from __future__ import annotations

import hashlib
import ntpath
import posixpath
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_serializer

from ..enrichment.identity import canonical_json, domain_id
from .contracts import SecondaryError, SecondaryMatchSet, Sha256, _Strict

RUN_KIND = 'engine-run'
EngineId = Literal['ghidriff-baseline', 'bindiff', 'rz-diff']
Status = Literal['ok', 'failed', 'cancelled', 'unsupported', 'timeout', 'cached']
Orientation = Literal['older->newer']
STDERR_STORED = 64 * 1024
PROVENANCE_MAX_KEYS = 16
PROVENANCE_MAX_CHARS = 256
_PROVENANCE_KEY = re.compile(r'^[a-z0-9_]{1,64}$')


class EngineRun(_Strict):
    """One attempt; never updated after it is written."""
    contract: Literal['engine-run/1'] = 'engine-run/1'
    run_id: str
    engine: EngineId
    engine_version: str | None
    executable_path_sha256: Sha256 | None
    argv_digest: Sha256
    older_sha256: Sha256
    newer_sha256: Sha256
    orientation: Orientation
    cache_key: Sha256
    status: Status
    error_code: str | None
    returncode: int | None
    started_utc: str
    duration_ms: int = Field(ge=0)
    stderr_tail: str = Field(max_length=STDERR_STORED)
    output_sha256: Sha256 | None
    match_set_id: str | None
    superseded_by: None = None
    # SPEC-29 §5 append-only addition: bounded engine-specific provenance (e.g. BinExport input hashes,
    # failure_kind). Omitted from serialised output when empty, so engine-run/1 rows written before it
    # round-trip byte-identically.
    provenance: dict[str, str] = Field(default_factory=dict)

    @field_validator('provenance')
    @classmethod
    def _bounded(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > PROVENANCE_MAX_KEYS:
            raise ValueError(f'provenance has more than {PROVENANCE_MAX_KEYS} keys')
        for key, text in value.items():
            if not _PROVENANCE_KEY.match(key) or len(text) > PROVENANCE_MAX_CHARS:
                raise ValueError('provenance key must be [a-z0-9_]{1,64} and values at most 256 characters')
        return value

    @model_serializer(mode='wrap')
    def _omit_empty(self, handler):
        data = handler(self)
        if not data.get('provenance'):
            data.pop('provenance', None)
        return data


@dataclass(frozen=True)
class EngineOutcome:
    run: EngineRun
    match_set: SecondaryMatchSet | None  # present iff run.status in {'ok', 'cached'}
    error: SecondaryError | None


def _basename(value: str) -> str:
    return ntpath.basename(value) if '\\' in value or ':' in value[:2] else posixpath.basename(value)


def argv_digest(argv: Sequence[str], older: Path | str | None = None, newer: Path | str | None = None) -> str:
    """Digest of argv with the executable reduced to its basename and input paths replaced by
    placeholders, so moving a project keeps the digest while a flag change alters it."""
    swaps = {str(older): '<older>', str(newer): '<newer>'} if older is not None and newer is not None else {}
    items = [_basename(argv[0]), *(swaps.get(a, a) for a in argv[1:])] if argv else []
    return hashlib.sha256(canonical_json(items)).hexdigest()


def cache_key(engine: str, engine_version: str | None, argv_digest_hex: str, older_sha256: str,
              newer_sha256: str, orientation: str = 'older->newer', *, extra: Sequence[str] = ()) -> str:
    """`extra` (SPEC-29 §5): further inputs that determine the output, e.g. the two `.BinExport` file
    hashes. Empty `extra` yields exactly the SPEC-28 key, so existing cache rows stay valid."""
    items: list = [engine, engine_version, argv_digest_hex, older_sha256, newer_sha256, orientation]
    if extra:
        items.append(list(extra))
    return hashlib.sha256(canonical_json(items)).hexdigest()


def path_sha256(path: str) -> str:
    return hashlib.sha256(path.encode('utf-8')).hexdigest()


def new_run_id(key: str, started_utc: str) -> str:
    return domain_id('engine-run', 1, {'cache_key': key, 'started_utc': started_utc})


_BIDI = frozenset('\u200e\u200f\u2028\u2029\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069')


def sanitize_stderr(text: str, limit: int = STDERR_STORED) -> str:
    """Control characters other than newline/tab become '?'; stored copy is size-capped."""
    clean = ''.join(c if c in '\n\t' or ord(c) >= 32 and ord(c) != 127 and c not in _BIDI else '?' for c in text)
    return clean[-limit:]


def as_v2(match_set: SecondaryMatchSet, run_id: str | None = None) -> SecondaryMatchSet:
    """Re-label a validated set as secondary/2 (same content, engine-keyed identity)."""
    update = {'contract': 'secondary/2'} | ({'run_id': run_id} if run_id else {})
    return SecondaryMatchSet.model_validate_json(match_set.model_copy(update=update).model_dump_json())
