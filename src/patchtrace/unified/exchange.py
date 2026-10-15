"""SPEC-31 owner <-> worker exchange (01 s4, 02 s10 item 3): the strict request and report models, the progress event
and the small file helpers both sides share. Private temporary files only: nothing here is persisted, so none of it is
schema-generated. Pure: pydantic + stdlib, no project database, no processes.

The owner writes one `unified-worker-request/1` into a private directory (every input file is listed with its SHA-256
and size and re-hashed by the worker); the worker answers with one `unified-worker-report/1` next to it. Error details in
a report are fixed slugs, never untrusted text (01 s6).
"""
from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from ..persistence import strict_json
from .limits import UnifiedError

ALL_SOURCES = ('ghidriff', 'bindiff', 'rz-diff', 'manual')
EXCHANGE_MAX_BYTES = 1024 * 1024
MESSAGES = {
    'PT-UNIFIED-INPUT': 'The unified inputs are not usable', 'PT-UNIFIED-PAIR': 'The inputs are not the project pair',
    'PT-UNIFIED-ORIENTATION': 'The inputs are in the wrong orientation',
    'PT-UNIFIED-UNSUPPORTED': 'Unified analysis is not supported for these inputs',
    'PT-UNIFIED-EXTRACT': 'Extraction failed', 'PT-UNIFIED-IR': 'The extracted data failed validation',
    'PT-UNIFIED-LIMIT': 'A unified limit was reached', 'PT-UNIFIED-TIMEOUT': 'Unified analysis reached its deadline',
    'PT-UNIFIED-CANCEL': 'Unified analysis was cancelled', 'PT-UNIFIED-STALE': 'The unified inputs changed',
    'PT-UNIFIED-STORE': 'The unified result could not be stored', 'PT-UNIFIED-INTERNAL': 'Unified analysis failed'}
_NOT_SLUG = re.compile(r'[^a-z0-9-]+')


def slug(text: object) -> str | None:
    """A machine slug `[a-z0-9-]{1,48}` from any text, or None."""
    clean = _NOT_SLUG.sub('-', str(text or '').lower()).strip('-')[:48]
    return clean or None


def fail(code: str, reason: str | None = None) -> UnifiedError:
    """A `UnifiedError` with the fixed message of its code (untrusted text never enters a message)."""
    return UnifiedError(code, MESSAGES[code], reason=slug(reason))


@dataclass(frozen=True)
class StageEvent:
    stage: str
    done: int
    total: int | None = None


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class WorkerFile(_Strict):
    path: str = Field(min_length=1, max_length=1024)
    sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    size: int = Field(ge=0)


class WorkerLayout(_Strict):
    image_base: int = Field(ge=0, le=2**64 - 1)
    size_of_image: int = Field(ge=1, le=2**32 - 1)


class WorkerIr(_Strict):
    """One placed ProgramIR sidecar the worker opens (the directory lies in the project, not in the private one: the
    worker re-verifies the manifest, the file hash, the key and the digest before it reads a row). `sections` are the
    PE sections of the artifact as (start rva, end rva) for the DATA-MAP/1 region shift."""
    directory: str = Field(min_length=1, max_length=1024)
    ir_key: str = Field(pattern=r'^[0-9a-f]{64}$')
    content_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    sections: tuple[tuple[int, int], ...] = Field(default=(), max_length=96)


class WorkerRequest(_Strict):
    """`unified-worker-request/1`: written by the owner into a private directory."""
    contract: Literal['unified-worker-request/1'] = 'unified-worker-request/1'
    older_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    newer_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    older_layout: WorkerLayout
    newer_layout: WorkerLayout
    run_id: str = Field(pattern=r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')
    backend_version: str = Field(max_length=64)
    raw_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    raw_status: Literal['ok', 'missing', 'hash-mismatch']
    raw_path: str | None = Field(default=None, max_length=1024)
    snapshot: WorkerFile
    snapshot_lines: int = Field(ge=0)
    secondary: tuple[WorkerFile, ...] = Field(default=(), max_length=8)
    sources: tuple[Literal['ghidriff', 'bindiff', 'rz-diff', 'manual'], ...] = Field(min_length=1, max_length=4)
    report_path: str = Field(min_length=1, max_length=1024)
    progress_path: str | None = Field(default=None, max_length=1024)
    budget_seconds: int = Field(ge=1, le=86_400)
    ir_older: WorkerIr | None = None        # ProgramIR is used for both sides or for neither (F1)
    ir_newer: WorkerIr | None = None
    residual: bool = True                   # False = backup B-07: the ladder without the residual passes P16-P19
    refacts: WorkerFile | None = None       # set: judge the pairs of this `unified-refacts/1` file again (S3b), the
                                            # staged result in the result directory is the first phase's

    @model_validator(mode='after')
    def _both_sides_or_none(self):
        if (self.ir_older is None) != (self.ir_newer is None):
            raise ValueError('ProgramIR is used for both sides or for neither')
        if self.refacts is not None and self.ir_older is None:
            raise ValueError('the decompiled text is judged against ProgramIR')
        return self


class WorkerReport(_Strict):
    """`unified-worker-report/1`: the worker's answer."""
    contract: Literal['unified-worker-report/1'] = 'unified-worker-report/1'
    ok: bool
    error_code: str | None = None
    reason: str | None = Field(default=None, max_length=48)
    status: Literal['complete', 'partial'] | None = None
    result_id: str | None = Field(default=None, pattern=r'^[0-9a-f]{64}$')
    raw_status: Literal['ok', 'missing', 'hash-mismatch', 'unparsable'] | None = None
    rows: int = Field(default=0, ge=0)
    facts: int = Field(default=0, ge=0)
    limitations: tuple[str, ...] = Field(default=(), max_length=64)
    stage_ms: dict[str, int] = Field(default_factory=dict)
    refacts: tuple[tuple[int, int], ...] = Field(default=(), max_length=64)   # (older rva, newer rva) worth a decompile


Rva = Annotated[int, Field(ge=0, le=2**32 - 1)]
REFACTS_MAX_BYTES = 128 * 1024 * 1024   # 64 pairs x two sides x L-29 characters would be 256 MiB; real texts are KiB


class WorkerRefacts(_Strict):
    """`unified-refacts/1`: the on-demand decompile (S3b) as the owner hands it to the worker - the pairs that were
    chosen (older rva, newer rva) and the C text the decompiler printed per side and function. A function without a
    text is simply absent; the worker uses the text of BOTH sides of a pair or none."""
    contract: Literal['unified-refacts/1'] = 'unified-refacts/1'
    pairs: tuple[tuple[Rva, Rva], ...] = Field(default=(), max_length=64)
    older: tuple[tuple[Rva, str], ...] = Field(default=(), max_length=64)
    newer: tuple[tuple[Rva, str], ...] = Field(default=(), max_length=64)

    def texts(self, side: str) -> dict[int, str]:
        return dict(self.older if side == 'older' else self.newer)


def write_refacts(path: Path, *, pairs: Iterable[tuple[int, int]], texts: Mapping[str, Mapping[int, str]]) -> WorkerFile:
    """Write the file and describe it for the request (path, SHA-256, size)."""
    document = WorkerRefacts(pairs=tuple(sorted(set(pairs))), older=tuple(sorted(texts.get('older', {}).items())),
                             newer=tuple(sorted(texts.get('newer', {}).items())))
    data = document.model_dump_json().encode('utf-8')
    write_atomic(Path(path), data)
    return WorkerFile(path=str(path), sha256=hashlib.sha256(data).hexdigest(), size=len(data))


def read_refacts(path: Path, *, expected_sha256: str | None = None) -> WorkerRefacts:
    """The strict reader of the file (a private file of this run, re-hashed when the request names its hash)."""
    try:
        if Path(path).stat().st_size > REFACTS_MAX_BYTES:
            raise fail('PT-UNIFIED-INPUT', 'refacts-invalid')
        data = Path(path).read_bytes()
        if expected_sha256 is not None and hashlib.sha256(data).hexdigest() != expected_sha256:
            raise fail('PT-UNIFIED-INPUT', 'refacts-invalid')
        text = data.decode('utf-8')
        strict_json(text)
        return WorkerRefacts.model_validate_json(text)
    except UnifiedError:
        raise
    except (OSError, ValueError, ValidationError):
        raise fail('PT-UNIFIED-INPUT', 'refacts-invalid') from None


def read_request(path: Path) -> WorkerRequest:
    try:
        if Path(path).stat().st_size > EXCHANGE_MAX_BYTES:
            raise fail('PT-UNIFIED-INPUT', 'request-too-large')
        text = Path(path).read_text(encoding='utf-8')
        strict_json(text)
        return WorkerRequest.model_validate_json(text)
    except UnifiedError:
        raise
    except (OSError, ValueError, ValidationError):
        raise fail('PT-UNIFIED-INPUT', 'request-invalid') from None


def read_report(path: Path) -> WorkerReport | None:
    """The worker's report, or None when it is missing, too large or invalid (the owner then classifies the exit)."""
    try:
        if Path(path).stat().st_size > EXCHANGE_MAX_BYTES:
            return None
        return WorkerReport.model_validate_json(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None


def write_atomic(path: Path, data: bytes) -> None:
    part = Path(f'{path}.part')
    part.write_bytes(data)
    os.replace(part, path)


def inside(path: str, directory: Path) -> Path:
    """A worker input or output must lie in the request's own private directory (no traversal, no symlink tricks)."""
    resolved = Path(path).resolve()
    if not Path(path).is_absolute() or not resolved.is_relative_to(directory):
        raise fail('PT-UNIFIED-INPUT', 'path-outside-private-dir')
    return resolved


def write_report(request_path: Path, report: WorkerReport) -> None:
    """Best effort: the report lives next to the request; failing to write it shows up as a missing report."""
    try:
        req = read_request(request_path)
        write_atomic(inside(req.report_path, Path(request_path).resolve().parent),
                     report.model_dump_json().encode('utf-8'))
    except (UnifiedError, OSError):
        pass


def error_report(exc: UnifiedError) -> WorkerReport:
    return WorkerReport(ok=False, error_code=exc.code, reason=exc.reason)
