"""Staging, identification and promotion of acquired files (SPEC-08 §4.5, §4.7).

Downloaded bytes are never executed or loaded; identification reads headers only. Only a
verified AMD64 PE can become a project input, and the project copy is made by the normal
`ProjectService.create` path so acquisition cannot bypass ingestion checks.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import struct
import tempfile
import zlib
from pathlib import Path

from ..ingestion import validate_pe
from .contracts import (
    AcquiredArtifact,
    AcquisitionError,
    BuildCandidate,
    DownloadPlan,
    PlannedDownload,
    Provenance,
    acquisition_id,
    validate_file_name,
)
from .transport import AcquisitionConsent, Transport

_CHUNK = 1024 * 1024
ANNOTATION_PREFIX = 'acquisition/1 provenance: '


def make_plan(older: BuildCandidate, newer: BuildCandidate, older_url: str, newer_url: str) -> DownloadPlan:
    for candidate in (older, newer):
        if not candidate.x64:
            raise AcquisitionError('PT-ACQ-INPUT', f'{candidate.sha256[:12]} is not an x64 build')
        if candidate.download == 'unavailable':
            raise AcquisitionError('PT-ACQ-NOTFOUND', f'{candidate.sha256[:12]} is update-package only')
    try:
        return DownloadPlan(downloads=tuple(
            PlannedDownload(side=side, file_name=c.file_name, sha256=c.sha256, size=c.size, url=url,
                            record_sha256=c.record_sha256)
            for side, c, url in (('older', older, older_url), ('newer', newer, newer_url))))
    except ValueError as exc:
        raise AcquisitionError('PT-ACQ-INPUT', f'invalid download plan: {exc}') from None


def create_staging(parent: Path | None = None) -> Path:
    # mkdtemp creates the directory 0700, so other local users cannot swap staged files.
    return Path(tempfile.mkdtemp(prefix='patchtrace-acquire-', dir=parent))


def remove_staging(staging: Path) -> None:
    def writable(func, path, _exc):
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        func(path)
    if Path(staging).exists():
        shutil.rmtree(staging, onexc=writable)


def _pe_machine(head: bytes) -> int | None:
    if len(head) < 64:
        return None
    offset = struct.unpack_from('<I', head, 0x3C)[0]
    if offset + 6 <= len(head) and head[offset:offset + 4] == b'PE\0\0':
        return struct.unpack_from('<H', head, offset + 4)[0]
    return None


def identify(path: Path) -> tuple[str, int | None]:
    """Return (format, machine). Header bytes only; CRC is computed while streaming."""
    path = Path(path)
    with path.open('rb') as stream:
        head = stream.read(4096)
        if head[:2] == b'MZ':
            machine = _pe_machine(head)
            try:
                validate_pe(path)
            except ValueError:
                return 'unknown', machine
            return 'pe', machine
        if len(head) >= 8 and head[4:8] in (b'PA30', b'PA31'):
            crc = zlib.crc32(head[4:])
            for chunk in iter(lambda: stream.read(_CHUNK), b''):
                crc = zlib.crc32(chunk, crc)
            if crc == struct.unpack_from('<I', head, 0)[0]:
                return head[4:8].decode('ascii').lower(), None
            return 'unknown', None
        if head[:4] == b'PA30':
            return 'pa30', None
    return 'unknown', None


def acquire(planned: PlannedDownload, consent: AcquisitionConsent, staging: Path,
            transport: Transport) -> AcquiredArtifact:
    """Download, verify and identify one planned file into `staging/<side>/<file_name>`."""
    name = validate_file_name(planned.file_name)
    side_dir = Path(staging) / planned.side
    side_dir.mkdir(mode=0o700, exist_ok=False)
    got = transport.download(planned, consent, side_dir)
    final = side_dir / name
    os.replace(got.path, final)
    final.chmod(stat.S_IREAD)
    fmt, machine = identify(final)
    return AcquiredArtifact(
        acquisition_id=acquisition_id(name, got.sha256), side=planned.side, file_name=name, path=str(final),
        sha256=got.sha256, size=got.size, format=fmt, machine=machine,
        provenance=Provenance(source_url=got.source_url, redirect_host=got.redirect_host,
                              retrieved_at=got.retrieved_at, winbindex_record_sha256=planned.record_sha256))


def promote(older: AcquiredArtifact, newer: AcquiredArtifact, name: str, root: Path):
    """Create a normal two-artifact project and record provenance as one note per artifact."""
    from ..service import ProjectService
    if (older.side, newer.side) != ('older', 'newer'):
        raise AcquisitionError('PT-ACQ-INPUT', 'promotion needs the older then the newer artifact')
    for item in (older, newer):
        if item.format != 'pe':
            raise AcquisitionError('PT-ACQ-VERIFY', f'{item.side} file is {item.format}, not an AMD64 PE')
    service = ProjectService.create(Path(older.path), Path(newer.path), name, root)
    try:
        by_side = {a.side: a for a in service.project.artifacts}
        for item in (older, newer):
            artifact = by_side[item.side]
            if artifact.sha256 != item.sha256:
                raise AcquisitionError('PT-ACQ-VERIFY', 'project copy does not match the acquired file')
            # AnalystAnnotation kinds are fixed in models.py, so provenance is a prefixed 'note'.
            record = item.model_dump(mode='json', exclude={'path'})
            service.annotate(artifact.id, ANNOTATION_PREFIX + json.dumps(record, sort_keys=True))
    except BaseException:
        service.close()
        raise
    return service
