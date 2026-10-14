"""In-process BinExport2 inspection: snapshot -> pre-scan -> parse -> check -> identity (SPEC-10b §6.2).

The worker subprocess calls this; tests call it directly. Production callers go through
`binexport_run.accept_binexport`, which isolates it in a memory/time-capped child.
"""
from __future__ import annotations

from pathlib import Path

from . import binexport_descriptor
from .binexport_check import check_message
from .binexport_identity import PeLayout, architecture_warning, classify_identity, detect_address_basis
from .binexport_limits import BinExportLimits, Budget, err, near_cap
from .binexport_models import BinExportSummary, Role
from .binexport_prescan import KNOWN, prescan
from .binexport_proto import ProtoUnavailable, load_binexport2_class, runtime_info
from .binexport_snapshot import take_snapshot
from .contracts import SecondaryError

LOOKALIKES = ((b'SQLite format 3\x00', 'sqlite'), (b'PK\x03\x04', 'zip'), (b'%PDF', 'pdf'),
              (b'\x7fELF', 'elf'), (b'MZ', 'pe'))


def sniff_lookalike(head: bytes) -> str | None:
    """Advisory only: used to explain a file the wire checks already rejected, never to reject one."""
    for magic, name in LOOKALIKES:
        if head.startswith(magic):
            return name
    stripped = head.lstrip(b' \t\r\n\xef\xbb\xbf')
    return 'json' if stripped[:1] in (b'{', b'[') else None


def alloc_failure(exc: Exception, limits: BinExportLimits) -> bool:
    """Measured (upb 7.36.2, Linux RLIMIT_AS): a cap hit during parse surfaces as DecodeError('... Arena alloc
    failed'), not MemoryError, and the failed doubling can leave the peak well below the cap (97 MiB peak at a
    120 MiB cap). So either signal means out-of-memory. An allocation failure is never a verdict on the file's
    format (upb bounds every allocation by the input length [inf]), so it must not be reported as INPUT."""
    return 'alloc failed' in str(exc).lower() or near_cap(limits.memory_bytes)


def load_class():
    try:
        return load_binexport2_class(), runtime_info()['protobuf_version']
    except ProtoUnavailable as exc:
        raise err('PT-SECONDARY-UNSUPPORTED', exc.reason, f'BinExport support unavailable: {exc.reason}') from None


def inspect_bytes(data: bytes, limits: BinExportLimits, budget: Budget):
    """Pre-scan then parse then check; returns (message, CheckReport, protobuf_version)."""
    try:
        stats = prescan(memoryview(data), limits, budget)
    except SecondaryError as exc:
        kind = sniff_lookalike(bytes(data[:16])) if exc.code == 'PT-SECONDARY-INPUT' else None
        if kind:
            raise err('PT-SECONDARY-INPUT', f'lookalike_{kind}',
                      f'file looks like {kind.upper()}, not a BinExport2 protobuf') from None
        raise
    cls, version = load_class()
    msg = cls()
    budget.check()
    try:
        consumed = msg.ParseFromString(data)  # C call, not interruptible: bounded by caps and the process kill
    except MemoryError:
        raise
    except Exception as exc:  # DecodeError's import path differs by runtime
        if alloc_failure(exc, limits):
            raise err('PT-SECONDARY-RUN', 'worker_oom', 'BinExport parse ran out of memory under the cap') from None
        raise err('PT-SECONDARY-INPUT', 'parse_failed', 'not a parseable BinExport2 message') from None
    if consumed is not None and consumed != len(data):
        raise err('PT-SECONDARY-INPUT', 'trailing_bytes', 'BinExport has trailing bytes after the message')
    for number, name in KNOWN.items():  # wire/parse agreement: a divergence means the pre-scan was bypassed
        if number in (1, 8):
            continue
        if len(getattr(msg, name)) != stats.counts.get(number, 0):
            raise err('PT-SECONDARY-INPUT', 'parse_failed', f'{name} count differs between wire and parse')
    budget.check()
    report = check_message(msg, limits, budget)
    return msg, report, version


def inspect_binexport(src: Path | str, snapshot: Path | str, *, artifact_sha256: str, role: Role,
                      limits: BinExportLimits, budget: Budget, pe_layout: PeLayout | None = None,
                      accept_unbound: bool = False) -> BinExportSummary:
    snap = take_snapshot(src, snapshot, limits, budget)
    data = snap.path.read_bytes()  # <= max_file_bytes by construction
    msg, report, version = inspect_bytes(data, limits, budget)
    del data  # free 1x before identity work
    meta = msg.meta_information
    binding = classify_identity(meta.executable_id, artifact_sha256, accept_unbound)
    basis = detect_address_basis(report.vertex_addresses, pe_layout)
    warnings = list(report.warnings)
    arch = architecture_warning(meta.architecture_name, pe_layout)
    if arch:
        warnings.append(arch)
    has_ts = meta.HasField('timestamp') if hasattr(meta, 'HasField') else meta.timestamp is not None
    return BinExportSummary(
        file_sha256=snap.sha256, file_size=snap.size, executable_id=meta.executable_id.strip(),
        executable_name=meta.executable_name, architecture_name=meta.architecture_name,
        timestamp=int(meta.timestamp) if has_ts else None, id_binding=binding, role=role, address_basis=basis,
        counts=dict(report.counts), function_addresses=report.vertex_addresses,
        vertex_types=report.vertex_types, warnings=tuple(warnings), protobuf_version=version,
        descriptor_proto_sha256=binexport_descriptor.PROTO_SHA256)
