"""Local Tier-W fetch plans, exact-preview consent, verification and provenance (SPEC-33 s4).

Plan construction and PE inspection are offline. Network operations require a
saved canonical plan, its displayed SHA-256, a byte-equivalent recomputation
from current inputs, and exact host consent. Nothing fetched is executed.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import threading
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Sequence
from urllib.parse import urlsplit

from patchtrace.acquisition.contracts import (
    AcquisitionConsent,
    AcquisitionError,
    PlannedDownload,
    SYMBOL_SERVER,
    symbol_server_url,
)
from patchtrace.acquisition.quarantine import acquire, create_staging, identify, remove_staging
from patchtrace.acquisition.transport import Transport
from patchtrace.pe_overview import inspect_pe

from ..label import AnnotationLog
from . import catalogue as catalogue_api
from .contracts import (
    Catalogue,
    FetchExclusion,
    FetchInput,
    FetchItem,
    FetchPlan,
    PairBinary,
    PairsDoc,
    load_fetch_plan,
)
from .msf import MsfError, read_identity
from .paths import Layout, TierWError, atomic_write, check_root, dumps, read_bytes
from .transport import SymbolTransport

FETCH_PLAN_LIMIT = 64 * 1024 * 1024
PDB_CAP_MIB_DEFAULT = 512
PDB_CAP_MIB_MAX = 2048
PDB_ESTIMATE_FLOOR = 4 * 1024 * 1024
DISK_MARGIN = 1024 * 1024 * 1024
_SYMBOL_HOSTS = frozenset({'msdl.microsoft.com'})
_SHA = re.compile(r'^[0-9a-f]{64}$')
_PDB_NAME = re.compile(r'^[A-Za-z0-9._-]{1,128}\\.pdb$', re.IGNORECASE)


def _digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def plan_bytes(plan: FetchPlan) -> bytes:
    return dumps(plan.model_dump(mode='json'))


def plan_sha256(plan: FetchPlan) -> str:
    return _digest_bytes(plan_bytes(plan))


def save_plan(plan: FetchPlan, destination: Path) -> str:
    data = plan_bytes(plan)
    atomic_write(Path(destination), data, read_only=True)
    return _digest_bytes(data)


def read_plan(source: Path) -> tuple[FetchPlan, bytes]:
    source = Path(source)
    if source.is_symlink() or not source.is_file():
        raise TierWError('PT-TIERW-INPUT', 'fetch plan must be a regular local file')
    raw = read_bytes(source, FETCH_PLAN_LIMIT)
    plan = load_fetch_plan(raw)
    if plan_bytes(plan) != raw:
        raise TierWError('PT-TIERW-INPUT', 'fetch plan is not in canonical preview form')
    return plan, raw


def _model_bytes(value) -> bytes:
    return dumps(value.model_dump(mode='json'))


def build_binary_plan(pairs: PairsDoc, catalogues: Sequence[Catalogue], pair_ids: Iterable[str], *,
                      max_files: int = 100_000) -> FetchPlan:
    """Build a deterministic offline plan from selected pairs and validated catalogues."""
    selected = tuple(sorted(set(pair_ids)))
    if not selected:
        raise TierWError('PT-TIERW-INPUT', 'select at least one Tier-W pair')
    pairs_by_id = {pair.id: pair for pair in pairs.pairs}
    missing = sorted(set(selected) - pairs_by_id.keys())
    if missing:
        raise TierWError('PT-TIERW-INPUT', f'unknown pair id: {missing[0]}')

    binaries = {binary.id: binary for binary in pairs.binaries}
    catalogue_by_name = {catalogue.file_name: catalogue for catalogue in catalogues}
    if len(catalogue_by_name) != len(catalogues):
        raise TierWError('PT-TIERW-INPUT', 'duplicate catalogue file name')
    uses: dict[str, set[str]] = defaultdict(set)
    binary_by_sha: dict[str, PairBinary] = {}
    for pair_id in selected:
        pair = pairs_by_id[pair_id]
        for binary_id in (pair.older, pair.newer):
            binary = binaries.get(binary_id)
            if binary is None:
                raise TierWError('PT-TIERW-INPUT', f'pair {pair_id} references a missing binary')
            previous = binary_by_sha.setdefault(binary.sha256, binary)
            if previous.file_name != binary.file_name or previous.record_sha256 != binary.record_sha256:
                raise TierWError('PT-TIERW-INPUT', 'one SHA-256 has conflicting catalogue identity')
            uses[binary.sha256].add(pair_id)

    entries: list[FetchItem] = []
    exclusions: list[FetchExclusion] = []
    for sha256 in sorted(binary_by_sha):
        binary = binary_by_sha[sha256]
        catalogue = catalogue_by_name.get(binary.file_name)
        build = next((item for item in catalogue.builds if item.sha256 == sha256), None) if catalogue else None
        if build is None or catalogue is None or build.record_sha256 != binary.record_sha256:
            raise TierWError('PT-TIERW-INPUT', f'catalogue does not verify pair binary {sha256[:12]}')
        reason = None
        if build.machine != 0x8664:
            reason = 'not-x64'
        elif build.download == 'unavailable':
            reason = 'unavailable'
        elif build.size_of_image is None:
            reason = 'unresolved-size'
        if reason:
            exclusions.append(FetchExclusion(file_name=binary.file_name, sha256=sha256, reason=reason))
            continue
        url = symbol_server_url(binary.file_name, build.timestamp, build.size_of_image)
        entries.append(FetchItem(
            kind='binary', file_name=binary.file_name, source_url=url, sha256=sha256,
            record_sha256=build.record_sha256, size=build.size, cap_bytes=build.size,
            timestamp=build.timestamp, size_of_image=build.size_of_image,
            pair_ids=tuple(sorted(uses[sha256])),
        ))

    entries.sort(key=lambda item: (item.sha256, item.file_name))
    deferred = entries[max_files:]
    entries = entries[:max_files]
    exclusions.extend(FetchExclusion(file_name=item.file_name, sha256=item.sha256, reason='deferred')
                      for item in deferred)
    source_digests = [FetchInput(source='pairs', sha256=_digest_bytes(_model_bytes(pairs)))]
    source_digests.extend(
        FetchInput(source=f'catalogue:{name}', sha256=_digest_bytes(_model_bytes(cat)))
        for name, cat in sorted(catalogue_by_name.items())
    )
    return FetchPlan(
        contract='tier-w-fetch-plan/1', tier='W', operation='binary', corpus_id=pairs.corpus_id,
        selected_pairs=selected, max_files=max_files,
        source_digests=tuple(sorted(source_digests, key=lambda item: item.source)),
        entries=tuple(entries),
        exclusions=tuple(sorted(exclusions, key=lambda item: (item.file_name, item.sha256 or '', item.reason))),
    )


def _local_binary(root: Path, entry: FetchItem) -> Path:
    return Path(root) / 'binaries' / entry.sha256 / entry.file_name


def build_pdb_plan(root: Path, binary_plan: FetchPlan, *, max_files: int = 100_000,
                   pdb_cap_mib: int = PDB_CAP_MIB_DEFAULT) -> FetchPlan:
    """Build a PDB plan offline, using only verified local binaries and CodeView records."""
    if binary_plan.operation != 'binary':
        raise TierWError('PT-TIERW-INPUT', 'PDB plan requires a binary fetch plan')
    if not 1 <= pdb_cap_mib <= PDB_CAP_MIB_MAX:
        raise TierWError('PT-TIERW-CONFIG', f'PDB cap must be 1..{PDB_CAP_MIB_MAX} MiB')
    root = check_root(root)
    binary_plan_hash = plan_sha256(binary_plan)
    entries: list[FetchItem] = []
    exclusions: list[FetchExclusion] = []
    inputs = [FetchInput(source='binary-plan', sha256=binary_plan_hash)]
    for binary in binary_plan.entries:
        path = _local_binary(root, binary)
        if path.is_symlink() or not path.is_file() or digest_file(path) != binary.sha256:
            raise TierWError('PT-TIERW-VERIFY', f'verified local binary is missing: {binary.sha256[:12]}')
        inputs.append(FetchInput(source=f'binary:{binary.sha256}', sha256=binary.sha256))
        try:
            overview = inspect_pe(path)
        except (OSError, ValueError):
            raise TierWError('PT-TIERW-VERIFY', f'local PE inspection failed: {binary.sha256[:12]}') from None
        codeview = overview.codeview
        if codeview is None:
            exclusions.append(FetchExclusion(file_name=binary.file_name, sha256=binary.sha256,
                                             reason='no-codeview'))
            continue
        name = codeview.pdb_path.replace('\\', '/').rsplit('/', 1)[-1]
        if not _PDB_NAME.fullmatch(name):
            exclusions.append(FetchExclusion(file_name=binary.file_name, sha256=binary.sha256,
                                             reason='no-codeview'))
            continue
        try:
            guid = str(uuid.UUID(codeview.guid))
        except (ValueError, AttributeError, TypeError):
            exclusions.append(FetchExclusion(file_name=binary.file_name, sha256=binary.sha256,
                                             reason='no-codeview'))
            continue
        if isinstance(codeview.age, bool) or not isinstance(codeview.age, int) or not 0 <= codeview.age <= 0xFFFFFFFF:
            exclusions.append(FetchExclusion(file_name=binary.file_name, sha256=binary.sha256,
                                             reason='no-codeview'))
            continue
        pdb_name = name.lower()
        guid_hex = uuid.UUID(guid).hex.upper()
        url = f'{SYMBOL_SERVER}/{pdb_name}/{guid_hex}{codeview.age:X}/{pdb_name}'
        entries.append(FetchItem(
            kind='pdb', file_name=pdb_name, source_url=url, cap_bytes=pdb_cap_mib * 1024 * 1024,
            binary_sha256=binary.sha256, binary_size=binary.size, guid=guid, age=codeview.age,
            pair_ids=binary.pair_ids,
        ))
    entries.sort(key=lambda item: (item.binary_sha256, item.file_name))
    deferred = entries[max_files:]
    entries = entries[:max_files]
    exclusions.extend(FetchExclusion(file_name=item.file_name, sha256=item.binary_sha256, reason='deferred')
                      for item in deferred)
    return FetchPlan(
        contract='tier-w-fetch-plan/1', tier='W', operation='pdb', corpus_id=binary_plan.corpus_id,
        selected_pairs=binary_plan.selected_pairs, max_files=max_files,
        source_digests=tuple(sorted(inputs, key=lambda item: item.source)),
        input_plan_sha256=binary_plan_hash, entries=tuple(entries),
        exclusions=tuple(sorted(exclusions, key=lambda item: (item.file_name, item.sha256 or '', item.reason))),
    )


def _confirmed_plan(plan_file: Path, expected_sha256: str, current_plan: FetchPlan,
                    operation: str) -> tuple[FetchPlan, str]:
    plan, raw = read_plan(plan_file)
    if plan.operation != operation or current_plan.operation != operation:
        raise TierWError('PT-TIERW-INPUT', f'expected a {operation} plan')
    if not isinstance(expected_sha256, str) or not _SHA.fullmatch(expected_sha256):
        raise TierWError('PT-TIERW-CONFIG', 'confirmation must be the displayed lowercase plan SHA-256')
    digest = _digest_bytes(raw)
    if digest != expected_sha256 or raw != plan_bytes(current_plan):
        raise TierWError('PT-TIERW-CONFIG', 'plan confirmation is stale or does not match the current offline preview')
    return plan, digest


def _consent(plan: FetchPlan, consent_hosts: Iterable[str]) -> AcquisitionConsent:
    urls = frozenset(item.source_url for item in plan.entries)
    hosts = frozenset(consent_hosts)
    required = frozenset(urlsplit(url).hostname or '' for url in urls)
    if hosts != required or (hosts and hosts != _SYMBOL_HOSTS):
        raise TierWError('PT-TIERW-CONFIG', 'consent hosts must exactly match the displayed plan')
    return AcquisitionConsent(hosts=hosts, urls=urls)


def _ledger(root: Path, plan: FetchPlan) -> AnnotationLog:
    return AnnotationLog(Layout(root).ledger(plan.corpus_id))


def _record(log: AnnotationLog, plan: FetchPlan, plan_digest: str, item: FetchItem,
            status: str, *, actual_sha256: str | None = None, actual_size: int | None = None,
            redirect_host: str | None = None, error_code: str | None = None) -> dict:
    identity = item.sha256 if item.kind == 'binary' else item.binary_sha256
    return log.append(
        phase='fetch', operation=plan.operation, corpus_id=plan.corpus_id,
        plan_sha256=plan_digest, item_sha256=identity, file_name=item.file_name, status=status,
        source_url=item.source_url, redirect_host=redirect_host, retrieved_at=None,
        expected_sha256=item.sha256, actual_sha256=actual_sha256, expected_size=item.size,
        actual_size=actual_size, error_code=error_code,
    )


def _file_has_binary(path: Path, item: FetchItem) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    try:
        if path.stat().st_size != item.size or digest_file(path) != item.sha256:
            return False
        fmt, machine = identify(path)
        return fmt == 'pe' and machine == 0x8664
    except OSError:
        return False


def _pdb_path(root: Path, item: FetchItem) -> Path:
    guid_age = f'{uuid.UUID(item.guid).hex.upper()}{item.age:X}'
    return Layout(root).pdb(item.file_name, guid_age)


def _file_has_pdb(path: Path, item: FetchItem) -> tuple[bool, str | None, int | None]:
    if path.is_symlink() or not path.is_file():
        return False, None, None
    try:
        size = path.stat().st_size
        if not 0 < size <= item.cap_bytes:
            return False, None, size
        identity = read_identity(path)
        if identity.guid.lower() != item.guid.lower() or identity.age != item.age:
            return False, None, size
        return True, digest_file(path), size
    except (OSError, MsfError, ValueError):
        return False, None, None


def required_free_bytes(root: Path, plan: FetchPlan, *, pdb_cap_mib: int = PDB_CAP_MIB_DEFAULT) -> int:
    """SPEC-33 s4 disk reserve: missing bytes + bounded PDB estimate + 1 GiB."""
    missing = 0
    if plan.operation == 'binary':
        for item in plan.entries:
            if not _file_has_binary(_local_binary(root, item), item):
                missing += item.size
        pdb_cap = min(max(1, pdb_cap_mib), PDB_CAP_MIB_MAX) * 1024 * 1024
        pdb_estimate = sum(min(pdb_cap, max(PDB_ESTIMATE_FLOOR, 2 * item.size)) for item in plan.entries)
    else:
        pdb_estimate = 0
        for item in plan.entries:
            if not _file_has_pdb(_pdb_path(root, item), item)[0]:
                missing += min(item.cap_bytes, max(PDB_ESTIMATE_FLOOR, 2 * item.binary_size))
    return missing + pdb_estimate + DISK_MARGIN


def _free_bytes(root: Path) -> int:
    probe = Path(root)
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    return shutil.disk_usage(probe).free


def _preflight(root: Path, plan: FetchPlan, free_bytes: int | None) -> None:
    required = required_free_bytes(root, plan)
    available = _free_bytes(root) if free_bytes is None else free_bytes
    if available < required:
        raise TierWError('PT-TIERW-CONFIG', f'insufficient free disk space: need {required} bytes, have {available}')


def _promote(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise TierWError('PT-TIERW-VERIFY', 'staged download is not a regular file')
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise TierWError('PT-TIERW-VERIFY', 'refusing to replace a symlinked destination')
    if destination.exists():
        os.chmod(destination, stat.S_IREAD | stat.S_IWRITE)
    os.replace(source, destination)
    os.chmod(destination, stat.S_IREAD)


def _status(error: Exception) -> tuple[str, str]:
    if isinstance(error, AcquisitionError):
        if error.code == 'PT-ACQ-NOTFOUND':
            return 'not-found', error.code
        if error.code == 'PT-ACQ-VERIFY':
            return 'rejected', error.code
        if error.code == 'PT-ACQ-CANCEL':
            return 'cancelled', error.code
        return 'failed', error.code
    if isinstance(error, TierWError):
        return 'rejected' if error.code == 'PT-TIERW-VERIFY' else 'failed', error.code
    if isinstance(error, OSError):
        return 'failed', 'PT-TIERW-NETWORK'
    return 'failed', 'PT-TIERW-VERIFY'


def fetch_binaries(plan_file: Path, expected_sha256: str, current_plan: FetchPlan, *,
                   consent_hosts: Iterable[str], root: Path, transport: Transport | None = None,
                   cancel: threading.Event | None = None, disk_free_bytes: int | None = None) -> list[dict]:
    """Fetch and validate every selected binary; preserve successful earlier entries on partial failure."""
    plan, digest = _confirmed_plan(plan_file, expected_sha256, current_plan, 'binary')
    if plan.corpus_id != current_plan.corpus_id:
        raise TierWError('PT-TIERW-CONFIG', 'fetch plan corpus changed')
    root = check_root(root)
    consent = _consent(plan, consent_hosts)
    _preflight(root, plan, disk_free_bytes)
    cancel = cancel or threading.Event()
    transport = transport or Transport(cancel=cancel)
    layout = Layout(root)
    if layout.staging.is_symlink():
        raise TierWError('PT-TIERW-CONFIG', 'staging directory must not be a symlink')
    layout.staging.mkdir(mode=0o700, parents=True, exist_ok=True)
    log = _ledger(root, plan)
    results = []
    for item in plan.entries:
        destination = _local_binary(root, item)
        if _file_has_binary(destination, item):
            _record(log, plan, digest, item, 'reused', actual_sha256=item.sha256, actual_size=item.size)
            results.append({'file_name': item.file_name, 'sha256': item.sha256, 'status': 'reused'})
            continue
        stage = create_staging(layout.staging)
        try:
            if cancel.is_set():
                raise AcquisitionError('PT-ACQ-CANCEL', 'acquisition cancelled', recoverable=True)
            planned = PlannedDownload(
                side='older', file_name=item.file_name, sha256=item.sha256, size=item.size,
                url=item.source_url, record_sha256=item.record_sha256,
            )
            acquired = acquire(planned, consent, stage, transport)
            if acquired.format != 'pe' or acquired.machine != 0x8664:
                raise AcquisitionError('PT-ACQ-VERIFY', 'download is not a valid AMD64 PE')
            if not _file_has_binary(Path(acquired.path), item):
                raise AcquisitionError('PT-ACQ-VERIFY', 'staged PE identity failed recheck')
            _promote(Path(acquired.path), destination)
            _record(log, plan, digest, item, 'fetched', actual_sha256=acquired.sha256,
                    actual_size=acquired.size, redirect_host=acquired.provenance.redirect_host)
            results.append({'file_name': item.file_name, 'sha256': item.sha256, 'status': 'fetched'})
        except (AcquisitionError, TierWError, OSError, ValueError) as error:
            status, code = _status(error)
            _record(log, plan, digest, item, status, error_code=code)
            results.append({'file_name': item.file_name, 'sha256': item.sha256, 'status': status,
                            'error_code': code})
            if status == 'cancelled':
                for rest in plan.entries[plan.entries.index(item) + 1:]:
                    _record(log, plan, digest, rest, 'cancelled', error_code='PT-TIERW-CANCEL')
                    results.append({'file_name': rest.file_name, 'sha256': rest.sha256, 'status': 'cancelled',
                                    'error_code': 'PT-TIERW-CANCEL'})
                break
        finally:
            remove_staging(stage)
    for exclusion in plan.exclusions:
        _record_exclusion(log, plan, digest, exclusion)
        results.append({'file_name': exclusion.file_name, 'sha256': exclusion.sha256,
                        'status': 'deferred' if exclusion.reason == 'deferred' else exclusion.reason})
    return results


def _record_exclusion(log: AnnotationLog, plan: FetchPlan, digest: str, exclusion: FetchExclusion) -> None:
    log.append(phase='fetch', operation=plan.operation, corpus_id=plan.corpus_id,
               plan_sha256=digest, item_sha256=exclusion.sha256, file_name=exclusion.file_name,
               status=exclusion.reason, source_url=None, redirect_host=None, retrieved_at=None,
               expected_sha256=exclusion.sha256, actual_sha256=None, expected_size=None, actual_size=None,
               error_code=None)


def fetch_pdbs(plan_file: Path, expected_sha256: str, current_plan: FetchPlan, *,
               consent_hosts: Iterable[str], root: Path, transport: SymbolTransport | None = None,
               cancel: threading.Event | None = None, disk_free_bytes: int | None = None) -> list[dict]:
    """Fetch PDBs only after a fresh local PE inspection and exact plan confirmation."""
    plan, digest = _confirmed_plan(plan_file, expected_sha256, current_plan, 'pdb')
    root = check_root(root)
    consent = _consent(plan, consent_hosts)
    _preflight(root, plan, disk_free_bytes)
    cancel = cancel or threading.Event()
    transport = transport or SymbolTransport(cancel=cancel)
    layout = Layout(root)
    layout.staging.mkdir(mode=0o700, parents=True, exist_ok=True)
    if layout.staging.is_symlink():
        raise TierWError('PT-TIERW-CONFIG', 'staging directory must not be a symlink')
    log = _ledger(root, plan)
    results = []
    for item in plan.entries:
        destination = _pdb_path(root, item)
        good, existing_sha, existing_size = _file_has_pdb(destination, item)
        if good:
            _record(log, plan, digest, item, 'reused', actual_sha256=existing_sha, actual_size=existing_size)
            results.append({'file_name': item.file_name, 'binary_sha256': item.binary_sha256,
                            'status': 'reused', 'sha256': existing_sha})
            continue
        stage = create_staging(layout.staging)
        try:
            if cancel.is_set():
                raise AcquisitionError('PT-ACQ-CANCEL', 'acquisition cancelled', recoverable=True)
            downloaded = transport.download_pdb(
                item.source_url, consent, stage, expected_guid=item.guid, expected_age=item.age,
                cap_bytes=item.cap_bytes,
            )
            _promote(downloaded.path, destination)
            _record(log, plan, digest, item, 'fetched', actual_sha256=downloaded.sha256,
                    actual_size=downloaded.size, redirect_host=downloaded.redirect_host)
            results.append({'file_name': item.file_name, 'binary_sha256': item.binary_sha256,
                            'status': 'fetched', 'sha256': downloaded.sha256})
        except (AcquisitionError, TierWError, OSError, ValueError) as error:
            status, code = _status(error)
            _record(log, plan, digest, item, status, error_code=code)
            results.append({'file_name': item.file_name, 'binary_sha256': item.binary_sha256,
                            'status': status, 'error_code': code})
            if status == 'cancelled':
                for rest in plan.entries[plan.entries.index(item) + 1:]:
                    _record(log, plan, digest, rest, 'cancelled', error_code='PT-TIERW-CANCEL')
                    results.append({'file_name': rest.file_name, 'binary_sha256': rest.binary_sha256,
                                    'status': 'cancelled', 'error_code': 'PT-TIERW-CANCEL'})
                break
        finally:
            remove_staging(stage)
    for exclusion in plan.exclusions:
        _record_exclusion(log, plan, digest, exclusion)
        results.append({'file_name': exclusion.file_name, 'sha256': exclusion.sha256,
                        'status': exclusion.reason})
    return results
