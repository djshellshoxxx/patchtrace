"""Tier-W fetch (SPEC-33 s4): plan, binaries, PDB identity and PDB download, resume, disk preflight, ledger.

Binaries take the existing acquisition path (`quarantine.acquire`, SHA-256 and size checked against Winbindex). PDB
identity comes from the stored PE's CodeView record; a downloaded PDB is kept only when the stdlib MSF reader finds
the same GUID and DBI age. All events go to the hash-chained ledger (`tier-w-fetch/1`); only host names of redirects
are recorded, never signed URLs. Nothing here opens a socket itself: callers pass a `SymbolTransport`.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import uuid
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

from patchtrace.acquisition import quarantine
from patchtrace.acquisition.contracts import AcquisitionError, PlannedDownload, symbol_server_url
from patchtrace.acquisition.transport import SYMBOL_HOST, AcquisitionConsent
from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.pe_overview.inspect import inspect_pe

from ..label import AnnotationLog
from . import msf
from .contracts import PairsDoc
from .paths import TIER, Layout, TierWError, check_corpus_id
from .transport import SymbolTransport, pdb_cap_bytes

CONTRACT = 'tier-w-fetch/1'
PDB_NAME = re.compile(r'[A-Za-z0-9._-]{1,128}')
X64 = 0x8664
MARGIN = 1 << 30
PDB_FLOOR = 4 << 20
DiskFree = Callable[[Path], int]


def pdb_name(pdb_path: str) -> str:
    """Basename of the CodeView path (split on both separators); must be a plain `.pdb` name."""
    name = pdb_path.replace('\\', '/').rsplit('/', 1)[-1]
    if not PDB_NAME.fullmatch(name) or not name.lower().endswith('.pdb'):
        raise TierWError('PT-TIERW-INPUT', 'CodeView PDB name is not a plain *.pdb file name')
    return name


def guid_age(guid: str, age: int) -> str:
    """Symbol-server key: GUID as 32 uppercase hex digits followed by the age in uppercase hex."""
    return uuid.UUID(guid).hex.upper() + f'{age:X}'


def pdb_url(name: str, guid: str, age: int) -> str:
    return f'https://{SYMBOL_HOST}/download/symbols/{name}/{guid_age(guid, age)}/{name}'


def pdb_request(pe_path: Path) -> tuple[str, str, int]:
    """(pdb name, guid, age) from the stored PE's CodeView record."""
    with VerifiedArtifactReader.open_path(pe_path) as reader:
        view = inspect_pe(reader).codeview
    if view is None:
        raise TierWError('PT-TIERW-INPUT', 'PE image has no CodeView (RSDS) record')
    return pdb_name(view.pdb_path), view.guid, view.age


def plan_binaries(pairs: PairsDoc, manifest: dict) -> list[PlannedDownload]:
    """One planned download per Tier-W manifest binary, in manifest order (offline: fetches and prints nothing)."""
    records = {b.sha256: b.record_sha256 for b in pairs.binaries}
    planned = []
    for binary in manifest['binaries']:
        if binary.get('tier') != TIER or binary['sha256'] not in records:
            raise TierWError('PT-TIERW-INPUT', f'manifest binary {binary.get("id")} is not in the pairs document')
        identity = binary['winbindex']
        if not binary.get('size') or not identity.get('virtual_size'):
            raise TierWError('PT-TIERW-INPUT', f'binary {binary["id"]} has no size or SizeOfImage; run resolve first')
        planned.append(PlannedDownload(
            side='older', file_name=binary['file_name'], sha256=binary['sha256'], size=binary['size'],
            url=symbol_server_url(binary['file_name'], identity['timestamp'], identity['virtual_size']),
            record_sha256=records[binary['sha256']]))
    return planned


def consent_for(urls: Iterable[str], hosts: Iterable[str]) -> AcquisitionConsent:
    """Consent covers exactly the planned URLs, and only when the owner named every host they use."""
    consent = AcquisitionConsent.for_urls(urls)
    missing = sorted(consent.hosts - set(hosts))
    if missing:
        raise TierWError('PT-TIERW-CONFIG', f'--consent-hosts must include {", ".join(missing)}')
    return consent


def disk_needed(binary_sizes: Sequence[int], pdb_cap: int) -> int:
    """Binary bytes + a PDB estimate (max(4 MiB, 2 x binary), capped) per binary + 1 GiB margin."""
    estimate = sum(min(pdb_cap, max(PDB_FLOOR, 2 * s)) for s in binary_sizes)
    return sum(binary_sizes) + estimate + MARGIN


def ensure_disk(root: Path, needed: int, free: DiskFree = lambda p: shutil.disk_usage(p).free) -> None:
    probe = Path(root)
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    available = free(probe)
    if available < needed:
        raise TierWError('PT-TIERW-CONFIG', f'{needed} bytes needed, {available} free under the corpus root')


def cancelled(layout: Layout) -> bool:
    return layout.cancel_file.exists()


class Ledger:
    """Typed view of the hash-chained fetch ledger."""

    def __init__(self, layout: Layout, corpus_id: str):
        self.log = AnnotationLog(layout.ledger(check_corpus_id(corpus_id)))

    def record(self, event: str, **fields) -> dict:
        return self.log.append(contract=CONTRACT, tier=TIER, event=event, **fields)

    def last(self, event: str, **match) -> dict | None:
        for item in reversed(self.log.events()):
            if item.get('event') == event and all(item.get(k) == v for k, v in match.items()):
                return item
        return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def fetch_binary(planned: PlannedDownload, root: Path, layout: Layout, ledger: Ledger, transport: SymbolTransport,
                 consent: AcquisitionConsent) -> dict:
    """Fetch one Winbindex binary into `<root>/binaries/<sha256>/<name>`; only x64 PE images are kept."""
    final = Path(root) / 'binaries' / planned.sha256 / planned.file_name
    if final.is_file() and sha256_file(final) == planned.sha256:
        return {'status': 'resumed', 'sha256': planned.sha256}
    layout.staging.mkdir(parents=True, exist_ok=True)
    staging = quarantine.create_staging(layout.staging)
    try:
        got = quarantine.acquire(planned, consent, staging, transport)
        if got.format != 'pe' or got.machine != X64:
            ledger.record('binary-rejected', file_sha256=planned.sha256, reason='not-x64-pe')
            return {'status': 'rejected', 'sha256': planned.sha256, 'reason': 'not-x64-pe'}
        final.parent.mkdir(parents=True, exist_ok=True)
        os.replace(got.path, final)
        final.chmod(stat.S_IREAD)
        prov = got.provenance
        ledger.record('binary-fetched', file_sha256=got.sha256, size=got.size, file_name=planned.file_name,
                      source_url=prov.source_url, redirect_host=prov.redirect_host,
                      retrieved_at=prov.retrieved_at, winbindex_record_sha256=prov.winbindex_record_sha256)
        return {'status': 'fetched', 'sha256': got.sha256}
    finally:
        quarantine.remove_staging(staging)


def fetch_pdb(pe_path: Path, layout: Layout, ledger: Ledger, transport: SymbolTransport,
              consent: AcquisitionConsent, *, cap: int | None = None) -> dict:
    """Fetch the PDB for one stored PE. Returns {status: fetched|resumed|missing|rejected, ...}. A remote 404 and a
    rejected body are results; cancel, network and consent errors propagate to the caller."""
    cap = pdb_cap_bytes() if cap is None else cap
    name, guid, age = pdb_request(pe_path)
    key = guid_age(guid, age)
    final = layout.pdb(name, key)
    previous = ledger.last('pdb-fetched', pdb=name.lower(), guid_age=key)
    if previous and final.is_file() and sha256_file(final) == previous['file_sha256']:
        return {'status': 'resumed', 'guid_age': key, 'sha256': previous['file_sha256']}
    layout.staging.mkdir(parents=True, exist_ok=True)
    try:
        got = transport.download_pdb(pdb_url(name, guid, age), consent, layout.staging, cap)
    except AcquisitionError as exc:
        if exc.code == 'PT-ACQ-NOTFOUND':
            ledger.record('pdb-missing', pdb=name.lower(), guid_age=key)
            return {'status': 'missing', 'guid_age': key}
        if exc.code == 'PT-ACQ-VERIFY':
            ledger.record('pdb-rejected', pdb=name.lower(), guid_age=key, reason='not-msf')
            return {'status': 'rejected', 'guid_age': key, 'reason': 'not-msf'}
        raise
    reason = _identity_mismatch(got.path, guid, age)
    if reason:
        got.path.unlink(missing_ok=True)
        ledger.record('pdb-rejected', pdb=name.lower(), guid_age=key, reason=reason, file_sha256=got.sha256)
        return {'status': 'rejected', 'guid_age': key, 'reason': reason}
    final.parent.mkdir(parents=True, exist_ok=True)
    os.replace(got.path, final)
    final.chmod(stat.S_IREAD)
    ledger.record('pdb-fetched', pdb=name.lower(), guid_age=key, file_sha256=got.sha256, size=got.size,
                  source_url=got.source_url, redirect_host=got.redirect_host, retrieved_at=got.retrieved_at)
    return {'status': 'fetched', 'guid_age': key, 'sha256': got.sha256}


def _identity_mismatch(path: Path, guid: str, age: int) -> str | None:
    try:
        info = msf.read_identity(path)
    except msf.MsfError as exc:
        return f'unreadable:{exc.code}'
    if uuid.UUID(info.guid) != uuid.UUID(guid) or info.age != age:
        return 'identity-mismatch'
    return None
