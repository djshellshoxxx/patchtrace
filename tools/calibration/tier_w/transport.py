"""Throttled symbol-server transport for PDBs (SPEC-33 s4.3-4.4).

Subclasses the acquisition `Transport` to reuse its open, retry, redirect-host and read machinery. A PDB has no
hash known in advance, so a size cap replaces the planned size and the SHA-256 is computed while streaming. The
body must start with the MSF 7.00 magic. Only the symbol host (consent-listed) and its single blob redirect are used.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from patchtrace.acquisition import transport as base
from patchtrace.acquisition.contracts import AcquisitionError
from patchtrace.acquisition.transport import AcquisitionConsent, Downloaded

from .msf import MAGIC

DEFAULT_PDB_CAP_MIB = 512
MAX_PDB_CAP_MIB = 2048
DEFAULT_MIN_INTERVAL = 2.0


def pdb_cap_bytes(cap_mib: int = DEFAULT_PDB_CAP_MIB) -> int:
    if not 1 <= cap_mib <= MAX_PDB_CAP_MIB:
        raise AcquisitionError('PT-ACQ-INPUT', f'--pdb-cap-mib must be 1..{MAX_PDB_CAP_MIB}')
    return cap_mib * 1024 * 1024


@dataclass
class SymbolTransport(base.Transport):
    """Every HTTP request waits at least `min_interval` seconds after the previous one (retries and probes too)."""
    min_interval: float = DEFAULT_MIN_INTERVAL
    _last: float | None = field(default=None, init=False, repr=False)

    def _open(self, method: str, url: str, timeout: float = base.TIMEOUT):
        if self._last is not None:
            wait = self.min_interval - (self.clock() - self._last)
            if wait > 0:
                self.sleep(wait, self.cancel)
            base._cancelled(self.cancel)
        self._last = self.clock()
        return super()._open(method, url, timeout)

    def download_pdb(self, url: str, consent: AcquisitionConsent, directory: Path, cap: int) -> Downloaded:
        base._consented(url, consent)
        if urllib.parse.urlsplit(url).hostname != base.SYMBOL_HOST:
            raise AcquisitionError('PT-ACQ-CONFIG', 'PDBs come only from the symbol server')
        return self._with_retries(lambda: self._pdb_once(url, Path(directory), cap))

    def _pdb_once(self, url: str, directory: Path, cap: int) -> Downloaded:
        redirect_host = None
        response = self._open('GET', url)
        try:
            if response.status == 404:
                raise AcquisitionError('PT-ACQ-NOTFOUND', 'PDB is not on the symbol server')
            if response.status in base.REDIRECT_STATUS:
                location = response.headers.get('Location')
                if not location:
                    raise AcquisitionError('PT-ACQ-PROVIDER', 'redirect without Location')
                try:
                    target = urllib.parse.urljoin(url, location)
                except ValueError:
                    raise AcquisitionError('PT-ACQ-NETWORK', 'invalid URL refused') from None
                redirect_host = base._check(target, blob=True)
                response.close()
                response = self._open('GET', target)
                if response.status in base.REDIRECT_STATUS:
                    raise AcquisitionError('PT-ACQ-NETWORK', 'more than one redirect refused')
            self._retryable(response)
            if response.status != 200:
                raise AcquisitionError('PT-ACQ-PROVIDER', f'download returned HTTP {response.status}')
            return self._stream(response, url, redirect_host, directory, cap)
        finally:
            response.close()

    def _stream(self, response, url: str, redirect_host: str | None, directory: Path, cap: int) -> Downloaded:
        fd, name = tempfile.mkstemp(prefix='.pdb-', dir=directory)
        path, digest, size = Path(name), hashlib.sha256(), 0
        try:
            with os.fdopen(fd, 'wb') as out:
                def sink(chunk: bytes) -> None:
                    nonlocal size
                    size += len(chunk)
                    digest.update(chunk)
                    out.write(chunk)
                self._read(response, sink, cap, 'PDB', self.clock() + base.DOWNLOAD_DEADLINE)
                out.flush()
                os.fsync(out.fileno())
            with path.open('rb') as check:
                if check.read(len(MAGIC)) != MAGIC:
                    raise AcquisitionError('PT-ACQ-VERIFY', 'body is not an MSF 7.00 PDB')
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return Downloaded(path, digest.hexdigest(), size, url, redirect_host, base._stamp(self.now()))
