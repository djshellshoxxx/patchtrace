"""Tier-W symbol-server PDB transport (SPEC-33 s4.3).

Reuses SPEC-08 transport retry, streaming, cancellation, redirect and deadline
machinery. The returned digest is computed locally; it is not an authenticity
claim. No URL with a signed redirect query is returned or persisted.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable

from patchtrace.acquisition.contracts import AcquisitionConsent, AcquisitionError, SYMBOL_SERVER
from patchtrace.acquisition.transport import (
    DOWNLOAD_DEADLINE,
    REDIRECT_STATUS,
    Downloaded,
    SYMBOL_HOST,
    Transport,
    _check,
    _consented,
)
from .msf import MsfError, is_pdb_magic, read_identity


class SymbolTransport(Transport):
    """Download a PDB after exact-plan consent and verify its MSF identity."""

    def download_pdb(self, url: str, consent: AcquisitionConsent, directory: Path, *,
                     expected_guid: str, expected_age: int, cap_bytes: int,
                     progress: Callable[[int, int], None] | None = None) -> Downloaded:
        _consented(url, consent)
        if urllib.parse.urlsplit(url).hostname != SYMBOL_HOST:
            raise AcquisitionError('PT-ACQ-CONFIG', 'PDB download is not a symbol-server URL')
        if not 0 < cap_bytes <= 2 * 1024 * 1024 * 1024:
            raise AcquisitionError('PT-ACQ-LIMIT', 'PDB size cap is outside the supported range')
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)

        def attempt() -> Downloaded:
            response = self._open('GET', url)
            redirect_host = None
            path = None
            try:
                if response.status == 404:
                    raise AcquisitionError('PT-ACQ-NOTFOUND', 'PDB is not on the symbol server')
                if response.status in REDIRECT_STATUS:
                    location = response.headers.get('Location')
                    if not location:
                        raise AcquisitionError('PT-ACQ-PROVIDER', 'PDB redirect omitted Location')
                    target = urllib.parse.urljoin(url, location)
                    redirect_host = _check(target, blob=True)
                    response.close()
                    response = self._open('GET', target)
                    if response.status in REDIRECT_STATUS:
                        raise AcquisitionError('PT-ACQ-NETWORK', 'more than one PDB redirect refused')
                self._retryable(response)
                if response.status != 200:
                    raise AcquisitionError('PT-ACQ-PROVIDER', f'PDB download returned HTTP {response.status}')
                fd, name = tempfile.mkstemp(prefix='.pdb-', dir=directory)
                path = Path(name)
                digest = hashlib.sha256()
                size = 0
                deadline = self.clock() + DOWNLOAD_DEADLINE
                if progress:
                    progress(0, cap_bytes)
                try:
                    with os.fdopen(fd, 'wb') as output:
                        def sink(chunk: bytes) -> None:
                            nonlocal size
                            size += len(chunk)
                            digest.update(chunk)
                            output.write(chunk)
                            if progress:
                                progress(size, cap_bytes)
                        self._read(response, sink, cap_bytes, 'PDB', deadline)
                        output.flush()
                        os.fsync(output.fileno())
                    with path.open('rb') as source:
                        if not is_pdb_magic(source.read(32)):
                            raise AcquisitionError('PT-ACQ-VERIFY', 'download is not an MSF 7.00 PDB')
                    identity = read_identity(path)
                    if (identity.guid.lower() != expected_guid.lower()
                            or identity.age != expected_age):
                        raise AcquisitionError('PT-ACQ-VERIFY', 'PDB GUID or age does not match the PE CodeView record')
                except BaseException:
                    path.unlink(missing_ok=True)
                    raise
                stamp = datetime.now(UTC).isoformat(timespec='seconds').replace('+00:00', 'Z')
                return Downloaded(path, digest.hexdigest(), size, url, redirect_host, stamp)
            except MsfError:
                if path is not None:
                    path.unlink(missing_ok=True)
                raise AcquisitionError('PT-ACQ-VERIFY', 'downloaded PDB structure is invalid') from None
            finally:
                response.close()

        return self._with_retries(attempt)
