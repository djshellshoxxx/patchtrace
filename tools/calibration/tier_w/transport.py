"""Throttled symbol-server transport for PDBs (SPEC-33 s4.3-4.4).

Subclasses the acquisition `Transport` to reuse its open, retry, redirect-host and read machinery. A PDB has no
hash known in advance, so a size cap replaces the planned size and the SHA-256 is computed while streaming. The
body must start with the MSF 7.00 magic. Only the symbol host (consent-listed) and its single blob redirect are used.
"""
from __future__ import annotations

import hashlib
import math
import os
import secrets
import tempfile
import urllib.parse
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from patchtrace import owned_publication as owned
from patchtrace.acquisition import transport as base
from patchtrace.acquisition.contracts import AcquisitionError, PlannedDownload
from patchtrace.acquisition.transport import AcquisitionConsent, Downloaded

from .msf import MAGIC, MsfError, read_identity_snapshot

DEFAULT_PDB_CAP_MIB = 512
MAX_PDB_CAP_MIB = 2048
DEFAULT_MIN_INTERVAL = 2.0


def pdb_cap_bytes(cap_mib: int = DEFAULT_PDB_CAP_MIB) -> int:
    if type(cap_mib) is not int or not 1 <= cap_mib <= MAX_PDB_CAP_MIB:
        raise AcquisitionError('PT-ACQ-INPUT', f'--pdb-cap-mib must be 1..{MAX_PDB_CAP_MIB}')
    return cap_mib * 1024 * 1024


def _close(resource, primary: BaseException | None, label: str) -> None:
    try:
        resource.close()
    except BaseException as exc:
        if primary is None:
            raise
        primary.add_note(f'{label} cleanup also failed: {type(exc).__name__}')


@dataclass
class SymbolTransport(base.Transport):
    """Every HTTP request waits at least `min_interval` seconds after the previous one (retries and probes too)."""
    min_interval: float = DEFAULT_MIN_INTERVAL
    _last: float | None = field(default=None, init=False, repr=False)

    def __post_init__(self):
        self._interval()

    def _interval(self) -> None:
        try:
            valid = (type(self.min_interval) in (int, float) and math.isfinite(self.min_interval)
                     and self.min_interval >= 0)
        except OverflowError:
            valid = False
        if not valid:
            raise AcquisitionError('PT-ACQ-CONFIG', 'request interval must be finite and non-negative')

    def _open(self, method: str, url: str, timeout: float = base.TIMEOUT):
        self._interval()
        if self._last is not None:
            wait = self.min_interval - (self.clock() - self._last)
            if wait > 0:
                self.sleep(wait, self.cancel)
            base._cancelled(self.cancel)
        self._last = self.clock()
        return super()._open(method, url, timeout)

    def _admit(self, url: str, consent: AcquisitionConsent, directory: Path) -> owned.DirectoryAnchor:
        base._consented(url, consent)
        if urllib.parse.urlsplit(url).hostname != base.SYMBOL_HOST:
            raise AcquisitionError('PT-ACQ-CONFIG', 'downloads come only from the symbol server')
        self._interval()
        try:
            return owned.directory_anchor(directory)
        except (OSError, owned.OwnedPublicationError):
            raise AcquisitionError('PT-ACQ-CONFIG', 'download staging requires an existing ordinary directory') from None

    def download(self, planned: PlannedDownload, consent: AcquisitionConsent, directory: Path,
                 progress: Callable[[int, int], None] | None = None) -> Downloaded:
        """Keep the current transport API while binding its returned path to verified owned bytes."""
        try:
            if not isinstance(planned, PlannedDownload):
                raise ValueError('not a download plan')
            planned = PlannedDownload.model_validate(planned.model_dump(mode='python'))
        except (ValueError, TypeError):
            raise AcquisitionError('PT-ACQ-INPUT', 'invalid binary download plan') from None
        anchor = self._admit(planned.url, consent, Path(directory))
        cap = min(base.MAX_DOWNLOAD_BYTES, planned.size)
        return self._with_retries(lambda: self._once(planned.url, anchor, cap, planned=planned, progress=progress))

    def download_pdb(self, url: str, consent: AcquisitionConsent, directory: Path, cap: int, *,
                     expected_guid: str | None = None, expected_age: int | None = None,
                     progress: Callable[[int, int], None] | None = None) -> Downloaded:
        if type(cap) is not int or not 1 <= cap <= MAX_PDB_CAP_MIB * 1024 * 1024:
            raise AcquisitionError('PT-ACQ-INPUT', 'PDB byte cap is outside the supported range')
        expected = None
        if expected_guid is not None or expected_age is not None:
            try:
                if type(expected_age) is not int or not 0 <= expected_age <= 0xFFFFFFFF:
                    raise ValueError('invalid age')
                expected = str(uuid.UUID(expected_guid)), expected_age
            except (ValueError, TypeError, AttributeError):
                raise AcquisitionError('PT-ACQ-INPUT', 'PDB identity requires a valid GUID and uint32 age') from None
        anchor = self._admit(url, consent, Path(directory))
        return self._with_retries(lambda: self._once(url, anchor, cap, expected=expected, progress=progress))

    def _once(self, url: str, anchor: owned.DirectoryAnchor, cap: int, *, planned: PlannedDownload | None = None,
              expected: tuple[str, int] | None = None, progress: Callable[[int, int], None] | None = None) -> Downloaded:
        owned.verify_anchor(anchor)
        redirect_host = None
        response, primary = None, None
        try:
            response = self._open('GET', url)
            if response.status == 404:
                raise AcquisitionError('PT-ACQ-NOTFOUND', 'file is not on the symbol server')
            if response.status in base.REDIRECT_STATUS:
                location = response.headers.get('Location')
                if not location:
                    raise AcquisitionError('PT-ACQ-PROVIDER', 'redirect without Location')
                try:
                    target = urllib.parse.urljoin(url, location)
                except ValueError:
                    raise AcquisitionError('PT-ACQ-NETWORK', 'invalid URL refused') from None
                redirect_host = base._check(target, blob=True)
                prior, response = response, None
                _close(prior, None, 'HTTP response')
                response = self._open('GET', target)
                if response.status in base.REDIRECT_STATUS:
                    raise AcquisitionError('PT-ACQ-NETWORK', 'more than one redirect refused')
            self._retryable(response)
            if response.status != 200:
                raise AcquisitionError('PT-ACQ-PROVIDER', f'download returned HTTP {response.status}')
            return self._stream(response, url, redirect_host, anchor, cap, planned=planned,
                                expected=expected, progress=progress)
        except BaseException as exc:
            primary = exc
            raise
        finally:
            if response is not None:
                _close(response, primary, 'HTTP response')

    def _stream(self, response, url: str, redirect_host: str | None, anchor: owned.DirectoryAnchor, cap: int, *,
                planned: PlannedDownload | None, expected: tuple[str, int] | None,
                progress: Callable[[int, int], None] | None) -> Downloaded:
        """Partials exist only through an owned handle; publish a named stage after verifying exact bytes."""
        output = tempfile.TemporaryFile(mode='w+b', buffering=0, dir=anchor.path)
        digest, size, primary = hashlib.sha256(), 0, None
        try:
            expected_size = planned.size if planned is not None else cap
            if progress:
                progress(0, expected_size)

            def sink(chunk: bytes) -> None:
                nonlocal size
                if output.write(chunk) != len(chunk):
                    raise AcquisitionError('PT-ACQ-VERIFY', 'short download staging write')
                size += len(chunk)
                digest.update(chunk)
                if progress:
                    progress(size, expected_size)

            self._read(response, sink, cap, 'download' if planned is not None else 'PDB',
                       self.clock() + base.DOWNLOAD_DEADLINE)
            output.flush()
            os.fsync(output.fileno())
            if planned is not None and (size != planned.size or digest.hexdigest() != planned.sha256):
                raise AcquisitionError('PT-ACQ-VERIFY', 'download size or SHA-256 differs from its plan')
            try:
                with owned.FileSnapshot(output.fileno(), maximum=cap, expected_size=size,
                                        expected_sha256=digest.hexdigest(),
                                        check=lambda: base._cancelled(self.cancel)) as snapshot:
                    if planned is None:
                        if snapshot.read(0, len(MAGIC)) != MAGIC:
                            raise AcquisitionError('PT-ACQ-VERIFY', 'body is not an MSF 7.00 PDB')
                        if expected is not None:
                            try:
                                identity = read_identity_snapshot(snapshot, lambda: bool(self.cancel and self.cancel.is_set()))
                            except MsfError:
                                base._cancelled(self.cancel)
                                raise AcquisitionError('PT-ACQ-VERIFY', 'PDB structure is invalid') from None
                            if (identity.guid, identity.age) != expected:
                                raise AcquisitionError('PT-ACQ-VERIFY', 'PDB GUID or age differs from the planned CodeView identity')
                    base._cancelled(self.cancel)
                    path = anchor.path / f'.{"download" if planned is not None else "pdb"}-{secrets.token_hex(16)}'
                    owned.publish_stream(path, snapshot, anchor=anchor)
                return Downloaded(path, digest.hexdigest(), size, url, redirect_host, base._stamp(self.now()))
            except owned.OwnedPublicationError:
                raise AcquisitionError('PT-ACQ-VERIFY', 'download staging identity or bytes changed') from None
        except BaseException as exc:
            primary = exc
            raise
        finally:
            _close(output, primary, 'Download staging')
