"""CAP-11: consented in-app 'Set up capa' download (pure service; the dialog is a thin view over it).

Nothing is fetched until the user confirmed the exact plan (URL, size, SHA-256): `ConsentToken.for_plan` is built only
from a displayed plan and `install` refuses a missing or different token before it opens a connection. The archive is
verified against the pinned size and SHA-256, the single executable member is extracted without running it and
verified against its own pinned digest, and only then moved into place. Any failure leaves nothing behind.
The pin is the `intel-tools-pin/1` mapping (tools/intel_tools_pin.json); the network is an injected opener."""
from __future__ import annotations

import hashlib
import io
import os
import re
import tempfile
import threading
import zipfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

ENGINE = 'capa'
MAX_ASSET = 512 * 1024 * 1024
MAX_EXECUTABLE = 1024 * 1024 * 1024
SHA256 = re.compile(r'^[0-9a-f]{64}$')
URL = re.compile(r'^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/download/[^\s]+$')
MANUAL = 'Use the manual steps in the Setup tab (download the pinned release yourself and verify its SHA-256).'

Opener = Callable[[str], Iterable[bytes]]


@dataclass(frozen=True)
class SetupPlan:
    version: str
    url: str
    size: int
    sha256: str
    executable: str
    executable_size: int
    executable_sha256: str

    def consent_text(self) -> str:
        return (f'PatchTrace will download capa {self.version} from:\n{self.url}\n'
                f'Size: {self.size} bytes\nSHA-256: {self.sha256}\n\n'
                'Only after you confirm is anything fetched. No project data is sent. The download is verified '
                'against this SHA-256 and the extracted program against its own pinned digest before it is '
                'used. PatchTrace extracts it and never runs it as part of the download.')


@dataclass(frozen=True)
class Unavailable:
    reason: str


@dataclass(frozen=True)
class ConsentToken:
    url: str
    sha256: str

    @classmethod
    def for_plan(cls, plan: SetupPlan) -> ConsentToken:
        return cls(plan.url, plan.sha256)


@dataclass(frozen=True)
class SetupResult:
    status: Literal['installed', 'refused', 'cancelled', 'failed']
    code: str
    message: str
    path: str | None = None


def _digest(value: object) -> bool:
    return isinstance(value, str) and bool(SHA256.match(value))


def _size(value: object, cap: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value <= cap


def plan_for(os_name: str, pin: Mapping) -> SetupPlan | Unavailable:
    """Plan from the pin, or `Unavailable` (manual steps) when the entry is missing or not trustworthy."""
    version = pin.get('engines', {}).get(ENGINE, {}).get('version')
    asset = pin.get('engines', {}).get(ENGINE, {}).get('assets', {}).get(os_name)
    if not isinstance(asset, Mapping) or not isinstance(version, str):
        return Unavailable(f'No pinned capa download for {os_name!r}. {MANUAL}')
    executable = asset.get('executable')
    checks = (asset.get('format') == 'zip', isinstance(asset.get('url'), str) and bool(URL.match(asset['url'])),
              _digest(asset.get('sha256')), _digest(asset.get('executable_sha256')),
              _size(asset.get('size'), MAX_ASSET), _size(asset.get('executable_size'), MAX_EXECUTABLE),
              isinstance(executable, str) and bool(executable) and PurePosixPath(executable).name == executable
              and executable not in ('.', '..'))
    if not all(checks):
        return Unavailable(f'The pinned capa entry is incomplete or untrusted. {MANUAL}')
    return SetupPlan(version, asset['url'], asset['size'], asset['sha256'], executable, asset['executable_size'],
                     asset['executable_sha256'])


class _Stop(Exception):
    def __init__(self, status: Literal['cancelled', 'failed'], code: str, message: str):
        super().__init__(message)
        self.result = SetupResult(status, code, message)


def _fetch(plan: SetupPlan, opener: Opener, cancel: threading.Event) -> bytes:
    data = bytearray()
    hasher = hashlib.sha256()
    for chunk in opener(plan.url):
        if cancel.is_set():
            raise _Stop('cancelled', 'cancelled', 'Download cancelled; nothing was installed.')
        data += chunk
        hasher.update(chunk)
        if len(data) > plan.size:
            raise _Stop('failed', 'size-mismatch', 'The download is larger than the pinned size.')
    if cancel.is_set():
        raise _Stop('cancelled', 'cancelled', 'Download cancelled; nothing was installed.')
    if len(data) != plan.size:
        raise _Stop('failed', 'size-mismatch', 'The download is smaller than the pinned size.')
    if hasher.hexdigest() != plan.sha256:
        raise _Stop('failed', 'sha256-mismatch', 'The download does not match the pinned SHA-256.')
    return bytes(data)


def _member(plan: SetupPlan, archive: bytes) -> bytes:
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            found = [i for i in zf.infolist() if not i.is_dir() and PurePosixPath(i.filename).name == plan.executable]
            if len(found) != 1:
                raise _Stop('failed', 'member-missing', f'Expected exactly one {plan.executable} in the archive.')
            info = found[0]
            if info.file_size != plan.executable_size:
                raise _Stop('failed', 'executable-mismatch', 'The extracted program has an unexpected size.')
            with zf.open(info) as handle:
                content = handle.read(plan.executable_size + 1)
    except zipfile.BadZipFile as error:
        raise _Stop('failed', 'archive-invalid', 'The archive could not be read.') from error
    if len(content) != plan.executable_size or hashlib.sha256(content).hexdigest() != plan.executable_sha256:
        raise _Stop('failed', 'executable-mismatch', 'The extracted program does not match its pinned SHA-256.')
    return content


def _place(content: bytes, directory: Path, name: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    handle, temp = tempfile.mkstemp(dir=directory, prefix='.capa-setup-')
    try:
        with os.fdopen(handle, 'wb') as out:
            out.write(content)
        target = directory / name
        os.replace(temp, target)
        return target
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise


def install(plan: SetupPlan, consent: ConsentToken | None, directory: Path, opener: Opener,
            cancel: threading.Event) -> SetupResult:
    if consent is None:
        return SetupResult('refused', 'consent-required', 'Nothing is downloaded without your confirmation.')
    if consent != ConsentToken.for_plan(plan):
        return SetupResult('refused', 'consent-mismatch', 'The confirmation does not match the download plan.')
    try:
        content = _member(plan, _fetch(plan, opener, cancel))
        path = _place(content, directory, plan.executable)
    except _Stop as stop:
        return stop.result
    except OSError as error:
        return SetupResult('failed', 'io-error', f'Could not save the program ({error.__class__.__name__}).')
    return SetupResult('installed', 'ok', f'capa {plan.version} verified and installed.', str(path))
