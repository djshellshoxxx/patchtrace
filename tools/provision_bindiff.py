"""CI-only BinDiff provisioning (SPEC-29 §10, D4/D5). Stdlib only; NEVER executes BinDiff.

usage: provision_bindiff.py --os {linux,windows} [--advisory] [--pin tools/bindiff_pin.json] [--cache DIR]
                            [--dest DIR] [--status-dir build/live-status] [--github-env FILE]

Downloads the pinned upstream release asset (https://github.com/google/bindiff/releases/download/ only),
verifies size and SHA-256 against the pin and extracts it without installing:
- Linux: a stdlib `ar` + `tar` reader, equivalent to `dpkg-deb -x` (no `dpkg -i`, no root, no maintainer
  scripts). Only regular files and directories are written; links (`usr/bin/bindiff -> /opt/...`,
  `bin/bindiff_ui -> bindiff`) are never materialised, and unsafe member names are refused.
- Windows: `msiexec /a` administrative extract (unverified on CI so far: use --advisory).
The extracted executable must then match the pinned size/SHA-256, and on Windows the VC++ 2015-2022 x64
runtime DLLs the exe imports must exist in System32 (`redist`). The pin is trust-on-first-use (upstream
publishes no digest); a pin without URL/size/SHA-256 is never trusted: `blocked` (`pin-missing`), exit 0.
Integrity failures (download, size or SHA-256 of the asset) are `failed`, exit 1, also with --advisory.
With --advisory, extraction/executable/redist problems are recorded as `blocked` with an `unverified:`
reason and exit 0, and PATCHTRACE_REQUIRE_LIVE_BINDIFF is not exported.
Run locally with --cache/--dest outside the source tree; --dest is only ever deleted if a previous run of
this tool created it (marker file).
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zlib
from pathlib import Path, PurePosixPath

ALLOWED_PREFIX = 'https://github.com/google/bindiff/releases/download/'
MAX_ASSET = 512 * 1024 * 1024
MAX_EXTRACT_BYTES = 1024 * 1024 * 1024
MAX_MEMBERS = 50_000
MARKER = '.patchtrace-bindiff-provisioned'
REDIST_DLLS = ('vcruntime140.dll', 'vcruntime140_1.dll', 'msvcp140.dll')
AR_MAGIC = b'!<arch>\n'
_TAR_MODES = {'data.tar': 'r|', 'data.tar.gz': 'r|gz', 'data.tar.xz': 'r|xz', 'data.tar.bz2': 'r|bz2'}
_SHA256 = re.compile(r'^[0-9a-f]{64}$')


class Blocked(Exception):
    pass


class Failed(Exception):
    pass


def load_pin(path: Path, os_name: str) -> dict:
    pin = json.loads(path.read_text(encoding='utf-8'))
    if pin.get('contract') != 'bindiff-pin/1':
        raise Failed('pin file has an unknown contract')
    asset = pin.get('assets', {}).get(os_name)
    if not isinstance(asset, dict):
        raise Failed(f'pin has no asset for {os_name}')
    url, sha, size = asset.get('url'), asset.get('sha256'), asset.get('size')
    if url is None or sha is None or size is None:
        raise Blocked(f'pin-missing: verified URL/size/SHA-256 for the {os_name} asset are not recorded '
                      f'({pin.get("gap", "no reason given")})')
    if not isinstance(url, str) or not url.startswith(ALLOWED_PREFIX):
        raise Failed('pin URL is not an upstream google/bindiff release download')
    if not isinstance(sha, str) or not _SHA256.match(sha):
        raise Failed('pin SHA-256 is malformed')
    if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= MAX_ASSET:
        raise Failed('pin size is malformed')
    exe_sha = asset.get('executable_sha256')
    if exe_sha is not None and (not isinstance(exe_sha, str) or not _SHA256.match(exe_sha)):
        raise Failed('pin executable SHA-256 is malformed')
    version_text = pin.get('version_text')
    return {'url': url, 'sha256': sha, 'size': size, 'version': str(pin.get('version')),
            'version_text': version_text if isinstance(version_text, str) else None,
            'name': str(asset.get('name') or url.rsplit('/', 1)[-1]), 'executable': asset.get('executable'),
            'executable_sha256': exe_sha, 'executable_size': asset.get('executable_size'),
            'trust': str(pin.get('trust') or 'unspecified')}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(asset: dict, cache: Path) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / f'{asset["sha256"]}.asset'
    if target.is_file() and sha256_file(target) == asset['sha256']:
        return target
    part = cache / f'{asset["sha256"]}.part'
    digest, total = hashlib.sha256(), 0
    try:
        with urllib.request.urlopen(asset['url'], timeout=120) as response, open(part, 'wb') as out:  # noqa: S310
            while chunk := response.read(1 << 20):
                total += len(chunk)
                if total > asset['size']:
                    raise Failed('download larger than the pinned size')
                digest.update(chunk)
                out.write(chunk)
    except OSError as exc:
        part.unlink(missing_ok=True)
        raise Failed(f'download failed: {type(exc).__name__}') from None
    except Failed:
        part.unlink(missing_ok=True)
        raise
    if total != asset['size'] or digest.hexdigest() != asset['sha256']:
        part.unlink(missing_ok=True)
        raise Failed(f'asset digest/size mismatch (got {digest.hexdigest()}, {total} bytes)')
    os.replace(part, target)
    return target


# ---- stdlib .deb extraction ------------------------------------------------------------------------------------

class _Section(io.RawIOBase):
    """Read-only window [start, start+length) of an open file (an `ar` member) for tarfile's stream mode."""

    def __init__(self, handle, start: int, length: int):
        self._handle, self._pos, self._end = handle, start, start + length

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        count = min(len(buffer), self._end - self._pos)
        if count <= 0:
            return 0
        self._handle.seek(self._pos)
        data = self._handle.read(count)
        buffer[:len(data)] = data
        self._pos += len(data)
        return len(data)


def ar_members(archive: Path) -> list[tuple[str, int, int]]:
    """(name, data offset, size) of each member of a common-format `ar` archive, bounds-checked."""
    size = archive.stat().st_size
    members: list[tuple[str, int, int]] = []
    with open(archive, 'rb') as handle:
        if handle.read(8) != AR_MAGIC:
            raise Failed('extract: not a Debian package (ar magic missing)')
        offset = 8
        while offset < size:
            handle.seek(offset)
            header = handle.read(60)
            if len(header) != 60 or header[58:60] != b'`\n':
                raise Failed('extract: malformed ar member header')
            try:
                name = header[:16].decode('ascii').strip().rstrip('/')
                length = int(header[48:58].decode('ascii').strip())
            except (UnicodeDecodeError, ValueError):
                raise Failed('extract: malformed ar member header') from None
            start = offset + 60
            if length < 0 or start + length > size:
                raise Failed('extract: ar member exceeds the archive (truncated download?)')
            members.append((name, start, length))
            if len(members) > 16:
                raise Failed('extract: too many ar members for a Debian package')
            offset = start + length + (length & 1)
    return members


def _safe_parts(name: str) -> tuple[str, ...] | None:
    """Relative path parts of a tar member, None for the archive root; raises on anything unsafe."""
    if name.startswith('/') or '\\' in name or '\x00' in name:
        raise Failed(f'extract: unsafe member name {name[:80]!r}')
    parts = tuple(part for part in PurePosixPath(name).parts if part != '.')
    if any(part == '..' or ':' in part or len(part) > 255 for part in parts) or len(parts) > 32:
        raise Failed(f'extract: unsafe member name {name[:80]!r}')
    return parts or None


def extract_deb(archive: Path, dest: Path) -> dict[str, int]:
    """Write the regular files and directories of `data.tar.*` under `dest` (never links or devices)."""
    members = {name: (start, length) for name, start, length in ar_members(archive)}
    if 'debian-binary' not in members:
        raise Failed('extract: debian-binary member missing')
    data_names = [name for name in members if name.startswith('data.tar')]
    if len(data_names) != 1:
        raise Failed('extract: expected exactly one data.tar member')
    data_name = data_names[0]
    if data_name not in _TAR_MODES:
        raise Failed(f'extract: {data_name} is not supported by the stdlib extractor (zstd or unknown '
                     'compression); use dpkg-deb -x')
    root = dest.resolve()
    root.mkdir(parents=True, exist_ok=True)
    stats = {'files': 0, 'dirs': 0, 'skipped_links': 0, 'bytes': 0}
    with open(archive, 'rb') as handle:
        start, length = members['debian-binary']
        handle.seek(start)
        if not handle.read(min(length, 16)).startswith(b'2.'):
            raise Failed('extract: unsupported debian-binary format version')
        start, length = members[data_name]
        stream = io.BufferedReader(_Section(handle, start, length), 1 << 20)
        try:
            with tarfile.open(fileobj=stream, mode=_TAR_MODES[data_name]) as tar:
                for count, member in enumerate(tar, 1):
                    if count > MAX_MEMBERS:
                        raise Failed('extract: too many members in data.tar')
                    parts = _safe_parts(member.name)
                    if parts is None:
                        continue
                    target = root.joinpath(*parts)
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                        stats['dirs'] += 1
                    elif member.isreg():
                        stats['bytes'] += member.size
                        if stats['bytes'] > MAX_EXTRACT_BYTES:
                            raise Failed('extract: package exceeds the extraction size limit')
                        target.parent.mkdir(parents=True, exist_ok=True)
                        source = tar.extractfile(member)
                        try:
                            with open(target, 'xb') as out:
                                shutil.copyfileobj(source, out, 1 << 20)
                        except FileExistsError:
                            raise Failed(f'extract: duplicate member {member.name[:80]!r}') from None
                        os.chmod(target, 0o755 if member.mode & 0o100 else 0o644)
                        stats['files'] += 1
                    else:  # symlinks, hard links, devices, FIFOs are never created
                        stats['skipped_links'] += 1
        except (tarfile.TarError, EOFError, OSError, ValueError, lzma.LZMAError, zlib.error) as exc:
            raise Failed(f'extract: corrupt or unwritable data archive ({type(exc).__name__})') from None
    return stats


# ---- Windows administrative extract (live-only) ----------------------------------------------------------------

def extract_msi(archive: Path, dest: Path) -> dict[str, int]:
    msi = archive.with_suffix('.msi')
    shutil.copyfile(archive, msi)
    dest.mkdir(parents=True, exist_ok=True)
    argv = ['msiexec', '/a', str(msi), '/qn', f'TARGETDIR={dest}']
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=600, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Failed(f'extract: msiexec /a could not run ({type(exc).__name__})') from None
    if result.returncode != 0:
        raise Failed(f'extract: msiexec /a exited {result.returncode}')
    return {}


def redist_status(system_root: str | None) -> dict[str, bool]:
    """Presence of the VC++ 2015-2022 x64 runtime DLLs bindiff.exe imports (static check, nothing loaded)."""
    base = Path(system_root) / 'System32' if system_root else None
    return {dll: bool(base and (base / dll).is_file()) for dll in REDIST_DLLS}


# ---- locate / verify / install -----------------------------------------------------------------------------------

def _regular(path: Path) -> bool:
    try:
        return not path.is_symlink() and path.is_file()
    except OSError:
        return False


def locate_executable(dest: Path, asset: dict, os_name: str) -> Path:
    name = 'bindiff' if os_name == 'linux' else 'bindiff.exe'
    pinned = asset.get('executable')
    if os_name == 'linux' and isinstance(pinned, str) and _regular(dest / pinned):
        return dest / pinned
    found = sorted(p for p in dest.rglob(name) if p.parent.name.lower() == 'bin' and _regular(p))
    if not found:
        raise Failed(f'extract: no bin/{name} in the extracted package')
    return found[0]


def verify_executable(exe: Path, asset: dict) -> str:
    digest = sha256_file(exe)
    expected, size = asset.get('executable_sha256'), asset.get('executable_size')
    if (expected is not None and digest != expected) or (size is not None and exe.stat().st_size != size):
        raise Failed(f'extracted executable size/SHA-256 differs from the pin (got {digest}, '
                     f'{exe.stat().st_size} bytes)')
    return digest


def prepare_dest(dest: Path) -> None:
    """Remove a previous provisioning result; never delete a directory this tool did not create."""
    if dest.exists():
        if not (dest / MARKER).is_file() and (not dest.is_dir() or any(dest.iterdir())):
            raise Failed(f'destination {dest.name!r} exists and was not created by this tool; refusing to '
                         'delete it')
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    (dest / MARKER).write_text('created by tools/provision_bindiff.py\n', encoding='utf-8')


def install(archive: Path, dest: Path, asset: dict, os_name: str) -> tuple[Path, dict]:
    prepare_dest(dest)
    if os_name == 'linux':
        details: dict = {'extraction': 'stdlib ar+tar (equivalent to dpkg-deb -x; no install, no scripts)',
                         **extract_deb(archive, dest)}
    else:
        details = {'extraction': 'msiexec /a (administrative extract)', **extract_msi(archive, dest)}
    exe = locate_executable(dest, asset, os_name)
    details['executable'] = exe.relative_to(dest).as_posix()
    details['executable_sha256'] = verify_executable(exe, asset)
    if os_name == 'windows':
        root = os.environ.get('SystemRoot') or os.environ.get('SYSTEMROOT')
        details['redist'] = redist_status(root)
        missing = [dll for dll, present in details['redist'].items() if not present]
        if missing:
            raise Failed(f'VC++ 2015-2022 x64 runtime missing from System32: {", ".join(missing)}')
    return exe, details


def export_env(path: Path, values: dict[str, str]) -> None:
    for key, value in values.items():
        if any(c in f'{key}{value}' for c in '\r\n'):
            raise Failed('refusing to export an environment value containing a newline')
    with open(path, 'a', encoding='utf-8') as env:
        env.writelines(f'{key}={value}\n' for key, value in values.items())


def write_status(status_dir: Path, status: str, reason: str, **extra) -> None:
    status_dir.mkdir(parents=True, exist_ok=True)
    record = {'engine': 'bindiff', 'stage': 'provision', 'status': status, 'reason': reason, **extra}
    (status_dir / 'bindiff-provision.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n',
                                                         encoding='utf-8')
    print(json.dumps(record, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--os', dest='os_name', choices=('linux', 'windows'), required=True)
    parser.add_argument('--advisory', action='store_true',
                        help='record extraction/executable/redist problems as blocked (unverified), exit 0')
    parser.add_argument('--pin', type=Path, default=Path(__file__).with_name('bindiff_pin.json'))
    parser.add_argument('--cache', type=Path, default=Path('build') / 'bindiff-cache')
    parser.add_argument('--dest', type=Path, default=Path('build') / 'bindiff')
    parser.add_argument('--status-dir', type=Path, default=Path('build') / 'live-status')
    parser.add_argument('--github-env', type=Path, default=None)
    args = parser.parse_args(argv)
    print('BinDiff is Apache-2.0 (https://github.com/google/bindiff); fetched from the upstream release, '
          'not redistributed by PatchTrace.')
    base = {'os': args.os_name, 'advisory': args.advisory}
    try:
        asset = load_pin(args.pin, args.os_name)
        archive = fetch(asset, args.cache)  # integrity: fatal in every mode
        try:
            exe, details = install(archive, args.dest.resolve(), asset, args.os_name)
        except Failed as exc:
            if args.advisory:
                raise Blocked(f'unverified: {exc}') from None
            raise
    except Blocked as exc:
        write_status(args.status_dir, 'blocked', str(exc), **base)
        print(f'::warning::LIVE ACCEPTANCE BLOCKED: bindiff ({exc})')
        return 0
    except (Failed, OSError, ValueError, subprocess.SubprocessError) as exc:
        write_status(args.status_dir, 'failed', f'provision: {exc}', **base)
        return 1
    write_status(args.status_dir, 'passed', 'provisioned', **base, asset=asset['name'], url=asset['url'],
                 sha256=asset['sha256'], trust=asset['trust'], **details)
    if args.github_env is not None:
        values = {'PATCHTRACE_BINDIFF': str(exe.resolve())}
        if not args.advisory:
            values['PATCHTRACE_REQUIRE_LIVE_BINDIFF'] = '1'
        if asset['version_text'] and asset['version_text'].startswith('BinDiff '):
            values['PATCHTRACE_BINDIFF_EXPECTED_VERSION'] = asset['version_text'][len('BinDiff '):]
        try:
            export_env(args.github_env, values)
        except Failed as exc:
            write_status(args.status_dir, 'failed', f'provision: {exc}', **base)
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
