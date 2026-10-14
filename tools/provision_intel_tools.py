"""CI-only provisioning of the pinned capa / FLOSS / diec releases (SPEC-29 tools T9). Stdlib only; NEVER executes them.

usage: provision_intel_tools.py --os {linux,windows} [--engine capa ...] [--advisory] [--pin tools/intel_tools_pin.json]
                                [--cache DIR] [--dest DIR] [--status-dir build/live-status] [--github-env FILE]

Downloads each pinned upstream asset (https://github.com/<owner>/<repo>/releases/download/ only), verifies size and
SHA-256 against the pin and extracts without installing or running anything: zip members through a safe-name
allow-list, `.deb` through `dpkg-deb --fsys-tarfile` into a stdlib tar reader that writes regular files and
directories only (links are never materialised). The extracted executable must then equal the pinned size and
SHA-256. A pin value that is missing, not a digest or the string UNMEASURED is never trusted: `blocked`
(`pin-missing`), exit 0. Integrity failures (download, size, SHA-256) are `failed`, exit 1, also with --advisory.
With --advisory, extraction and executable problems are recorded as `blocked` (`unverified:`), exit 0.
Exports PATCHTRACE_CAPA / _FLOSS / _DIEC / _DIEC_DB to --github-env. --dest is only deleted if this tool made it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

ENGINES = ('capa', 'floss', 'diec')
URL = re.compile(r'^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/download/[^\s]+$')
SHA256 = re.compile(r'^[0-9a-f]{64}$')
MAX_ASSET = 512 * 1024 * 1024
MAX_MEMBERS = 50_000
MAX_EXTRACT = 1024 * 1024 * 1024
MARKER = '.patchtrace-intel-tools-provisioned'
ENV_NAMES = {'capa': 'PATCHTRACE_CAPA', 'floss': 'PATCHTRACE_FLOSS', 'diec': 'PATCHTRACE_DIEC'}


class Blocked(Exception):
    pass


class Failed(Exception):
    pass


def load_pin(path: Path) -> dict:
    pin = json.loads(path.read_text(encoding='utf-8'))
    if pin.get('contract') != 'intel-tools-pin/1':
        raise Failed('pin file has an unknown contract')
    return pin


def trusted(asset: dict) -> None:
    """Raise Blocked for a pin entry that cannot be trusted (missing, UNMEASURED or malformed)."""
    for key in ('sha256', 'executable_sha256'):
        if not isinstance(asset.get(key), str) or not SHA256.match(asset[key]):
            raise Blocked(f'pin-missing: {key} is not a measured SHA-256')
    for key in ('size', 'executable_size'):
        if not isinstance(asset.get(key), int) or asset[key] <= 0:
            raise Blocked(f'pin-missing: {key} is not a measured size')
    if not isinstance(asset.get('url'), str) or not URL.match(asset['url']):
        raise Blocked('pin-missing: the asset URL is not a GitHub release download URL')


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def download(asset: dict, cache: Path) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / asset['name']
    if not (target.is_file() and target.stat().st_size == asset['size'] and sha256_file(target) == asset['sha256']):
        part = target.with_suffix(target.suffix + '.part')
        total = 0
        with urllib.request.urlopen(asset['url'], timeout=300) as response, open(part, 'wb') as out:  # noqa: S310
            if not response.geturl().startswith('https://'):
                raise Failed('download redirected away from HTTPS')
            while chunk := response.read(1 << 20):
                total += len(chunk)
                if total > MAX_ASSET:
                    raise Failed('asset is larger than the download limit')
                out.write(chunk)
        os.replace(part, target)
    if target.stat().st_size != asset['size']:
        raise Failed(f'{asset["name"]}: size {target.stat().st_size} differs from the pin {asset["size"]}')
    if sha256_file(target) != asset['sha256']:
        raise Failed(f'{asset["name"]}: SHA-256 differs from the pin')
    return target


def safe_relative(name: str) -> PurePosixPath | None:
    text = name.replace('\\', '/')
    while text.startswith('./'):
        text = text[2:]
    path = PurePosixPath(text)
    if not text or not path.parts or path.is_absolute() or '..' in path.parts or ':' in path.parts[0]:
        return None
    return path


def extract_zip(archive: Path, dest: Path, asset: dict) -> None:
    written = 0
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            raise Blocked('unverified: archive has too many members')
        for info in infos:
            relative = safe_relative(info.filename)
            if relative is None:
                raise Failed(f'unsafe archive member name {info.filename[:60]!r}')
            if not asset.get('extract_all') and info.filename != asset['executable']:
                continue
            if stat.S_ISLNK(info.external_attr >> 16):
                continue
            target = dest.joinpath(*relative.parts)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            written += info.file_size
            if written > MAX_EXTRACT:
                raise Blocked('unverified: extraction exceeds the size limit')
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, 'wb') as out:
                shutil.copyfileobj(src, out)


def extract_deb(archive: Path, dest: Path, asset: dict) -> None:
    wanted = (asset['executable'], asset.get('database', '\0'))
    proc = subprocess.Popen(['dpkg-deb', '--fsys-tarfile', str(archive)], stdout=subprocess.PIPE)  # noqa: S603, S607
    written = 0
    try:
        with tarfile.open(fileobj=proc.stdout, mode='r|') as tar:
            for member in tar:
                if member.name.strip('/') in ('', '.'):
                    continue
                relative = safe_relative(member.name)
                if relative is None:
                    raise Failed(f'unsafe archive member name {member.name[:60]!r}')
                text = relative.as_posix()
                if not any(text == w or text.startswith(w + '/') for w in wanted):
                    continue
                target = dest.joinpath(*relative.parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif member.isreg():       # links, devices and fifos are never materialised
                    written += member.size
                    if written > MAX_EXTRACT:
                        raise Blocked('unverified: extraction exceeds the size limit')
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with open(target, 'wb') as out:
                        shutil.copyfileobj(tar.extractfile(member), out)
    finally:
        if proc.stdout:
            proc.stdout.close()
        proc.wait()


def provision_engine(engine: str, pin: dict, os_name: str, cache: Path, dest: Path) -> dict:
    asset = pin['engines'][engine]['assets'][os_name]
    trusted(asset)
    archive = download(asset, cache)
    target = dest / engine
    target.mkdir(parents=True, exist_ok=True)
    (extract_deb if asset['format'] == 'deb' else extract_zip)(archive, target, asset)
    exe = target.joinpath(*asset['executable'].split('/'))
    if not exe.is_file():
        raise Blocked(f'unverified: {asset["executable"]} was not extracted')
    if exe.stat().st_size != asset['executable_size'] or sha256_file(exe) != asset['executable_sha256']:
        raise Failed(f'{engine}: the extracted executable differs from the pinned size/SHA-256')
    if os.name != 'nt':
        exe.chmod(0o755)
    result = {'engine': engine, 'executable': str(exe), 'version': pin['engines'][engine]['version']}
    if asset.get('database'):
        result['database'] = str(target.joinpath(*asset['database'].split('/')))
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--os', choices=('linux', 'windows'), required=True)
    ap.add_argument('--engine', action='append', choices=ENGINES)
    ap.add_argument('--advisory', action='store_true')
    root = Path(__file__).resolve().parents[1]
    ap.add_argument('--pin', type=Path, default=root / 'tools' / 'intel_tools_pin.json')
    ap.add_argument('--cache', type=Path, default=root / 'build' / 'intel-tools-cache')
    ap.add_argument('--dest', type=Path, default=root / 'build' / 'intel-tools')
    ap.add_argument('--status-dir', type=Path, default=root / 'build' / 'live-status')
    ap.add_argument('--github-env', type=Path)
    args = ap.parse_args(argv)
    engines = args.engine or list(ENGINES)
    status, reason, provisioned = 'passed', 'all pinned tools provisioned', []
    try:
        pin = load_pin(args.pin)
        if args.dest.exists() and (args.dest / MARKER).exists():
            shutil.rmtree(args.dest)
        args.dest.mkdir(parents=True, exist_ok=True)
        (args.dest / MARKER).write_text('provisioned by tools/provision_intel_tools.py\n', encoding='utf-8')
        for engine in engines:
            provisioned.append(provision_engine(engine, pin, args.os, args.cache, args.dest))
    except Blocked as exc:
        status, reason = 'blocked', str(exc)
    except Failed as exc:
        status, reason = 'failed', str(exc)
    except (OSError, urllib.error.URLError, zipfile.BadZipFile, tarfile.TarError, subprocess.SubprocessError) as exc:
        status, reason = ('blocked', f'unverified: {type(exc).__name__}') if args.advisory else (
            'failed', f'{type(exc).__name__}: {exc}')
    if status == 'blocked' and not args.advisory and not reason.startswith('pin-missing'):
        status = 'failed'
    args.status_dir.mkdir(parents=True, exist_ok=True)
    (args.status_dir / 'intel-tools-provision.json').write_text(json.dumps(
        {'engine': 'intel-tools-provision', 'status': status, 'reason': reason, 'mocked': False,
         'os': args.os, 'tools': [{k: v for k, v in p.items() if k != 'executable'} for p in provisioned]},
        indent=2, sort_keys=True) + '\n', encoding='utf-8')
    if status == 'passed' and args.github_env:
        with open(args.github_env, 'a', encoding='utf-8') as env:
            for item in provisioned:
                env.write(f'{ENV_NAMES[item["engine"]]}={item["executable"]}\n')
                if item.get('database'):
                    env.write(f'PATCHTRACE_DIEC_DB={item["database"]}\n')
    print(f'{status}: {reason}', file=sys.stderr)
    return 1 if status == 'failed' else 0


if __name__ == '__main__':
    raise SystemExit(main())
