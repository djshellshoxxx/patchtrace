"""CI-only BinDiff provisioning (SPEC-29 §10, D4/D5). Stdlib only; NEVER executes BinDiff.

usage: provision_bindiff.py --os {linux,windows} [--pin tools/bindiff_pin.json] [--cache DIR] [--dest DIR]
                            [--status-dir build/live-status] [--github-env FILE]

Downloads the pinned upstream release asset (https://github.com/google/bindiff/releases/download/ only),
verifies size and SHA-256 against the pin, and extracts it without installing: `dpkg-deb -x` on Linux (no
`dpkg -i`, no root, no postinst), `msiexec /a` administrative extract on Windows. A pin without a verified
URL/size/SHA-256 is never trusted on first use: the script records `blocked` (reason `pin-missing`) and
exits 0 so the job reports the gap instead of hiding it. Download/verify/extract failures record `failed`
(reason `provision`) and exit 1.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

ALLOWED_PREFIX = 'https://github.com/google/bindiff/releases/download/'
MAX_ASSET = 512 * 1024 * 1024
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
    return {'url': url, 'sha256': sha, 'size': size, 'version': str(pin.get('version'))}


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
    if total != asset['size'] or digest.hexdigest() != asset['sha256']:
        part.unlink(missing_ok=True)
        raise Failed(f'asset digest/size mismatch (got {digest.hexdigest()}, {total} bytes)')
    os.replace(part, target)
    return target


def extract(archive: Path, dest: Path, os_name: str) -> Path:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    if os_name == 'linux':
        argv = ['dpkg-deb', '-x', str(archive), str(dest)]
        name = 'bindiff'
    else:
        msi = archive.with_suffix('.msi')
        shutil.copyfile(archive, msi)
        argv = ['msiexec', '/a', str(msi), '/qn', f'TARGETDIR={dest}']
        name = 'bindiff.exe'
    result = subprocess.run(argv, capture_output=True, text=True, timeout=600, check=False)
    if result.returncode != 0:
        raise Failed(f'extract failed: {argv[0]} exited {result.returncode}')
    found = sorted(p for p in dest.rglob(name) if p.is_file() and not p.is_symlink() and p.parent.name == 'bin')
    if not found:
        raise Failed(f'extract: no bin/{name} in the extracted package')
    return found[0]


def write_status(status_dir: Path, status: str, reason: str, **extra) -> None:
    status_dir.mkdir(parents=True, exist_ok=True)
    record = {'engine': 'bindiff', 'stage': 'provision', 'status': status, 'reason': reason, **extra}
    (status_dir / 'bindiff-provision.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n',
                                                         encoding='utf-8')
    print(json.dumps(record, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--os', dest='os_name', choices=('linux', 'windows'), required=True)
    parser.add_argument('--pin', type=Path, default=Path(__file__).with_name('bindiff_pin.json'))
    parser.add_argument('--cache', type=Path, default=Path('build') / 'bindiff-cache')
    parser.add_argument('--dest', type=Path, default=Path('build') / 'bindiff')
    parser.add_argument('--status-dir', type=Path, default=Path('build') / 'live-status')
    parser.add_argument('--github-env', type=Path, default=None)
    args = parser.parse_args(argv)
    print('BinDiff is Apache-2.0 (https://github.com/google/bindiff); fetched from the upstream release, '
          'not redistributed by PatchTrace.')
    try:
        asset = load_pin(args.pin, args.os_name)
        archive = fetch(asset, args.cache)
        exe = extract(archive, args.dest.resolve(), args.os_name)
    except Blocked as exc:
        write_status(args.status_dir, 'blocked', str(exc))
        print(f'::warning::LIVE ACCEPTANCE BLOCKED: bindiff ({exc})')
        return 0
    except (Failed, OSError, ValueError, subprocess.SubprocessError) as exc:
        write_status(args.status_dir, 'failed', f'provision: {exc}')
        return 1
    write_status(args.status_dir, 'passed', 'provisioned', executable_name=exe.name, url=asset['url'],
                 sha256=asset['sha256'])
    if args.github_env is not None:
        with open(args.github_env, 'a', encoding='utf-8') as env:
            env.write(f'PATCHTRACE_BINDIFF={exe}\nPATCHTRACE_REQUIRE_LIVE_BINDIFF=1\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
