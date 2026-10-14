"""Verify the two backend pins that have no vendor digest, and rebuild the Ghidriff source tarball.

Stdlib only. Modes:
  rebuild  fetch the pinned commit and write the deterministic source tarball (used by build_backend_bundle.py)
  verify   run on a networked CI runner; writes pin-verify.json. NO trust on first use: a digest is recorded
           only after a signature check (python.org Sigstore bundle and/or GPG) or a content comparison with
           the commit (Ghidriff) succeeded. Any mismatch or bad signature exits non-zero.

usage:
  verify_backend_pins.py rebuild --repo URL --commit SHA --out FILE
  verify_backend_pins.py verify --out pin-verify.json [--sigstore-identity ID --sigstore-issuer URL]
                                [--gpg-fingerprint FPR] [--pin tools/backend_pin.json] [--workdir DIR]

Deterministic recipe (git-rebuilt): `git archive --format=tar --prefix=ghidriff-<sha7>/ <commit>`, every member
rewritten with mtime 315532800, uid/gid 0, empty owner names, modes 0644/0755, GNU tar format, then gzip at
level 0 (stored deflate blocks, header mtime 0, no file name), so the bytes do not depend on the zlib build.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path

FIXED_MTIME = 315532800
_HEX40 = re.compile(r'^[0-9a-f]{40}$')
SCHEMA = 'patchtrace-pin-verify/1'
PAGES = ('https://www.python.org/downloads/metadata/sigstore/', 'https://www.python.org/downloads/release/python-31210/',
         'https://www.python.org/downloads/')


class VerifyError(Exception):
    pass


Run = Callable[[Sequence[str], Path | None], subprocess.CompletedProcess]


def _run(argv: Sequence[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), cwd=cwd, capture_output=True, text=True, check=False, timeout=900)


def _git(args: Sequence[str], cwd: Path, run: Run) -> str:
    result = run(['git', '-c', 'core.autocrlf=false', *args], cwd)
    if result.returncode != 0:
        raise VerifyError(f'git {" ".join(args[:3])} failed: {(result.stderr or "").strip()[-400:]}')
    return result.stdout.strip()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while chunk := stream.read(1 << 20):
            hasher.update(chunk)
    return hasher.hexdigest()


# ----- Ghidriff: fetch a commit, rebuild the tarball deterministically -----------------------------------
def fetch_commit(repo: str, commit: str, dest: Path, run: Run = _run) -> str:
    """Fetch exactly `commit` into a fresh repository at `dest`; returns the tree hash. Fails if HEAD differs."""
    if not _HEX40.match(commit):
        raise VerifyError('commit must be a full 40-hex SHA')
    dest.mkdir(parents=True, exist_ok=True)
    _git(['init', '-q'], dest, run)
    _git(['fetch', '-q', '--no-tags', '--depth', '1', repo, commit], dest, run)
    head = _git(['rev-parse', 'FETCH_HEAD^{commit}'], dest, run)
    if head != commit:
        raise VerifyError(f'fetched commit {head} is not the pinned {commit}')
    return _git(['rev-parse', f'{commit}^{{tree}}'], dest, run)


def _normalised_tar(raw: bytes) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as src, tarfile.open(fileobj=out, mode='w', format=tarfile.GNU_FORMAT) as dst:
        for member in src:
            info = tarfile.TarInfo(member.name)
            info.type, info.mtime, info.uid, info.gid, info.uname, info.gname = member.type, FIXED_MTIME, 0, 0, '', ''
            if member.isdir():
                info.mode = 0o755
                dst.addfile(info)
            elif member.isreg():
                info.mode = 0o755 if member.mode & 0o111 else 0o644
                info.size = member.size
                dst.addfile(info, src.extractfile(member))
            elif member.issym():
                info.mode, info.linkname = 0o777, member.linkname
                dst.addfile(info)
            else:
                raise VerifyError(f'unsupported member type in git archive: {member.name!r}')
    return out.getvalue()


def build_tarball(repo_dir: Path, commit: str, out: Path, run: Run = _run) -> dict:
    """Write the deterministic `.tar.gz` of `commit` from `repo_dir`; returns tree hash, sha256 and size."""
    tree = _git(['rev-parse', f'{commit}^{{tree}}'], repo_dir, run)
    prefix = f'ghidriff-{commit[:7]}/'
    proc = subprocess.run(['git', '-c', 'core.autocrlf=false', '-c', 'core.eol=lf', 'archive', '--format=tar', f'--prefix={prefix}', commit], cwd=repo_dir,
                          capture_output=True, check=False, timeout=900)
    if proc.returncode != 0:
        raise VerifyError(f'git archive failed: {proc.stderr.decode(errors="replace")[-400:]}')
    tar = _normalised_tar(proc.stdout)
    gz = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=gz, compresslevel=0, mtime=0) as stream:
        stream.write(tar)
    data = gz.getvalue()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    return {'tree': tree, 'prefix': prefix, 'sha256': sha256_bytes(data), 'size': len(data)}


def rebuild_tarball(repo: str, commit: str, work: Path, run: Run = _run) -> tuple[Path, dict]:
    """Fetch `commit` from `repo` into `work/ghidriff-git` and rebuild the tarball at `work/ghidriff-source.tar.gz`."""
    clone = work / 'ghidriff-git'
    if clone.exists():
        shutil.rmtree(clone)
    tree = fetch_commit(repo, commit, clone, run)
    info = build_tarball(clone, commit, work / 'ghidriff-source.tar.gz', run)
    if info['tree'] != tree:
        raise VerifyError('tree hash changed between fetch and archive')
    info['commit'] = commit
    return work / 'ghidriff-source.tar.gz', info


def _members(path: Path) -> dict[str, tuple]:
    """relative path -> (kind, detail) for files and symlinks (directories and the top directory are ignored)."""
    result: dict[str, tuple] = {}
    with tarfile.open(path, 'r:*') as tar:
        for member in tar:
            parts = member.name.split('/', 1)
            if member.isdir() or len(parts) < 2 or not parts[1]:
                continue
            rel = parts[1]
            if member.isreg():
                body = tar.extractfile(member).read()
                result[rel] = ('file', sha256_bytes(body), bool(member.mode & 0o111))
            elif member.issym():
                result[rel] = ('symlink', member.linkname)
            else:
                result[rel] = ('other', member.type.decode('latin-1'))
    return result


def compare_tarballs(rebuilt: Path, downloaded: Path) -> dict:
    """Member-by-member comparison (names, content sha256, exec bit, symlink targets). Returns a summary dict."""
    a, b = _members(rebuilt), _members(downloaded)
    only_rebuilt, only_downloaded = sorted(set(a) - set(b)), sorted(set(b) - set(a))
    different = sorted(name for name in set(a) & set(b) if a[name] != b[name])
    return {'members': len(a), 'only_in_rebuilt': only_rebuilt[:20], 'only_in_downloaded': only_downloaded[:20],
            'different': different[:20], 'identical': not (only_rebuilt or only_downloaded or different) and bool(a)}


# ----- python.org: sigstore and gpg ----------------------------------------------------------------------
def _fetch(url: str, dest: Path | None = None, limit: int = 64 << 20) -> bytes:
    if not url.startswith('https://'):
        raise VerifyError(f'refusing non-HTTPS URL {url}')
    request = urllib.request.Request(url, headers={'User-Agent': 'patchtrace-pin-verify/1'})
    with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310 (https checked above)
        data = response.read(limit + 1)
    if len(data) > limit:
        raise VerifyError(f'{url} is larger than {limit} bytes')
    if dest is not None:
        dest.write_bytes(data)
    return data


def _page_text(url: str) -> str:
    try:
        html = _fetch(url, limit=4 << 20).decode('utf-8', 'replace')
    except Exception as error:  # noqa: BLE001  (informational only)
        return f'[fetch failed: {error}]'
    html = re.sub(r'(?is)<(script|style).*?</\1>', ' ', html)
    return re.sub(r'\s+', ' ', re.sub(r'(?s)<[^>]+>', ' ', html)).strip()


def _tool_version(argv: Sequence[str], run: Run) -> str:
    try:
        result = run(argv, None)
        return (result.stdout or result.stderr or '').strip().splitlines()[0]
    except (OSError, IndexError, subprocess.SubprocessError):
        return 'unavailable'


def verify_sigstore(file: Path, bundle: Path, identity: str, issuer: str, run: Run = _run) -> dict:
    result = run([sys.executable, '-m', 'sigstore', 'verify', 'identity', '--bundle', str(bundle), '--cert-identity', identity,
                  '--cert-oidc-issuer', issuer, str(file)], None)
    ok = result.returncode == 0
    return {'method': 'sigstore', 'ok': ok, 'identity': identity, 'issuer': issuer,
            'output': ((result.stdout or '') + (result.stderr or '')).strip()[-800:]}


def verify_gpg(file: Path, signature: Path, fingerprint: str, home: Path, run: Run = _run) -> dict:
    fingerprint = re.sub(r'\s+', '', fingerprint).upper()
    home.mkdir(parents=True, exist_ok=True)
    home.chmod(0o700)
    base = ['gpg', '--batch', '--homedir', str(home)]
    recv = run([*base, '--keyserver', 'hkps://keys.openpgp.org', '--recv-keys', fingerprint], None)
    if recv.returncode != 0:
        return {'method': 'gpg', 'ok': False, 'fingerprint': fingerprint, 'output': f'key import failed: {recv.stderr.strip()[-400:]}'}
    result = run([*base, '--status-fd', '1', '--verify', str(signature), str(file)], None)
    valid = [line.split() for line in (result.stdout or '').splitlines() if line.startswith('[GNUPG:] VALIDSIG')]
    # VALIDSIG <signing-subkey-fpr> ... <primary-key-fpr> (last field)
    primary = valid[0][-1].upper() if valid else ''
    signing = valid[0][2].upper() if valid else ''
    ok = result.returncode == 0 and fingerprint in (primary, signing)
    return {'method': 'gpg', 'ok': ok, 'fingerprint': fingerprint, 'signing_key': signing, 'primary_key': primary,
            'output': ((result.stdout or '') + (result.stderr or '')).strip()[-800:]}


def verify_all(args: argparse.Namespace, run: Run = _run) -> tuple[dict, list[str]]:
    from importlib import metadata  # local: keeps `rebuild` free of any import cost
    pin = json.loads(Path(args.pin).read_text(encoding='utf-8'))
    work = Path(args.workdir)
    work.mkdir(parents=True, exist_ok=True)
    problems: list[str] = []
    try:
        sigstore_version = metadata.version('sigstore')
    except metadata.PackageNotFoundError:
        sigstore_version = 'not installed'
    evidence: dict = {
        'schema': SCHEMA,
        'tools': {'python': sys.version.split()[0], 'git': _tool_version(['git', '--version'], run),
                  'gpg': _tool_version(['gpg', '--version'], run), 'sigstore': sigstore_version},
    }
    # (1) python.org embeddable zip
    entry = pin['components']['python-windows']
    url = entry['url']
    zpath = work / url.rsplit('/', 1)[-1]
    py: dict = {'url': url, 'checks': []}
    evidence['python_windows'] = py
    pages = {page: _page_text(page) for page in PAGES}
    py['published_pages_text'] = {page: text[:6000] for page, text in pages.items()}
    try:
        data = _fetch(url, zpath, limit=64 << 20)
        py['sha256'], py['size'] = sha256_bytes(data), len(data)
        sig_bundle, sig_asc = work / (zpath.name + '.sigstore'), work / (zpath.name + '.asc')
        have_bundle = have_asc = False
        try:
            _fetch(url + '.sigstore', sig_bundle, limit=1 << 20)
            have_bundle = True
        except Exception as error:  # noqa: BLE001
            py['sigstore_download'] = f'failed: {error}'
        try:
            _fetch(url + '.asc', sig_asc, limit=1 << 20)
            have_asc = True
        except Exception as error:  # noqa: BLE001
            py['asc_download'] = f'failed: {error}'
        if args.sigstore_identity and args.sigstore_issuer and have_bundle:
            check = verify_sigstore(zpath, sig_bundle, args.sigstore_identity, args.sigstore_issuer, run)
            check['identity_named_on_python_org_pages'] = any(args.sigstore_identity in t for t in pages.values())
            py['checks'].append(check)
            if not check['identity_named_on_python_org_pages']:
                problems.append('the sigstore identity is not named on the fetched python.org pages (supplied by the integrator, not confirmed)')
        if args.gpg_fingerprint and have_asc:
            check = verify_gpg(zpath, sig_asc, args.gpg_fingerprint, work / 'gnupg', run)
            check['fingerprint_named_on_python_org_pages'] = (re.sub(r'\s+', '', args.gpg_fingerprint).upper()
                                                              in re.sub(r'\s+', '', ' '.join(pages.values())).upper())
            py['checks'].append(check)
        if not py['checks']:
            problems.append('no signature check could run: supply --sigstore-identity/--sigstore-issuer (and/or --gpg-fingerprint); '
                            'read the python.org page text printed in the log')
        bad = [c for c in py['checks'] if not c['ok']]
        if bad:
            problems.append('python-windows signature verification FAILED: ' + ', '.join(c['method'] for c in bad))
        good = [c['method'] for c in py['checks'] if c['ok']]
        py['verified_by'] = good
        py['proposed_digest_source'] = ('sigstore-verified' if 'sigstore' in good else 'gpg-verified') if good and not bad else None
    except Exception as error:  # noqa: BLE001
        problems.append(f'python-windows: {error}')
    # (2) ghidriff
    gh = pin['ghidriff']
    commit = gh['sha']
    ev: dict = {'repo': gh['repo'], 'commit': commit}
    evidence['ghidriff'] = ev
    try:
        tarball, info = rebuild_tarball(gh['repo'], commit, work, run)
        second_dir = work / 'second'
        second_dir.mkdir(exist_ok=True)
        again = build_tarball(work / 'ghidriff-git', commit, second_dir / 'again.tar.gz', run)
        ev.update(tree=info['tree'], rebuilt_sha256=info['sha256'], rebuilt_size=info['size'],
                  rebuilt_twice_identical=again['sha256'] == info['sha256'])
        if not ev['rebuilt_twice_identical']:
            problems.append('ghidriff: two rebuilds differ (recipe is not deterministic)')
        ev['github_tarball_url'] = gh['source_tarball']['url']
        gh_tar = work / 'github-archive.tar.gz'
        _fetch(gh['source_tarball']['url'], gh_tar, limit=64 << 20)
        ev['github_tarball_sha256'], ev['github_tarball_size'] = sha256_file(gh_tar), gh_tar.stat().st_size
        ev['content_comparison'] = compare_tarballs(tarball, gh_tar)
        if not ev['content_comparison']['identical']:
            problems.append('ghidriff: rebuilt tarball content differs from the GitHub archive tarball')
        ev['proposed_digest_source'] = 'git-rebuilt' if not problems else None
    except Exception as error:  # noqa: BLE001
        problems.append(f'ghidriff: {error}')
    evidence['problems'] = problems
    evidence['result'] = 'verified' if not problems else 'FAILED'
    evidence['record_in_pin'] = None if problems else {
        'components.python-windows': {'sha256': py['sha256'], 'size': py['size'], 'digest_source': py['proposed_digest_source']},
        'ghidriff.source_tarball': {'sha256': ev['rebuilt_sha256'], 'size': ev['rebuilt_size'], 'digest_source': 'git-rebuilt'},
    }
    return evidence, problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='mode', required=True)
    rb = sub.add_parser('rebuild')
    rb.add_argument('--repo', required=True)
    rb.add_argument('--commit', required=True)
    rb.add_argument('--out', type=Path, required=True)
    vf = sub.add_parser('verify')
    vf.add_argument('--pin', type=Path, default=Path(__file__).resolve().with_name('backend_pin.json'))
    vf.add_argument('--out', type=Path, default=Path('pin-verify.json'))
    vf.add_argument('--workdir', type=Path, default=Path('pin-verify-work'))
    vf.add_argument('--sigstore-identity', default='')
    vf.add_argument('--sigstore-issuer', default='')
    vf.add_argument('--gpg-fingerprint', default='')
    args = parser.parse_args(argv)
    try:
        if args.mode == 'rebuild':
            tmp = args.out.parent / '.rebuild-work'
            path, info = rebuild_tarball(args.repo, args.commit, tmp)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, args.out)
            shutil.rmtree(tmp, ignore_errors=True)
            print(json.dumps(info, indent=2))
            return 0
        evidence, problems = verify_all(args)
    except VerifyError as error:
        print(f'FAIL: {error}', file=sys.stderr)
        return 1
    text = json.dumps(evidence, indent=2, sort_keys=True)
    args.out.write_text(text + '\n', encoding='utf-8')
    print(text)
    for line in problems:
        print(f'FAIL: {line}', file=sys.stderr)
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
