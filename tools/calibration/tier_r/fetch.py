"""Explicit network step (SPEC-32 s2): fetch ONE pinned commit of an allow-listed HTTPS git repository.

git runs with a private HOME, no system/global config (no hooks, filters, credential helpers or LFS), HTTPS only,
`core.symlinks=false` (a symlink in an untrusted tree is checked out as a plain text file), a depth-1 fetch of the exact
40-hex commit, and `git rev-parse HEAD` must equal the pin. Size and file-count caps apply; `.git` is removed after
verification and a `.ka-fetched.json` receipt (with the licence file's SHA-256) is written. Nothing fetched is executed.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
from pathlib import Path

from .toolchain import Toolchain, ToolError, run_tool, tool_env

ALLOWED_HOSTS = ('github.com',)
_URL = re.compile(r'^https://(?P<host>[A-Za-z0-9.-]+)/(?P<owner>[A-Za-z0-9._-]+)/(?P<repo>[A-Za-z0-9._-]+?)(\.git)?$')
_COMMIT = re.compile(r'^[0-9a-f]{40}$')
MAX_FILES = 50_000
MAX_BYTES = 512 * 1024 * 1024
RECEIPT = '.ka-fetched.json'


class FetchError(RuntimeError):
    pass


def checkout_dir(store: Path, project: str, commit: str) -> Path:
    return Path(store) / 'src' / project / commit


def validate(url: str, commit: str, allowed_hosts=ALLOWED_HOSTS) -> None:
    m = _URL.match(url or '')
    if not m or m.group('host').lower() not in allowed_hosts:
        raise FetchError(f'refusing {url!r}: only https://{"|".join(allowed_hosts)}/<owner>/<repo> is allowed')
    if not _COMMIT.match(commit or ''):
        raise FetchError('the pin must be a full 40-hex commit')


def receipt(dest: Path) -> dict | None:
    path = Path(dest) / RECEIPT
    try:
        return json.loads(path.read_text(encoding='utf-8')) if path.is_file() else None
    except (OSError, ValueError):
        return None


def _tree_stats(root: Path) -> tuple[int, int]:
    files = total = 0
    for path in root.rglob('*'):
        if path.is_symlink() or not path.is_file():
            continue
        files += 1
        total += path.stat().st_size
        if files > MAX_FILES or total > MAX_BYTES:
            raise FetchError('checkout exceeds the size or file-count limit')
    return files, total


def file_sha256(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() and not path.is_symlink() else None


def fetch_commit(url: str, commit: str, dest: Path, tools: Toolchain, *, license_file: str | None = None,
                 expected_license_sha256: str | None = None, allowed_hosts=ALLOWED_HOSTS,
                 timeout: float = 900) -> dict:
    """Fetch and verify one commit into `dest` (idempotent). Returns the receipt."""
    validate(url, commit, allowed_hosts)
    dest = Path(dest)
    done = receipt(dest)
    if done and done.get('commit') == commit and done.get('verified'):
        _check_license(done, expected_license_sha256)
        return done
    git = tools.path('git')
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='ka-fetch-', dir=dest.parent) as private:
        work = Path(private) / 'tree'
        home = Path(private) / 'home'
        home.mkdir()
        env = tool_env(tmp=Path(private), network=True, path_dirs=[str(Path(git).parent)],
                       extra={'HOME': str(home), 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': str(home / 'none'),
                              'GIT_TERMINAL_PROMPT': '0', 'GIT_LFS_SKIP_SMUDGE': '1'})
        safe = ['-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always', '-c', 'core.symlinks=false',
                '-c', f'core.hooksPath={home / "no-hooks"}', '-c', 'credential.helper=', '-c', 'submodule.recurse=false',
                '-c', 'advice.detachedHead=false']
        try:
            run_tool([git, 'init', '-q', str(work)], cwd=Path(private), env=env, timeout=60, check=True)
            run_tool([git, *safe, 'fetch', '-q', '--depth', '1', '--no-tags', url, commit], cwd=work, env=env,
                     timeout=timeout, check=True)
            run_tool([git, *safe, 'checkout', '-q', '--detach', 'FETCH_HEAD'], cwd=work, env=env, timeout=timeout,
                     check=True)
            head = run_tool([git, 'rev-parse', 'HEAD'], cwd=work, env=env, timeout=60, check=True).log_tail.strip()
            info = run_tool([git, 'show', '-s', '--format=%ct%n%an%n%s', 'HEAD'], cwd=work, env=env, timeout=60,
                            check=True).log_tail.splitlines()
        except ToolError as exc:
            raise FetchError(f'git fetch of {commit[:12]} failed: {exc}') from None
        if head != commit:
            raise FetchError(f'fetched HEAD {head} does not equal the pin {commit}')
        shutil.rmtree(work / '.git', ignore_errors=True)
        files, total = _tree_stats(work)
        doc = {'contract': 'tier-r-fetch/1', 'url': url, 'commit': commit, 'verified': True, 'files': files,
               'bytes': total, 'commit_time': int(info[0]) if info and info[0].isdigit() else 0,
               'subject': info[2][:200] if len(info) > 2 else '',
               'license_file': license_file,
               'license_sha256': file_sha256(work / license_file) if license_file else None}
        (work / RECEIPT).write_text(json.dumps(doc, indent=1, sort_keys=True) + '\n', encoding='utf-8')
        if dest.exists():
            shutil.rmtree(dest)
        work.rename(dest)
    _check_license(doc, expected_license_sha256)
    return doc


def _check_license(doc: dict, expected: str | None) -> None:
    if expected and doc.get('license_sha256') != expected:
        raise FetchError(f'licence file hash {doc.get("license_sha256")} differs from the pinned {expected}: '
                         're-read the licence before using this commit')
