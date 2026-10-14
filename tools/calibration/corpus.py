"""Corpus manifest tooling (spec §3): `init`, `verify`, `guard`, `fetch-plan`, `fetch`.

Microsoft binaries never enter git: Tier-W files live under PATCHTRACE_CALIB_ROOT (default
~/.patchtrace-calibration/, must be outside the work tree); `guard` fails on any PE/ELF image outside the
fixture allow-list and on any work-tree file whose hash equals a Tier-W manifest entry. Nothing fetched is
ever executed. Winbindex is used for identity metadata only (its licence is reported as GPL-3.0 but is
UNCONFIRMED); none of its data is vendored or copied into the repository.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

from .contracts import Binary, ContractError, CorpusManifest, load_manifest

ROOT_ENV = 'PATCHTRACE_CALIB_ROOT'
DEFAULT_ROOT = Path.home() / '.patchtrace-calibration'
FIXTURE_ALLOW = ('tests/fixtures/',)
MAX_DOWNLOAD = 512 * 1024 * 1024


def calib_root(environ=None) -> Path:
    env = os.environ if environ is None else environ
    return Path(env.get(ROOT_ENV) or DEFAULT_ROOT).expanduser().resolve()


def binary_path(root: Path, binary: Binary) -> Path:
    return root / 'binaries' / binary.sha256 / binary.file_name


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def executable_magic(head: bytes) -> str | None:
    """'pe' for an MZ image with a PE signature (or a bare MZ stub), 'elf' for ELF, else None."""
    if head[:4] == b'\x7fELF':
        return 'elf'
    if head[:2] == b'MZ':
        if len(head) >= 0x40:
            (lfanew,) = struct.unpack_from('<I', head, 0x3C)
            if lfanew + 4 <= len(head) and head[lfanew:lfanew + 4] == b'PE\0\0':
                return 'pe'
        return 'pe' if len(head) >= 0x40 else None
    return None


def _inside(path: Path, tree: Path) -> bool:
    try:
        path.resolve().relative_to(tree.resolve())
        return True
    except ValueError:
        return False


def candidate_files(worktree: Path, include_untracked: bool = True) -> list[str]:
    """Tracked (+ untracked-not-ignored: what could be committed) files; os.walk fallback without git."""
    extra = ['--others', '--exclude-standard'] if include_untracked else []
    try:
        out = subprocess.run(['git', '-C', str(worktree), 'ls-files', '-z', '--cached', *extra],
                             capture_output=True, check=True, timeout=60).stdout
        return sorted({p for p in out.decode('utf-8', 'replace').split('\0') if p})
    except (OSError, subprocess.SubprocessError):
        files = []
        for base, dirs, names in os.walk(worktree):
            dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', '.venv', 'build', 'dist'}]
            files += [str((Path(base) / n).relative_to(worktree)).replace(os.sep, '/') for n in names]
        return sorted(files)


def guard(worktree: Path, manifest: CorpusManifest | None = None, files: Iterable[str] | None = None,
          allow: Sequence[str] = FIXTURE_ALLOW) -> list[str]:
    """Problems that must block a commit/CI run. Empty list means clean."""
    problems = []
    tier_w = {b.sha256: b.id for b in manifest.binaries if b.tier == 'W'} if manifest else {}
    files = list(files if files is not None else candidate_files(worktree))
    for rel in files:
        path = worktree / rel
        if not path.is_file() or path.is_symlink():
            continue
        try:
            with open(path, 'rb') as handle:
                head = handle.read(4096)
        except OSError:
            continue
        kind = executable_magic(head)
        if kind and not any(rel.startswith(prefix) for prefix in allow):
            problems.append(f'{rel}: {kind.upper()} image outside the fixture allow-list')
        if tier_w and (found := tier_w.get(_sha256_file(path))):
            problems.append(f'{rel}: equals Tier-W binary {found} (never commit)')
    root = calib_root()
    if _inside(root, worktree):
        problems.append(f'{ROOT_ENV} ({root}) is inside the work tree')
    from .tier_w.guard import tier_w_problems  # SPEC-33 s12 hook (Tier-W owner)
    problems += tier_w_problems(worktree, files)
    return problems


def verify(manifest: CorpusManifest, root: Path, worktree: Path | None = None) -> dict:
    """Re-hash every local file. Missing files are reported, never substituted."""
    out = {'ok': [], 'missing': [], 'mismatch': [], 'errors': []}
    if worktree is not None and _inside(root, worktree):
        out['errors'].append('corpus root is inside the git work tree')
    for b in sorted(manifest.binaries, key=lambda b: b.id):
        path = binary_path(root, b)
        if not path.is_file():
            out['missing'].append(b.id)
            continue
        if _sha256_file(path) != b.sha256 or (b.size is not None and path.stat().st_size != b.size):
            out['mismatch'].append(b.id)
        else:
            out['ok'].append(b.id)
    return out


def fetch_plan(manifest: CorpusManifest) -> list[dict]:
    from patchtrace.acquisition.contracts import symbol_server_url
    plan = []
    for b in sorted(manifest.binaries, key=lambda b: b.id):
        if b.tier == 'W' and b.winbindex is not None:
            plan.append({'id': b.id, 'sha256': b.sha256, 'url': symbol_server_url(
                b.file_name, b.winbindex.timestamp, b.winbindex.virtual_size)})
    return plan


def fetch(manifest: CorpusManifest, root: Path, download: Callable[[str], bytes]) -> dict:
    """Download Tier-W files by Winbindex identity; keep only hash-verified bytes; never execute them."""
    out = {'stored': [], 'present': [], 'failed': []}
    by_id = {b.id: b for b in manifest.binaries}
    for item in fetch_plan(manifest):
        b = by_id[item['id']]
        target = binary_path(root, b)
        if target.is_file() and _sha256_file(target) == b.sha256:
            out['present'].append(b.id)
            continue
        try:
            data = download(item['url'])
        except Exception as exc:  # noqa: BLE001 - reported per file
            out['failed'].append(f'{b.id}: {type(exc).__name__}')
            continue
        if hashlib.sha256(data).hexdigest() != b.sha256:
            out['failed'].append(f'{b.id}: hash mismatch (not stored)')
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + '.part')
        tmp.write_bytes(data)
        os.replace(tmp, target)
        out['stored'].append(b.id)
    return out


def _urllib_download(url: str) -> bytes:  # pragma: no cover - live network, explicit --download only
    import urllib.request
    if not url.startswith('https://'):
        raise ValueError('https only')
    with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310
        data = response.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError('download too large')
    return data


def init_manifest(corpus_id: str, tool_git: str, created: str) -> dict:
    return {'contract': 'calibration-corpus/1', 'corpus_id': corpus_id, 'created': created, 'tool_git': tool_git,
            'binaries': [], 'pairs': [], 'lineages': [],
            'split': {'salt': 'c9-v1', 'method': 'sha256(lineage_id|salt) -> u; <.60 dev, <.85 locked-test, '
                                                'else shift-test', 'shift_test_lineages': []}}


def main(argv: Sequence[str] | None = None) -> int:
    if (args_in := list(sys.argv[1:] if argv is None else argv))[:1] == ['known-answer']:  # SPEC-32 s12 hook
        import importlib.util
        if importlib.util.find_spec(f'{__package__}.tier_r.cli') is None:
            return print('known-answer: tier_r.cli is not available', file=sys.stderr) or 2
        return importlib.import_module(f'{__package__}.tier_r.cli').main(args_in[1:])
    parser = argparse.ArgumentParser(description='Calibration corpus manifest tooling (dev-only).')
    sub = parser.add_subparsers(dest='cmd', required=True)
    p_init = sub.add_parser('init')
    p_init.add_argument('corpus_id')
    p_init.add_argument('--tool-git', default='unknown')
    p_init.add_argument('--created', required=True)
    for name in ('verify', 'fetch-plan', 'fetch'):
        p = sub.add_parser(name)
        p.add_argument('manifest', type=Path)
    sub.choices['fetch'].add_argument('--download', action='store_true', help='actually download (network)')
    p_guard = sub.add_parser('guard')
    p_guard.add_argument('--manifest', type=Path)
    p_guard.add_argument('--worktree', type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    if args.cmd == 'init':
        json.dump(init_manifest(args.corpus_id, args.tool_git, args.created), sys.stdout, indent=2)
        print()
        return 0
    try:
        manifest = load_manifest(args.manifest.read_bytes()) if getattr(args, 'manifest', None) else None
    except (OSError, ContractError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    if args.cmd == 'guard':
        problems = guard(args.worktree, manifest)
        for line in problems:
            print(line)
        return 1 if problems else 0
    if args.cmd == 'verify':
        result = verify(manifest, calib_root(), Path.cwd())
        print(json.dumps(result, indent=2))
        return 1 if result['mismatch'] or result['errors'] else 0
    if args.cmd == 'fetch-plan' or not args.download:
        print(json.dumps(fetch_plan(manifest), indent=2))
        return 0
    result = fetch(manifest, calib_root(), _urllib_download)
    print(json.dumps(result, indent=2))
    return 1 if result['failed'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
