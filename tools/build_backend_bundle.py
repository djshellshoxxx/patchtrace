"""Zero-download backend bundle builder (BUNDLE plan, slice B2: `check` only).

`check` is a read-only inventory dry-run of an already extracted Ghidra, JDK or
Python tree against the SPEC-06 path policy (`patchtrace.offline_bundle`). It
never executes, installs, downloads or modifies anything; it lists the names
that `build_offline_bundle` would refuse or that Windows could not extract.
Later slices extend this module with the build pipeline.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from patchtrace import offline_bundle as policy

# BUNDLE plan section 6: longest relative path under backend/ must stay <= 150.
MAX_RELATIVE_PATH = 150
PAYLOAD_PREFIX = 'payload'
EXIT_OK, EXIT_OFFENDERS, EXIT_USAGE = 0, 1, 2


@dataclass(frozen=True)
class Offender:
    path: str
    reason: str


def _part_reasons(part: str) -> list[str]:
    reasons = []
    if part in ('', '.', '..'):
        reasons.append('empty-or-dot-component')
    if part.endswith(' ') or part.endswith('.'):
        reasons.append('trailing-space-or-dot')
    if ':' in part or any(char in part for char in '<>"|?*'):
        reasons.append('windows-forbidden-character')
    if any(ord(char) < 32 or ord(char) == 127 for char in part):
        reasons.append('control-character')
    if '\\' in part:
        reasons.append('backslash')
    if part.split('.')[0].rstrip(' ').upper() in policy.WINDOWS_RESERVED:
        reasons.append('windows-reserved-device-name')
    return reasons


def path_reasons(relative: str) -> list[str]:
    """Reasons a payload-relative POSIX path violates the SPEC-06 policy (empty: allowed)."""
    try:
        relative.encode('utf-8')
    except UnicodeEncodeError:
        return ['not-valid-utf8']
    reasons = []
    if len(relative) > 512:
        reasons.append('path-over-512')
    for part in relative.split('/'):
        for reason in _part_reasons(part):
            if reason not in reasons:
                reasons.append(reason)
    if not reasons:
        try:
            policy._safe_relative(relative)
        except policy.OfflineBundleError:
            reasons.append('rejected-by-spec06-policy')
    return reasons


@dataclass(frozen=True)
class CheckReport:
    root: str
    prefix: str
    files: int
    directories: int
    total_bytes: int
    longest_path: int
    offenders: tuple[Offender, ...]

    @property
    def clean(self) -> bool:
        return not self.offenders

    def to_json(self) -> dict:
        return {
            'schema': 'patchtrace-bundle-check/1', 'root': self.root, 'prefix': self.prefix,
            'files': self.files, 'directories': self.directories, 'total_bytes': self.total_bytes,
            'longest_path': self.longest_path, 'clean': self.clean,
            'offenders': [{'path': item.path, 'reason': item.reason} for item in self.offenders],
        }


def check_tree(root: Path, *, prefix: str = '') -> CheckReport:
    """Inventory `root` as it would sit at `<prefix>/` inside backend/payload (lstat only)."""
    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        raise NotADirectoryError(f'not a real directory: {root}')
    prefix = prefix.strip('/')
    offenders: list[Offender] = []
    seen: dict[str, str] = {}
    counts = {'files': 0, 'directories': 0, 'bytes': 0, 'longest': 0}
    base = len(PAYLOAD_PREFIX) + 1 + (len(prefix) + 1 if prefix else 0)

    def visit(relative: str, *, directory: bool, mode: int, size: int) -> None:
        shown = f'{prefix}/{relative}' if prefix else relative
        if directory:
            counts['directories'] += 1
        else:
            counts['files'] += 1
            counts['bytes'] += size
        counts['longest'] = max(counts['longest'], len(shown))
        reasons = path_reasons(shown)
        if base + len(relative) > MAX_RELATIVE_PATH:
            reasons.append(f'longer-than-{MAX_RELATIVE_PATH}-under-backend')
        if stat.S_ISLNK(mode):
            reasons.append('symbolic-link')
        elif not directory and not stat.S_ISREG(mode):
            reasons.append('special-file')
        if not directory and size > policy.MAX_FILE:
            reasons.append('file-over-2GiB')
        canonical = unicodedata.normalize('NFC', shown).casefold()
        if canonical in seen and seen[canonical] != shown:
            reasons.append(f'collides-with:{seen[canonical]}')
        seen.setdefault(canonical, shown)
        offenders.extend(Offender(shown, reason) for reason in reasons)

    for current, names, leaves in os.walk(root, followlinks=False):
        names.sort()
        here = Path(current).relative_to(root).as_posix()
        here = '' if here == '.' else here
        for name in list(names):
            info = os.lstat(os.path.join(current, name))
            visit(f'{here}/{name}' if here else name, directory=True, mode=info.st_mode, size=0)
            if stat.S_ISLNK(info.st_mode):
                names.remove(name)
        for name in sorted(leaves):
            info = os.lstat(os.path.join(current, name))
            visit(f'{here}/{name}' if here else name, directory=False, mode=info.st_mode,
                  size=info.st_size)
    if counts['files'] > policy.MAX_MEMBERS:
        offenders.append(Offender('(tree)', f'more-than-{policy.MAX_MEMBERS}-files'))
    if counts['bytes'] > policy.MAX_TOTAL:
        offenders.append(Offender('(tree)', 'total-over-8GiB'))
    return CheckReport(str(root), prefix, counts['files'], counts['directories'], counts['bytes'],
                       counts['longest'], tuple(offenders))


def _run_check(args: argparse.Namespace) -> int:
    try:
        report = check_tree(args.tree, prefix=args.prefix)
    except OSError as error:
        print(f'error: {error}', file=sys.stderr)
        return EXIT_USAGE
    if args.json:
        print(json.dumps(report.to_json(), indent=2, ensure_ascii=True))
    else:
        print(f'{report.root}: {report.files} files, {report.directories} directories, '
              f'{report.total_bytes} bytes, longest path {report.longest_path}')
        for item in report.offenders[:args.limit]:
            print(f'OFFENDER {item.reason}: {item.path!r}')
        if len(report.offenders) > args.limit:
            print(f'... {len(report.offenders) - args.limit} more')
        print('clean' if report.clean else f'{len(report.offenders)} offender(s)')
    return EXIT_OK if report.clean else EXIT_OFFENDERS


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='PatchTrace backend bundle tooling')
    sub = parser.add_subparsers(dest='command', required=True)
    check = sub.add_parser('check', help='dry-run an extracted tree against the SPEC-06 path policy')
    check.add_argument('tree', type=Path, help='extracted Ghidra, JDK or Python directory')
    check.add_argument('--prefix', default='', help='payload folder it will occupy (ghidra, jdk, python)')
    check.add_argument('--json', action='store_true')
    check.add_argument('--limit', type=int, default=200, help='max offenders printed in text mode')
    check.set_defaults(func=_run_check)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    raise SystemExit(main())
