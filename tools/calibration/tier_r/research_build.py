"""Build the R1 development suite across existing Tier R profiles, sequentially; never execute targets.

Receipts describe builds and authored-label cross-checks, not independent review or engine acceptance.
Stock profile flags are retained, including their discovery limitations and export-name visibility.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from . import contracts as C
from . import factory as F
from .build import OPTS, BuildError
from .labeler import label_authored
from .output_store import read_output_bytes
from .receipts import validate_spelling, write_new_receipt
from .toolchain import Blocked, ToolError, probe

REPO = Path(__file__).resolve().parents[3]
DEFAULT_SUITE = REPO / 'corpus' / 'ours' / 'r1-pilot' / 'defined'
PROFILES = ('msvc-free', 'mingw-gcc', 'mingw-clang')
MAX_MATRIX_CELLS = 512
MAX_SUITE_VERSIONS = 64
MAX_SUITE_ENTRIES = 4096
MAX_SOURCE_BYTES = 16 * 1024 * 1024
NOTES = (
    'Development fixtures; authored labels require independent binary review. No engine was evaluated.',
    'Built target images are never executed. Stock profile flags are unchanged.',
    'Equal endpoint code can make named correspondence ambiguous; see the suite README.',
)


def _outside_repository(path: Path) -> Path:
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('artifact paths must be absolute')
    path = path.resolve()
    if path.is_relative_to(REPO):
        raise ValueError('generated artifacts must be outside the repository')
    return path


def _new_receipt_path(path: Path) -> Path:
    """Check the original CLI spelling before resolving aliases or starting builds."""
    path = Path(path)
    validate_spelling(path)
    if path.is_relative_to(REPO):
        raise ValueError('generated artifacts must be outside the repository')
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('receipt destination and parent paths cannot contain symlinks')
    target = _outside_repository(path)
    if target.exists():
        raise ValueError('receipt already exists; choose a new output path')
    return target


def _visibility(profile: str) -> str:
    if profile == 'msvc-free':
        return ('No export names are injected. A stripped no-entry DLL may expose no discoverable function starts; '
                'zero discovery is an observability finding, not matching success. This is Clang, not MSVC cl.')
    return ('MinGW stock linking may automatically export function names; stripping debug information does not '
            'remove export names. Treat this as a potentially name-visible condition pending PE inspection.')


def _source_files(root: Path, entry_budget: list[int] | None = None) -> tuple[str, ...]:
    """Enumerate a bounded plain source tree; reject special entries before reading them."""
    files, pending = [], [root]
    entry_budget = entry_budget if entry_budget is not None else [0]
    total = 0
    while pending:
        folder = pending.pop()
        info = folder.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or getattr(info, 'st_file_attributes', 0) & 0x400):
            raise ValueError('research suite directories must be ordinary directories')
        with os.scandir(folder) as children:
            for child in children:
                entry_budget[0] += 1
                if entry_budget[0] > MAX_SUITE_ENTRIES:
                    raise ValueError('research suite source entry limit exceeded')
                info = child.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                    raise ValueError('research suite cannot contain linked or reparse entries')
                path = Path(child.path)
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                elif not stat.S_ISREG(info.st_mode):
                    raise ValueError('research suite cannot contain special entries')
                elif path.suffix == '.c':
                    raw = read_output_bytes(path, MAX_SOURCE_BYTES - total)
                    total += len(raw)
                    files.append(path.relative_to(root).as_posix())
    if not files:
        raise ValueError('research suite version has no C source files')
    return tuple(sorted(files))


def _suite_bases(suite_dir: Path) -> tuple[C.Suite, dict[str, F.BaseSource]]:
    suite = C.load_suite(read_output_bytes(suite_dir / 'suite.json', C.MAX_DOC_BYTES))
    if len(suite.versions) > MAX_SUITE_VERSIONS or len(set(suite.versions)) != len(suite.versions):
        raise ValueError('research suite has too many or duplicate versions')
    if any(version in {'.', '..'} for version in suite.versions):
        raise ValueError('research suite versions must name child directories without traversal')
    if len(suite.pairs) > MAX_MATRIX_CELLS:
        raise ValueError('research matrix cell limit exceeded')
    bases, entries = {}, [0]
    for version in suite.versions:
        root = suite_dir / version
        bases[version] = F.BaseSource(
            project=suite.project, lineage=F.pair_id('L-ours', suite.suite, suite.project), family='synthetic',
            source={'suite': f'{suite.suite}/{suite.project}', 'version': version, 'license_spdx': suite.license_spdx},
            root=root, files=_source_files(root, entries), output=f'{suite.project}.dll', profile='msvc-free',
            defines=tuple(suite.build.defines), std='c11', tag=version)
    return suite, bases


def _write_labels(store: Path, doc: dict) -> Path:
    name = doc['pair_id']
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-'
    if type(name) is not str or not 1 <= len(name) <= 96 or any(character not in alphabet for character in name):
        raise ValueError('research label identity is not a safe filename')
    path = store / 'labels' / f'{name}.json'
    write_new_receipt(path, C.dump_json(doc), create_parents=True)
    return path


def build_pilot(store: Path, *, profiles: Sequence[str] = PROFILES, opts: Sequence[str] = OPTS,
                suite_dir: Path | None = None) -> dict:
    """Build each profile/optimization/pair independently using existing factory APIs.

    Invalid inputs fail before tool probing. Tool, compile, analysis and persistence failures are retained
    as blocked entries and later configurations continue. No flags, truth labels or engine results are changed.
    """
    store = _outside_repository(store)
    profiles, opts = tuple(profiles), tuple(opts)
    if not profiles or any(profile not in PROFILES for profile in profiles):
        raise ValueError(f'profiles must be a nonempty selection of {PROFILES}')
    if not opts or any(opt not in OPTS for opt in opts):
        raise ValueError(f'opts must be a nonempty selection of {OPTS}')
    suite_dir = Path(suite_dir or DEFAULT_SUITE).resolve()
    suite, bases = _suite_bases(suite_dir)
    for index, pair in enumerate(suite.pairs, start=1):
        for side, version in (('old', pair.old), ('new', pair.new)):
            if version not in suite.versions or version not in bases:
                raise ValueError(f"suite pair {index} {side} version {version!r} is not a declared available version")
    if len(profiles) * len(opts) * len(suite.pairs) > MAX_MATRIX_CELLS:
        raise ValueError('research matrix cell limit exceeded')
    cells = [(profile, opt, pair, F.pair_id('research', profile, opt, suite.suite, suite.project,
                                          pair.old, pair.new))
             for profile in profiles for opt in opts for pair in suite.pairs]
    if len({cell[3] for cell in cells}) != len(cells):
        raise ValueError('duplicate or truncated pair IDs would overwrite label documents')
    tools = probe()
    session = F.Session(tools, store)
    entries = []
    for profile, opt, pair, pid in cells:
        notes = [*NOTES, _visibility(profile)]
        entry = {'profile': profile, 'opt': opt, 'pair_id': pid, 'status': 'blocked',
                 'stage': 'toolchain', 'notes': notes}
        entries.append(entry)
        reason = tools.profile_status(profile)
        if reason:
            entry.update(reason=reason, error_type='Blocked')
            continue
        try:
            old_base = replace(bases[pair.old], profile=profile)
            new_base = replace(bases[pair.new], profile=profile)
            entry['stage'] = 'build'
            old_b = session.build(old_base.spec(opt=opt, variant=pair.old.lower()[:32]))
            new_b = session.build(new_base.spec(opt=opt, variant=pair.new.lower()[:32]))
            entry['stage'] = 'analyze'
            old = session.side(old_b, old_base.root)
            new = session.side(new_b, new_base.root)
            entry['stage'] = 'label'
            functions, problems = label_authored(old, new, pair.truth)
            doc = F.finalize(pid=pid, stratum='authored', method='suite', base_old=old_base,
                             base_new=new_base, old=old, new=new, label_source='authored-truth',
                             functions=functions, case={'suite': suite.suite, 'project': suite.project,
                                                       'old': pair.old, 'new': pair.new,
                                                       'intent': pair.intent[:2000], 'problems': problems[:100]},
                             notes=notes)
            entry['stage'] = 'persist'
            path = _write_labels(store, doc)
            disagreements = doc['summary']['disagreements']
            entry.update(status='findings' if problems or disagreements else 'built', stage='complete',
                         labels_path=str(path), labels_digest_sha256=doc['digest_sha256'],
                         older=doc['older'], newer=doc['newer'], disagreements=disagreements,
                         problems=problems[:100], problem_count=len(problems))
        except (Blocked, ToolError, BuildError, F.FactoryError, ValueError, OSError) as exc:
            entry.update(reason=str(exc)[:4000], error_type=type(exc).__name__)
    states = {entry['status'] for entry in entries}
    status = ('blocked' if states == {'blocked'} else 'partial' if 'blocked' in states else
              'findings' if 'findings' in states else 'built')
    return {'command': 'research-build', 'status': status, 'store': str(store),
            'suite': {'directory': str(suite_dir), 'suite': suite.suite, 'project': suite.project},
            'tools': tools.describe(), 'entries': entries, 'notes': list(NOTES)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--store', required=True, type=Path, help='absolute artifact store outside the repository')
    parser.add_argument('--output', required=True, type=Path, help='new absolute .json receipt outside the repository')
    parser.add_argument('--suite', type=Path, default=DEFAULT_SUITE)
    parser.add_argument('--profiles', default=','.join(PROFILES), help='comma-separated stock Tier R profiles')
    parser.add_argument('--opts', default=','.join(OPTS), help='comma-separated optimization levels')
    args = parser.parse_args(argv)
    receipt = None
    try:
        _new_receipt_path(args.output)
        receipt = build_pilot(args.store, profiles=args.profiles.split(','), opts=args.opts.split(','),
                              suite_dir=args.suite)
        text = json.dumps(receipt, indent=2, sort_keys=True) + '\n'
        _new_receipt_path(args.output)
        write_new_receipt(args.output, text.encode('utf-8'), create_parents=True)
    except (ValueError, OSError, RecursionError) as exc:
        error = {'command': 'research-build', 'status': 'error', 'reason': str(exc)[:4000]}
        if receipt is not None:
            error['receipt'] = receipt
        print(json.dumps(error))
        return 2
    print(text, end='')
    return {'built': 0, 'findings': 1, 'partial': 1, 'blocked': 3}[receipt['status']]


if __name__ == '__main__':
    raise SystemExit(main())
