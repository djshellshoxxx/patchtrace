"""Build the R1 development suite across existing Tier R profiles, sequentially; never execute targets.

Receipts describe builds and authored-label cross-checks, not independent review or engine acceptance.
Stock profile flags are retained, including their discovery limitations and export-name visibility.
"""
from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from . import factory as F
from .build import OPTS, BuildError
from .labeler import label_authored
from .toolchain import Blocked, ToolError, probe

REPO = Path(__file__).resolve().parents[3]
DEFAULT_SUITE = REPO / 'corpus' / 'ours' / 'r1-pilot' / 'defined'
PROFILES = ('msvc-free', 'mingw-gcc', 'mingw-clang')
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


def _visibility(profile: str) -> str:
    if profile == 'msvc-free':
        return ('No export names are injected. A stripped no-entry DLL may expose no discoverable function starts; '
                'zero discovery is an observability finding, not matching success. This is Clang, not MSVC cl.')
    return ('MinGW stock linking may automatically export function names; stripping debug information does not '
            'remove export names. Treat this as a potentially name-visible condition pending PE inspection.')


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
    suite, bases = F.suite_bases(suite_dir)
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
            path = F.write_doc(store, doc)
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
    parser.add_argument('--output', required=True, type=Path, help='absolute JSON receipt outside the repository')
    parser.add_argument('--suite', type=Path, default=DEFAULT_SUITE)
    parser.add_argument('--profiles', default=','.join(PROFILES), help='comma-separated stock Tier R profiles')
    parser.add_argument('--opts', default=','.join(OPTS), help='comma-separated optimization levels')
    args = parser.parse_args(argv)
    try:
        output = _outside_repository(args.output)
        receipt = build_pilot(args.store, profiles=args.profiles.split(','), opts=args.opts.split(','),
                              suite_dir=args.suite)
        text = json.dumps(receipt, indent=2, sort_keys=True) + '\n'
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding='utf-8')
    except (ValueError, OSError) as exc:
        print(json.dumps({'command': 'research-build', 'status': 'error', 'reason': str(exc)[:4000]}))
        return 2
    print(text, end='')
    return {'built': 0, 'findings': 1, 'partial': 1, 'blocked': 3}[receipt['status']]


if __name__ == '__main__':
    raise SystemExit(main())
