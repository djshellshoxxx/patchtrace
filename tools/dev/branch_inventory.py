"""Read-only inventory and classification of remote branches against a base ref.

Purpose: give the consolidation coordinator one deterministic JSON record per branch (ahead/behind,
patch-equivalence via ``git cherry``, files touched by unique commits, PR metadata) and a class
(MERGED, EQUIVALENT, SUPERSEDED, DOCS, LIVE, STALE) plus file-overlap clusters for LIVE branches.

Only read-only git commands run (``rev-list``, ``merge-base``, ``cherry``, ``diff-tree``, ``show``,
``patch-id``, ``log``, ``for-each-ref``, ``diff``). No network. Commands are argument arrays, never
shell strings. PR metadata comes from an optional JSON file the caller fetched separately.

Usage:
    python tools/dev/branch_inventory.py --repo . --base origin/main [--prs prs.json] [--now ISO] [--out FILE]

``prs.json`` is a list of objects with at least ``number`` and ``head`` (branch name without the remote
prefix); optional ``base``, ``draft``, ``checks``. Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

DOCS_PREFIXES = ('docs/', 'tasks/', 'help/', 'site/')
# Hub files almost every branch edits. They are reported per branch but do not create cluster edges,
# otherwise every LIVE branch collapses into one cluster.
HUB_FILES = frozenset({
    'src/patchtrace/ui.py', 'src/patchtrace/tooltips.py', 'src/patchtrace/panel_manifest.py',
    'src/patchtrace/cli.py', 'src/patchtrace/backend.py', 'pyproject.toml', 'src/patchtrace/optional_deps.py',
    'src/patchtrace/enrichment/storage.py', '.gitattributes', 'tools/frozen_smoke.py', 'tests/test_tooltips.py',
    'tests/test_acceptance_smoke.py',
})
HUB_PREFIXES = ('.github/workflows/', 'tools/build_')
# A file touched by at least this many branches says nothing about topic and is treated as a hub too.
HUB_THRESHOLD = 8
STALE_DAYS = 14


@dataclass
class Branch:
    name: str
    head: str
    ahead: int
    behind: int
    merge_base: str
    last_commit: str
    last_author: str
    cherry_upstream: int
    cherry_unique: int
    unique_commits: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    docs_only: bool = False
    rewritten_on_base: list[str] = field(default_factory=list)
    pr: dict | None = None
    klass: str = ''
    reason: str = ''
    superseded_by: str | None = None
    cluster: int | None = None


def git(repo: Path, *args: str, stdin: str | None = None) -> str:
    result = subprocess.run(['git', '-C', str(repo), *args], input=stdin, capture_output=True, text=True,
                            encoding='utf-8', errors='replace', check=False)
    if result.returncode != 0:
        raise RuntimeError(f'git {" ".join(args[:3])} failed: {result.stderr.strip()[:300]}')
    return result.stdout


def is_docs_path(path: str) -> bool:
    return path.startswith(DOCS_PREFIXES) or path.endswith('.md')


def list_remote_branches(repo: Path, remote: str, base: str) -> list[str]:
    out = git(repo, 'for-each-ref', '--format=%(refname:short)', f'refs/remotes/{remote}/')
    skip = {base, f'{remote}/HEAD', remote}
    return sorted(ref for ref in out.split() if ref not in skip)


def parse_cherry(text: str) -> tuple[list[str], list[str]]:
    """Return (upstream_equivalent, unique) commit SHAs from ``git cherry`` output."""
    upstream, unique = [], []
    for line in text.splitlines():
        mark, _, sha = line.partition(' ')
        if mark == '+':
            unique.append(sha.strip())
        elif mark == '-':
            upstream.append(sha.strip())
    return upstream, unique


def patch_ids(repo: Path, shas: list[str]) -> dict[str, str]:
    """Map commit SHA -> stable patch-id. Commits with an empty diff get no entry."""
    result: dict[str, str] = {}
    for start in range(0, len(shas), 200):
        chunk = shas[start:start + 200]
        shown = git(repo, 'show', '--no-color', '--format=commit %H', '-p', *chunk)
        for line in git(repo, 'patch-id', '--stable', stdin=shown).splitlines():
            pid, _, sha = line.partition(' ')
            if sha:
                result[sha.strip()] = pid
    return result


def commit_files(repo: Path, sha: str) -> list[str]:
    out = git(repo, 'diff-tree', '--no-commit-id', '--name-only', '-r', '--root', sha)
    return [line for line in out.splitlines() if line]


def inspect_branch(repo: Path, ref: str, base: str, remote: str) -> Branch:
    behind, ahead = (int(n) for n in git(repo, 'rev-list', '--left-right', '--count', f'{base}...{ref}').split())
    head = git(repo, 'rev-parse', ref).strip()
    merge_base = git(repo, 'merge-base', base, ref).strip()
    date, _, author = git(repo, 'log', '-1', '--format=%cI%x09%an', ref).strip().partition('\t')
    upstream, unique = parse_cherry(git(repo, 'cherry', base, ref)) if ahead else ([], [])
    files = sorted({path for sha in unique for path in commit_files(repo, sha)})
    rewritten = []
    if files:
        changed_on_base = set(git(repo, 'diff', '--name-only', merge_base, base).splitlines())
        rewritten = sorted(set(files) & changed_on_base)
    return Branch(name=ref.removeprefix(f'{remote}/'), head=head, ahead=ahead, behind=behind, merge_base=merge_base,
                  last_commit=date, last_author=author, cherry_upstream=len(upstream), cherry_unique=len(unique),
                  unique_commits=unique, files=files, docs_only=bool(files) and all(map(is_docs_path, files)),
                  rewritten_on_base=rewritten)


def find_superseding(branches: list[Branch], pids: dict[str, str]) -> None:
    """Mark a branch SUPERSEDED when another branch's unique patch set strictly contains its own.

    Ties (identical patch sets) resolve deterministically: the branch with an open PR, then the newest, keeps
    the content; the others point at it. Among candidate supersets the largest, then PR-bearing, then
    name-sorted one is chosen.
    """
    sets = {b.name: frozenset(pids.get(sha, f'empty:{sha}') for sha in b.unique_commits) for b in branches}

    def keeper_rank(b: Branch) -> tuple:
        return (b.pr is not None, b.last_commit, b.name)

    for b in branches:
        mine = sets[b.name]
        if not mine:
            continue
        candidates = []
        for other in branches:
            theirs = sets[other.name]
            if other.name == b.name or not mine <= theirs:
                continue
            if mine == theirs and keeper_rank(other) <= keeper_rank(b):
                continue
            candidates.append(other)
        if candidates:
            best = sorted(candidates, key=lambda o: (-len(sets[o.name]), o.pr is None, o.name))[0]
            b.superseded_by = best.name


def classify(b: Branch, now: datetime) -> None:
    if b.ahead == 0:
        b.klass, b.reason = 'MERGED', '0 commits ahead of base'
    elif b.cherry_unique == 0:
        b.klass, b.reason = 'EQUIVALENT', f'{b.cherry_upstream} commits, all patch-equivalent upstream'
    elif b.superseded_by:
        b.klass, b.reason = 'SUPERSEDED', f'unique patches contained in {b.superseded_by}'
    elif b.docs_only:
        b.klass, b.reason = 'DOCS', f'{b.cherry_unique} unique commits touch docs/trackers only'
    else:
        age = now - datetime.fromisoformat(b.last_commit)
        code_rewritten = [p for p in b.rewritten_on_base if not is_docs_path(p)]
        if b.pr is None and age > timedelta(days=STALE_DAYS) and code_rewritten:
            b.klass = 'STALE'
            b.reason = f'no PR, {age.days} days old, {len(code_rewritten)} code files rewritten on base'
        else:
            b.klass, b.reason = 'LIVE', f'{b.cherry_unique} unique commits touching code'


def hub_files(pool: list[Branch], threshold: int) -> set[str]:
    counts: dict[str, int] = {}
    for b in pool:
        for path in b.files:
            counts[path] = counts.get(path, 0) + 1
    return {p for p, n in counts.items() if p in HUB_FILES or p.startswith(HUB_PREFIXES) or n >= threshold}


def cluster_live(branches: list[Branch], threshold: int = HUB_THRESHOLD) -> tuple[list[dict], list[str]]:
    """Union-find over LIVE/STALE branches sharing a non-docs, non-hub file. Returns (clusters largest first, hubs)."""
    pool = [b for b in branches if b.klass in ('LIVE', 'STALE')]
    hubs = hub_files(pool, threshold)
    parent = {b.name: b.name for b in pool}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    owner: dict[str, str] = {}
    for b in pool:
        for path in b.files:
            if is_docs_path(path) or path in hubs:
                continue
            if path in owner:
                parent[find(b.name)] = find(owner[path])
            else:
                owner[path] = b.name
    groups: dict[str, list[Branch]] = {}
    for b in pool:
        groups.setdefault(find(b.name), []).append(b)
    ordered = sorted(groups.values(), key=lambda g: (-len(g), min(m.name for m in g)))
    clusters = []
    for index, members in enumerate(ordered):
        for m in members:
            m.cluster = index
        paths = sorted({p for m in members for p in m.files if not is_docs_path(p) and p not in hubs})
        clusters.append({'id': index, 'branches': sorted(m.name for m in members),
                         'prs': sorted(m.pr['number'] for m in members if m.pr),
                         'top_dirs': sorted({'/'.join(p.split('/')[:3]) for p in paths})[:12]})
    return clusters, sorted(hubs)


def build_inventory(repo: Path, base: str, remote: str, prs: list[dict], now: datetime,
                    hub_threshold: int = HUB_THRESHOLD) -> dict:
    by_head = {pr['head']: pr for pr in prs}
    branches = [inspect_branch(repo, ref, base, remote) for ref in list_remote_branches(repo, remote, base)]
    for b in branches:
        b.pr = by_head.get(b.name)
    all_unique = sorted({sha for b in branches for sha in b.unique_commits})
    find_superseding(branches, patch_ids(repo, all_unique) if all_unique else {})
    for b in branches:
        classify(b, now)
    clusters, hubs = cluster_live(branches, hub_threshold)
    counts: dict[str, int] = {}
    for b in branches:
        counts[b.klass] = counts.get(b.klass, 0) + 1
    return {'base': base, 'base_sha': git(repo, 'rev-parse', base).strip(), 'generated_at': now.isoformat(),
            'counts': dict(sorted(counts.items())), 'hub_files': hubs, 'clusters': clusters,
            'branches': [asdict(b) for b in branches]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--repo', type=Path, default=Path('.'))
    parser.add_argument('--base', default='origin/main')
    parser.add_argument('--remote', default='origin')
    parser.add_argument('--prs', type=Path, help='JSON list of PRs: number, head, base, draft, checks')
    parser.add_argument('--now', help='ISO timestamp used for staleness (default: current UTC time)')
    parser.add_argument('--out', type=Path, help='write JSON here instead of stdout')
    parser.add_argument('--hub-threshold', type=int, default=HUB_THRESHOLD,
                        help='files touched by at least this many live branches do not join clusters')
    args = parser.parse_args(argv)
    now = datetime.fromisoformat(args.now) if args.now else datetime.now(UTC)
    if now.tzinfo is None:
        parser.error('--now must include a UTC offset')
    prs = json.loads(args.prs.read_text(encoding='utf-8')) if args.prs else []
    if not isinstance(prs, list) or not all(isinstance(p, dict) and 'number' in p and 'head' in p for p in prs):
        parser.error('--prs must be a JSON list of objects with number and head')
    try:
        inventory = build_inventory(args.repo, args.base, args.remote, prs, now, args.hub_threshold)
    except RuntimeError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    text = json.dumps(inventory, indent=1, sort_keys=False) + '\n'
    if args.out:
        args.out.write_text(text, encoding='utf-8', newline='\n')
    else:
        sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
