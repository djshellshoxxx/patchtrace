"""Expand a captured branch census with read-only Git object metadata.

This records ancestry and paths, never semantic equivalence or merge eligibility.
No checkout, fetch, update-ref, index write, hook, external diff or target program
is invoked. At most two Git subprocesses run concurrently.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path('/workspace/scratch/837fe19aae3a')
SHA = re.compile(r'[0-9a-f]{40}\Z')


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=ROOT / 'PatchTrace-publication')
    parser.add_argument('--branches', type=Path, default=ROOT / 'evidence/live-branches-20261121.json')
    parser.add_argument('--prs', type=Path, default=ROOT / 'evidence/live-prs-tags-20261121.json')
    parser.add_argument('--dispositions', type=Path, default=ROOT / 'historical-review/semantic-dispositions.json')
    parser.add_argument('--output', type=Path, default=ROOT / 'evidence/reference-inventory')
    parser.add_argument('--main', default='fdc2696c23bdbfe7668348f25e3b336ce33039f7')
    parser.add_argument('--candidate', default='6b6fcd3597a604212032ffc453477aeb6edc69ff')
    args = parser.parse_args()
    assert SHA.fullmatch(args.main) and SHA.fullmatch(args.candidate)
    environment = os.environ.copy()
    environment['GIT_OPTIONAL_LOCKS'] = '0'
    environment['GIT_PAGER'] = 'cat'
    started = utc()

    def git(*command: str, allow_no_merge_base: bool = False) -> str:
        result = subprocess.run(['git', '-C', str(args.repo), *command],
                                capture_output=True, text=True, encoding='utf-8',
                                errors='surrogateescape', env=environment, check=False)
        if result.returncode and not (allow_no_merge_base and result.returncode == 1):
            raise RuntimeError(f'git {command[0]} exited {result.returncode}: {result.stderr[:800].strip()}')
        return result.stdout.rstrip('\n')

    for baseline in (args.main, args.candidate):
        if git('cat-file', '-t', baseline) != 'commit':
            raise ValueError('Baseline is not an exact commit object')

    branch_input = json.loads(args.branches.read_text())
    pr_input = json.loads(args.prs.read_text())
    disposition_input = json.loads(args.dispositions.read_text())
    branches = branch_input['branches']
    prs_by_ref: dict[str, list] = {}
    for pr in pr_input['pull_requests']:
        prs_by_ref.setdefault(pr['head']['ref'], []).append(pr)
    scopes_by_head = {(row['branch'], row['head']): row for row in disposition_input['branches']}
    if len({row['name'] for row in branches}) != len(branches):
        raise ValueError('Duplicate captured branch name')

    def changed_paths(left: str, right: str) -> list[dict]:
        output = git('diff', '--no-ext-diff', '--no-textconv', '--no-renames',
                     '--name-status', '-z', left, right)
        chunks = output.split('\0') if output else []
        if chunks and chunks[-1] == '':
            chunks.pop()
        if len(chunks) % 2:
            raise ValueError('Unexpected NUL-delimited name-status output')
        return [{'status': chunks[i], 'path': chunks[i + 1]} for i in range(0, len(chunks), 2)]

    def inspect(row: dict) -> dict:
        head = row['sha']
        if not SHA.fullmatch(head):
            raise ValueError('Captured head is not an exact lowercase SHA-1 object ID')
        record = {'branch': row['name'], 'head': head, 'protected_at_capture': row['protected'],
                  'state': 'DISCOVERED', 'whole_branch_semantic_classification': None,
                  'semantic_review_status': 'PENDING'}
        record['pull_requests'] = [
            {'number': pr['number'], 'url': pr['url'], 'title': pr['title'], 'state': pr['state'],
             'draft': pr['draft'], 'merged_at': pr['merged_at'], 'head_sha': pr['head']['sha'],
             'head_matches_snapshot': pr['head']['sha'] == head,
             'base_ref': pr['base']['ref'], 'base_sha': pr['base']['sha']}
            for pr in prs_by_ref.get(row['name'], [])]
        scope = scopes_by_head.get((row['name'], head))
        if scope:
            record['semantic_review_status'] = 'PARTIALLY_REVIEWED'
            record['scoped_disposition'] = {
                'source': str(args.dispositions), 'source_sha256': digest(args.dispositions),
                'scope': scope['scope'], 'excluded': scope['excluded'],
                'classification': scope['scoped_classification'],
                'whole_branch_status': scope['branch_review_status'],
                'delete_authorized': False}
        try:
            object_type = git('cat-file', '-t', head)
            if object_type != 'commit':
                raise ValueError(f'Captured head has object type {object_type!r}, not commit')
            record['commit_object_available'] = True
            commit, tree, parents = git('show', '--no-patch', '--format=%H%x00%T%x00%P', head).split('\0')
            if commit != head:
                raise ValueError('Returned commit identity does not match captured head')
            record['tree'] = tree
            record['parents'] = parents.split()
            for label, baseline in [('main', args.main), ('pr348', args.candidate)]:
                bases = git('merge-base', '--all', baseline, head, allow_no_merge_base=True).splitlines()
                behind, ahead = map(int, git('rev-list', '--left-right', '--count', baseline + '...' + head).split())
                record[label] = {'baseline': baseline, 'merge_bases': bases, 'ahead': ahead, 'behind': behind,
                                 'head_contained_by_ancestry': ahead == 0,
                                 'baseline_contained_by_head_ancestry': behind == 0,
                                 'branch_changes_from_merge_bases': [
                                     {'merge_base': base, 'paths': changed_paths(base, head)} for base in bases]}
            record['unique_nonmerge_commits_vs_pr348'] = git(
                'rev-list', '--no-merges', '--reverse', args.candidate + '..' + head).splitlines()
            record['file_differences_from_pr348'] = changed_paths(args.candidate, head)
            record['technical_status'] = 'COMPLETE'
        except (RuntimeError, ValueError) as failure:
            record.setdefault('commit_object_available', False)
            record['technical_status'] = 'BLOCKED'
            record['technical_error'] = str(failure)
        return record

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        records = list(executor.map(inspect, branches))
    result = {
        'schema': 'patchtrace.branch-technical-inventory/1',
        'started_at_utc': started, 'finished_at_utc': utc(),
        'repository': 'djshellshoxxx/PatchTrace',
        'baselines': {'main': args.main, 'pr348': args.candidate},
        'inputs': {str(p): {'sha256': digest(p)} for p in (args.branches, args.prs, args.dispositions)},
        'method_script_sha256': digest(Path(__file__)),
        'method': {
            'max_git_subprocesses': 2, 'optional_git_locks': False,
            'external_diff_and_textconv': False, 'rename_detection': False,
            'path_status_format': 'NUL-delimited status/path pairs; JSON escapes non-ASCII bytes',
            'ahead_behind': 'head-only and baseline-only reachable commit counts, including merge commits',
            'unique_commits': 'non-merge commit IDs reachable from head but not PR348; no patch-equivalence claim',
            'commands': ['cat-file -t <head>', 'show --no-patch --format=%H%x00%T%x00%P <head>',
                         'merge-base --all <baseline> <head>',
                         'rev-list --left-right --count <baseline>...<head>',
                         'rev-list --no-merges --reverse <pr348>..<head>',
                         'diff --no-ext-diff --no-textconv --no-renames --name-status -z <left> <right>']},
        'limits': ['This is technical object/ancestry/path metadata, not semantic code review.',
                   'No branch is classified mergeable, duplicate, superseded, or safe to delete from metadata alone.',
                   'Three exact historical scopes link existing partial reviews; whole-branch status remains partial.',
                   'Captured REST branch and PR pages were sequential, not an atomic server snapshot.',
                   'PR join uses captured ref name and separately records exact-head equality; fork repository identities were not in the supplied normalized PR snapshot.',
                   'No source, index, refs, remote state, target binaries, or native analysis engines were modified or executed.'],
        'branches': records}
    args.output.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(result, ensure_ascii=True, separators=(',', ':')) + '\n').encode()
    (args.output / 'technical-inventory.json').write_bytes(data)
    summary = {'schema': result['schema'], 'branches': len(records),
               'technical_complete': sum(r['technical_status'] == 'COMPLETE' for r in records),
               'blocked': sum(r['technical_status'] == 'BLOCKED' for r in records),
               'partially_reviewed_branches': sum(r['semantic_review_status'] == 'PARTIALLY_REVIEWED' for r in records),
               'semantic_pending_branches': sum(r['semantic_review_status'] == 'PENDING' for r in records),
               'pr_records_joined': sum(len(r['pull_requests']) for r in records),
               'exact_head_pr_joins': sum(p['head_matches_snapshot'] for r in records for p in r['pull_requests']),
               'unique_pr_numbers_joined': len({p['number'] for r in records for p in r['pull_requests']}),
               'input_pr_records': len(pr_input['pull_requests']),
               'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
               'baselines': result['baselines'], 'started_at_utc': started,
               'finished_at_utc': result['finished_at_utc']}
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
