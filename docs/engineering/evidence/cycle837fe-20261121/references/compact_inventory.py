"""Losslessly encode repeated Git paths and commit identifiers for publication."""
from __future__ import annotations

import copy
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode()


def runs(values):
    output = []
    if not values:
        return output
    start = end = values[0]
    for value in values[1:] + [None]:
        if value is not None and value == end + 1:
            end = value
            continue
        if end - start >= 2:
            output.append([start, end])
        else:
            output.extend(range(start, end + 1))
        start = end = value
    return output


def expand_runs(values):
    for value in values:
        if isinstance(value, list):
            yield from range(value[0], value[1] + 1)
        else:
            yield value


def expand(data):
    result = copy.deepcopy(data)
    info = result.pop('compact_encoding')
    result['schema'] = info['original_schema']
    paths = result.pop('path_table')
    commits = result.pop('commit_table')
    groups = result.pop('path_sets')

    def decode(index):
        rows = [{'status': status, 'path': paths[path_index]}
                for status, values in groups[index].items() for path_index in expand_runs(values)]
        return sorted(rows, key=lambda row: row['path'].encode('utf-8', 'surrogateescape'))

    for branch in result['branches']:
        for baseline in ('main', 'pr348'):
            for changes in branch.get(baseline, {}).get('branch_changes_from_merge_bases', []):
                changes['paths'] = decode(changes.pop('path_set_ref'))
        if 'file_differences_from_pr348_ref' in branch:
            branch['file_differences_from_pr348'] = decode(branch.pop('file_differences_from_pr348_ref'))
        if 'unique_nonmerge_commit_refs_vs_pr348' in branch:
            branch['unique_nonmerge_commits_vs_pr348'] = [
                commits[index] for index in branch.pop('unique_nonmerge_commit_refs_vs_pr348')]
    assert hashlib.sha256(canonical(result)).hexdigest() == info['expanded_canonical_sha256']
    return result


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expand', type=Path, help='Expand a compact .json or .json.gz instead of building it')
    parser.add_argument('--output', type=Path, help='Expanded JSON output file (required with --expand)')
    args = parser.parse_args()
    if args.expand:
        if args.output is None:
            parser.error('--output is required with --expand')
        content = gzip.decompress(args.expand.read_bytes()) if args.expand.suffix == '.gz' else args.expand.read_bytes()
        result = expand(json.loads(content))
        args.output.write_bytes(canonical(result) + b'\n')
        print('Expanded JSON verified against its canonical SHA-256.')
        return

    original_path = ROOT / 'technical-inventory.json'
    original = json.loads(original_path.read_text())
    collections = []
    for branch in original['branches']:
        for baseline in ('main', 'pr348'):
            collections.extend(changes['paths'] for changes in branch.get(baseline, {}).get('branch_changes_from_merge_bases', []))
        if 'file_differences_from_pr348' in branch:
            collections.append(branch['file_differences_from_pr348'])
    paths = sorted({row['path'] for values in collections for row in values},
                   key=lambda value: value.encode('utf-8', 'surrogateescape'))
    path_indices = {path: index for index, path in enumerate(paths)}
    commits = sorted({sha for branch in original['branches'] for sha in branch.get('unique_nonmerge_commits_vs_pr348', [])})
    commit_indices = {sha: index for index, sha in enumerate(commits)}
    groups = []
    group_indices = {}

    def encode(rows):
        values = {}
        for row in rows:
            values.setdefault(row['status'], []).append(path_indices[row['path']])
        group = {status: runs(sorted(indices)) for status, indices in sorted(values.items())}
        key = canonical(group)
        if key not in group_indices:
            group_indices[key] = len(groups)
            groups.append(group)
        return group_indices[key]

    compact = copy.deepcopy(original)
    compact['schema'] = 'patchtrace.branch-technical-inventory.compact/1'
    for branch in compact['branches']:
        for baseline in ('main', 'pr348'):
            for changes in branch.get(baseline, {}).get('branch_changes_from_merge_bases', []):
                changes['path_set_ref'] = encode(changes.pop('paths'))
        if 'file_differences_from_pr348' in branch:
            branch['file_differences_from_pr348_ref'] = encode(branch.pop('file_differences_from_pr348'))
        if 'unique_nonmerge_commits_vs_pr348' in branch:
            branch['unique_nonmerge_commit_refs_vs_pr348'] = [
                commit_indices[sha] for sha in branch.pop('unique_nonmerge_commits_vs_pr348')]
    compact['compact_encoding'] = {
        'original_schema': original['schema'],
        'expanded_original_sha256': hashlib.sha256(original_path.read_bytes()).hexdigest(),
        'expanded_canonical_sha256': hashlib.sha256(canonical(original)).hexdigest(),
        'format': 'path_set_ref indexes path_sets; each status maps path_table indices as singleton integers or inclusive [start,end] ranges; commit references preserve original traversal order',
        'verification': 'Expanded Python JSON value equals the complete original inventory; canonical SHA-256 checked'}
    compact['path_table'] = paths
    compact['commit_table'] = commits
    compact['path_sets'] = groups
    assert expand(compact) == original
    data = canonical(compact) + b'\n'
    (ROOT / 'technical-inventory.compact.json').write_bytes(data)
    zipped = gzip.compress(data, mtime=0)
    (ROOT / 'technical-inventory.compact.json.gz').write_bytes(zipped)
    assert expand(json.loads(gzip.decompress(zipped))) == original
    summary_path = ROOT / 'summary.json'
    summary = json.loads(summary_path.read_text())
    summary['compact'] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                          'gzip_bytes': len(zipped), 'gzip_sha256': hashlib.sha256(zipped).hexdigest(),
                          'unique_paths': len(paths), 'unique_commits': len(commits), 'unique_path_sets': len(groups),
                          'lossless_json_roundtrip_verified': True,
                          'expanded_canonical_sha256': compact['compact_encoding']['expanded_canonical_sha256']}
    summary_path.write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary['compact'], indent=2))


if __name__ == '__main__':
    main()
