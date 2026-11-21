#!/usr/bin/env python3
"""Guarded records assembly; authoring never executes this helper.

After root hydrates the real qualified primary merge and supplies the required
promotion context, invoke without arguments to validate/print a plan, or --apply
to write it. No install, source test, staging, commit, network, or ref operation.
Optional context: historical_summary_markdown (text), historical_dispositions
(list), additional_completed_tasks (unique-id objects, status COMPLETE), and
additional_evidence ({source: workspace-relative, destination: filename, sha256}).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

ROOT = Path('/workspace/scratch/837fe19aae3a')
REPO = ROOT / 'PatchTrace-codex5-followup'
EVIDENCE = Path('docs/engineering/evidence/cycle837fe-codex5-20261121')
REPORT = Path('docs/engineering/cycle837fe-codex5-20261121.md')
LEDGER = Path('docs/engineering/task-ledger.json')
HANDOFF = Path('docs/engineering-handoffs/cycle837fe-combined-pr349-20261121.md')
PREFIXED = (HANDOFF, Path('docs/qa.md'), Path('tasks/todo.md'))
CONTEXT = ROOT / 'primary-main-promotion-context.json'
PRIMARY_DIR = ROOT / 'evidence/final-ae69-qualification'
PRIMARY_HEAD = 'ae69f1e65d7c4564ec5b0e6d7a80119193fabc4e'
PRIMARY_TREE = 'c3f09435deb99ca0ddb3406e27ab315dba7740cf'
MAIN_BEFORE = 'fdc2696c23bdbfe7668348f25e3b336ce33039f7'
CODE = '5b5328ee83ee4990b3311f7ac90e2f5e5f76f800'
TREE = '1e12edd510399fd92da6867cd071394ceb7fc95b'
REMOTE = '92dfc4d4d2ef9d604bc9db1a639d4f19add535a8'
DONOR = '36b58a7d857690a8bf0093bcee1edd5036189b30'
DONOR_BASE = 'f928a0cef29eac2b603d390c40fb86448111b91b'
TASK_ID = 'codex5-per-command-audit-20261121'
MARKERS = ('[no release]', '[no deploy]')
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
PROMOTE_IDS = frozenset({
    'search-header-help-20261121-837fe', 'service-postcommit-snapshot-20261121-837fe',
    'backup-cleanup-cancellation-20261121-837fe', '837fe-codex1-direct-actions',
    '837fe-intel-windows-version-names', '837fe-intel-probe-diagnostics',
    '837fe-pr349-spec-registry', '837fe-combined-pr349-qualification',
    '837fe-intel-synthetic-windows-identity', '837fe-native-c4-combined-qualification',
    '837fe-tier-r-immutable-pin-contract',
})
CODE_PATHS = frozenset({
    'docs/audits/codex-workflows-1.md',
    'docs/engineering-handoffs/codex5-command-audit-20261121.md',
    'docs/engineering/evidence/codex5-per-command-audit-20261121.json',
    'docs/modules.md', 'docs/specs/REGISTRY.md', 'docs/specs/ci-pip-command-audit.md',
    'tests/test_codex5_command_audit_20261121.py', 'tools/ci_pip_install_audit.py',
})
FROZEN_EVIDENCE = {
    'root-validation.zip': 'b0cf012bab566eb9b9102a167ef820b0401d131844f09769c5d610ee4ab44b89',
    'author-history.zip': '888cae02ac96bc90a9a51061f2d1e2ee38935ea8a1187f9c60b0921e585ba878',
    'independent-review.json': '4ccb598ec92de0f21e7babdc9d77e211b6baaa7205ea92c2fab0f04d698a3a94',
    'independent-review.zip': '356c89a7e9ffd7c01e25d47e98ed02b291be0c69bc0e22934ee609e61c99f7e6',
    'combined-focused.json': '27455559d2548974c9e6a59f6e8a7d5623d85f579cb7d94633327084cf63a926',
    'code-publication-mapping.json': '2c8b88e12db391d8cd90e2ef2b1ce2e31502ca81c374481334e59094cef974ff',
}
OPEN_GATES = [
    'Broad CODEX-5 host/build/application/dev/signing/engine hash closures; both strict expected failures remain.',
    'Ghidra original-archive cache-hit acceptance remains a distinct gate.',
    'Tier R coverage warnings, Tier W environment blocks, and native blocked checks remain; green wrapper jobs do not erase them.',
    'Manual, trust, accessibility, full raw provenance, and separate L1/L2/L3 acceptance remain open.',
    'New CODEX-5 source still requires final publication, applicable hosted/full qualification, and guarded main merge.',
]


def require(condition: object, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def git(*args: str) -> bytes:
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0')
    for key in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_NAMESPACE',
                'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES'):
        env.pop(key, None)
    return subprocess.check_output(['git', '--no-replace-objects', *args], cwd=REPO, env=env)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')


def parse_json(data: bytes, label: str) -> dict:
    def pairs(items):
        obj = {}
        for key, value in items:
            require(key not in obj, f'{label}: duplicate key {key!r}')
            obj[key] = value
        return obj

    def constant(value):
        raise RuntimeError(f'{label}: nonfinite JSON {value}')

    value = json.loads(data.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
    require(isinstance(value, dict), f'{label}: expected object')
    json_bytes(value)  # Reject overflowing numbers and unpaired surrogates too.
    return value


def regular_file(path: Path) -> Path:
    require(path.is_relative_to(ROOT), f'Path outside workspace: {path}')
    cursor = ROOT
    for part in path.relative_to(ROOT).parts:
        cursor /= part
        require(not cursor.is_symlink(), f'Symlink refused: {cursor}')
    require(path.is_file(), f'Required file absent: {path}')
    require(path.resolve().is_relative_to(ROOT.resolve()), f'Escaped workspace: {path}')
    return path


def load(path: Path) -> dict:
    return parse_json(regular_file(path).read_bytes(), str(path))


def safe_member(name: object) -> str:
    require(isinstance(name, str) and name and '\\' not in name and '\x00' not in name,
            f'Invalid evidence path: {name!r}')
    path = PurePosixPath(name)
    require(not path.is_absolute() and '..' not in path.parts and str(path) == name,
            f'Noncanonical evidence path: {name!r}')
    return name


def check_zip(path: Path) -> None:
    with zipfile.ZipFile(regular_file(path)) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), f'Duplicate ZIP members: {path}')
        for name in names:
            safe_member(name.rstrip('/'))
        require(archive.testzip() is None, f'ZIP CRC failure: {path}')


def pristine_worktree() -> None:
    require(git('rev-parse', 'HEAD').decode().strip() == CODE, 'Integration HEAD moved')
    require(git('rev-parse', 'HEAD^{tree}').decode().strip() == TREE, 'Integration tree mismatch')
    require(not git('diff', '--name-only') and not git('diff', '--cached', '--name-only'),
            'Tracked or staged changes are present')
    untracked = git('ls-files', '--others', '--exclude-standard', '-z').decode().split('\0')
    require(all(not name or name.startswith(EVIDENCE.as_posix() + '/') for name in untracked),
            'Untracked files outside the authorized evidence directory')
    require(set(git('diff', '--name-only', PRIMARY_HEAD, CODE).decode().splitlines()) == CODE_PATHS,
            'Frozen CODEX-5 code/spec/test delta changed')


def promotion_context() -> tuple[dict, dict]:
    context = load(CONTEXT)  # Never substitute a fabricated/fallback context.
    for field in ('merged', 'opt_outs_verified', 'all_applicable_automated_jobs_passed'):
        require(context.get(field) is True, f'Unqualified promotion context: {field}')
    expected = {'source_head': PRIMARY_HEAD, 'source_tree': PRIMARY_TREE, 'main_before': MAIN_BEFORE,
                'actual_tree': PRIMARY_TREE, 'actual_parents': [MAIN_BEFORE, PRIMARY_HEAD]}
    for field, value in expected.items():
        require(context.get(field) == value, f'Primary context mismatch: {field}')
    merge = context.get('merge_commit')
    require(isinstance(merge, str) and HEX40.fullmatch(merge), 'Invalid actual merge commit')
    raw = git('cat-file', 'commit', merge)  # Root must hydrate the real object first.
    require(hashlib.sha1(b'commit ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == merge,
            'Actual merge object identity mismatch')
    headers, message = raw.split(b'\n\n', 1)
    parents = [line[7:].decode() for line in headers.splitlines() if line.startswith(b'parent ')]
    trees = [line[5:].decode() for line in headers.splitlines() if line.startswith(b'tree ')]
    require(parents == [MAIN_BEFORE, PRIMARY_HEAD] and trees == [PRIMARY_TREE], 'Actual Git merge parents/tree mismatch')
    require(all(marker.encode() in message for marker in MARKERS), 'Actual merge lacks both opt-out markers')
    require(isinstance(context.get('summary_markdown'), str) and context['summary_markdown'].strip(), 'Missing promotion summary')
    digest = context.get('qualification_archive_sha256')
    require(isinstance(digest, str) and HEX64.fullmatch(digest), 'Invalid primary archive digest')
    qualification = load(PRIMARY_DIR / 'final-qualification.json')
    require(qualification.get('schema') == 'patchtrace/final-qualification/1', 'Unknown final qualification schema')
    source = qualification.get('source', {})
    require(str(source.get('repo_full_name', '')).casefold() == 'djshellshoxxx/patchtrace', 'Wrong qualification repository')
    expected = {'pull_request': 349, 'head_sha': PRIMARY_HEAD, 'head_tree_sha': PRIMARY_TREE,
                'base_sha': MAIN_BEFORE, 'synthetic_merge_tree_sha': PRIMARY_TREE,
                'synthetic_merge_parents': [MAIN_BEFORE, PRIMARY_HEAD]}
    for field, value in expected.items():
        require(source.get(field) == value, f'Qualification source mismatch: {field}')
    require(isinstance(source.get('synthetic_merge_sha'), str) and HEX40.fullmatch(source['synthetic_merge_sha']),
            'Missing qualified synthetic merge identity')
    verdict = qualification.get('verdict', {})
    for field in ('source_consistent', 'all_owned_runs_completed_successfully',
                  'all_required_qa_jobs_successful', 'all_applicable_ci_jobs_successful'):
        require(verdict.get(field) is True, f'Incomplete final qualification: {field}')
    require(verdict.get('qualification_status') == 'qualified_with_documented_open_gates'
            and verdict.get('native_coverage_limits_remaining') is True
            and verdict.get('expected_failures_remaining') is True, 'Documented open gates must remain explicit')
    ids = qualification.get('qa', {}).get('required_job_ids', [])
    require(isinstance(ids, list) and len(ids) == 10
            and all(isinstance(item, int) and not isinstance(item, bool) and item > 0 for item in ids)
            and len(set(ids)) == 10, 'Missing ten distinct required QA jobs')
    require(isinstance(qualification.get('runs'), list) and len(qualification['runs']) == 7, 'Observer run census incomplete')
    for field, value in {'manifest_file': 'evidence-manifest.json', 'archive_file': 'final-ae69-evidence.zip',
                         'archive_receipt_file': 'archive-receipt.json'}.items():
        require(qualification.get('evidence', {}).get(field) == value, 'Unexpected evidence names')
    verify_primary_archive(context, qualification)
    return context, qualification


def verify_primary_archive(context: dict, qualification: dict) -> None:
    receipt = load(PRIMARY_DIR / 'archive-receipt.json')
    manifest = load(PRIMARY_DIR / 'evidence-manifest.json')
    archive_path = regular_file(PRIMARY_DIR / 'final-ae69-evidence.zip')
    require(receipt.get('head_sha') == PRIMARY_HEAD and receipt.get('head_tree_sha') == PRIMARY_TREE, 'Archive receipt source mismatch')
    require(receipt.get('archive_crc_verified') is True and receipt.get('all_manifest_members_verified') is True, 'Archive not verified')
    require(receipt.get('archive_file') == archive_path.name and receipt.get('manifest_file') == 'evidence-manifest.json', 'Receipt name mismatch')
    require(receipt.get('archive_sha256') == context['qualification_archive_sha256'] == file_sha(archive_path)
            and receipt.get('archive_bytes') == archive_path.stat().st_size, 'Primary archive hash/size mismatch')
    manifest_raw = regular_file(PRIMARY_DIR / 'evidence-manifest.json').read_bytes()
    require(receipt.get('manifest_sha256') == sha(manifest_raw), 'Primary manifest hash mismatch')
    require(manifest.get('schema') == 'patchtrace/evidence-manifest/1', 'Wrong manifest schema')
    files = manifest.get('files')
    require(isinstance(files, list) and files and receipt.get('payload_file_count') == len(files), 'Manifest count mismatch')
    with zipfile.ZipFile(archive_path) as archive:
        names = archive.namelist()
        expected = {safe_member(item.get('path')) for item in files}
        require(len(expected) == len(files) and len(names) == len(set(names)), 'Duplicate ZIP/manifest members')
        require(set(names) == expected | {'evidence-manifest.json'}, 'Unaccounted primary ZIP members')
        require(archive.testzip() is None and archive.read('evidence-manifest.json') == manifest_raw, 'Primary ZIP CRC/manifest mismatch')
        require('final-qualification.json' in expected
                and parse_json(archive.read('final-qualification.json'), 'archived qualification') == qualification
                and archive.read('final-qualification.json') == (PRIMARY_DIR / 'final-qualification.json').read_bytes(),
                'Qualification receipt is not hash-bound in archive')
        for item in files:
            name = item['path']
            require(isinstance(item.get('sha256'), str) and HEX64.fullmatch(item['sha256']), f'Invalid member hash: {name}')
            require(archive.getinfo(name).file_size == item.get('bytes'), f'Member size mismatch: {name}')
            digest = hashlib.sha256()
            with archive.open(name) as stream:
                for block in iter(lambda: stream.read(1 << 20), b''):
                    digest.update(block)
            require(digest.hexdigest() == item['sha256'], f'Member digest mismatch: {name}')


def validate_frozen_evidence() -> tuple[dict, dict, dict]:
    directory = REPO / EVIDENCE
    for name, expected in FROZEN_EVIDENCE.items():
        require(file_sha(regular_file(directory / name)) == expected, f'Frozen evidence changed: {name}')
    for path in directory.rglob('*'):
        if path.is_file():
            regular_file(path)
            if path.suffix == '.zip':
                check_zip(path)
    focused = load(directory / 'combined-focused.json')
    require(focused.get('head') == focused.get('head_after') == CODE and focused.get('tree') == TREE,
            'Root qualification source mismatch')
    require(focused.get('returncode') == 0 and focused.get('dirty_before') == focused.get('dirty_after') == '',
            'Root qualification was not clean/successful')
    require(focused.get('junit_counts') == {'passed': 1548, 'failed': 0, 'errors': 0, 'skipped': 0, 'xfailed': 2}
            and focused.get('case_count') == focused.get('distinct_case_count') == 1550, 'Root count mismatch')
    require(sum(isinstance(arg, str) and arg.startswith('tests/') for arg in focused['command']) == 66
            and focused.get('seconds') == 84.021, 'Root selector/time mismatch')
    with zipfile.ZipFile(directory / 'root-validation.zip') as archive:
        require(archive.read('focused.json') == (directory / 'combined-focused.json').read_bytes(), 'Root archive/focused mismatch')
        for name in ('ruff', 'dependencies', 'source-binding'):
            result = parse_json(archive.read(name + '.json'), name)
            require(result.get('head') == result.get('head_after') == CODE and result.get('tree') == TREE
                    and result.get('returncode') == 0 and result.get('dirty_before') == result.get('dirty_after') == '',
                    f'Root {name} receipt failed/source mismatch')
    peer = load(directory / 'independent-review.json')
    require(peer.get('head') == CODE and peer.get('tree') == TREE
            and peer.get('verdict') == 'no-remaining-blocker-identified-in-reviewed-bounded-audit-scope', 'Peer source/verdict mismatch')
    maintained = peer.get('maintained', {})
    skips = maintained.get('skipped', [])
    require(maintained.get('passed') == 226 and maintained.get('tests') == maintained.get('distinct_testcases') == 228
            and maintained.get('failures') == maintained.get('errors') == 0
            and maintained.get('clean_before') is True and maintained.get('clean_after') is True
            and len(skips) == 2 and all(item.get('details', {}).get('type') == 'pytest.xfail' for item in skips), 'Peer maintained mismatch')
    require(peer.get('independent_extended_lexical_controls') == {'distinct': 20, 'passed': 20, 'failed': 0}, 'Peer lexical mismatch')
    controls = peer.get('original_independent_yaml_controls', [])
    require(len(controls) == 3 and all(item.get('pass') is True for item in controls), 'Peer YAML mismatch')
    require(peer.get('typed_mark_controls') == {'cases': 4, 'deliberate_hard_failures': 3,
            'dedicated_expected_failure': 1, 'all_expected_outcomes_observed': True}, 'Typed xfail mismatch')
    require(peer.get('current_census') == {'workflows': 21, 'runs': 200, 'installs': 42, 'unprotected': 41}, 'Audit census mismatch')
    for item in peer.get('source_blobs', []):
        require(file_sha(regular_file(REPO / safe_member(item['path']))) == item['sha256'], 'Peer source blob changed')
    with zipfile.ZipFile(directory / 'author-history.zip') as archive:
        full = parse_json(archive.read('validation/v1/full.json'), 'original full attempt')
        require(full.get('source_base') == PRIMARY_HEAD and full.get('dirty_before')
                and full.get('source_head_after') == '93b053a88e4373d9f5c69cd68f96e1a49305d579'
                and full.get('exit_code') == -9 and full.get('elapsed_seconds') == 498.536
                and full.get('source_files_unchanged') is True, 'Original incomplete full receipt mismatch')
        handoff = archive.read('HANDOFF.md').decode()
        require('wrapper exit **247**' in handoff and 'cause is undetermined' in handoff, 'Original wrapper/cause record absent')
    mapping_raw = regular_file(ROOT / 'codex5-code-publication-mapping.json').read_bytes()
    require(sha(mapping_raw) == FROZEN_EVIDENCE['code-publication-mapping.json'], 'Root mapping changed')
    mapping = parse_json(mapping_raw, 'code mapping')
    require(mapping.get('source_head') == CODE and mapping.get('remote_head') == REMOTE
            and mapping.get('tree') == TREE and mapping.get('base') == PRIMARY_HEAD
            and mapping.get('ref_movement') is False and len(mapping.get('mappings', [])) == 3, 'Static mapping mismatch')
    translated = {PRIMARY_HEAD: PRIMARY_HEAD}
    for item in mapping['mappings']:
        local, remote = item['local_commit'], item['remote_commit']
        require(HEX40.fullmatch(local) and HEX40.fullmatch(remote), 'Invalid mapped commit')
        tree = git('rev-parse', local + '^{tree}').decode().strip()
        parents = git('rev-list', '--parents', '-n', '1', local).decode().split()[1:]
        require(all(parent in translated for parent in parents), 'Unverified mapping parent')
        expected_parents = [translated[parent] for parent in parents]
        record = item.get('verified_remote_commit', {})
        require(item.get('tree') == tree and item.get('original_parents') == parents
                and item.get('remote_parents') == expected_parents and record.get('sha') == remote
                and record.get('tree', {}).get('sha') == tree
                and [parent['sha'] for parent in record.get('parents', [])] == expected_parents
                and all(marker in record.get('message', '') for marker in MARKERS), 'Remote code/tree/parents mismatch')
        translated[local] = remote
    require(translated.get(CODE) == REMOTE, 'Final mapped source missing')
    return focused, peer, full


def donor_record() -> tuple[dict, list[str]]:
    donor = parse_json(git('show', DONOR + ':' + LEDGER.as_posix()), 'donor ledger')
    base = parse_json(git('show', DONOR_BASE + ':' + LEDGER.as_posix()), 'donor base ledger')
    base_ids = {task['id'] for task in base['tasks']}
    additions = [task for task in donor['tasks'] if task['id'] not in base_ids]
    require(len(additions) == 1 and additions[0].get('id') == TASK_ID, 'Unexpected donor task delta')
    require(donor['notes'][:len(base['notes'])] == base['notes'], 'Donor altered earlier notes')
    notes = donor['notes'][len(base['notes']):]
    require(len(notes) == 2 and all(isinstance(note, str) for note in notes), 'Expected exactly two donor notes')
    return deepcopy(additions[0]), deepcopy(notes)


def qualification_record(focused: dict, full: dict) -> dict:
    return {
        'source_commit': CODE, 'source_tree': TREE, 'remote_code_commit': REMOTE,
        'distinct_affected_passed': 1548, 'case_count': 1550, 'selection_node_selectors': 66,
        'failed': 0, 'errors': 0, 'ordinary_skipped': 0, 'xfailed': 2,
        'expected_failure_ids': deepcopy(focused['expected_failure_ids']), 'command_seconds': 84.021,
        'whole_tree_ruff': 'passed', 'dependencies': 'passed',
        'isolated_source_import': 'passed; clean source-bound checkout before and after',
        'independent_review': {'passed': 226, 'strict_xfailed': 2, 'lexical_controls': 20,
                               'yaml_controls': 3, 'typed_expected_outcomes': True, 'counts_overlap_root_selection': True},
        'final_source_hosted': 'PENDING for future final follow-up PR/records source',
        'main_merge_status': 'PENDING for new CODEX-5 source',
        'prior_full_attempt': {'source': full['source_head_after'], 'started_from_modified_worktree': True,
                               'exit_code': -9, 'wrapper_exit_code': 247, 'seconds': 498.536,
                               'cause': 'unknown', 'aggregate_summary': None, 'second_local_full_attempt': False,
                               'evidence': (EVIDENCE / 'author-history.zip').as_posix()},
        'evidence': (EVIDENCE / 'combined-focused.json').as_posix(),
    }


def assemble_ledger(original: dict, context: dict, qualification: dict,
                    peer: dict, branch: str, created: str) -> dict:
    ledger = deepcopy(original)
    old_ids = [task['id'] for task in original['tasks']]
    require(len(old_ids) == len(set(old_ids)) == 98 and TASK_ID not in old_ids, 'Authoritative 98-task base mismatch')
    candidates = {task['id'] for task in original['tasks']
                  if task.get('status') == 'TESTING' and task.get('implementation_status') == 'COMPLETE'}
    require(candidates == PROMOTE_IDS, 'Primary implemented TESTING task set changed')
    donor, notes = donor_record()
    extras = context.get('additional_completed_tasks', [])
    require(isinstance(extras, list), 'additional_completed_tasks must be a list')
    extra_ids = []
    for supplied in extras:
        require(isinstance(supplied, dict) and isinstance(supplied.get('id'), str) and supplied['id'].strip(), 'Completed task needs id')
        require(supplied.get('status', 'COMPLETE') == 'COMPLETE', 'Additional task is not complete')
        extra_ids.append(supplied['id'])
    require(len(extra_ids) == len(set(extra_ids)) and not (set(extra_ids) & {*old_ids, TASK_ID}), 'Additional task IDs collide')
    historical = context.get('historical_dispositions', [])
    require(isinstance(historical, list) and all(isinstance(item, dict) for item in historical), 'historical_dispositions must be a list')
    promotion = {key: deepcopy(context[key]) for key in (
        'merged', 'source_head', 'source_tree', 'main_before', 'merge_commit', 'actual_parents',
        'actual_tree', 'opt_outs_verified', 'all_applicable_automated_jobs_passed', 'qualification_archive_sha256')}
    promotion['evidence'] = (EVIDENCE / 'primary-promotion-context.json').as_posix()
    promotion['scope'] = 'Primary ae69 only; documented open gates remain; not new CODEX-5 source qualification.'
    keys = ('updated_at', 'integration_branch', 'local_integration_branch', 'checkpoint_local_commit',
            'aggregate_source_commit', 'aggregate_source_tree', 'remote_publication', 'current_qualification',
            'current_handoff', 'continuation', 'main_merge_eligible', 'release_ready')
    history = {'context': 'Primary ae69 promoted; prior source-specific records before CODEX-5 follow-up',
               'recorded_at': created, 'prior_ledger_evidence': (EVIDENCE / 'prior-ledger-ae69.json').as_posix(),
               'previous_current_fields': {key: deepcopy(original[key]) for key in keys if key in original},
               'updated_tasks_before_promotion': deepcopy([t for t in original['tasks'] if t['id'] in PROMOTE_IDS]),
               'original_donor_task': deepcopy(donor), 'original_donor_notes': deepcopy(notes)}
    require(isinstance(ledger.get('continuation_history'), list), 'Existing continuation history shape changed')
    ledger['continuation_history'].append(history)
    for task in ledger['tasks']:
        if task['id'] in PROMOTE_IDS:
            task.update(status='MERGED', merge_status='MERGED', blockers=[], dependencies=[],
                        primary_promotion=deepcopy(promotion),
                        next_action='Primary implementation merged through verified ae69 promotion; product/native/manual and accuracy limits remain. New CODEX-5 follow-up is separate.')
    task = deepcopy(donor)
    task.update(status='TESTING', implementation_status='COMPLETE', source_commit=CODE,
                source_tree=TREE, remote_code_commit=REMOTE, base_commit=PRIMARY_HEAD,
                owner='Author/reviewer released; root837FE owns follow-up publication and qualification',
                branch=branch, target_integration_branch=branch,
                merge_status='Hosted qualification and main merge pending for new CODEX-5 source',
                source_paths=sorted(CODE_PATHS), test_results=deepcopy(qualification), original_donor_checkpoint=deepcopy(donor),
                dependencies=['Future exact-source hosted/full qualification and reviewed guarded main merge'],
                blockers=['New CODEX-5 source is not yet hosted-qualified or merged'],
                result_or_next_action='Bounded repair complete and independently reviewed; publish reviewed records, qualify actual final source, and retain both strict CODEX-5 xfails and broader closure gates.')
    ledger['tasks'].append(task)
    for supplied in extras:
        extra = deepcopy(supplied)
        extra.setdefault('status', 'COMPLETE')
        ledger['tasks'].append(extra)
    ledger['notes'].extend(deepcopy(notes))
    ledger.update(updated_at=created, integration_branch=branch, local_integration_branch=branch,
                  checkpoint_local_commit=CODE, aggregate_source_commit=CODE, aggregate_source_tree=TREE,
                  current_qualification=deepcopy(qualification), current_handoff=HANDOFF.as_posix(),
                  release_ready=False, main_merge_eligible=False)
    ledger['primary_main_promotion_837fe'] = deepcopy(promotion)
    ledger['continuation'] = {'owner': 'root837FE', 'status': 'TESTING', 'code_commit': CODE,
                              'report': REPORT.as_posix(), 'release_ready': False, 'main_merge_eligible': False,
                              'next_action': 'Review/publish follow-up records, then inspect actual final PR/CI and guarded merge eligibility; keep [no release] [no deploy].'}
    ledger['remote_publication'] = {'status': 'Static unreferenced code objects verified; follow-up PR/ref publication not performed by this helper',
                                    'branch': None, 'pr_number': None, 'base_branch': 'main', 'base_commit': context['merge_commit'],
                                    'verified_code_remote_commit': REMOTE, 'verified_code_tree': TREE,
                                    'commit_mapping': (EVIDENCE / 'code-publication-mapping.json').as_posix(),
                                    'ref_movement_by_mapping': False, 'final_records_head': None,
                                    'head_rule': 'Resolve fresh final follow-up PR/ref/CI after publication; mapped identity does not establish publication or qualification.'}
    ledger['codex5_followup_837fe'] = {'status': 'TESTING', 'implementation_status': 'COMPLETE',
                                     'code_commit': CODE, 'code_tree': TREE, 'remote_code_commit': REMOTE,
                                     'recovered_donor': DONOR, 'qualification': deepcopy(qualification),
                                     'current_census': deepcopy(peer['current_census']), 'open_gates': deepcopy(OPEN_GATES),
                                     'historical_dispositions': deepcopy(historical),
                                     'original_census_preserved': {'unmatched': 181, 'patch_equivalent': 16},
                                     'main_merge_eligible': False, 'release_ready': False, 'report': REPORT.as_posix()}
    require([t['id'] for t in ledger['tasks'][:98]] == old_ids, 'Existing task IDs/order changed')
    require(len({t['id'] for t in ledger['tasks']}) == 99 + len(extras), 'Duplicate assembled task IDs')
    require(ledger['notes'] == original['notes'] + notes, 'Prior/donor note order changed')
    require(ledger['continuation_history'][:-1] == original['continuation_history'], 'Prior histories changed')
    for before, after in zip(original['tasks'], ledger['tasks'][:98], strict=True):
        if before['id'] not in PROMOTE_IDS:
            require(before == after, f'Out-of-scope task changed: {before["id"]}')
    for key in set(original) - set(keys) - {'tasks', 'notes', 'continuation_history'}:
        require(ledger[key] == original[key], f'Prior top-level record changed: {key}')
    return ledger


def render_report(context: dict) -> bytes:
    historical = context.get('historical_summary_markdown', '')
    require(isinstance(historical, str), 'historical_summary_markdown must be text')
    gates = '\n'.join('- ' + gate for gate in OPEN_GATES)
    text = f'''# CODEX-5 bounded audit follow-up — 2026-11-21

## Current result and source identities

Primary PR #349 source `{PRIMARY_HEAD}` / tree `{PRIMARY_TREE}` was promoted by actual merge `{context['merge_commit']}`. The verified ordered parents are `{MAIN_BEFORE}` and `{PRIMARY_HEAD}`; the actual merge tree equals `{PRIMARY_TREE}`. Both **[no release] [no deploy]** are present in its message. This is completed primary promotion with documented open gates retained.

The new bounded CODEX-5 repair is local code `{CODE}` / tree `{TREE}`, mapped to verified remote code object `{REMOTE}`. Its recovered donor is `{DONOR}`. These are static prepublication code identities. The mapping moved no refs; this helper creates no commit, ref or PR. Resolve the actual final follow-up PR/head/tree and hosted checks after publication. Primary ae69 results and mapped objects do not qualify the new source. Its task is **implementation COMPLETE / TESTING / hosted and main merge pending**. `release_ready=false` and new-source `main_merge_eligible=false`.

## Primary qualification and promotion

{context['summary_markdown'].strip()}

Primary archive SHA-256: `{context['qualification_archive_sha256']}`. The external receipt, manifest, final JSON, ZIP CRCs and every member digest were checked before assembly. Applicable automated job success does not erase native/environment limits: BinDiff Windows remains **6 passed / 1 blocked**, Tier R **5/11 completed**, Tier W environment blocks and CODEX-5 expected failure remain explicit. Intel evidence is separately scoped. No release or deployment is performed by this helper.

## Bounded repair and validation

The audit reads actual `jobs[].steps[].run` YAML scalars through the existing declared PyYAML dependency. It preserves literal/folded YAML boundaries, conditional/negated commands, quote/escape/comment context, and explicit refusal of unsupported executable substitutions. Parser errors remain hard failures; only the dedicated missing-hash-protection exception satisfies the new strict expected failure. It is a bounded lexical audit, not a general shell evaluator or complete lock implementation. Runtime choices and all workflow bytes remain unchanged. Current census: **21 workflows / 200 run steps / 42 explicit installs / 41 unprotected**; Pages is the one protected install.

Root's clean `{CODE}` selection completed **1,548 passed / 2 strict CODEX-5 xfailed**, **1,550 distinct cases**, **66 selectors**, **84.021 seconds**. Whole-tree Ruff, pip consistency and isolated editable binding passed. Final independent review completed **226 passed / 2 strict xfailed**, **20 lexical controls**, **3 original YAML controls**, and the expected typed parser/xfail outcomes. Counts overlap and must not be added. Original donor fixture-only evidence and both blocked intermediate revisions remain preserved.

The only local full attempt started on the first repair's modified working tree, later frozen as `93b053a88e4373d9f5c69cd68f96e1a49305d579`. It ended with child **-9 (SIGKILL)**, wrapper **247**, after **498.536 seconds**, without an aggregate pytest summary. Cause: **unknown**. It is not a clean ae69 pass, an OOM diagnosis or final-source qualification. Final stdout and the exact receipt remain in the author-history archive. **No second local full run occurred.**

## Scoped historical consolidation

{historical.strip() or 'Root-supplied scoped dispositions/completed records are retained in the context and ledger; no global semantic-exhaustion or deletion conclusion is made.'}

The original **181 unmatched / 16 patch-equivalent** census remains unchanged. Java/license/ancillary completed records supplied through context are appended under unique IDs, without changing earlier inventory snapshots or inferring native acceptance.

## Remaining gates

{gates}

## Preservation and next ownership

`evidence/cycle837fe-codex5-20261121/prior-ledger-ae69.json` preserves the entire prior ledger byte-for-byte. Existing 98 task IDs/order and histories are preserved through deep copies. Only the 11 implemented primary TESTING tasks are promoted to MERGED using actual merge evidence. The donor contributes only its scoped task and two original notes; its entire ledger is never substituted. The repaired donor task remains TESTING. Additional completed records come explicitly from context.

The existing handoff, QA and todo text remains verbatim after a new prefix; earlier current-state statements are historical checkpoints. Existing evidence is preserved. The payload manifest binds every evidence file except itself. Preserve donor `{DONOR}` as recoverable original history in any later publication DAG; this helper performs no history/ref operation. Root owns final record review, publication and exact-source CI decisions. Component authoring and independent review are released.
'''
    return text.encode('utf-8')


def prefix_record(path: Path, old: bytes, context: dict) -> bytes:
    link = ('../engineering/' if path == HANDOFF else
            'engineering/' if path.as_posix() == 'docs/qa.md' else '../docs/engineering/')
    prefix = f'''## Current CODEX-5 follow-up after qualified primary promotion

Primary PR #349 source `{PRIMARY_HEAD}` / tree `{PRIMARY_TREE}` is merged through `{context['merge_commit']}`, with actual ordered parents/tree and both **[no release] [no deploy]** verified. Its final evidence retains documented native/environment limits and expected failures.

New code `{CODE}` / tree `{TREE}` maps to static remote code object `{REMOTE}`. Root: **1,548 passed / 2 strict CODEX-5 xfailed**, **1,550 distinct cases**, **66 selectors**, **84.021s**; whole-tree Ruff/pip/isolated binding passed. Final peer: **226 passed / 2 strict xfailed**, **20 lexical / 3 YAML controls**, plus typed failure controls. Counts overlap. The repaired task is **implementation COMPLETE / TESTING**; final follow-up publication, hosted qualification and guarded main merge remain pending. Static mapped identities are not live final PR/CI outcomes. Release readiness and new-source merge eligibility remain false.

The first-repair full attempt remains incomplete: modified working tree, SIGKILL **-9**, wrapper **247**, **498.536s**, unknown cause, no aggregate summary. No second local full run occurred. Broader CODEX-5, Ghidra archive-cache acceptance, Tier R/Tier W/native limits, manual/trust/accessibility, full provenance and separate L1/L2/L3 gates remain open. The original **181/16** census is retained.

[Current report]({link}cycle837fe-codex5-20261121.md) · [Ledger]({link}task-ledger.json). Root owns publication/qualification; authoring and independent review are released.

### Preserved historical checkpoints

All earlier text below remains verbatim as source-specific history. Its earlier pending-main/current-owner wording is superseded only by the scoped current record above.

'''.encode()
    return prefix + old


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='write the validated plan; default only validates/prints')
    args = parser.parse_args()
    pristine_worktree()
    fixed = [CONTEXT, *(PRIMARY_DIR / name for name in (
        'final-qualification.json', 'archive-receipt.json', 'evidence-manifest.json', 'final-ae69-evidence.zip'))]
    known_inputs = {path: file_sha(regular_file(path)) for path in fixed}
    context, _primary = promotion_context()
    focused, peer, full = validate_frozen_evidence()
    original_raw = regular_file(REPO / LEDGER).read_bytes()
    require(original_raw == git('show', CODE + ':' + LEDGER.as_posix()), 'Ledger differs from frozen source')
    original = parse_json(original_raw, 'authoritative ledger')
    branch = git('branch', '--show-current').decode().strip()
    require(branch, 'Integration checkout needs its owned branch')
    created = datetime.now(UTC).isoformat()
    qualification = qualification_record(focused, full)
    ledger = assemble_ledger(original, context, qualification, peer, branch, created)
    outputs: dict[Path, bytes | Path] = {}

    def add(relative: Path, content: bytes | Path) -> None:
        require(relative not in outputs, f'Duplicate output: {relative}')
        safe_member(relative.as_posix())
        require(relative in {LEDGER, REPORT, *PREFIXED} or relative.is_relative_to(EVIDENCE), 'Unauthorized output')
        target = REPO / relative
        cursor = REPO
        for part in relative.parts:
            cursor /= part
            require(not cursor.is_symlink(), f'Output symlink: {cursor}')
        if isinstance(content, Path):
            content = regular_file(content)
            digest = file_sha(content)
            require(content not in known_inputs or known_inputs[content] == digest, f'Input changed: {content}')
            known_inputs[content] = digest
        else:
            digest = sha(content)
        if target.exists() and relative not in {LEDGER, *PREFIXED}:
            require(target.is_file() and file_sha(target) == digest, f'Refusing to overwrite existing evidence/report: {relative}')
        outputs[relative] = content

    add(LEDGER, json_bytes(ledger))
    add(REPORT, render_report(context))
    for path in PREFIXED:
        old = regular_file(REPO / path).read_bytes()
        require(old == git('show', CODE + ':' + path.as_posix()), f'Historical text changed: {path}')
        updated = prefix_record(path, old, context)
        require(updated.endswith(old), f'Historical preservation failed: {path}')
        add(path, updated)
    add(EVIDENCE / 'prior-ledger-ae69.json', original_raw)
    for source, destination in [
        (CONTEXT, 'primary-promotion-context.json'),
        (PRIMARY_DIR / 'final-qualification.json', 'primary-final-qualification.json'),
        (PRIMARY_DIR / 'evidence-manifest.json', 'primary-evidence-manifest.json'),
        (PRIMARY_DIR / 'archive-receipt.json', 'primary-archive-receipt.json'),
        (PRIMARY_DIR / 'final-ae69-evidence.zip', 'primary-final-ae69-evidence.zip'),
        (Path(__file__).resolve(), 'records-assembly-helper.py'),
    ]:
        add(EVIDENCE / destination, source)
    add(EVIDENCE / 'qualification.json', json_bytes(qualification))
    add(EVIDENCE / 'historical-dispositions.json', json_bytes({
        'original_census': {'unmatched': 181, 'patch_equivalent': 16},
        'original_census_rewritten': False, 'dispositions': deepcopy(context.get('historical_dispositions', []))}))
    donor, notes = donor_record()
    add(EVIDENCE / 'recovered-donor-task-and-notes.json', json_bytes({
        'source': DONOR, 'base': DONOR_BASE, 'task': donor, 'notes': notes, 'entire_donor_ledger_substituted': False}))
    extras = context.get('additional_evidence', [])
    require(isinstance(extras, list), 'additional_evidence must be a list')
    for item in extras:
        require(isinstance(item, dict) and set(item) == {'source', 'destination', 'sha256'}, 'Invalid additional evidence object')
        source_name, destination = safe_member(item['source']), safe_member(item['destination'])
        require(len(PurePosixPath(destination).parts) == 1, 'Additional destination must be a filename')
        require(isinstance(item['sha256'], str) and HEX64.fullmatch(item['sha256']), 'Invalid additional digest')
        source = regular_file(ROOT / source_name)
        require(file_sha(source) == item['sha256'], f'Additional hash mismatch: {source_name}')
        if source.suffix == '.zip' or destination.endswith('.zip'):
            check_zip(source)
        add(EVIDENCE / destination, source)
    existing = {p.relative_to(REPO): file_sha(regular_file(p))
                for p in (REPO / EVIDENCE).rglob('*') if p.is_file()}
    state_before = git('status', '--porcelain=v1', '--untracked-files=all').decode()
    payloads = {p.relative_to(EVIDENCE).as_posix(): {'path': p.relative_to(EVIDENCE).as_posix(),
                 'bytes': (REPO / p).stat().st_size, 'sha256': digest}
                for p, digest in existing.items() if p.name != 'manifest.json'}
    for path, content in outputs.items():
        if path.is_relative_to(EVIDENCE):
            name = path.relative_to(EVIDENCE).as_posix()
            payloads[name] = {'path': name, 'bytes': len(content) if isinstance(content, bytes) else content.stat().st_size,
                              'sha256': sha(content) if isinstance(content, bytes) else file_sha(content)}
    add(EVIDENCE / 'manifest.json', json_bytes({
        'schema': 'patchtrace/codex5-records-evidence-manifest/1', 'created_at': created,
        'code_source': CODE, 'code_tree': TREE, 'static_mapped_code': REMOTE,
        'primary_merged_source': PRIMARY_HEAD, 'primary_merge_commit': context['merge_commit'],
        'qualification_context_sha256': known_inputs[CONTEXT],
        'payloads': [payloads[name] for name in sorted(payloads)], 'manifest_lists_itself': False,
        'counts_overlap': True, 'release_ready': False, 'new_source_main_merge_eligible': False,
        'stage_commit_ref_pr_operations': False}))
    plan = {'mode': 'apply' if args.apply else 'validate-only', 'primary_merge_commit': context['merge_commit'],
            'code': CODE, 'tree': TREE, 'mapped_code': REMOTE, 'preserved_original_tasks': 98,
            'primary_tasks_promoted': sorted(PROMOTE_IDS), 'appended_task_ids': [t['id'] for t in ledger['tasks'][98:]],
            'appended_donor_notes': 2, 'payload_count': len(payloads),
            'writes': sorted(path.as_posix() for path in outputs), 'source_workflow_test_edits': False,
            'release_ready': False, 'new_source_main_merge_eligible': False}
    for path, digest in known_inputs.items():
        require(file_sha(regular_file(path)) == digest, f'Input changed during validation: {path}')
    if not args.apply:
        print(json.dumps(plan, indent=2))
        return
    write_plan(outputs, existing, known_inputs, state_before)
    plan['result'] = 'records written for root review; no staging, commit, ref, PR, release or deployment operation'
    plan['status_after'] = git('status', '--short').decode()
    print(json.dumps(plan, indent=2))


def write_plan(outputs: dict, existing: dict, known_inputs: dict, state_before: str) -> None:
    with tempfile.TemporaryDirectory(prefix='codex5-records-stage-', dir=ROOT) as temporary:
        stage = Path(temporary)
        for path, content in outputs.items():
            target = stage / path
            target.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                target.write_bytes(content)
            else:
                shutil.copyfile(content, target)
                require(file_sha(target) == known_inputs[content], f'Input changed while copying: {content}')
            if target.suffix == '.zip':
                check_zip(target)
        pristine_worktree()
        require(git('status', '--porcelain=v1', '--untracked-files=all').decode() == state_before,
                'Integration changed during preparation')
        for path, digest in known_inputs.items():
            require(file_sha(regular_file(path)) == digest, f'Evidence/context changed: {path}')
        for path, digest in existing.items():
            require(file_sha(regular_file(REPO / path)) == digest, f'Existing evidence changed: {path}')
        # Each replacement is atomic; original ledger/text remains in snapshots/HEAD.
        for path in sorted(outputs, key=lambda p: (p == LEDGER, p.as_posix())):
            target = REPO / path
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                regular_file(target)
                if file_sha(target) == file_sha(stage / path):
                    continue
            temporary_name = None
            try:
                with tempfile.NamedTemporaryFile(prefix='.codex5-records-', dir=target.parent, delete=False) as stream:
                    temporary_name = Path(stream.name)
                    with (stage / path).open('rb') as source:
                        shutil.copyfileobj(source, stream)
                    stream.flush()
                    os.fsync(stream.fileno())
                temporary_name.chmod(0o644)
                os.replace(temporary_name, target)
            finally:
                if temporary_name is not None and temporary_name.exists():
                    temporary_name.unlink()
        for path in outputs:
            require(file_sha(regular_file(REPO / path)) == file_sha(stage / path), f'Written output mismatch: {path}')
    require(git('rev-parse', 'HEAD').decode().strip() == CODE, 'HEAD changed during records write')
    require(not git('diff', '--cached', '--name-only'), 'Index changed during records write')
    allowed = {LEDGER.as_posix(), *(p.as_posix() for p in PREFIXED)}
    require(set(git('diff', '--name-only').decode().splitlines()) <= allowed, 'Out-of-scope tracked changes')
    require(not git('diff', '--name-only', '--', 'src', 'tests', 'tools', '.github/workflows'), 'Frozen source bytes changed')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, AttributeError,
            subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        raise SystemExit(f'CODEX-5 records assembly refused: {error}') from error
