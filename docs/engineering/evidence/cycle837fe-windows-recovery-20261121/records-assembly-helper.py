"""Prepare append-preserving ledger records after verified PR351 promotion.

No source edits, staging, commits, branch movement, PR operation or qualification run.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import zipfile

ROOT = Path('/workspace/scratch/837fe19aae3a')
SOURCE = 'f596471b8909ec8e28e0624041d60f03d520591d'
NATIVE_ORIGINAL = '88df8cfbe51f91a6bc08c6863cd5d63f86500ca0'
TREE = 'dffeed541749850ef54a130cec0fa56c0fd2f01c'
WINDOWS_SOURCE = '1c70cd5f8053f75c269da673a24a82f221180650'
WINDOWS_TREE = 'a39d650ca7fa2b41ece017ea492396722a4142d9'
PRIOR = 'd6679abc6dfddbadce0391c8d18289f7f96338d6'
PRIOR_TREE = '6001ef506c38930fd590bd827f428b997c3b2797'
EVIDENCE = Path('docs/engineering/evidence/cycle837fe-windows-recovery-20261121')
REPORT = Path('docs/engineering/cycle837fe-windows-recovery-20261121.md')
LEDGER = Path('docs/engineering/task-ledger.json')
HANDOFF = Path('docs/engineering-handoffs/cycle837fe-combined-pr349-20261121.md')
PREFIXED = (HANDOFF, Path('docs/qa.md'), Path('tasks/todo.md'))
PROMOTE = {'codex5-per-command-audit-20261121', '837fe-pages-configuration-hold'}
LEGACY_FIELDS = {
    'buildenv-header-help-20261121-95fe': {'status', 'result_or_next_action'},
    'historical-audit-gates-cycle2': {'status', 'result_or_next_action'},
    'registered-header-help': {'status', 'result_or_next_action', 'parallel_scope_837fe.qualification'},
}
LEGACY_STATES = {'buildenv-header-help-20261121-95fe': 'MERGED',
                 'historical-audit-gates-cycle2': 'BLOCKED', 'registered-header-help': 'TESTING'}
FIELDS = ('updated_at', 'integration_branch', 'local_integration_branch', 'checkpoint_local_commit',
          'aggregate_source_commit', 'aggregate_source_tree', 'remote_publication', 'current_qualification',
          'current_handoff', 'continuation', 'main_merge_eligible', 'release_ready')
TASK_FIELDS = {'id', 'status', 'description', 'source_branch', 'source_commit', 'target_integration_branch',
               'assigned_worker', 'files_owned', 'implementation_status', 'test_results', 'audit_findings',
               'dependencies', 'blockers', 'merge_status', 'evidence_links', 'next_action'}


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode()


def relative(value):
    path = PurePosixPath(value)
    check(not path.is_absolute() and '\\' not in value and all(p not in ('.', '..') for p in path.parts),
          f'Unsafe path: {value}')
    return Path(*path.parts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--context', required=True, type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    repo = args.repo.resolve()

    def git(*items):
        return subprocess.check_output(['git', *items], cwd=repo)

    check(git('rev-parse', 'HEAD').decode().strip() == SOURCE, 'Wrong frozen source')
    check(git('rev-parse', 'HEAD^{tree}').decode().strip() == TREE, 'Wrong frozen tree')
    check(not git('status', '--porcelain=v1').strip(), 'Worktree must start clean')
    branch = git('branch', '--show-current').decode().strip()
    check(bool(branch), 'Owned branch required')
    context_raw = args.context.read_bytes()
    context = json.loads(context_raw)
    check(context.get('apply_authorized_now') is True and context.get('blockers') == [], 'Prerequisites incomplete')
    promotion = context['verified_pr351_promotion']
    check(promotion['merged'] is True and promotion['pr_number'] == 351, 'Actual PR351 merge proof required')
    check(promotion['source_head'] == PRIOR and promotion['source_tree'] == PRIOR_TREE, 'Wrong qualified source')
    check(promotion['actual_tree'] == PRIOR_TREE and promotion['actual_parents'] ==
          ['9023761a4066ac1c50c127ac09d0ba5f56cdc9e4', PRIOR], 'Actual ancestry/tree mismatch')
    check(promotion['all_applicable_automated_jobs_passed'] and promotion['opt_outs_verified'], 'Qualification missing')
    merge = promotion['merge_commit']
    check(isinstance(merge, str) and re.fullmatch(r'[0-9a-f]{40}', merge), 'Invalid actual merge identity')
    check(git('cat-file', '-t', merge).strip() == b'commit', 'Actual merge must name a fetched commit object')
    raw_commit = git('cat-file', 'commit', merge).decode('utf-8')
    header, message = raw_commit.split('\n\n', 1)
    actual_tree = [line[5:] for line in header.splitlines() if line.startswith('tree ')]
    actual_parents = [line[7:] for line in header.splitlines() if line.startswith('parent ')]
    check(actual_tree == [PRIOR_TREE] and actual_tree == [promotion['actual_tree']], 'Git merge tree mismatch')
    check(actual_parents == ['9023761a4066ac1c50c127ac09d0ba5f56cdc9e4', PRIOR] and
          actual_parents == promotion['actual_parents'], 'Git merge ordered parents mismatch')
    subject, _, body = message.partition('\n')
    check(all(marker in subject and marker in body for marker in ('[no release]', '[no deploy]')),
          'Actual merge subject and body must each retain both publication holds')
    review = context['independent_windows_review']
    check(review['head'] == WINDOWS_SOURCE and review['tree'] == WINDOWS_TREE and review['blockers'] == [],
          'Wrong Windows component review')
    check(git('show', '-s', '--format=%P', NATIVE_ORIGINAL).decode().strip() == WINDOWS_SOURCE and
          git('show', '-s', '--format=%P', SOURCE).decode().strip() == NATIVE_ORIGINAL,
          'Combined source must retain the original native source and corrective child')
    check(git('rev-list', '--reverse', '--first-parent', WINDOWS_SOURCE + '..' + SOURCE).decode().splitlines() ==
          [NATIVE_ORIGINAL, SOURCE], 'Unexpected combined source history')
    check(git('rev-parse', WINDOWS_SOURCE + '^{tree}').decode().strip() == WINDOWS_TREE,
          'Windows source tree mismatch')
    changed = set(git('diff', '--name-only', WINDOWS_SOURCE, SOURCE).decode().splitlines())
    check(changed == {'.github/workflows/live-backend.yml', 'docs/specs/REGISTRY.md',
                      'docs/specs/windows-acceptance-and-milestone-builds.md',
                      'tests/test_live_ghidra_archive.py'}, 'Unexpected combined source changes')
    native_review = context['independent_ghidra_review']
    check(native_review['head'] == SOURCE and native_review['tree'] == TREE and native_review['blockers'] == [],
          'Wrong Ghidra component review')
    original_raw = (repo / LEDGER).read_bytes()
    check(original_raw == git('show', SOURCE + ':' + LEDGER.as_posix()), 'Ledger drift')
    original = json.loads(original_raw)
    check(len(original['tasks']) == 104 and len(original['notes']) == 46, 'Unexpected ledger baseline')
    ids = [t['id'] for t in original['tasks']]
    check(len(set(ids)) == 104 and PROMOTE <= set(ids), 'Original task identities changed')
    ledger = deepcopy(original)
    created = datetime.now(timezone.utc).isoformat()
    ledger['continuation_history'].append({
        'context': 'Verified actual PR351 promotion before separate Windows recovery qualification',
        'recorded_at': created, 'prior_ledger_evidence': (EVIDENCE / 'prior-ledger-d667.json').as_posix(),
        'previous_current_fields': {k: deepcopy(original[k]) for k in FIELDS if k in original},
        'previous_codex5_followup': deepcopy(original['codex5_followup_837fe']),
        'legacy_rows_before_reconciliation': [deepcopy(t) for t in original['tasks'] if t['id'] in LEGACY_FIELDS],
        'updated_tasks_before_promotion': [deepcopy(t) for t in original['tasks'] if t['id'] in PROMOTE]})
    legacy = context['reviewed_legacy_reconciliation']
    check(legacy['baseline_ledger_sha256'] == sha(original_raw), 'Legacy ledger baseline mismatch')
    check(legacy['independent_review_verdict'] == 'CLEAR', 'Legacy independent review missing')
    by_id = {t['id']: t for t in ledger['tasks']}
    before_by_id = {t['id']: t for t in original['tasks']}
    check(set(legacy['before_rows']) == set(LEGACY_FIELDS), 'Unexpected legacy row set')
    for task_id, before in legacy['before_rows'].items():
        check(before_by_id[task_id] == before, 'Legacy whole-row before guard failed')
    seen = set()
    for change in legacy['changes']:
        task_id, field = change['task_id'], change['field']
        check(task_id in LEGACY_FIELDS and field in LEGACY_FIELDS[task_id], 'Unexpected legacy field')
        check((task_id, field) not in seen, 'Duplicate legacy field')
        seen.add((task_id, field))
        target = by_id[task_id]
        keys = field.split('.')
        for key in keys[:-1]:
            target = target[key]
        check(target[keys[-1]] == change['before'], 'Legacy field before guard failed')
        target[keys[-1]] = deepcopy(change['after'])
    check(seen == {(task_id, field) for task_id, fields in LEGACY_FIELDS.items() for field in fields},
          'Incomplete legacy reconciliation')
    for task_id, state in LEGACY_STATES.items():
        check(by_id[task_id]['status'] == state, 'Legacy state must use the reviewed user enum')
    for task in ledger['tasks']:
        if task['id'] in PROMOTE:
            task['historical_prepublication_test_results'] = deepcopy(task['test_results'])
            task.update(status='MERGED', merge_status='MERGED', dependencies=[],
                        actual_pr351_promotion=deepcopy(promotion),
                        test_results=deepcopy(context['pr351_qualification_summary']),
                        latest_hosted_qualification=deepcopy(context['pr351_qualification_summary']),
                        next_action='Source merged through qualified PR351; wider gates remain. ' +
                                    context['post_pr351_pages_status'])
            task['blockers'] = ([] if task['id'] != '837fe-pages-configuration-hold' or
                                context['post_pr351_pages_accepted'] else
                                ['Automatic held-main Pages skip/upload observation remains pending.'])
            if 'result_or_next_action' in task:
                task['result_or_next_action'] = task['next_action']
    additions = deepcopy(context['additional_tasks'])
    new_ids = [t['id'] for t in additions]
    check(new_ids == context['proposed_new_task_ids'], 'Incomplete or reordered new task list')
    check(len(new_ids) == len(set(new_ids)) and not set(new_ids).intersection(ids), 'Duplicate new task')
    for task in additions:
        check(TASK_FIELDS <= set(task), f'Incomplete task: {task.get("id")}')
        check(task['status'] in {'TESTING', 'COMPLETE', 'BLOCKED', 'SUPERSEDED'}, 'Unqualified new task state')
        check(task['target_integration_branch'] == branch, 'Wrong task target')
    ledger['tasks'].extend(additions)
    qualification = deepcopy(context['current_recovery_qualification'])
    check(qualification['source_commit'] == SOURCE and qualification['source_tree'] == TREE, 'Wrong tested source')
    ledger.update(updated_at=created, integration_branch=branch, local_integration_branch=branch,
                  checkpoint_local_commit=SOURCE, aggregate_source_commit=SOURCE, aggregate_source_tree=TREE,
                  current_qualification=qualification, current_handoff=HANDOFF.as_posix(),
                  main_merge_eligible=False, release_ready=False)
    ledger['remote_publication'] = deepcopy(context['planned_publication'])
    ledger['continuation'] = {'owner': 'root837FE', 'status': 'TESTING', 'code_commit': SOURCE,
                              'report': REPORT.as_posix(), 'release_ready': False, 'main_merge_eligible': False,
                              'next_action': 'Review/publish records, qualify exact final-source full/Qt/platform and '
                                             'downloaded Windows checks, then guarded REST merge with both holds.'}
    ledger['pr351_main_promotion_837fe'] = deepcopy(promotion)
    completed_gate = ('New CODEX-5 source still requires final publication, applicable hosted/full '
                      'qualification, and guarded main merge.')
    check(original['codex5_followup_837fe']['open_gates'].count(completed_gate) == 1,
          'Expected prepublication C5 gate changed')
    ledger['codex5_followup_837fe'].update(
        status='MERGED', actual_main_promotion=deepcopy(promotion),
        historical_prepublication_qualification=deepcopy(original['codex5_followup_837fe']['qualification']),
        qualification=deepcopy(context['pr351_qualification_summary']),
        exact_hosted_qualification=deepcopy(context['pr351_qualification_summary']),
        open_gates=[gate for gate in original['codex5_followup_837fe']['open_gates'] if gate != completed_gate],
        postmerge_pages_status=context['post_pr351_pages_status'])
    ledger['windows_recovery_837fe'] = {'status': 'TESTING', 'source_commit': SOURCE, 'source_tree': TREE,
                                       'qualification': deepcopy(qualification), 'report': REPORT.as_posix(),
                                       'historical_dispositions': deepcopy(context['historical_dispositions']),
                                       'original_census_preserved': {'unmatched': 181, 'patch_equivalent': 16},
                                       'release_ready': False}
    check(ledger['notes'] == original['notes'], 'Prior notes changed')
    check(ledger['continuation_history'][:-1] == original['continuation_history'], 'Prior history changed')
    check([t['id'] for t in ledger['tasks'][:104]] == ids, 'Prior task order changed')
    for before, after in zip(original['tasks'], ledger['tasks'][:104], strict=True):
        if before['id'] in LEGACY_FIELDS:
            restored = deepcopy(after)
            for field in LEGACY_FIELDS[before['id']]:
                old, new = before, restored
                keys = field.split('.')
                for key in keys[:-1]:
                    old, new = old[key], new[key]
                new[keys[-1]] = deepcopy(old[keys[-1]])
            check(restored == before, 'Unrelated legacy task field changed')
        else:
            check(before['id'] in PROMOTE or before == after, 'Unrelated task changed')
    for key in set(original) - set(FIELDS) - {'tasks', 'continuation_history', 'codex5_followup_837fe'}:
        check(original[key] == ledger[key], f'Unrelated prior field changed: {key}')
    outputs = {LEDGER: encode(ledger), EVIDENCE / 'prior-ledger-d667.json': original_raw,
               EVIDENCE / 'promotion-and-recovery-context.json': context_raw,
               EVIDENCE / 'records-assembly-helper.py': Path(__file__).read_bytes()}
    report = context['report_markdown']
    check(SOURCE in report and promotion['merge_commit'] in report, 'Report source identity missing')
    outputs[REPORT] = report.encode()
    for path in PREFIXED:
        old = (repo / path).read_bytes()
        check(old == git('show', SOURCE + ':' + path.as_posix()), 'Historical prose drift')
        outputs[path] = context['prefixes'][path.as_posix()].encode() + old
        check(outputs[path].endswith(old), 'Prior prose not preserved')
    for edit in context.get('reviewed_document_replacements', []):
        path = relative(edit['path'])
        check(path in {Path('docs/release-process.md'), Path('docs/windows.md'), Path('docs/package-audit.md')},
              'Unexpected current documentation edit')
        old = (repo / path).read_bytes()
        check(sha(old) == edit['before_sha256'], 'Current documentation drift')
        outputs[path] = edit['after_text'].encode()
        if path == Path('docs/package-audit.md'):
            check(outputs[path].startswith(old), 'Dated package audit history must remain byte-identical')
    for item in context['static_evidence_inputs']:
        source = ROOT / relative(item['source'])
        dest = relative(item['destination'])
        check(len(dest.parts) == 1 and source.is_file() and not source.is_symlink(), 'Invalid evidence input')
        content = source.read_bytes()
        check(sha(content) == item['sha256'] and len(content) == item['bytes'], 'Evidence input drift')
        if source.suffix == '.zip':
            with zipfile.ZipFile(source) as archive:
                check(archive.testzip() is None, 'Evidence CRC failure')
        check(EVIDENCE / dest not in outputs, 'Duplicate evidence output')
        outputs[EVIDENCE / dest] = content
    payloads = [{'path': p.relative_to(EVIDENCE).as_posix(), 'bytes': len(b), 'sha256': sha(b)}
                for p, b in sorted(outputs.items()) if p.is_relative_to(EVIDENCE)]
    outputs[EVIDENCE / 'manifest.json'] = encode({'schema': 'patchtrace/windows-recovery-record-manifest/1',
                                                'source_commit': SOURCE, 'source_tree': TREE,
                                                'prior_actual_main_merge': promotion['merge_commit'],
                                                'payloads': payloads, 'lists_itself': False})
    for path in outputs:
        check(not (repo / path).is_symlink(), 'Output symlink refused')
        if path.is_relative_to(EVIDENCE) or path == REPORT:
            check(not (repo / path).exists(), 'Existing evidence will not be overwritten')
    check(args.context.read_bytes() == context_raw, 'Context changed during preparation')
    if args.apply:
        check(not git('status', '--porcelain=v1').strip(), 'Concurrent worktree change')
        for path, content in outputs.items():
            target = repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        check(all((repo / p).read_bytes() == b for p, b in outputs.items()), 'Output readback failure')
    print(json.dumps({'source': SOURCE, 'tree': TREE, 'prior_promoted': promotion['merge_commit'],
                      'original_tasks': 104, 'promoted_tasks': sorted(PROMOTE), 'new_tasks': new_ids,
                      'payloads': len(payloads), 'writes': [p.as_posix() for p in sorted(outputs)],
                      'bytes': sum(len(b) for b in outputs.values()), 'applied': args.apply}, indent=2))


if __name__ == '__main__':
    main()
