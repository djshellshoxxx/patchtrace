"""Append-preserving records after actual PR357 promotion; no commit/ref operations."""
from pathlib import Path, PurePosixPath
from copy import deepcopy
from datetime import datetime, timezone
from io import BytesIO
import argparse, hashlib, json, re, subprocess, zipfile

BASE = 'd60ac40daf767fe6a93ae152feb21235f6e75e0b'
BASE_TREE = '4a07cd88ded407bef30a8aeb81961e4041822dc2'
OLD_MAIN = '3a16290c0fcc4e0c21712fe10474a3ff33fad336'
SIGSTORE_SOURCE = '9610919d29010d53cf00af3b7c38207ffd84f945'
SIGSTORE_TREE = '3d5e2965ef26235610a08fd8378cac078c6bd9a0'
E = Path('docs/engineering/evidence/cycle837fe-network-recovery-20261121')
LEDGER = Path('docs/engineering/task-ledger.json')
REPORT = Path('docs/engineering/cycle837fe-network-recovery-20261121.md')
HANDOFF = Path('docs/engineering-handoffs/cycle837fe-combined-pr349-20261121.md')
PREFIXES = (HANDOFF, Path('docs/qa.md'), Path('tasks/todo.md'))
STATES = {'DISCOVERED','OWNED','IMPLEMENTING','TESTING','AUDITING','READY_TO_MERGE','MERGED','BLOCKED','SUPERSEDED','COMPLETE'}
REQUIRED = {'id','status','description','source_branch','source_commit','target_integration_branch','assigned_worker','files_owned','implementation_status','test_results','audit_findings','dependencies','blockers','merge_status','evidence_links','next_action'}
CURRENT = ('updated_at','integration_branch','local_integration_branch','checkpoint_local_commit','aggregate_source_commit','aggregate_source_tree','remote_publication','current_qualification','current_handoff','continuation','main_merge_eligible','release_ready')
def check(ok, message):
    if not ok: raise RuntimeError(message)
def sha(data): return hashlib.sha256(data).hexdigest()
def encode(value): return (json.dumps(value, indent=2, ensure_ascii=False)+'\n').encode()

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--repo', type=Path, required=True); parser.add_argument('--context', type=Path, required=True); parser.add_argument('--apply', action='store_true'); args=parser.parse_args()
    repo=args.repo.resolve(); raw_context=args.context.read_bytes(); context=json.loads(raw_context)
    def git(*items): return subprocess.check_output(['git', *items], cwd=repo)
    check(context['apply_authorized_now'] is True and context['blockers']==[], 'Prerequisites incomplete')
    source, tree=context['source_head'], context['source_tree']; branch=git('branch','--show-current').decode().strip()
    check(branch==context['target_integration_branch'] and branch, 'Wrong owned branch')
    check(git('rev-parse','HEAD').decode().strip()==source and git('rev-parse','HEAD^{tree}').decode().strip()==tree, 'Wrong frozen source')
    check(not git('status','--porcelain=v1').strip(), 'Source must start clean')
    check(subprocess.run(['git','merge-base','--is-ancestor',BASE,source],cwd=repo).returncode==0, 'Missing published d60 ancestor')
    promotion=context['actual_pr357_promotion']
    check(promotion['merged'] is True and promotion['pr_number']==357, 'Actual PR357 merge required')
    check(promotion['source_head']==BASE and promotion['source_tree']==BASE_TREE and promotion['all_applicable_automated_jobs_passed'] and promotion['opt_outs_verified'], 'Wrong or unqualified promotion')
    check(isinstance(promotion['merge_commit'],str) and re.fullmatch(r'[0-9a-f]{40}',promotion['merge_commit']) is not None, 'Actual promotion requires a literal lowercase full commit SHA')
    check(git('cat-file','-t',promotion['merge_commit']).strip()==b'commit', 'Actual promotion must identify a commit object')
    header,message=git('cat-file','commit',promotion['merge_commit']).decode().split('\n\n',1)
    parents=[x[7:] for x in header.splitlines() if x.startswith('parent ')]; trees=[x[5:] for x in header.splitlines() if x.startswith('tree ')]
    check(parents==[OLD_MAIN,BASE]==promotion['actual_parents'] and trees==[BASE_TREE]==[promotion['actual_tree']], 'Fetched merge identity mismatch')
    subject,_,body=message.partition('\n'); check(all(m in subject and m in body for m in ('[no release]','[no deploy]')), 'Merge publication holds missing')
    check(not git('diff','--name-only',BASE,promotion['merge_commit']).strip(), 'Main differs from incorporated d60')
    qualification=context['current_source_qualification']
    check(qualification['source']==source and qualification['tree']==tree and qualification['independent_verdict']=='CLEAR' and qualification['source_blockers']==[], 'Final source review incomplete')
    check(context['independent_network_review']['source']=='96baaee20f390a3f2a5629de3764d32323bb80e5' and context['independent_network_review']['verdict']=='CLEAR', 'Missing network review')
    check(context['independent_pilot_review']['source']==context['pilot_source'] and context['independent_pilot_review']['verdict']=='CLEAR', 'Missing pilot review')
    check(source==SIGSTORE_SOURCE and tree==SIGSTORE_TREE and context.get('sigstore_source')==SIGSTORE_SOURCE, 'Exact final Sigstore source and tree required')
    check(context['independent_sigstore_review']['source']==SIGSTORE_SOURCE and context['independent_sigstore_review']['tree']==SIGSTORE_TREE and context['independent_sigstore_review']['verdict']=='CLEAR', 'Exact Sigstore independent review required')
    check(git('rev-parse',SIGSTORE_SOURCE+'^{tree}').decode().strip()==SIGSTORE_TREE, 'Reviewed Sigstore object tree mismatch')
    original_raw=(repo/LEDGER).read_bytes()
    check(original_raw==git('show',source+':'+LEDGER.as_posix())==git('show',BASE+':'+LEDGER.as_posix()), 'Ledger drift')
    original=json.loads(original_raw); check(len(original['tasks'])==116 and len(original['notes'])==46, 'Wrong baseline census')
    ids=[t['id'] for t in original['tasks']]; check(len(set(ids))==116, 'Duplicate baseline IDs')
    ledger=deepcopy(original); by_id={t['id']:t for t in ledger['tasks']}; old_by_id={t['id']:t for t in original['tasks']}
    changes=context['task_updates']; check(len({u['id'] for u in changes})==len(changes), 'Duplicate task update')
    for update in changes:
        check(update['id'] in old_by_id and old_by_id[update['id']]==update['before'], 'Original whole task mismatch')
        check('id' not in update['patch'] and update['patch'].get('status',old_by_id[update['id']]['status']) in STATES, 'Invalid task patch')
        by_id[update['id']].update(deepcopy(update['patch']))
    additions=deepcopy(context['additional_tasks']); new_ids=[t['id'] for t in additions]
    check(new_ids==context['new_task_ids'] and len(set(new_ids))==len(new_ids) and not set(new_ids).intersection(ids), 'New task identities/order mismatch')
    for task in additions:
        check(REQUIRED<=set(task) and task['status'] in STATES and task['target_integration_branch']==branch, 'Invalid new task')
    ledger['tasks'].extend(additions); created=datetime.now(timezone.utc).isoformat()
    ledger['continuation_history'].append({'recorded_at':created,'context':'Actual PR357 promotion and separate network/pilot candidate','prior_ledger_evidence':(E/'prior-ledger-d60.json').as_posix(),'prior_current_fields':{k:deepcopy(original[k]) for k in CURRENT if k in original},'changed_tasks_before':[deepcopy(u['before']) for u in changes]})
    ledger.update(updated_at=created,integration_branch=branch,local_integration_branch=branch,checkpoint_local_commit=source,aggregate_source_commit=source,aggregate_source_tree=tree,current_handoff=HANDOFF.as_posix(),current_qualification=deepcopy(qualification),remote_publication=deepcopy(context['remote_publication']),continuation=deepcopy(context['continuation']),main_merge_eligible=False,release_ready=False)
    check('pr357_main_promotion_837fe' not in original and 'network_recovery_837fe' not in original, 'Already applied')
    ledger['pr357_main_promotion_837fe']=deepcopy(promotion); ledger['network_recovery_837fe']=deepcopy(context['network_recovery'])
    windows_update=context['windows_recovery_update']
    check(windows_update['before']==original['windows_recovery_837fe'], 'Complete previous Windows checkpoint required')
    check(windows_update['patch']['status']=='MERGED' and windows_update['patch']['source_commit']==BASE and windows_update['patch']['source_tree']==BASE_TREE, 'Windows checkpoint must describe qualified d60 promotion')
    ledger['continuation_history'][-1]['prior_windows_recovery_837fe']=deepcopy(original['windows_recovery_837fe'])
    ledger['windows_recovery_837fe'].update(deepcopy(windows_update['patch']))
    changed_ids={u['id'] for u in changes}
    check(ledger['notes']==original['notes'] and [t['id'] for t in ledger['tasks'][:116]]==ids, 'Prior notes/order changed')
    check(all(by_id[i]==old_by_id[i] for i in ids if i not in changed_ids), 'Unexpected original task change')
    outputs={LEDGER:encode(ledger),E/'prior-ledger-d60.json':original_raw,E/'assembly-context.json':raw_context,E/'assembly-driver.py':Path(__file__).read_bytes()}
    report=Path(context['report_path']).read_bytes(); check(sha(report)==context['report_sha256'], 'Report drift'); outputs[REPORT]=report
    prefix_proof=[]
    for path in PREFIXES:
        before=(repo/path).read_bytes(); check(before==git('show',source+':'+path.as_posix()), 'Prior record drift')
        prefix=context['record_prefixes'][path.as_posix()].encode(); check(prefix and prefix.endswith(b'\n\n'), 'Prefix requires blank line')
        after=prefix+before; check(after.count(before)==1 and after.endswith(before), 'Prior bytes not retained once'); outputs[path]=after
        prefix_proof.append({'path':path.as_posix(),'before_bytes':len(before),'before_sha256':sha(before),'prefix_bytes':len(prefix),'prefix_sha256':sha(prefix),'after_bytes':len(after),'after_sha256':sha(after),'prior_complete_bytes_preserved_once':True})
    for item in context['static_inputs']:
        name=PurePosixPath(item['name'])
        check(not name.is_absolute() and len(name.parts)==1 and name.name not in ('.','..') and '\\' not in item['name'], 'Unsafe evidence name')
        path=E/name.name; check(path not in outputs, 'Duplicate output')
        data=Path(item['source_path']).read_bytes(); check(len(data)==item['bytes'] and sha(data)==item['sha256'], 'Evidence drift')
        if name.suffix=='.zip':
            with zipfile.ZipFile(BytesIO(data)) as archive: check(archive.testzip() is None, 'Archive CRC failure')
        outputs[path]=data
    preservation={'schema':'patchtrace/network-record-preservation/1','source':source,'tree':tree,'prior_tasks':116,'prior_notes':46,'new_tasks':len(additions),'prior_task_order_preserved':True,'prior_notes_identical':True,'changed_task_ids':sorted(changed_ids),'unchanged_prior_tasks':116-len(changed_ids),'before_task_states_retained':True,'prefixes':prefix_proof,'historical_census':'Original181unmatched/16patch-equivalent unchanged','planned_final_record_parents':[source,promotion['merge_commit']],'main_content_already_incorporated':True}
    outputs[E/'preservation.json']=encode(preservation)
    manifest={'schema':'patchtrace/evidence-manifest/1','source':source,'tree':tree,'files':[{'path':path.relative_to(E).as_posix(),'bytes':len(data),'sha256':sha(data)} for path,data in sorted(outputs.items()) if path.is_relative_to(E)]}
    outputs[E/'manifest.json']=encode(manifest)
    check(not (repo/E).exists() and not (repo/REPORT).exists(), 'Recovery records already exist')
    target=repo if args.apply else Path(context['preview_directory']); check(args.apply or not target.exists(), 'Preview exists')
    receipt=Path(context['assembly_receipt_path']); check(not receipt.exists(), 'Receipt already exists')
    for path,data in outputs.items():
        check(path in (LEDGER,REPORT,*PREFIXES) or path.is_relative_to(E), 'Unexpected output')
        destination=target/path; destination.parent.mkdir(parents=True,exist_ok=True); destination.write_bytes(data)
    inventory={'source':source,'tree':tree,'applied':args.apply,'context_sha256':sha(raw_context),'outputs':[{'path':path.as_posix(),'bytes':len(data),'sha256':sha(data),'git_blob':hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()} for path,data in sorted(outputs.items())],'preservation':preservation}
    check(git('rev-parse','HEAD').decode().strip()==source, 'HEAD moved')
    if args.apply:
        check(set(git('diff','--name-only').decode().splitlines())=={LEDGER.as_posix(),*(p.as_posix() for p in PREFIXES)}, 'Unexpected tracked changes')
    receipt.parent.mkdir(parents=True,exist_ok=True); receipt.write_bytes(encode(inventory))
    print(json.dumps({'applied':args.apply,'outputs':len(outputs),'prior_tasks':116,'tasks_after':len(ledger['tasks']),'unchanged_prior_tasks':116-len(changed_ids),'final_hosted_qualification':'PENDING'}))

if __name__=='__main__':main()
