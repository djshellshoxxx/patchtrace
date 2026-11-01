from pathlib import Path
import datetime,json,os,subprocess,sys,time
ROOT=Path('/workspace/scratch/142cb233d750/gt12-bench-20261101')
REPO=Path('/workspace/scratch/142cb233d750/wt-bench')
PYTHON='/workspace/scratch/142cb233d750/bench-venv/bin/python'
EXPECTED='1f5f0b808149a30d222a35937667b36a5407bc0d'
stage=sys.argv[1]
if stage not in ('facts','read_model','ui_calls'): raise ValueError('Unexpected stage')
report,log,receipt=(ROOT/f'{stage}-initial.{ext}' for ext in ('json','log','invocation.json'))
if any(p.exists() for p in (report,log,receipt)): raise RuntimeError('Refusing to overwrite prior evidence')
def source():
 return {'commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip(),'dirty_tracked':subprocess.check_output(['git','status','--porcelain','--untracked-files=no'],cwd=REPO,text=True).splitlines()}
before=source()
if before['commit']!=EXPECTED or before['dirty_tracked']: raise RuntimeError(f'Unexpected source state {before}')
argv=[PYTHON,'-m','tools.unified.bench','--stages',stage,'--seed','1','--insns','50','--out',str(report)]
entry={'argv':argv,'cwd':str(REPO),'before':before,'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Synthetic generated IR/persisted records/offscreen Qt. No native engine or target execution.'}
start=time.monotonic()
with log.open('w') as out:
 result=subprocess.run(argv,cwd=REPO,env={**os.environ,'QT_QPA_PLATFORM':'offscreen'},stdout=out,stderr=subprocess.STDOUT,check=False)
entry.update(returncode=result.returncode,elapsed_seconds=round(time.monotonic()-start,3),after=source())
receipt.write_text(json.dumps(entry,indent=2)+'\n')
print(json.dumps(entry,indent=2),flush=True)
raise SystemExit(result.returncode)
