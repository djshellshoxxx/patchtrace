import hashlib, importlib.metadata, json, os, platform, resource, subprocess, time
from datetime import UTC, datetime
from pathlib import Path
repo=Path('/workspace/scratch/b1d1356aa953/patchtrace-integration')
out=Path('/workspace/scratch/b1d1356aa953/generation30-evidence')
python='/workspace/scratch/b1d1356aa953/patchtrace-venv/bin/python'
def git(*args): return subprocess.check_output(['git',*args],cwd=repo,text=True).strip()
command=[python,'-m','pytest','-q','--junitxml='+str(out/'full-suite.xml')]
info={'schema':'patchtrace-local-qualification/1','source_commit':git('rev-parse','HEAD'),'source_tree':git('rev-parse','HEAD^{tree}'),'initial_worktree_status':git('status','--porcelain'),'started_at_utc':datetime.now(UTC).isoformat(),'platform':platform.platform(),'python':platform.python_version(),'command':command,'state':'running','dependencies':{n:importlib.metadata.version(n) for n in ['PySide6','shiboken6','pydantic','protobuf','pytest','pytest-qt','ruff','hypothesis','psutil','rapidfuzz','yara-x','iced-x86']}}
(out/'full-suite-run.json').write_text(json.dumps(info,indent=2)+'\n')
env=dict(os.environ,QT_QPA_PLATFORM='offscreen',PYTHONPATH=str(repo/'src'))
start=time.monotonic()
with (out/'full-suite.log').open('w') as log:
 result=subprocess.run(command,cwd=repo,env=env,stdout=log,stderr=subprocess.STDOUT)
usage=resource.getrusage(resource.RUSAGE_CHILDREN)
info.update(state='completed',returncode=result.returncode,finished_at_utc=datetime.now(UTC).isoformat(),duration_seconds=time.monotonic()-start,max_rss_kib=usage.ru_maxrss,user_cpu_seconds=usage.ru_utime,system_cpu_seconds=usage.ru_stime,final_head=git('rev-parse','HEAD'),final_worktree_status=git('status','--porcelain'))
info['log_sha256']=hashlib.sha256((out/'full-suite.log').read_bytes()).hexdigest()
if (out/'full-suite.xml').is_file():info['junit_sha256']=hashlib.sha256((out/'full-suite.xml').read_bytes()).hexdigest()
(out/'full-suite-run.json').write_text(json.dumps(info,indent=2)+'\n')
print(json.dumps({k:info[k] for k in ['source_commit','state','returncode','duration_seconds','max_rss_kib']}),flush=True)
raise SystemExit(result.returncode if result.returncode>=0 else 128-result.returncode)
