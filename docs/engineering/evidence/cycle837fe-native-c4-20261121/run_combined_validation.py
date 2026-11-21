from __future__ import annotations
import datetime, json, os, resource, subprocess, sys, time
from pathlib import Path
import xml.etree.ElementTree as ET
ROOT=Path('/workspace/scratch/837fe19aae3a')
PLAN=json.loads((ROOT/'native-c4-test-plan.json').read_text())
CWD=Path(PLAN['cwd'])
OUT=ROOT/'evidence/native-c4-final'
OUT.mkdir(parents=True, exist_ok=True)
def git(*args):
    return subprocess.check_output(['git',*args],cwd=CWD,text=True).strip()
def run(label,command):
    receipt={'label':label,'command':command,'cwd':str(CWD),'head':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'dirty_before':git('status','--porcelain'),'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'qt_platform':'offscreen','pythonpath':None}
    if receipt['dirty_before']: raise RuntimeError('Candidate must be clean')
    env=dict(os.environ);env.pop('PYTHONPATH',None);env['QT_QPA_PLATFORM']='offscreen'
    started=time.monotonic()
    with (OUT/(label+'.log')).open('w') as log:
        child=subprocess.Popen(command,cwd=CWD,env=env,stdout=log,stderr=subprocess.STDOUT)
        receipt['pid']=child.pid
        (OUT/(label+'.running.json')).write_text(json.dumps(receipt,indent=2)+'\n')
        receipt['returncode']=child.wait()
    receipt['seconds']=round(time.monotonic()-started,3)
    receipt['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    receipt['head_after']=git('rev-parse','HEAD');receipt['dirty_after']=git('status','--porcelain')
    receipt['child_ru_maxrss_kib_observed']=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    if label=='focused' and (OUT/'focused.xml').exists():
        cases=list(ET.parse(OUT/'focused.xml').getroot().iter('testcase'))
        counts={'passed':0,'failed':0,'errors':0,'skipped':0,'xfailed':0}
        for c in cases:
            if c.find('failure') is not None:counts['failed']+=1
            elif c.find('error') is not None:counts['errors']+=1
            elif c.find('skipped') is not None:counts['xfailed' if c.find('skipped').get('type')=='pytest.xfail' else 'skipped']+=1
            else:counts['passed']+=1
        receipt['junit_counts']=counts;receipt['case_count']=len(cases)
        receipt['distinct_case_count']=len({(c.get('classname'),c.get('name')) for c in cases})
        receipt['expected_failure_ids']=[c.get('classname','')+'::'+c.get('name','') for c in cases if c.find('skipped') is not None and c.find('skipped').get('type')=='pytest.xfail']
    (OUT/(label+'.json')).write_text(json.dumps(receipt,indent=2)+'\n')
    (OUT/(label+'.running.json')).unlink()
    print(json.dumps(receipt),flush=True)
    return receipt['returncode']
label=sys.argv[1]
commands={'focused':[PLAN['python'],'-m','pytest','-q',*PLAN['selection'],'--junitxml='+str(OUT/'focused.xml')], 'ruff':[PLAN['python'],'-m','ruff','check','src','tests','tools'], 'dependencies':[PLAN['python'],'-m','pip','check'], 'source-binding':[PLAN['python'],'-I','-c',"from pathlib import Path; import patchtrace; p=Path(patchtrace.__file__).resolve(); print(p); assert p == Path('/workspace/scratch/837fe19aae3a/PatchTrace-native-followup/src/patchtrace/__init__.py')"]}
sys.exit(run(label,commands[label]))
