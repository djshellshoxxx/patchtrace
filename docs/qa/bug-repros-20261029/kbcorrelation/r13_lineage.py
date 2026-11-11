import random, copy, collections, traceback
from patchtrace.kbcorrelation.lineage import index_rows, timeline, change_in_kb, predecessor
from patchtrace.kbcorrelation.resolver import resolve
from patchtrace.kbcorrelation.products import scope_for
good = lambda i, kb, sha, d, ubr, **k: {'sha256': sha*64 if len(sha)==1 else sha, 'kb': kb, 'version_key':'11-24H2', 'release_date': d,
   'release_version': ubr, 'heading': f'OS Build 26100.{ubr.split(".")[1]}', 'heading_class':'standard','variant':'full','download':'direct',
   'download_url':'https://x/y','record_sha256':'c'*64,'size':1000,'machine_type':0x8664,'file_version':'10.0.26100.1', **k}
rows=[good(0,'KB5000001','a','2099-01-01','26100.1'), good(1,'KB5000002','b','2099-02-01','26100.2'), good(2,'KB5000003','b','2099-03-01','26100.3'),
      good(3,'KB5000004','c','2099-04-01','26100.4')]
scope = scope_for('a'*64,'P','Windows 11 Version 24H2 for x64-based Systems')
print('winbindex_key', scope.winbindex_key)
r,rej = index_rows(rows, file_name='ntdll.dll'); print(len(r), rej)
res = resolve(r, kb='KB5000004', scope=scope, file_name='ntdll.dll'); print(res.changed_in_kb, [(p.older.sha256[:1],p.newer.sha256[:1],p.grade,p.reason_codes) for p in res.pairs])
res = resolve(r, kb='KB5000003', scope=scope, file_name='ntdll.dll'); print(res.changed_in_kb, res.last_changed_in, [(p.older.sha256[:1],p.newer.sha256[:1],p.grade,p.reason_codes) for p in res.pairs])
# fuzz
vals=[None,True,0,-1,10**30,1.5,'','x','٢٠٩٩-٠١-٠١','٢٦١٠٠.١','KB5000001','a'*64,[],{},['a'],' ', float('nan')]
random.seed(5); seen=collections.Counter(); ex={}
keys=list(rows[0].keys())
for n in range(6000):
    rs=copy.deepcopy(rows)
    for _ in range(random.choice([1,2,3])):
        row=random.choice(rs); row[random.choice(keys)] = copy.deepcopy(random.choice(vals))
    try:
        rr,_=index_rows(rs, file_name='ntdll.dll')
        for kb in ('KB5000001','KB5000003','KB5000004'):
            resolve(rr, kb=kb, scope=scope, file_name='ntdll.dll', fixed_build='26100.2')
    except Exception as e:
        tb=traceback.extract_tb(e.__traceback__)[-1]
        key=(type(e).__name__, tb.filename.split('/')[-1], tb.lineno); seen[key]+=1; ex.setdefault(key,str(e)[:100])
for k,c in seen.items(): print(c,k,ex[k])
print('fuzz crashes', sum(seen.values()))
