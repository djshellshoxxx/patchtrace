import json, time, tracemalloc
from dataclasses import replace
from patchtrace.kbcorrelation.sources import cvrf
from patchtrace.kbcorrelation.limits import KbcLimits
N=2000; K=50
calls=0
orig=cvrf.make_edge
def counting(**kw):
    global calls; calls+=1; return orig(**kw)
cvrf.make_edge=counting
prods=[{'product_id':f'P{i}','name':f'Mystery product {i}'} for i in range(N)]
desc='\n'.join(f'KB{1000+k}' for k in range(K))
d={'dialect':'cvrf-json/0','document':{'release_id':'2099-Feb'},'product_tree':prods,
   'vulnerabilities':[{'cve':'CVE-2099-0001','remediations':[{'type':2,'description':desc,'product_ids':[p['product_id'] for p in prods]}]}]}
raw=json.dumps(d).encode()
lim=KbcLimits(cvrf_edges_per_doc=1000)
doc=cvrf.parse_cvrf(raw,lim)
t=time.time()
try:
    cvrf.build_edges(doc,'a'*64,lim)
except cvrf.SourceError as e: print('raised',e.code)
print(f'limit=1000 edges; make_edge calls before refusal = {calls} (N*K={N*K}); {time.time()-t:.1f}s')
