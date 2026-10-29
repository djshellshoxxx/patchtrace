import sys, time, resource
sys.path.insert(0,'tests')
from kev_helpers import document, entry, render, parse_bytes
rows=[entry(i, shortDescription='x'*4096, notes='y; '*1000, vendorProject='‮'*100) for i in range(1,20001)]
raw=render(document(rows, **{'x'*10:1}))
print('bytes', len(raw))
t=time.time()
try: parse_bytes(raw)
except Exception as e: print(type(e).__name__, getattr(e,'code',''), str(e)[:80])
print('secs %.1f'%(time.time()-t))
rows=[entry(i) for i in range(1,20001)]
raw=render(document(rows)); print('realistic bytes',len(raw)); t=time.time(); parse_bytes(raw); print('secs %.1f'%(time.time()-t), 'maxrss MB', resource.getrusage(resource.RUSAGE_SELF).ru_maxrss//1024)
