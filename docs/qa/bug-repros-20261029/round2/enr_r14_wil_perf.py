import sys, time
sys.path[:0] = [__import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'src')]
from patchtrace.enrichment import wil
from patchtrace.enrichment.views import FunctionView
def fv(code):
    return FunctionView('f','a','r','newer','fn',0x1000,tuple(code),None,False)
for gates in (10_000, 40_000):
    code = ['if (a) { b(); }'] * gates + ['x = Feature_%d;' % (i % 50) for i in range(4000)]
    f = fv(code)
    t = time.time(); s = wil._scan(f); print(f'gates={gates} sites={len(s.sites)} chars={sum(map(len,code))} _scan {time.time()-t:.1f}s', flush=True)
