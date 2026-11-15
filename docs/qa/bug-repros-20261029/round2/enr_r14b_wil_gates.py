import sys, time
sys.path[:0] = [__import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'src')]
from patchtrace.enrichment import wil
from patchtrace.enrichment.views import FunctionView
# 20,000 lines (the views cap), many `if` per line, ONE Feature site: pure _gates cost
line = 'if (a) { b(); } ' * 6   # ~96 chars
code = [line] * 19_999 + ['x = Feature_1;']
f = FunctionView('f','a','r','newer','fn',0x1000,tuple(code),None,False)
print('chars', sum(map(len, code)), 'gates', sum(l.count('if (') for l in code))
t = time.time(); s = wil._scan(f); print(f'sites={len(s.sites)} _scan {time.time()-t:.1f}s')
