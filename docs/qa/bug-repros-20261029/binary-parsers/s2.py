import time, random
from patchtrace.strings.edits import Candidate, pair_edits
random.seed(1)
def mk(tag, n, L=253):
    out=[]
    for i in range(n):
        s=''.join(random.choice('ab') for _ in range(L))
        out.append(Candidate(f'{tag}{i}'.encode(), s, frozenset({'f1'})))
    return out
o=mk('o',64); n=mk('n',64)
t=time.time(); r=pair_edits(o,n); print('64x64 one function: %.1fs'%(time.time()-t), len(r.pairs))
# many functions
import sys
K=int(sys.argv[1]) if len(sys.argv)>1 else 0
