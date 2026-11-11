import sys, time
sys.path[:0]=[__import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'src')]
from patchtrace.search import fuzzy
from patchtrace.search.contracts import FunctionRef
import random
rnd = random.Random(1)
def names(n, tag):
    return [FunctionRef(function_id=f'{tag}{i}', name=''.join(rnd.choice('abcdefghijklmnop') for _ in range(14)), side=tag) for i in range(n)]
for n in (5000, 20000):
    o = names(n,'older'); nw = names(n,'newer')
    t=time.time(); h=fuzzy.counterpart_hints(o,nw) ; print(n, 'hints', len(h), round(time.time()-t,1),'s')
