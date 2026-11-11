from enr_h import *
import random, collections
from patchtrace.search.errors import SearchError
s, svc = make()
search(s, 'container')  # build
rnd = random.Random(7)
alpha = list('ab AND OR NOT NEAR ( ) " * - : ^ { } + ~ . , _ @ ? 0x1f 12345 \\ \' ; %') + ['é','ß','ﬃ','İ','٣','①','Ⅷ','́','中','🙂','ﷺ','­','​','kind:','side:','in:','is:','scope:','NEAR(','kind:string']
mx = ['auto','words','exact','prefix','substring','similar']
seen = collections.Counter(); samples = {}
for i in range(4000):
    q = ' '.join(''.join(rnd.choice(alpha) for _ in range(rnd.randint(1,4))) for _ in range(rnd.randint(1,5)))
    mode = rnd.choice(mx)
    try:
        r = search(s, q, mode=mode); seen['ok']+=1
    except SearchError as e:
        seen[e.code]+=1
        if e.code != 'PT-SEARCH-QUERY': samples.setdefault(e.code,(q,mode,e.message))
    except Exception as e:
        k=type(e).__name__; seen[k]+=1; samples.setdefault(k,(q,mode,str(e)[:100]))
print(seen); print(samples)
