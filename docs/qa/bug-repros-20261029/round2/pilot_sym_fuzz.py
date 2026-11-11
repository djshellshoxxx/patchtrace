import random, string, time
from patchtrace.symbols.decoration import parse_decoration
random.seed(1)
alpha = '?@0123456789_$AaBbZzV.UWXYC'
t=time.time(); bad=0
worst=0
for n in range(300000):
    L = random.randint(0, 60)
    s = ''.join(random.choice(alpha) for _ in range(L))
    t0=time.time()
    try:
        d = parse_decoration(s)
    except Exception as e:
        bad+=1
        if bad<5: print('EXC', repr(s), type(e).__name__, e)
    worst=max(worst,time.time()-t0)
print('done', bad, time.time()-t, worst)
# adversarial
for s in ['?'+'a@'*250+'@@Z', '??0'+'a@'*250+'@@Z', '?a@0@1@2@3@4@5@6@7@8@9@@Z', '??1@@Z', '?@@Z', '??0a@@@Z', '?a@@', '?a@@@', '__imp_?a@@Z@4','@ILT+5(?a@@Z)','@ILT+5()' , '_R'+'0'*500, '_ZN'+'a17h'*100]:
    try:
        d=parse_decoration(s[:512]); print(d.kind, d.qualified_name and d.qualified_name[:40], d.tail, d.complex)
    except Exception as e: print('EXC', s[:30], type(e).__name__, e)
