import json, random, copy, collections, traceback
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.sources.cvrf import SourceError
from patchtrace.kbcorrelation.wiring import IntelligenceAdvisory
adv = IntelligenceAdvisory()
base = json.load(open('tests/fixtures/kbcorrelation/csaf-kb-valid.json'))
raw0 = json.dumps(base).encode()
d = import_bytes(raw0, now='2099-03-01T00:00:00Z', advisory=adv)
print(d.counts(), [e.relation for e in d.edges][:5])
vals=[None,True,0,-1,10**30,1.5,'','x','KB1234','CVE-2099-0001',[],{},['a'],' ','https://support.microsoft.com/help/1234\n','details KB5000001',[1]]
def paths(o,p=()):
    yield p
    if isinstance(o,dict):
        for k,v in o.items(): yield from paths(v,p+(k,))
    elif isinstance(o,list):
        for i,v in enumerate(o): yield from paths(v,p+(i,))
allp=[p for p in paths(base) if p]
def setp(o,p,v):
    for k in p[:-1]: o=o[k]
    o[p[-1]]=v
random.seed(3); seen=collections.Counter(); ex={}; ok=0
for n in range(3000):
    dd=copy.deepcopy(base)
    for _ in range(random.choice([1,2])):
        p=random.choice(allp)
        try: setp(dd,p,copy.deepcopy(random.choice(vals)))
        except Exception: pass
    raw=json.dumps(dd).encode()
    try: import_bytes(raw, now='2099-03-01T00:00:00Z', advisory=adv); ok+=1
    except SourceError: pass
    except Exception as e:
        tb=traceback.extract_tb(e.__traceback__)[-1]
        key=(type(e).__name__, tb.filename.split('/')[-1], tb.lineno); seen[key]+=1; ex.setdefault(key,(p,str(e)[:100]))
print('accepted',ok)
for k,c in seen.items(): print(c,k,ex[k])
