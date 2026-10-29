import json, random, copy, collections, traceback
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.sources.cvrf import SourceError
base = json.load(open('tests/fixtures/kbcorrelation/cvrf-2099-Feb-neg.json'))
vals = [None, True, False, 0, -1, 10**30, 1.5, '', 'x', 'KB1234', '\x00', '\ud800', 'CVE-2099-0001', [], {}, [1], ['a'], {'a': 1}, [[]], ' ', 'A'*70000, ['KB1234\x0bKB5555']]
def paths(o, p=()):
    yield p
    if isinstance(o, dict):
        for k, v in o.items(): yield from paths(v, p+(k,))
    elif isinstance(o, list):
        for i, v in enumerate(o): yield from paths(v, p+(i,))
allp = [p for p in paths(base) if p]
random.seed(1)
seen = collections.Counter(); ex = {}
def setp(o, p, v):
    for k in p[:-1]: o = o[k]
    o[p[-1]] = v
for n in range(6000):
    d = copy.deepcopy(base)
    for _ in range(random.choice([1,1,2])):
        p = random.choice(allp)
        try: setp(d, p, copy.deepcopy(random.choice(vals)))
        except Exception: pass
    try: raw = json.dumps(d).encode('utf-8', 'surrogatepass')
    except Exception: continue
    try:
        import_bytes(raw, now='2099-03-01T00:00:00Z')
    except SourceError: pass
    except Exception as e:
        key = (type(e).__name__, traceback.extract_tb(e.__traceback__)[-1].lineno, traceback.extract_tb(e.__traceback__)[-1].filename.split('/')[-1])
        seen[key] += 1; ex.setdefault(key, (p, raw[:0], str(e)[:100]))
for k, c in seen.items(): print(c, k, ex[k][0], ex[k][2])
print('done', sum(seen.values()))
