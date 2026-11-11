import sys; sys.path.insert(0, __import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'tests'))
from pilot_localize_support import *
from patchtrace.pilot import why, contracts as c
cand = candidate(1, 'read_item')
bundle = build([cand], [(cand, observation('b1:BND', ref='s1', line=14))], cves={CVE_A: (hypothesis('R-MEMORY-READ','CWE-125'),)})
a = run(bundle)
lead = a.leads[0]
refs = tuple(c.FunctionRef(rva=0x1000+i*16, name=f'fn_{i}') for i in range(10)) + (c.FunctionRef(rva=0x2000, name='fn_0'),)
lead = lead.model_copy(update={'older': tuple(sorted(refs, key=lambda r: r.rva)), 'newer': tuple(sorted(refs, key=lambda r: r.rva))})
ex = why.Explainer(a)
for l in ex.explain(lead):
    if 'Older' in l: print(l)
print('---- footer when many alternatives')
alts = tuple(observation('die:toolchain-changed', role='context', ref=f'r{i}', detail=f'alt {i}') for i in range(70))
lead2 = a.leads[0]
a2 = a.model_copy(update={'observations': tuple(sorted(a.observations + alts, key=lambda o: o.obs_id))})
lead2 = lead2.model_copy(update={'alternative_ids': tuple(sorted(o.obs_id for o in alts))})
lines = why.Explainer(a2).explain(lead2)
print(len(lines), lines[-2:])
print('FOOTER present:', any(why.FOOTER in l for l in lines))
