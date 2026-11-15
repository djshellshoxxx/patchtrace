import sys; sys.path.insert(0, __import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'tests'))
from pilot_localize_support import *
from patchtrace.pilot import read_model, report
cand = candidate(1, 'read_item')
cand2 = candidate(2, 'write_item')
bundle = build([cand, cand2], [], cves={CVE_A: (hypothesis('R-MEMORY-READ','CWE-125'),)})
a = run(bundle)
ctx = [c for c in a.cves if c.cve == CVE_A][0]
print('counts', ctx.counts)
m = read_model.LeadsModel(a)
for c in m.contexts: print(repr(c.label), '|', repr(c.counts_line), '| rows:', len(m.rows(c.cve)))
