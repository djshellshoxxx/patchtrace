import sys; sys.path.insert(0, __import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'tests'))
from pilot_localize_support import *
cands = [candidate(i, f'fn_{i}') for i in range(300)]
a = run(build(cands, [], cves={CVE_A: (hypothesis('R-MEMORY-READ','CWE-125'),), CVE_B: (hypothesis('R-MEMORY-READ','CWE-125'),)}))
print('candidates', len(cands), 'queue_count', a.queue_count)
print([l for l in a.limitations if 'no fit' in l])
print({str(c.cve): c.counts.queue for c in a.cves})
