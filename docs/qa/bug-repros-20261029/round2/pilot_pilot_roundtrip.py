import sys; sys.path.insert(0, __import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'tests'))
from pilot_localize_support import *
from patchtrace.pilot import report, keys, store
from patchtrace.pilot.contracts import PilotAssessment
names = ['café', 'café', '\U0001F600x', 'é́', 'ﬁ', 'Å', 'Å']
cands = [candidate(i, n) for i, n in enumerate(names)]
a = run(build(cands, [(cands[0], observation('b1:BND', ref='s1', line=14, detail='café detail'))], cves={CVE_A: (hypothesis('R-MEMORY-READ','CWE-125'),)}))
txt = report.to_json(a)
b = PilotAssessment.model_validate_json(txt)
print('roundtrip equal:', a == b)
keys.verify_assessment(b)
# canonical sidecar roundtrip
data = keys.canonical_bytes(a)
c = PilotAssessment.model_validate_json(data)
print('canonical roundtrip equal:', a == c)
if a != c:
    for x, y in zip(a.leads, c.leads):
        if x != y: print(x.older, y.older); break
keys.verify_assessment(c)
m = keys.make_manifest(a, keys.default_config(), created_utc='2099-01-01T00:00:00Z')
try:
    keys.verify_manifest(m, c); print('verify manifest vs read-back ok')
except Exception as e: print('verify manifest FAIL', e)
