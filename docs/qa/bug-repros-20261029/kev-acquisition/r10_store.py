import sys, tempfile, os, json
sys.path.insert(0,'tests')
from pathlib import Path
from kev_helpers import document, entry, render, at
from patchtrace.kev.service import KevService
from patchtrace.kev.store import KevStore
d = tempfile.mkdtemp(); svc = KevService(d, now=lambda: at(2098,2,2))
def put(rel, n=2, **kw):
    raw = render(document([entry(i) for i in range(1,n+1)], dateReleased=rel, catalogVersion=rel[:10].replace('-','.')))
    p = f'{d}/in_{rel[:10]}.json'; open(p,'wb').write(raw); return svc.import_file(p, **kw)
# round trip with lone surrogate
raw = b'{"catalogVersion":"1","dateReleased":"2098-01-10T10:00:00Z","count":1,"vulnerabilities":[{"cveID":"CVE-2098-0001","vendorProject":"a\\ud800","product":"b","vulnerabilityName":"n","dateAdded":"2098-01-01","shortDescription":"d","requiredAction":"r","dueDate":"2098-01-02","notes":"x\\ud800y"}]}'
open(d+'/s.json','wb').write(raw); r = svc.import_file(d+'/s.json'); print('surrogate import', r.result.outcome, 'load ok:', svc.store.load_current() is not None)
a = put('2098-02-01T00:00:00Z'); b = put('2098-02-05T00:00:00Z'); c = put('2098-02-09T00:00:00Z')
store = svc.store
# damage: delete snapshot file of b but leave meta; then prune keep=1
bm = store.read_meta(b.meta.snapshot_id)
os.unlink(store.root/'snapshots'/f'{bm.raw_sha256}.json.gz')
print('before prune meta files', sorted(os.listdir(store.root/'meta')).__len__())
res = store.prune(1, yes=True)
print('prune removed', len(res.removed), 'meta files left', len(os.listdir(store.root/'meta')), 'snaps left', len(os.listdir(store.root/'snapshots')))
print('orphan meta of missing snapshot still present:', (store.root/'meta'/f'{b.meta.snapshot_id}.json').exists())
