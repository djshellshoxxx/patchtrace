import sys, tempfile
sys.path.insert(0,'tests')
from kev_helpers import document, entry, render, parse_bytes, at
from patchtrace.kev.service import KevService
from patchtrace.kev.contracts import KevError
d = tempfile.mkdtemp()
svc = KevService(d, now=lambda: at(2026,10,29))
def put(released, n=2):
    raw = render(document([entry(i) for i in range(1,n+1)], dateReleased=released, catalogVersion=released[:10].replace('-','.')))
    p = f'{d}/f_{released[:4]}.json'; open(p,'wb').write(raw); return svc.import_file(p)
r = put('2099-01-01T00:00:00Z')            # typo/hostile catalog: release date 73 years in the future
print('future install  :', r.result.outcome)
r = put('2026-10-29T08:00:00Z')            # the genuine catalog released today
print('genuine install :', r.result.outcome, 'in use =', r.in_use.date_released)
cur = svc.store.load_current().catalog.meta
print('current now     :', cur.catalog_version, cur.date_released)
