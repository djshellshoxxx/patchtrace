import sys, tempfile
sys.path.insert(0,'tests')
from kev_helpers import document, entry, render, parse_bytes, RETRIEVED
from patchtrace.kev import store as S
d = tempfile.mkdtemp(); st = S.KevStore(d)
def cat(rel):
    raw = render(document([entry(1),entry(2)], dateReleased=rel, catalogVersion=rel[:10])); return raw, parse_bytes(raw)
raw1, c1 = cat('2098-02-01T00:00:00Z'); st.install(raw1, c1, now=RETRIEVED)
raw2, c2 = cat('2098-02-02T00:00:00Z')
orig = S._publish; state = {'n': 0}
def racing(directory, name, data, sleep):
    orig(directory, name, data, sleep)
    state['n'] += 1
    if state['n'] == 1:                    # right after the snapshot file of install #2 is written, another process prunes
        print('concurrent prune:', st.prune(5, yes=True))
S._publish = racing
print('install ->', st.install(raw2, c2, now=RETRIEVED).outcome)
S._publish = orig
print('load_current:', st.load_current().notes if st.load_current() else None, '| in use:', st.load_current().catalog.meta.date_released)
print('pointer names:', st._read_pointer()[0].snapshot_id[:8], 'new snapshot:', c2.meta.snapshot_id[:8])
try: st.load(c2.meta.snapshot_id)
except Exception as e: print('load(new) ->', e)
